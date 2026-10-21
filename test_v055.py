"""v0.55: name services on the DNS layout (multicast DNS, NetBIOS name service opcodes, hinted LLMNR)."""
import random
import unittest

from protocol_engine import Config, Inspector
from protocol_engine.appid import classify
from protocol_engine.datagram import DatagramInspector
from protocol_engine.wire import dns_probe
from protocol_fixtures import (DNS, DNS_RESPONSE, LLMNR_CONFLICT, LLMNR_QUERY, LLMNR_RESPONSE, MDNS_ANNOUNCEMENT, MDNS_KNOWN_ANSWER, MDNS_PLAIN_QUERY,
                               MDNS_PROBE, MDNS_QUERY, MDNS_RESPONSE, MDNS_SHARED_ANNOUNCEMENT, NBNS_NEGATIVE_RESPONSE, NBNS_POSITIVE_RESPONSE, NBNS_QUERY,
                               NBNS_QUERY_RESPONSE, NBNS_REFRESH, NBNS_REGISTRATION, NBNS_RELEASE, NBNS_WACK, NBSTAT_RESPONSE, RIP_RESPONSE, dns_message,
                               dns_name, dns_record, nbstat_response, netbios_name)

LOCAL_A = dns_name(b"laptop", b"local") + b"\x00\x01\x00\x01"


def datagram(data, hint=None, config=None):
    return DatagramInspector(config).inspect(data, hint)


def fields(observation, *names):
    return {e.field: e.value for e in observation.evidence if e.field in names}


def stream(data, hint=None):
    inspector = Inspector(protocol_hint=hint)
    inspector.feed(data)
    inspector.end()
    return inspector.observation


class MulticastDNSTests(unittest.TestCase):
    CASES = ((MDNS_QUERY, "query", "ptr", "unicast-requested"), (MDNS_PLAIN_QUERY, "query", "a", "plain"), (MDNS_RESPONSE, "response", "ptr", "announcement"),
             (MDNS_KNOWN_ANSWER, "query", "ptr", "known-answer"), (MDNS_PROBE, "query", "any", "probe"), (MDNS_ANNOUNCEMENT, "response", "a", "announcement"),
             (MDNS_SHARED_ANNOUNCEMENT, "response", "ptr", "announcement"))

    def test_profiles_identify_with_closed_labels(self):
        for data, message, qtype, profile in self.CASES:
            observation = datagram(data)
            self.assertEqual((observation.status, observation.application_protocol), ("identified", "mdns"), data)
            self.assertEqual(fields(observation, "dns_message", "dns_query_type", "mdns_profile"),
                             {"dns_message": message, "dns_query_type": qtype, "mdns_profile": profile}, data)
            verdict = classify(observation, "udp", 5353)
            self.assertEqual((verdict.app, verdict.port_usage), ("mdns", "standard"))
            self.assertNotIn("Printer", repr(observation))
            self.assertNotIn("laptop", repr(observation))
            self.assertNotIn("192.0.2", repr(observation))
        self.assertEqual(datagram(MDNS_QUERY, "mdns").application_protocol, "mdns")
        self.assertEqual(datagram(MDNS_QUERY, "dns").application_protocol, "mdns")     # the dns candidate decides the family by structure
        self.assertEqual(fields(datagram(MDNS_RESPONSE), "dns_rcode"), {"dns_rcode": "noerror"})
        # Unicast DNS stays dns: no marker, one question.
        self.assertEqual((datagram(DNS).application_protocol, datagram(DNS_RESPONSE).application_protocol), ("dns", "dns"))
        self.assertEqual(classify(datagram(DNS), "udp", 53).app, "dns")

    def test_marker_and_section_rules(self):
        local_query = dns_message(0, 0x0000, questions=(LOCAL_A,))
        self.assertEqual(fields(datagram(local_query), "mdns_profile"), {"mdns_profile": "plain"})      # .local alone is a marker
        example = dns_name(b"laptop", b"example") + b"\x00\x01\x00\x01"
        self.assertEqual(datagram(dns_message(0, 0x0000, questions=(example,))).application_protocol, "dns")
        self.assertEqual(datagram(dns_message(0, 0x0000, questions=(dns_name(b"laptop", b"localdomain") + b"\x00\x01\x00\x01",))).application_protocol, "dns")
        qu_example = dns_message(0, 0x0000, questions=(dns_name(b"laptop", b"example") + b"\x00\x01\x80\x01",))
        self.assertEqual(fields(datagram(qu_example), "mdns_profile"), {"mdns_profile": "unicast-requested"})   # the QU bit is a marker on its own
        two_plain = dns_message(0, 0x0000, questions=(example, example))
        self.assertEqual(datagram(two_plain).status, "unknown")                                        # several questions without markers
        self.assertEqual(datagram(dns_message(0, 0x0000, questions=(LOCAL_A,) * 8)).application_protocol, "mdns")
        self.assertEqual(datagram(dns_message(0, 0x0000, questions=(LOCAL_A,) * 9)).status, "unknown")   # question budget
        # Review round 1: a query never carries the cache-flush bit (RFC 6762 10.2), in known answers or probe authority records.
        service = dns_name(b"_http", b"_tcp", b"local")
        flushed_known_answer = dns_message(0, 0x0000, questions=(service + b"\x00\x0c\x00\x01",),
                                           answers=(dns_record(service, 12, 0x8001, 4500, dns_name(b"p", b"_http", b"_tcp", b"local")),))
        flushed_probe = dns_message(0, 0x0000, questions=(LOCAL_A[:-4] + b"\x00\xff\x80\x01",),
                                    authority=(dns_record(dns_name(b"laptop", b"local"), 1, 0x8001, 120, bytes(4)),))
        self.assertEqual(datagram(flushed_known_answer).status, "malformed")
        self.assertEqual(datagram(flushed_probe).status, "malformed")
        # A shared record announcement (no question, no flush bit) is named by its first record owner.
        shared = datagram(MDNS_SHARED_ANNOUNCEMENT)
        self.assertEqual((shared.application_protocol, fields(shared, "mdns_profile", "dns_query_type")), ("mdns", {"mdns_profile": "announcement", "dns_query_type": "ptr"}))
        two_shared = dns_message(0, 0x8400, answers=(dns_record(service, 12, 1, 4500, dns_name(b"a", b"_http", b"_tcp", b"local")),
                                                     dns_record(b"\xc0\x0c", 12, 1, 4500, dns_name(b"b", b"_http", b"_tcp", b"local"))))   # compressed second owner
        self.assertEqual(fields(datagram(two_shared), "mdns_profile"), {"mdns_profile": "announcement"})
        malformed = (
            dns_message(0, 0x8000, answers=(dns_record(dns_name(b"laptop", b"local"), 1, 1, 120, bytes(4)),)),   # response without AA
            dns_message(0, 0x8403, answers=(dns_record(dns_name(b"laptop", b"local"), 1, 0x8001, 120, bytes(4)),)),   # rcode on a response
            dns_message(0, 0x0400, questions=(LOCAL_A,)),                                              # AA on a query
            dns_message(0, 0x0003, questions=(LOCAL_A,)),                                              # rcode on a query
            dns_message(0, 0x8400, answers=(dns_record(dns_name(b"laptop", b"example"), 1, 1, 120, bytes(4)),)),   # no question, no marker
            dns_message(0, 0x8400, answers=(dns_record(dns_name(b"laptop", b"local"), 1, 0x8001, 120, bytes(3)),)),   # bad A size
            MDNS_RESPONSE[:-1],
        )
        for data in malformed:
            self.assertEqual(datagram(data).status, "malformed", data[:12].hex())
        # Unsolicited announcement probe: a zero-question message must be a response with answers.
        self.assertFalse(dns_probe(dns_message(0, 0x0000)))
        self.assertFalse(dns_probe(dns_message(0, 0x8400)))
        self.assertFalse(dns_probe(dns_message(0, 0x8400, answers=(b"\x00" + b"\x00\x01\x00\x01" + bytes(6),))))   # root first label
        self.assertTrue(dns_probe(MDNS_ANNOUNCEMENT))
        self.assertFalse(dns_probe(RIP_RESPONSE))
        self.assertFalse(dns_probe(MDNS_ANNOUNCEMENT[:12]))
        self.assertTrue(dns_probe(DNS[:12]))                                                          # the TCP dispatch passes twelve header bytes
        # Over TCP the family stays dns; the marker row is kept. (mDNS is UDP only: a TCP message with the all-zero
        # mDNS flags word reads as a Kafka header on the TCP route, a pre-existing dispatch order outside this profile.)
        tcp_query = dns_message(0x1234, 0x0100, questions=(dns_name(b"laptop", b"local") + b"\x00\x01\x00\x01",))
        tcp = stream(len(tcp_query).to_bytes(2, "big") + tcp_query)
        self.assertEqual((tcp.application_protocol, fields(tcp, "mdns_profile")), ("dns", {"mdns_profile": "plain"}))
        self.assertEqual(classify(tcp, "tcp", 53).app, "dns")

    def test_mutations_and_contexts_are_bounded(self):
        rng = random.Random(55)
        for data, _, _, _ in self.CASES:
            for _ in range(60):
                changed = bytearray(data)
                changed[rng.randrange(len(changed))] = rng.randrange(256)
                observation = datagram(bytes(changed))
                self.assertIn(observation.status, ("identified", "unknown", "malformed", "budget_exhausted"))
                self.assertNotIn("Printer", repr(observation))
            for cut in range(len(data)):
                self.assertIn(datagram(data[:cut]).status, ("unknown", "malformed", "budget_exhausted"))
        with_contexts = datagram(MDNS_QUERY, config=Config(retain_contexts=True))
        self.assertEqual((with_contexts.application_protocol, fields(with_contexts, "mdns_profile")), ("mdns", {"mdns_profile": "unicast-requested"}))
        heuristics = datagram(MDNS_QUERY, config=Config(heuristics=True))
        self.assertEqual(fields(heuristics, "dns_query_shape"), {"dns_query_shape": "ordinary"})


class NetBIOSNameServiceTests(unittest.TestCase):
    CASES = ((NBNS_QUERY, "query", "query", "noerror"), (NBNS_REGISTRATION, "query", "registration", None), (NBNS_RELEASE, "query", "release", None),
             (NBNS_REFRESH, "query", "refresh", None), (NBNS_WACK, "response", "wack", "noerror"), (NBNS_POSITIVE_RESPONSE, "response", "registration", "noerror"),
             (NBNS_NEGATIVE_RESPONSE, "response", "registration", "yxdomain"), (NBNS_QUERY_RESPONSE, "response", "query", "noerror"),
             (NBSTAT_RESPONSE, "response", "query", "noerror"))

    def test_opcodes_identify_the_family(self):
        for data, message, opcode, rcode in self.CASES:
            observation = datagram(data)
            self.assertEqual((observation.status, observation.application_protocol), ("identified", "netbios-ns"), data[:4].hex())
            expected = {"dns_message": message, "nbns_opcode": opcode, "dns_query_type": "nbstat" if data is NBSTAT_RESPONSE else "nb"}
            if message == "response":
                expected["dns_rcode"] = rcode
            self.assertEqual(fields(observation, "dns_message", "nbns_opcode", "dns_query_type", "dns_rcode"), expected, data[:4].hex())
            verdict = classify(observation, "udp", 137)
            self.assertEqual((verdict.app, verdict.port_usage), ("netbios-ns", "standard"))
            self.assertNotIn("FILESERVER", repr(observation))
            self.assertNotIn(netbios_name(b"FILESERVER")[1:33].decode(), repr(observation))
            self.assertNotIn("192.0.2", repr(observation))
        self.assertEqual(datagram(NBNS_REGISTRATION, "netbios-ns").application_protocol, "netbios-ns")
        self.assertEqual(datagram(NBNS_REGISTRATION, "dns").application_protocol, "netbios-ns")
        self.assertEqual(classify(datagram(NBNS_NEGATIVE_RESPONSE), "udp", 137).risks, ())          # ACT_ERR (yxdomain) is not a flow risk
        refused = NBNS_NEGATIVE_RESPONSE[:3] + bytes((0x85,)) + NBNS_NEGATIVE_RESPONSE[4:]              # RFS_ERR reads as refused
        self.assertEqual((fields(datagram(refused), "dns_rcode"), classify(datagram(refused), "udp", 137).risks), ({"dns_rcode": "refused"}, ("dns-error-response",)))

    def test_section_and_name_rules(self):
        nb = netbios_name(b"FILESERVER")
        question = nb + b"\x00\x20\x00\x01"
        address = dns_record(b"\xc0\x0c", 32, 1, 300000, b"\x00\x00" + bytes((192, 0, 2, 5)))
        malformed = (
            dns_message(0x8001, 0x2910, questions=(question,)),                                            # registration without the additional record
            dns_message(0x8001, 0x2910, questions=(question,), additional=(address, address)),             # two additional records
            dns_message(0x8001, 0x2910, questions=(question,), answers=(address,)),                        # answers in a request
            dns_message(0x8001, 0x2913, questions=(question,), additional=(address,)),                     # rcode in a request
            dns_message(0x8001, 0x2910, questions=(question,), additional=(dns_record(b"\xc0\x0c", 32, 1, 300000, b"\x00\x00" + bytes(3)),)),   # 5-byte NB data
            dns_message(0x8001, 0xad80, answers=(dns_record(nb, 32, 1, 300000, b"\x00\x00" + bytes(4)),), additional=(address,)),   # response with additional
            NBNS_WACK[:-1],
        )
        for data in malformed:
            self.assertEqual(datagram(data).status, "malformed", data[:4].hex())
        # Review round 1: record data keyed by message kind (RFC 1002 4.2.x).
        nb_record = lambda rdata, opcode_flags=0x8580: dns_message(0x8004, opcode_flags, answers=(dns_record(nb, 32, 1, 300000, rdata),))
        self.assertEqual(datagram(nb_record(b"\x29\x10")).status, "malformed")                       # two-byte data outside a WACK
        self.assertEqual(datagram(nb_record(b"\x00\x00" + bytes(4) + b"\x00\x00" + bytes(4))).application_protocol, "netbios-ns")   # multi-homed
        self.assertEqual(datagram(nb_record(b"\x00\x01" + bytes(4))).status, "malformed")             # NB_FLAGS reserved bit
        self.assertEqual(fields(datagram(nb_record(b"\x80\x00" + bytes(4))), "nbns_opcode"), {"nbns_opcode": "query"})   # group name flag is legal
        self.assertEqual(datagram(dns_message(0x8004, 0xbc00, answers=(dns_record(nb, 32, 1, 2, b"\x29\x10\x00\x00\x00\x00"),))).status, "malformed")   # WACK with 6 bytes
        self.assertEqual(datagram(dns_message(0x8004, 0x3c00, questions=(question,), additional=(dns_record(b"\xc0\x0c", 32, 1, 2, b"\x29\x10"),))).status, "malformed")   # WACK as a request
        status_rr = lambda rdata: dns_message(0x8004, 0x8400, answers=(dns_record(nb, 33, 1, 0, rdata),))
        self.assertEqual(datagram(status_rr(b"")).status, "malformed")                                   # empty node status
        self.assertEqual(datagram(status_rr(bytes((5,)) + bytes(18 * 2 + 46))).status, "malformed")      # NUM_NAMES beyond the data
        self.assertEqual(datagram(status_rr(bytes((1,)) + bytes(18 + 45))).status, "malformed")          # statistics truncated
        self.assertEqual(datagram(nbstat_response(names=0)).application_protocol, "netbios-ns")
        self.assertEqual(datagram(nbstat_response(flags=0x0401)).status, "malformed")                   # NAME_FLAGS reserved bit
        self.assertEqual(datagram(nbstat_response(flags=0xe400)).application_protocol, "netbios-ns")    # group, H-node, active
        self.assertEqual(datagram(dns_message(0x8004, 0x0000, questions=(nb + b"\x00\x21\x00\x01",), answers=(dns_record(nb, 33, 1, 0, bytes((0,)) + bytes(46)),))).status, "malformed")   # node status in a request
        self.assertNotIn("FILESERVER", repr(datagram(NBSTAT_RESPONSE)))
        # Opcodes 5..8 need the encoded name; an ordinary name with a registration opcode is outside every profile.
        # (Transaction ids 0x0001/0x0002 would also select the TFTP candidate, whose rejection is malformed.)
        plain = dns_message(0x8001, 0x2910, questions=(dns_name(b"fileserver") + b"\x00\x20\x00\x01",),
                            additional=(dns_record(b"\xc0\x0c", 32, 1, 300000, b"\x00\x00" + bytes(4)),))
        self.assertEqual(datagram(plain).status, "unknown")
        self.assertEqual(datagram(dns_message(0x8001, 0x4810, questions=(question,), additional=(address,))).status, "unknown")   # opcode 9
        self.assertEqual(datagram(dns_message(0x8001, 0x2910, questions=(question, question), additional=(address,))).status, "unknown")   # two questions
        # A query-opcode NB question over TCP stays dns with its rows; registrations over TCP are not a profile.
        tcp = stream(len(NBNS_QUERY).to_bytes(2, "big") + NBNS_QUERY)
        self.assertEqual((tcp.application_protocol, fields(tcp, "nbns_opcode", "dns_query_type")), ("dns", {"nbns_opcode": "query", "dns_query_type": "nb"}))
        self.assertEqual(classify(tcp, "tcp", 137).app, "netbios-ns")
        self.assertEqual(stream(len(NBNS_REGISTRATION).to_bytes(2, "big") + NBNS_REGISTRATION).status, "unknown")

    def test_mutations_stay_bounded_and_isolated(self):
        rng = random.Random(137)
        for data, _, _, _ in self.CASES:
            for _ in range(60):
                changed = bytearray(data)
                changed[rng.randrange(len(changed))] = rng.randrange(256)
                observation = datagram(bytes(changed))
                self.assertIn(observation.status, ("identified", "unknown", "malformed", "budget_exhausted"))
                self.assertNotIn("FILESERVER", repr(observation))
            for cut in range(len(data)):
                self.assertNotEqual(datagram(data[:cut]).status, "identified")
        self.assertEqual(datagram(RIP_RESPONSE).application_protocol, "rip/2")                      # RIP words never read as a DNS layout


class LLMNRTests(unittest.TestCase):
    def test_hint_only_profile(self):
        for data, message, flags in ((LLMNR_QUERY, "query", "none"), (LLMNR_RESPONSE, "response", "none"), (LLMNR_CONFLICT, "query", "conflict")):
            observation = datagram(data, "llmnr")
            self.assertEqual((observation.status, observation.application_protocol), ("identified", "llmnr"), data[:4].hex())
            self.assertEqual(fields(observation, "dns_message", "llmnr_flags", "dns_query_type"), {"dns_message": message, "llmnr_flags": flags, "dns_query_type": "a"})
            self.assertEqual(classify(observation, "udp", 5355).app, "llmnr")
            self.assertNotIn("laptop", repr(observation))
        # Without the hint the same bytes are DNS (or malformed where the C bit reads as AA): the port never decides.
        self.assertEqual(datagram(LLMNR_QUERY).application_protocol, "dns")
        self.assertEqual(datagram(LLMNR_CONFLICT).status, "malformed")
        tentative = dns_message(1, 0x8100, questions=(dns_name(b"laptop") + b"\x00\x01\x00\x01",),
                                answers=(dns_record(dns_name(b"laptop"), 1, 1, 30, bytes(4)),))
        self.assertEqual(fields(datagram(tentative, "llmnr"), "llmnr_flags"), {"llmnr_flags": "tentative"})
        malformed = (dns_message(1, 0x0100, questions=(dns_name(b"laptop") + b"\x00\x01\x00\x01",)),          # T bit on a query
                     dns_message(1, 0x0003, questions=(dns_name(b"laptop") + b"\x00\x01\x00\x01",)),          # rcode on a query
                     dns_message(1, 0x0000, questions=(dns_name(b"laptop") + b"\x00\x01\x00\x01",), answers=(dns_record(dns_name(b"laptop"), 1, 1, 30, bytes(4)),)))
        for data in malformed:
            self.assertEqual(datagram(data, "llmnr").status, "malformed", data[:4].hex())
        unsupported = (dns_message(1, 0x0010, questions=(dns_name(b"laptop") + b"\x00\x01\x00\x01",)),        # Z bits
                       dns_message(1, 0x0800, questions=(dns_name(b"laptop") + b"\x00\x01\x00\x01",)),        # opcode 1
                       dns_message(1, 0x0000, questions=(dns_name(b"laptop") + b"\x00\x01\x00\x01",) * 2),   # two questions
                       dns_message(1, 0x0000, questions=(LOCAL_A,)),                                          # .local is mDNS
                       NBNS_QUERY)                                                                            # NetBIOS name
        for data in unsupported:
            self.assertEqual(datagram(data, "llmnr").status, "unknown", data[:4].hex())
        self.assertEqual(datagram(LLMNR_QUERY, "mdns").application_protocol, "dns")                 # hints select the validator, structure names the family


if __name__ == "__main__":
    unittest.main()
