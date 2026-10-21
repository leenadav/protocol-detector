"""v0.54: LDAP StartTLS shift, IRC family, TURN methods over STUN framing, DNS query-type classes and RPC over HTTP."""
import random
import unittest

from analyze_pcap import Analyzer
from make_sample_pcap import A, B, frame
from packets import decode_packet
from protocol_engine import Config, Inspector
from protocol_engine.appid import classify, session_verdict
from protocol_engine.datagram import DatagramInspector
from protocol_engine.dispatch import select
from protocol_engine.irc import split_message
from protocol_engine.wire import dns_query_type_class
from protocol_fixtures import (DNS, DNS_SRV_QUERY, IRC_CAP_LS, IRC_NICK, IRC_PING, IRC_SERVER_NOTICE, IRC_SERVER_WELCOME, IRC_UNPREFIXED_NOTICE,
                               IRC_USER, LDAP, LDAP_STARTTLS_OID, LDAP_STARTTLS_REFUSED, LDAP_STARTTLS_REQUEST, LDAP_STARTTLS_RESPONSE,
                               LDAP_STARTTLS_UNNAMED, LDAP_WHOAMI_REQUEST, NBNS_QUERY, NBSTAT_QUERY, RPC_IN_DATA_REQUEST, STUN, TLS_SERVER13,
                               TURN_ALLOCATE, TURN_ALLOCATE_ERROR, TURN_CHANNEL_BIND, TURN_REFRESH, TURN_SEND_INDICATION, ldap_extended,
                               netbios_name, stun_message)
from proxy_demo import client_hello

HELLO = client_hello()


def stream(data, hint=None, **kwargs):
    inspector = Inspector(protocol_hint=hint, **kwargs)
    inspector.feed(data)
    inspector.end()
    return inspector.observation


def fields(observation, *names):
    return {e.field: e.value for e in observation.evidence if e.field in names}


class LDAPStartTLSTests(unittest.TestCase):
    def test_request_and_named_response_shift_to_tls(self):
        request = stream(LDAP_STARTTLS_REQUEST)
        self.assertEqual((request.status, request.application_protocol, request.scope), ("identified", "ldap", "initial_message"))
        self.assertEqual(fields(request, "ldap_message", "ldap_extended", "shift", "shifted_payload"),
                         {"ldap_message": "extended_request", "ldap_extended": "starttls", "shift": "ldap-starttls", "shifted_payload": "incomplete"})
        shifted = stream(LDAP_STARTTLS_REQUEST + HELLO)
        self.assertEqual((shifted.status, shifted.encryption, shifted.application_protocol), ("identified", "tls", None))
        self.assertEqual(fields(shifted, "shift", "shift_from"), {"shift": "ldap-starttls", "shift_from": "ldap"})
        self.assertTrue(shifted.reason.startswith("After ldap-starttls"))
        verdict = classify(shifted, "tcp", 389)
        self.assertEqual((verdict.app, verdict.shifted_from, "ldap" in verdict.implicitly_uses), ("ssl", "ldap", True))
        self.assertNotIn("cleartext-credential-protocol", verdict.risks)
        response = stream(LDAP_STARTTLS_RESPONSE + TLS_SERVER13)
        self.assertEqual((response.status, response.encryption), ("identified", "tls"))
        self.assertEqual(fields(response, "shift", "shift_from", "selected_tls_version"), {"shift": "ldap-starttls", "shift_from": "ldap", "selected_tls_version": "1.3"})
        alone = stream(LDAP_STARTTLS_RESPONSE)
        self.assertEqual((alone.application_protocol, alone.scope), ("ldap", "negotiation_response"))
        self.assertEqual(fields(alone, "ldap_message", "ldap_extended", "ldap_result", "shift"),
                         {"ldap_message": "extended_response", "ldap_extended": "starttls", "ldap_result": "success", "shift": "ldap-starttls"})

    def test_unnamed_refused_and_other_extended_operations_do_not_shift(self):
        unnamed = stream(LDAP_STARTTLS_UNNAMED + TLS_SERVER13)
        self.assertEqual((unnamed.application_protocol, unnamed.encryption), ("ldap", None))
        self.assertEqual(fields(unnamed, "ldap_extended", "ldap_result", "shift"), {"ldap_extended": "unnamed", "ldap_result": "success"})
        refused = stream(LDAP_STARTTLS_REFUSED + TLS_SERVER13)
        self.assertEqual(fields(refused, "ldap_extended", "ldap_result", "shift"), {"ldap_extended": "starttls", "ldap_result": "unavailable"})
        whoami = stream(LDAP_WHOAMI_REQUEST)
        self.assertEqual((whoami.application_protocol, fields(whoami, "ldap_extended", "shift")), ("ldap", {"ldap_extended": "whoami"}))
        self.assertEqual(classify(whoami, "tcp", 389).app, "ldap")
        bind = stream(LDAP)
        self.assertEqual(fields(bind, "ldap_message"), {"ldap_message": "bind_request"})
        self.assertIn("cleartext-credential-protocol", classify(bind, "tcp", 389).risks)
        self.assertNotIn("cleartext-credential-protocol", classify(stream(LDAP_STARTTLS_REQUEST), "tcp", 389).risks)

    def test_extended_operation_rules(self):
        # requestName must be a numeric OID; StartTLS takes no value; trailing fields and controls are rejected or unsupported.
        self.assertEqual(stream(ldap_extended(1, 0x77, b"starttls")).status, "malformed")
        with_value = LDAP_STARTTLS_REQUEST
        body = with_value[7:] + b"\x81\x01x"
        operation = b"\x77" + bytes((len(body),)) + body
        message = b"\x02\x01\x01" + operation
        self.assertEqual(stream(b"\x30" + bytes((len(message),)) + message).status, "malformed")
        other_value = ldap_extended(2, 0x77, b"1.3.6.1.4.1.4203.1.11.1")
        body = other_value[7:] + b"\x81\x0cVALUE-SECRET"
        operation = b"\x77" + bytes((len(body),)) + body
        message = b"\x02\x01\x02" + operation
        valued = stream(b"\x30" + bytes((len(message),)) + message)
        self.assertEqual((valued.status, fields(valued, "ldap_extended")), ("identified", {"ldap_extended": "password-modify"}))
        self.assertNotIn("VALUE-SECRET", repr(valued))
        body = LDAP_STARTTLS_RESPONSE[7:] + b"\x8b\x01x"
        operation = b"\x78" + bytes((len(body),)) + body
        message = b"\x02\x01\x01" + operation
        self.assertEqual(stream(b"\x30" + bytes((len(message),)) + message).status, "malformed")
        controls = LDAP_STARTTLS_REQUEST + b"\xa0\x00"
        controls = b"\x30" + bytes((controls[1] + 2,)) + controls[2:]
        self.assertEqual(stream(controls).status, "unknown")
        bad_code = ldap_extended(1, 0x78, LDAP_STARTTLS_OID, 124)
        self.assertEqual(stream(bad_code).status, "malformed")
        self.assertEqual(stream(ldap_extended(1, 0x78, b"not.an.oid", 0)).status, "malformed")
        self.assertNotIn(LDAP_STARTTLS_OID.decode(), repr(stream(LDAP_STARTTLS_REQUEST).evidence))
        for split in range(1, len(LDAP_STARTTLS_REQUEST + HELLO)):
            inspector = Inspector()
            data = LDAP_STARTTLS_REQUEST + HELLO
            inspector.feed(data[:split])
            inspector.feed(data[split:])
            self.assertEqual(inspector.observation, stream(data), split)

    def test_analyzer_correlates_an_unnamed_success_response(self):
        def flow(response):
            cr, cs = 1000, 9000
            request = LDAP_STARTTLS_REQUEST
            return [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18),
                    frame(A, B, cr, cs, 24, request), frame(B, A, cs, cr + len(request), 24, response),
                    frame(A, B, cr + len(request), cs + len(response), 24, HELLO),
                    frame(B, A, cs + len(response), cr + len(request) + len(HELLO), 24, TLS_SERVER13)]

        def run(frames):
            records = []
            analyzer = Analyzer(on_session=records.append)
            for number, data in enumerate(frames):
                analyzer.process(number, decode_packet(data))
            directions = analyzer.manager.connections[analyzer.manager.key(A, B)]["directions"]
            client, server = directions[A].inspector.observation, directions[B].inspector.observation
            analyzer.finish("done")
            return analyzer, client, server, records[0]

        analyzer, client, server, record = run(flow(LDAP_STARTTLS_UNNAMED))
        self.assertEqual(analyzer.counts["ldap_starttls_correlated"], 1)
        self.assertEqual((client.encryption, server.encryption), ("tls", "tls"))
        self.assertEqual(fields(server, "shift", "shift_from", "selected_tls_version"), {"shift": "ldap-starttls", "shift_from": "ldap", "selected_tls_version": "1.3"})
        self.assertEqual((record["app"], record["shifted_from"], record["client_protocol"], record["server_protocol"]), ("ssl", "ldap", "tls", "tls"))
        self.assertNotIn("cleartext-credential-protocol", record["risks"])
        analyzer, client, server, record = run(flow(LDAP_STARTTLS_RESPONSE))
        self.assertEqual(analyzer.counts["ldap_starttls_correlated"], 0)     # the named response shifted by itself
        self.assertEqual((client.encryption, server.encryption, record["app"]), ("tls", "tls", "ssl"))
        analyzer, client, server, record = run(flow(LDAP_STARTTLS_REFUSED))
        self.assertEqual((analyzer.counts["ldap_starttls_correlated"], server.application_protocol, fields(server, "shift")), (0, "ldap", {}))
        verdict = session_verdict(client, server, "tcp", 389, 400, 200, True, None)
        self.assertEqual(verdict.app, "ssl")   # the client did start TLS; the server direction stayed with its refusal


class IRCTests(unittest.TestCase):
    CLIENT = ((IRC_NICK, "nick", "initial_message"), (IRC_USER, "user", "initial_message"), (IRC_CAP_LS, "cap", "initial_message"),
              (IRC_UNPREFIXED_NOTICE, "notice", "protocol_header"), (IRC_PING, "ping", "protocol_header"))
    SERVER = ((IRC_SERVER_NOTICE, "notice"), (IRC_SERVER_WELCOME, "numeric"), (b":irc.example.org PING :abc\r\n", "ping"),
              (b":irc.example.org CAP * LS :multi-prefix sasl\r\n", "cap"), (b":alice!~a@192.0.2.1 NICK :alice2\r\n", "nick"),
              (b":irc.example.org 433 * alice :Nickname is already in use\r\n", "numeric"))

    def test_registration_and_server_lines_identify_with_closed_labels(self):
        for data, label, scope in self.CLIENT:
            observation = stream(data)
            self.assertEqual((observation.status, observation.application_protocol, observation.scope), ("identified", "irc", scope), data)
            self.assertEqual(fields(observation, "irc_message"), {"irc_message": label})
            self.assertEqual(classify(observation, "tcp", 6667).app, "irc")
            self.assertEqual(classify(observation, "tcp", 6667).port_usage, "standard")
        for data, label in self.SERVER:
            observation = stream(data)
            self.assertEqual((observation.status, observation.application_protocol, observation.scope), ("identified", "irc", "protocol_header"), data)
            self.assertEqual(fields(observation, "irc_message"), {"irc_message": label})
            self.assertNotIn("alice", repr(observation.evidence))
            self.assertNotIn("example", repr(observation.evidence))
        self.assertEqual(select(b":"), "irc")
        pass_line = stream(b"PASS s3cret\r\n")
        self.assertEqual((pass_line.status, fields(pass_line, "ambiguous_candidates")), ("unknown", {"ambiguous_candidates": "ftp,pop3,irc"}))
        self.assertNotIn("s3cret", repr(pass_line))
        user = stream(b"USER alice\r\n")
        self.assertEqual(fields(user, "ambiguous_candidates"), {"ambiguous_candidates": "ftp,pop3"})
        self.assertEqual(session_verdict(stream(IRC_NICK), stream(IRC_SERVER_NOTICE), "tcp", 6667, 40, 60, True, None).app, "irc")

    def test_grammar_rules(self):
        malformed = (b"NICK\r\n", b"NICK 1abc\r\n", b"NICK a b\r\n", b"NICK " + b"a" * 65 + b"\r\n", b"USER a b c d e\r\n",
                     b"USER a b c :" + b"x" * 300 + b"\r\n", b"CAP\r\n", b"CAP FOO\r\n", b"CAP LS 30\r\n", b"CAP LS 302 x y\r\n",
                     b"NOTICE alice :hi\r\n", b"PING\r\n", b":irc.example.org 001\r\n", b":irc.example.org 001 #chan :x\r\n",
                     b": NOTICE * :x\r\n", b":irc.example.org\r\n", b":irc.example.org  NOTICE * :x\r\n", b":a!b PRIVMSG x :y\r\n",
                     b":irc.example.org NOTICE *\r\n", b":irc.example.org 001 alice " + b" ".join([b"p"] * 16) + b"\r\n",
                     b":irc.example.org NOTICE * :" + b"x" * 600 + b"\r\n", b"NICK alice\n")
        for data in malformed:
            observation = stream(data)
            self.assertIn(observation.status, ("malformed", "budget_exhausted"), (data, observation))
        unsupported = (b":irc.example.org FOOBAR x\r\n", b":alice!a@h TOPIC #c :t\r\n")
        for data in unsupported:
            self.assertEqual(stream(data).status, "unknown", data)
        prefix, command, params = split_message(b":nick!user@host PRIVMSG #chan :hello world")
        self.assertEqual((prefix, command, params), (b"nick!user@host", b"PRIVMSG", [b"#chan", b"hello world"]))
        self.assertEqual(stream(b"USER alice 0 * :Alice Example\r\n", "irc").application_protocol, "irc")
        self.assertEqual(stream(b"PASS secret\r\n", "irc").application_protocol, "irc")
        self.assertEqual(stream(b"GET / HTTP/1.1\r\n\r\n", "irc").status, "unknown")

    def test_split_points_and_mutations_are_bounded(self):
        rng = random.Random(54)
        for data, _, _ in self.CLIENT + tuple((d, label, "protocol_header") for d, label in self.SERVER):
            whole = stream(data)
            for split in range(1, len(data)):
                inspector = Inspector()
                inspector.feed(data[:split])
                inspector.feed(data[split:])
                inspector.end()
                self.assertEqual(inspector.observation, whole, (data, split))
            for _ in range(40):
                changed = bytearray(data)
                changed[rng.randrange(len(changed))] = rng.randrange(256)
                observation = stream(bytes(changed))
                self.assertIn(observation.status, ("identified", "unknown", "malformed", "incomplete", "budget_exhausted"))
                if observation.status == "identified" and observation.application_protocol == "irc":
                    self.assertNotIn("alice", repr(observation.evidence))
        self.assertEqual(stream(b":" + b"a" * 600).status, "malformed")      # 512-byte IRC line limit, before any newline
        self.assertEqual(stream(b":" + b"a" * 500).status, "incomplete")


class TURNTests(unittest.TestCase):
    def test_turn_methods_identify_with_method_and_class(self):
        expected = ((TURN_ALLOCATE, "allocate", "request"), (TURN_ALLOCATE_ERROR, "allocate", "error-response"), (TURN_REFRESH, "refresh", "request"),
                    (TURN_CHANNEL_BIND, "channel-bind", "request"), (TURN_SEND_INDICATION, "send", "indication"), (STUN, "binding", "request"))
        for data, method, klass in expected:
            datagram = DatagramInspector().inspect(data)
            self.assertEqual((datagram.status, datagram.application_protocol), ("identified", "stun"), data)
            self.assertEqual(fields(datagram, "stun_method", "stun_class"), {"stun_method": method, "stun_class": klass})
            self.assertEqual(classify(datagram, "udp", 3478).app, "turn" if method != "binding" else "stun")
            tcp = stream(data)
            self.assertEqual((tcp.application_protocol, fields(tcp, "stun_method", "stun_class")), ("stun", {"stun_method": method, "stun_class": klass}))
        self.assertNotIn("example.org", repr(DatagramInspector().inspect(TURN_ALLOCATE_ERROR)))
        self.assertNotIn("Unauthorized", repr(DatagramInspector().inspect(TURN_ALLOCATE_ERROR)))
        turn = classify(DatagramInspector().inspect(TURN_ALLOCATE), "udp", 3478)
        self.assertEqual((turn.port_usage, "stun" in turn.implicitly_uses), ("standard", True))

    def test_turn_attribute_and_class_rules(self):
        malformed = (stun_message(0x0006),                                             # Send as a request
                     stun_message(0x0007),                                             # Data as a request
                     stun_message(0x0013),                                             # Allocate as an indication
                     stun_message(0x0106),                                             # Send as a success response
                     stun_message(0x0003, b"\x00\x19\x00\x04\x05\x00\x00\x00"),          # REQUESTED-TRANSPORT neither UDP nor TCP
                     stun_message(0x0003, b"\x00\x19\x00\x04\x11\x01\x00\x00"),          # reserved bytes set
                     stun_message(0x0003, b"\x00\x19\x00\x08\x11\x00\x00\x00\x00\x00\x00\x00"),  # wrong size
                     stun_message(0x0009, b"\x00\x0c\x00\x04\x30\x00\x00\x00"),          # CHANNEL-NUMBER below 0x4000
                     stun_message(0x0009, b"\x00\x0c\x00\x04\x40\x00\x00\x01"),          # CHANNEL-NUMBER reserved bytes
                     stun_message(0x0003, b"\x00\x18\x00\x01\x01\x00\x00\x00"),          # EVEN-PORT reserved bits
                     stun_message(0x0113, b"\x00\x09\x00\x04\x00\x00\x07\x01"),          # ERROR-CODE class 7
                     stun_message(0x0113, b"\x00\x09\x00\x04\x00\x01\x04\x01"),          # ERROR-CODE reserved
                     stun_message(0x0113, b"\x00\x09\x00\x03\x00\x00\x04"),              # ERROR-CODE too short
                     stun_message(0x0003, b"\x00\x14\x00\x04abc"),                       # length past message
                     stun_message(0x0003, b"\x00\x06\x00\x04ab\x00\x00" + b"\x00\x06\x02\x02" + b"u" * 514 + b"\x00\x00"))
        for data in malformed:
            self.assertEqual(DatagramInspector().inspect(data).status, "malformed", data[:4].hex())
            self.assertNotEqual(stream(data).status, "identified", data[:4].hex())
        self.assertEqual(DatagramInspector().inspect(stun_message(0x000e)).status, "unknown")          # method 14 undefined
        binding_indication = DatagramInspector().inspect(stun_message(0x0011))                            # RFC 5389 keepalive
        self.assertEqual(fields(binding_indication, "stun_method", "stun_class"), {"stun_method": "binding", "stun_class": "indication"})
        self.assertEqual(classify(binding_indication, "udp", 3478).app, "stun")
        data_indication = stun_message(0x0017, b"\x00\x12\x00\x08\x00\x01\x30\x39\xe1\x12\xa4\x42" + b"\x00\x13\x00\x01x\x00\x00\x00")
        self.assertEqual(fields(DatagramInspector().inspect(data_indication), "stun_method", "stun_class"), {"stun_method": "data", "stun_class": "indication"})
        realm_too_long = stun_message(0x0003, b"\x00\x14\x03\x00" + b"r" * 768)
        self.assertEqual(DatagramInspector().inspect(realm_too_long).status, "malformed")
        connection_attempt = stun_message(0x001c, b"\x00\x2a\x00\x04\x00\x00\x00\x01" + b"\x00\x12\x00\x08\x00\x01\x30\x39\xe1\x12\xa4\x42")
        self.assertEqual(fields(DatagramInspector().inspect(connection_attempt), "stun_method", "stun_class"), {"stun_method": "connection-attempt", "stun_class": "indication"})


class DNSQueryTypeTests(unittest.TestCase):
    def test_netbios_name_service_is_told_from_dns_by_label_and_type(self):
        nbns = DatagramInspector().inspect(NBNS_QUERY)
        self.assertEqual((nbns.application_protocol, fields(nbns, "dns_query_type", "dns_message")), ("dns", {"dns_query_type": "nb", "dns_message": "query"}))
        self.assertEqual(classify(nbns, "udp", 137).app, "netbios-ns")
        self.assertEqual(classify(nbns, "udp", 137).port_usage, "standard")
        nbstat = DatagramInspector().inspect(NBSTAT_QUERY)
        self.assertEqual((fields(nbstat, "dns_query_type"), classify(nbstat, "udp", 137).app), ({"dns_query_type": "nbstat"}, "netbios-ns"))
        srv = DatagramInspector().inspect(DNS_SRV_QUERY)
        self.assertEqual((fields(srv, "dns_query_type"), classify(srv, "udp", 53).app), ({"dns_query_type": "srv"}, "dns"))
        self.assertEqual(fields(DatagramInspector().inspect(DNS), "dns_query_type"), {"dns_query_type": "a"})
        self.assertEqual(dns_query_type_class(b"example.com", 32), "other")
        self.assertEqual(dns_query_type_class(b"z" * 32 + b".example", 32), "other")        # 'z' is outside the A-P alphabet
        self.assertEqual(dns_query_type_class(b"a" * 32 + b".example", 32), "nb")           # expanded names are lowercase
        self.assertEqual(dns_query_type_class(b"z" * 32, 33), "srv")
        self.assertEqual(dns_query_type_class(b"", 1), "a")
        self.assertEqual(dns_query_type_class(b"x", 65), "https")
        self.assertEqual(dns_query_type_class(b"x", 99), "other")
        tcp = stream(b"\x00" + bytes((len(NBNS_QUERY),)) + NBNS_QUERY)
        self.assertEqual((tcp.application_protocol, fields(tcp, "dns_query_type")), ("dns", {"dns_query_type": "nb"}))
        self.assertNotIn("FILESERVER", repr(nbns))
        self.assertNotIn(netbios_name(b"FILESERVER")[1:33].decode(), repr(nbns))
        with_contexts = DatagramInspector(Config(retain_contexts=True)).inspect(NBNS_QUERY)
        self.assertEqual(fields(with_contexts, "dns_query_type"), {"dns_query_type": "nb"})


class RPCOverHTTPTests(unittest.TestCase):
    def test_rpc_methods_name_the_application(self):
        request = stream(RPC_IN_DATA_REQUEST)
        self.assertEqual((request.status, request.application_protocol, fields(request, "http_method")), ("identified", "http/1.1", {"http_method": "RPC_IN_DATA"}))
        verdict = classify(request, "tcp", 443)
        self.assertEqual((verdict.app, "web-browsing" in verdict.implicitly_uses, verdict.port_usage), ("ms-rpc-over-http", True, "standard"))
        for method in (b"RPC_OUT_DATA", b"RPC_CONNECT"):
            observation = stream(method + b" /rpc/rpcproxy.dll HTTP/1.1\r\nHost: mail.example.org\r\n\r\n")
            self.assertEqual((observation.application_protocol, classify(observation, "tcp", 80).app), ("http/1.1", "ms-rpc-over-http"))
        extension = stream(b"RPC_OTHER /x HTTP/1.1\r\nHost: h\r\n\r\n")
        self.assertEqual((fields(extension, "http_method"), classify(extension, "tcp", 80).app), ({"http_method": "extension"}, "web-browsing"))
        self.assertNotIn("rpcproxy", repr(request.evidence))


if __name__ == "__main__":
    unittest.main()
