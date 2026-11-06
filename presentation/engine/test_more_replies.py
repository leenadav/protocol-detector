"""v0.49: direction evidence (DHCP, NTP, MongoDB, WireGuard) and the remaining server replies."""
import random
import struct
import unittest

from protocol_engine import Config, DatagramInspector, Inspector
from protocol_engine.appid import session_verdict
from protocol_engine.dispatch import select
from protocol_fixtures import (DHCP, DHCP_OFFER, FASTCGI_END, FASTCGI_STDOUT, GIT, GIT_REFS, GIT_VERSION2, L2TP, L2TP_SCCRP, MEMCACHED,
                               MEMCACHED_ERROR, MEMCACHED_RESPONSE, MONGODB, MONGODB_REPLY, NETBIOS_SS, NTP, NTP_SERVER, PPTP, PPTP_SCCRP, TFTP,
                               TFTP_ERROR, TFTP_OACK, WIREGUARD, WIREGUARD_RESPONSE)

LEAKS = ("server-host", "vendor-x", "Not found", "File not found", "Status: 200", "refs/heads/main", "plchldr", "1428")


def datagram(data, hint=None):
    return DatagramInspector().inspect(data, hint)


def stream(data, hint=None, config=None):
    inspector = Inspector(config, protocol_hint=hint)
    inspector.feed(data)
    return inspector.observation


def fields(observation, prefix):
    return {e.field: e.value for e in observation.evidence if e.field.startswith(prefix)}


class MoreRepliesTests(unittest.TestCase):
    def assert_identified(self, observation, label, **expected):
        self.assertEqual((observation.status, observation.application_protocol or observation.encryption), ("identified", label), observation)
        found = {e.field: e.value for e in observation.evidence}
        for key, value in expected.items():
            self.assertEqual(found.get(key), value, (key, found))
        text = repr(observation)
        for leak in LEAKS:
            self.assertNotIn(leak, text)
        return observation

    def test_datagram_direction_evidence(self):
        self.assert_identified(datagram(DHCP), "dhcp/4", dhcp_operation="request", dhcp_message="discover")
        self.assert_identified(datagram(DHCP_OFFER), "dhcp/4", dhcp_operation="reply", dhcp_message="offer")
        ack = DHCP_OFFER[:-2] + b"\x05\xff"
        self.assert_identified(datagram(ack), "dhcp/4", dhcp_message="ack")
        self.assert_identified(datagram(NTP, "ntp"), "ntp/4", ntp_mode="client")
        self.assert_identified(datagram(NTP_SERVER, "ntp"), "ntp/4", ntp_mode="server")
        self.assertEqual(datagram(NTP_SERVER).status, "unknown")   # still hint-only
        self.assert_identified(datagram(WIREGUARD), "wireguard", message_type="handshake_initiation")
        self.assert_identified(datagram(WIREGUARD_RESPONSE), "wireguard", message_type="handshake_response")
        verdict = session_verdict(datagram(DHCP), datagram(DHCP_OFFER), "udp", 67, 300, 300, True, None)
        self.assertEqual((verdict.app, verdict.client_protocol, verdict.server_protocol), ("dhcp", "dhcp/4", "dhcp/4"))

    def test_tftp_server_packets(self):
        self.assert_identified(datagram(TFTP), "tftp", tftp_packet="request")
        self.assert_identified(datagram(TFTP_OACK), "tftp", tftp_packet="oack")
        self.assert_identified(datagram(TFTP_ERROR, "tftp"), "tftp", tftp_packet="error")
        self.assertNotEqual(datagram(TFTP_ERROR).status, "identified")   # ERROR shares its first bytes with NetFlow v5: hint required
        self.assertEqual(datagram(b"\x00\x05\x00\x02\x00", "tftp").status, "malformed")   # empty message, five bytes
        rejected = [b"\x00\x06", b"\x00\x06blksize\x00", b"\x00\x06blksize\x00\x00", b"\x00\x06blksize\x00abc\x00", b"\x00\x06a\x00b\x00a\x00c\x00",
                    b"\x00\x06other\x001\x00", b"\x00\x06blksize\x001\x00blksize\x002\x00",
                    b"\x00\x05\x00\x09msg\x00", b"\x00\x05\x00\x01msg", b"\x00\x05\x00\x01m\x01g\x00", b"\x00\x03\x00\x01data", b"\x00\x04\x00\x01",
                    b"\x00\x06" + b"o\x00v\x00" * 17]
        for data in rejected:
            self.assertNotEqual(datagram(data).status, "identified", data)
            self.assertNotEqual(datagram(data, "tftp").status, "identified", data)

    def test_l2tp_and_pptp_replies(self):
        self.assert_identified(datagram(L2TP), "l2tp/2", l2tp_message="sccrq")
        self.assert_identified(datagram(L2TP_SCCRP), "l2tp/2", l2tp_message="sccrp")
        self.assertNotEqual(datagram(L2TP[:4] + b"\x00\x05\x00\x00" + L2TP[8:]).status, "identified")   # SCCRQ with a tunnel id
        self.assertNotEqual(datagram(L2TP_SCCRP[:4] + bytes(4) + L2TP_SCCRP[8:]).status, "identified")  # SCCRP without one
        self.assertNotEqual(datagram(L2TP_SCCRP[:19] + b"\x03" + L2TP_SCCRP[20:]).status, "identified")  # SCCCN
        request, reply = stream(PPTP), stream(PPTP_SCCRP)
        self.assert_identified(request, "pptp", pptp_message="sccrq")
        self.assert_identified(reply, "pptp", pptp_message="sccrp", pptp_result="ok")
        self.assertEqual(reply.scope, "negotiation_response")
        for result, error, ok in ((2, 3, True), (3, 0, True), (5, 0, True), (0, 0, False), (6, 0, False), (1, 2, False), (2, 7, False)):
            data = PPTP_SCCRP[:14] + bytes([result, error]) + PPTP_SCCRP[16:]
            self.assertEqual(stream(data).status == "identified", ok, (result, error))
        self.assertNotEqual(stream(PPTP_SCCRP[:8] + b"\x00\x03" + PPTP_SCCRP[10:]).status, "identified")   # StopCCRQ
        verdict = session_verdict(request, reply, "tcp", 1723, 156, 156, True, None)
        self.assertEqual(verdict.app, "pptp")

    def test_mongodb_direction(self):
        self.assert_identified(stream(MONGODB, "mongodb"), "mongodb", mongodb_message="request")
        reply = self.assert_identified(stream(MONGODB_REPLY, "mongodb"), "mongodb", mongodb_message="reply")
        self.assertEqual(reply.scope, "response_header")

    def test_memcached_responses_and_netbios_neighbour(self):
        self.assert_identified(stream(MEMCACHED), "memcached/binary", memcached_message="request")
        self.assert_identified(stream(MEMCACHED_RESPONSE), "memcached/binary", memcached_message="response", memcached_status="no-error")
        self.assert_identified(stream(MEMCACHED_ERROR), "memcached/binary", memcached_message="response", memcached_status="key-not-found")
        self.assert_identified(stream(NETBIOS_SS), "netbios-ss")
        self.assertEqual(select(NETBIOS_SS[:24]), "netbios-ss")
        self.assertEqual(select(MEMCACHED_RESPONSE[:24]), "memcached")
        self.assertIsNone(select(b"\x81\x00\x00"))

        def response(opcode, key=0, extras=0, value=b"", status=0, datatype=0):
            body = key + extras + len(value)
            return struct.pack("!BBHBBHIIQ", 0x81, opcode, key, extras, datatype, status, body, 0, 0) + b"k" * key + bytes(extras) + value
        for opcode, kwargs in ((1, {}), (4, {}), (5, {"value": bytes(8)}), (11, {"value": b"1.6.0"}), (12, {"key": 3, "extras": 4, "value": b"v"}),
                               (16, {"key": 2, "value": b"3"}), (16, {}), (10, {})):
            self.assert_identified(stream(response(opcode, **kwargs)), "memcached/binary", memcached_message="response")
        self.assert_identified(stream(response(1, status=2)), "memcached/binary", memcached_status="key-exists")
        rejected = [response(0, key=1, extras=4), response(0, extras=0), response(1, value=b"x"), response(5, value=bytes(7)), response(11),
                    response(0, extras=4, status=0x99), response(0, extras=4, datatype=1), response(0, extras=4, status=1), response(0x30),
                    response(12, extras=4)]
        for data in rejected:
            self.assertNotEqual(stream(data).status, "identified", data[:12].hex())
        verdict = session_verdict(stream(MEMCACHED), stream(MEMCACHED_RESPONSE), "tcp", 11211, 27, 33, True, None)
        self.assertEqual(verdict.app, "memcached")

    def test_git_server_lines(self):
        self.assert_identified(stream(GIT), "git", git_message="service-request")
        refs = self.assert_identified(stream(GIT_REFS), "git", git_message="ref-advertisement")
        self.assertEqual(refs.scope, "negotiation_response")
        self.assert_identified(stream(GIT_VERSION2), "git", git_message="version-2")
        sha256 = b"b" * 64 + b" refs/heads/main\x00agent=x\n"
        self.assert_identified(stream("{:04x}".format(len(sha256) + 4).encode() + sha256), "git", git_message="ref-advertisement")
        self.assertEqual(select(GIT_REFS[:24]), "git")
        self.assertIsNone(select(GIT_REFS[:12]))
        self.assertEqual(select(GIT_VERSION2[:14]), "git")
        self.assertEqual(select(b"0032git-upload-pack /x\x00"), "git_text")
        rejected_lines = [b"a" * 40 + b" HEAD\x00caps", b"a" * 40 + b" HEAD\n", b"a" * 40 + b"  HEAD\x00x\n", b"a" * 40 + b" other\x00x\n",
                          b"a" * 40 + b" HEAD\x00a\x00b\n", b"a" * 40 + b" HE\x01D\x00x\n", b"g" * 40 + b" HEAD\x00x\n", b"version 3\n"]
        for line in rejected_lines:
            data = "{:04x}".format(len(line) + 4).encode() + line
            self.assertNotEqual(stream(data).status, "identified", line[:12])
        for split in range(1, len(GIT_REFS), 9):
            inspector = Inspector()
            inspector.feed(GIT_REFS[:split])
            inspector.feed(GIT_REFS[split:])
            self.assertEqual(inspector.observation, refs, split)

    def test_fastcgi_application_records(self):
        out = self.assert_identified(stream(FASTCGI_STDOUT), "fastcgi/1", fastcgi_record="stdout")
        self.assertEqual(out.scope, "response_record")
        self.assert_identified(stream(FASTCGI_END), "fastcgi/1", fastcgi_record="end-request")
        self.assert_identified(stream(b"\x01\x07\x00\x02\x00\x03\x05\x00" + b"err" + bytes(5)), "fastcgi/1", fastcgi_record="stderr")
        rejected = [b"\x01\x06\x00\x01\x00\x00\x00\x00",                             # empty STDOUT alone
                    b"\x01\x03\x00\x01\x00\x08\x00\x00" + bytes(4) + b"\x04" + bytes(3),   # protocol status 4
                    b"\x01\x03\x00\x01\x00\x08\x00\x00" + bytes(4) + b"\x00\x01\x00\x00",  # reserved byte set
                    b"\x01\x03\x00\x01\x00\x07\x00\x00" + bytes(7),                   # END_REQUEST of seven bytes
                    b"\x01\x06\x00\x00\x00\x0c\x04\x00" + b"Status: 200\n" + bytes(4),  # request id zero
                    b"\x01\x06\x00\x01\x00\x0c\x04\x01" + b"Status: 200\n" + bytes(4)]  # reserved header byte
        for data in rejected:
            self.assertNotEqual(stream(data).status, "identified", data[:8].hex())
        self.assertEqual(select(FASTCGI_STDOUT[:24]), "fastcgi")
        self.assertEqual(select(FASTCGI_END[:24]), "fastcgi")

    def test_mutations_never_raise_or_leak(self):
        generator = random.Random(49)
        for base, hint, udp in ((DHCP_OFFER, None, True), (TFTP_OACK, None, True), (TFTP_ERROR, None, True), (L2TP_SCCRP, None, True),
                                (PPTP_SCCRP, None, False), (MEMCACHED_RESPONSE, None, False), (MEMCACHED_ERROR, None, False), (GIT_REFS, None, False),
                                (FASTCGI_STDOUT, None, False), (FASTCGI_END, None, False), (MONGODB_REPLY, "mongodb", False)):
            for _ in range(200):
                data = bytearray(base)
                data[generator.randrange(len(data))] = generator.randrange(256)
                observation = datagram(bytes(data), hint) if udp else stream(bytes(data), hint, Config(max_bytes=4096))
                self.assertIn(observation.status, ("identified", "unknown", "malformed", "detecting", "budget_exhausted"))
                for leak in LEAKS:
                    self.assertNotIn(leak, repr(observation))


if __name__ == "__main__":
    unittest.main()
