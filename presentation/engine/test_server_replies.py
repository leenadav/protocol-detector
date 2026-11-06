"""v0.44: server replies for SMB2 NEGOTIATE, Kerberos KDC replies and errors, DCE/RPC bind_ack/bind_nak."""
import random
import struct
import unittest

from protocol_engine import Config, DatagramInspector, Inspector
from protocol_engine.appid import classify, session_verdict
from protocol_engine.dispatch import select
from protocol_engine.risks import RISKS
from protocol_fixtures import (DCERPC, DCERPC_BIND_ACK, DCERPC_BIND_NAK, KERBEROS, KERBEROS_AS_REP, KERBEROS_ERROR, KERBEROS_TCP,
                               KERBEROS_TGS_REP, NDR20, SMB2, SMB2_RESPONSE, SMB311_RESPONSE, _ber, _krb_principal, dcerpc_pdu,
                               krb_error, krb_rep, smb2_response)

LEAKS = ("EXAMPLE", "krbtgt", "user", "placeholder", "135")


def stream(data, hint=None, config=None):
    inspector = Inspector(config, protocol_hint=hint)
    inspector.feed(data)
    return inspector.observation


def datagram(data):
    return DatagramInspector().inspect(data)


def fields(observation, prefix):
    return {e.field: e.value for e in observation.evidence if e.field.startswith(prefix)}


def tcp(message):
    return len(message).to_bytes(4, "big") + message


class ServerReplyTests(unittest.TestCase):
    def assert_identified(self, observation, protocol, scope, **expected):
        self.assertEqual((observation.status, observation.application_protocol, observation.scope), ("identified", protocol, scope), observation)
        found = {e.field: e.value for e in observation.evidence}
        for key, value in expected.items():
            self.assertEqual(found.get(key), value, (key, found))
        text = repr(observation)
        for leak in LEAKS:
            self.assertNotIn(leak, text)

    def test_smb2_negotiate_response(self):
        self.assert_identified(stream(SMB2_RESPONSE), "smb2", "negotiation_response", smb_dialect="3.0.2", smb_signing="enabled")
        self.assert_identified(stream(SMB311_RESPONSE), "smb2", "negotiation_response", smb_dialect="3.1.1", smb_signing="required")
        self.assert_identified(stream(SMB2), "smb2", "negotiation_request")
        for dialect, label in ((0x202, "2.0.2"), (0x210, "2.1"), (0x2ff, "wildcard"), (0x300, "3.0")):
            self.assert_identified(stream(smb2_response(dialect=dialect, token=b"")), "smb2", "negotiation_response", smb_dialect=label)
        verdict = session_verdict(stream(SMB2), stream(SMB2_RESPONSE), "tcp", 445, 108, 140, True, None)
        # v0.59: the fixture server enables signing without requiring it.
        self.assertEqual((verdict.app, verdict.port_usage, verdict.risks), ("smb", "standard", ("desktop-or-file-sharing-session", "smb-signing-not-required")))
        rejected = [
            smb2_response(security_mode=0),                                           # signing disabled is outside MS-SMB2
            smb2_response(dialect=0x303),                                             # unknown dialect
            smb2_response(dialect=0x311),                                             # 3.1.1 without contexts
            smb2_response(context_count=1),                                           # contexts on a 3.0.2 response
            smb2_response(dialect=0x311, contexts=struct.pack("<HHIHHH", 1, 38, 0, 2, 32, 1) + bytes(34), context_count=1),  # two hashes selected
            smb2_response(dialect=0x311, contexts=struct.pack("<HHIHH", 2, 4, 0, 1, 2), context_count=1),                   # no preauth context
            SMB2_RESPONSE[:4] + SMB2_RESPONSE[4:8] + b"\x01\x00\x00\xc0" + SMB2_RESPONSE[12:],                                # error status
            SMB2_RESPONSE[:4 + 120] + b"\x7f\x00" + SMB2_RESPONSE[4 + 122:],                                                 # security buffer offset
            SMB2_RESPONSE[:4 + 122] + b"\xff\x00" + SMB2_RESPONSE[4 + 124:],                                                 # security buffer length
            SMB2_RESPONSE[:4 + 64] + b"\x40\x00" + SMB2_RESPONSE[4 + 66:],                                                   # body structure size
            SMB2_RESPONSE[:4 + 92] + bytes(4) + SMB2_RESPONSE[4 + 96:],                                                      # zero transfer size
            SMB2_RESPONSE[:4 + 16] + b"\x03\x00\x00\x00" + SMB2_RESPONSE[4 + 20:],                                           # async flag
        ]
        for data in rejected:
            observation = stream(data)
            self.assertNotEqual(observation.status, "identified", (data[:8].hex(), observation.reason))
        for split in range(1, len(SMB311_RESPONSE), 7):
            inspector = Inspector()
            inspector.feed(SMB311_RESPONSE[:split])
            inspector.feed(SMB311_RESPONSE[split:])
            self.assertEqual(fields(inspector.observation, "smb_"), {"smb_dialect": "3.1.1", "smb_signing": "required", "smb_encryption": "supported",
                                                                    "smb_encryption_cipher": "aes-128-gcm"}, split)   # v0.59 posture rows

    def test_kerberos_replies_and_errors(self):
        self.assert_identified(stream(KERBEROS_TCP), "kerberos", "initial_message", kerberos_message="as-req")
        self.assert_identified(stream(tcp(KERBEROS_AS_REP)), "kerberos", "negotiation_response", kerberos_message="as-rep")
        self.assert_identified(stream(tcp(KERBEROS_TGS_REP)), "kerberos", "negotiation_response", kerberos_message="tgs-rep")
        self.assert_identified(stream(tcp(KERBEROS_ERROR)), "kerberos", "negotiation_response", kerberos_message="error", kerberos_error="25")
        for data, name in ((KERBEROS, "as-req"), (KERBEROS_AS_REP, "as-rep"), (KERBEROS_TGS_REP, "tgs-rep"), (KERBEROS_ERROR, "error")):
            observation = datagram(data)
            self.assertEqual((observation.status, fields(observation, "kerberos_message")), ("identified", {"kerberos_message": name}))
            for leak in LEAKS:
                self.assertNotIn(leak, repr(observation))
            self.assertEqual(datagram(data).application_protocol, "kerberos")
        self.assertEqual(classify(datagram(KERBEROS_ERROR), "udp", 88).risks, ())
        failed = datagram(krb_error(code=24))
        self.assertEqual((fields(failed, "kerberos_error"), classify(failed, "udp", 88).risks), ({"kerberos_error": "24"}, ("kerberos-error-response",)))
        self.assertEqual(classify(datagram(krb_error(code=6)), "udp", 88).risks, ("kerberos-error-response",))
        self.assertIn("kerberos-error-response", RISKS)
        verdict = session_verdict(stream(KERBEROS_TCP), stream(tcp(krb_error(code=18))), "tcp", 88, 102, 99, True, None)
        self.assertEqual((verdict.app, verdict.risks), ("kerberos", ("kerberos-error-response",)))
        base = (_ber(0xa0, _ber(2, b"\x05")) + _ber(0xa1, _ber(2, b"\x0b")) + _ber(0xa3, _ber(0x1b, b"R")) + _ber(0xa4, _krb_principal(b"u"))
                + _ber(0xa5, _ber(0x61, _ber(0x30, b"\x02\x01\x05"))) + _ber(0xa6, _ber(0x30, b"\x02\x01\x12")))
        rejected = [
            krb_rep(fields=base.replace(b"\xa0\x03\x02\x01\x05", b"\xa0\x03\x02\x01\x04", 1)),            # pvno 4
            krb_rep(fields=base.replace(b"\xa1\x03\x02\x01\x0b", b"\xa1\x03\x02\x01\x0d", 1)),            # msg-type disagrees with the tag
            krb_rep(fields=base.replace(_ber(0xa3, _ber(0x1b, b"R")), b"", 1)),                            # crealm missing
            krb_rep(fields=base.replace(_ber(0xa3, _ber(0x1b, b"R")), _ber(0xa3, _ber(0x1b, b"")), 1)),    # empty realm
            krb_rep(fields=base.replace(_ber(0xa5, _ber(0x61, _ber(0x30, b"\x02\x01\x05"))), _ber(0xa5, _ber(0x30, b"\x02\x01\x05")), 1)),  # ticket tag
            krb_rep(fields=base + _ber(0xa7, _ber(2, b"\x01"))),                                             # field outside AS-REP
            krb_rep(fields=_ber(0xa1, _ber(2, b"\x0b")) + base[5:]),                                         # out of order
            krb_error(fields=krb_error()[4:][:-14] + b"\x00"),                                                # broken framing
            krb_error(code=128),                                                                              # error-code beyond RFC 4120
            krb_error(fields=krb_error()[4:].replace(b"\xa4\x11\x18\x0f20260101120000Z", b"\xa4\x11\x18\x0f2026010112000Z!", 1)),  # time not UTC
            krb_error(fields=krb_error()[4:].replace(_ber(0xa9, _ber(0x1b, b"EXAMPLE.ORG")), b"", 1)),           # realm missing
            krb_error(fields=krb_error()[4:].replace(_ber(0xa6, _ber(2, b"\x19")), _ber(0xa6, _ber(2, b"\xff")), 1)),  # negative error code
        ]
        for data in rejected:
            for observation in (datagram(data), stream(tcp(data))):
                self.assertNotEqual(observation.status, "identified", (data[:12].hex(), observation.reason))
        self.assertEqual(select(tcp(KERBEROS_ERROR)[:24]), "kerberos")
        self.assertEqual(select(tcp(KERBEROS_AS_REP)[:24]), "kerberos")
        for split in range(1, len(KERBEROS_AS_REP) + 4, 9):
            inspector = Inspector()
            data = tcp(KERBEROS_AS_REP)
            inspector.feed(data[:split])
            inspector.feed(data[split:])
            self.assertEqual(fields(inspector.observation, "kerberos_"), {"kerberos_message": "as-rep", "kerberos_reply_etype": "aes-sha1",
                                                                          "kerberos_ticket_etype": "aes-sha1"}, split)   # etypes since v0.63

    def test_dcerpc_bind_ack_and_nak(self):
        self.assert_identified(stream(DCERPC), "dcerpc/5.0", "bind_request", dcerpc_pdu="bind", offered_transfer_syntax="ndr/2.0")
        self.assert_identified(stream(DCERPC_BIND_ACK), "dcerpc/5.0", "bind_response", dcerpc_pdu="bind-ack", accepted_transfer_syntax="ndr/2.0")
        self.assert_identified(stream(DCERPC_BIND_NAK), "dcerpc/5.0", "bind_response", dcerpc_pdu="bind-nak")
        verdict = session_verdict(stream(DCERPC), stream(DCERPC_BIND_ACK), "tcp", 135, 72, 60, True, None)
        self.assertEqual((verdict.app, verdict.port_usage), ("dce-rpc", "standard"))
        rejection = dcerpc_pdu(0x0c, struct.pack("<HHI", 0x10b8, 0x10b8, 0) + struct.pack("<H", 0) + bytes(2) + b"\x01\x00\x00\x00" + b"\x02\x00\x01\x00" + bytes(20))
        self.assert_identified(stream(rejection), "dcerpc/5.0", "bind_response", dcerpc_pdu="bind-ack")
        self.assertNotIn("accepted_transfer_syntax", fields(stream(rejection), "accepted"))
        big_endian = dcerpc_pdu(0x0d, struct.pack(">H", 9) + b"\x01" + b"\x05\x00", "big")
        self.assert_identified(stream(big_endian), "dcerpc/5.0", "bind_response", dcerpc_pdu="bind-nak")
        rejected = [
            dcerpc_pdu(0x0c, struct.pack("<HHI", 0, 0x10b8, 0) + struct.pack("<H", 4) + b"135\x00" + bytes(2) + b"\x01\x00\x00\x00" + bytes(4) + NDR20),   # zero transfer size
            dcerpc_pdu(0x0c, struct.pack("<HHI", 0x10b8, 0x10b8, 0) + struct.pack("<H", 4) + b"135\x01" + bytes(2) + b"\x01\x00\x00\x00" + bytes(4) + NDR20),  # address not terminated
            dcerpc_pdu(0x0c, struct.pack("<HHI", 0x10b8, 0x10b8, 0) + struct.pack("<H", 4) + b"135\x00" + bytes(2) + b"\x00\x00\x00\x00"),              # no results
            dcerpc_pdu(0x0c, struct.pack("<HHI", 0x10b8, 0x10b8, 0) + struct.pack("<H", 4) + b"135\x00" + bytes(2) + b"\x01\x00\x00\x00" + bytes(4) + NDR20 + b"\x00"),  # trailing byte
            dcerpc_pdu(0x0c, struct.pack("<HHI", 0x10b8, 0x10b8, 0) + struct.pack("<H", 4) + b"135\x00" + bytes(2) + b"\x01\x00\x00\x00" + b"\x04\x00\x00\x00" + NDR20),  # result 4
            dcerpc_pdu(0x0c, struct.pack("<HHI", 0x10b8, 0x10b8, 0) + struct.pack("<H", 4) + b"135\x00" + bytes(2) + b"\x01\x00\x00\x00" + bytes(4) + bytes(20)),  # nil accepted syntax
            dcerpc_pdu(0x0c, struct.pack("<HHI", 0x10b8, 0x10b8, 0) + struct.pack("<H", 4) + b"135\x00" + bytes(2) + b"\x01\x00\x00\x00" + b"\x02\x00\x00\x00" + NDR20),  # rejected with a syntax
            dcerpc_pdu(0x0d, struct.pack("<H", 10) + b"\x01" + b"\x05\x00"),                                 # reason 10
            dcerpc_pdu(0x0d, struct.pack("<H", 9) + b"\x00"),                                                # no versions
            dcerpc_pdu(0x0d, struct.pack("<H", 9) + b"\x01" + b"\x04\x00"),                                  # version 4 only
            dcerpc_pdu(0x0d, struct.pack("<H", 9) + b"\x02" + b"\x05\x00"),                                  # count beyond the PDU
            dcerpc_pdu(0x0e, bytes(40)),                                                                      # alter_context is outside the profile
        ]
        for data in rejected:
            observation = stream(data)
            self.assertNotEqual(observation.status, "identified", (data[:20].hex(), observation.reason))
        self.assertEqual(select(DCERPC_BIND_ACK[:24]), "dcerpc")
        self.assertEqual(select(DCERPC_BIND_NAK[:21]), "dcerpc")
        for data in (DCERPC_BIND_ACK, DCERPC_BIND_NAK):
            for split in range(1, len(data)):
                inspector = Inspector()
                inspector.feed(data[:split])
                inspector.feed(data[split:])
                self.assertEqual(inspector.observation, stream(data), split)

    def test_mutations_never_raise_or_leak(self):
        generator = random.Random(44)
        for base in (SMB2_RESPONSE, SMB311_RESPONSE, tcp(KERBEROS_AS_REP), tcp(KERBEROS_ERROR), DCERPC_BIND_ACK, DCERPC_BIND_NAK):
            for _ in range(250):
                data = bytearray(base)
                data[generator.randrange(len(data))] = generator.randrange(256)
                inspector = Inspector(Config(max_bytes=4096))
                inspector.feed(bytes(data))
                self.assertIn(inspector.observation.status, ("identified", "unknown", "malformed", "detecting", "budget_exhausted"))
                text = repr(inspector.observation)
                for leak in ("EXAMPLE", "krbtgt", "placeholder"):
                    self.assertNotIn(leak, text)
        for base in (KERBEROS_AS_REP, KERBEROS_ERROR, KERBEROS_TGS_REP):
            for _ in range(250):
                data = bytearray(base)
                data[generator.randrange(len(data))] = generator.randrange(256)
                observation = datagram(bytes(data))
                self.assertIn(observation.status, ("identified", "unknown", "malformed", "budget_exhausted"))
                self.assertNotIn("EXAMPLE", repr(observation))


if __name__ == "__main__":
    unittest.main()
