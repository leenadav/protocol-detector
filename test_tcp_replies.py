"""v0.47: TCP server replies for Modbus, GIOP, TACACS+, SMB1 and AMQP."""
import random
import struct
import unittest

from protocol_engine import Config, Inspector
from protocol_engine.appid import classify, session_verdict
from protocol_engine.dispatch import select
from protocol_engine.risks import RISKS
from protocol_fixtures import (AMQP_START, GIOP, GIOP_LOCATE_REPLY, GIOP_REPLY, MODBUS, MODBUS_EXCEPTION, MODBUS_RESPONSE, SMB1, SMB1_RESPONSE,
                               TACACS, TACACS_REPLY, amqp_frame, amqp_longstr, giop_message, modbus_frame, smb1_response)

LEAKS = ("placeholder", "PLAIN", "en_US", "demo")


def stream(data, hint=None, config=None):
    inspector = Inspector(config, protocol_hint=hint)
    inspector.feed(data)
    return inspector


def fields(observation, prefix):
    return {e.field: e.value for e in observation.evidence if e.field.startswith(prefix)}


class TCPReplyTests(unittest.TestCase):
    def assert_identified(self, data, protocol, scope, **expected):
        observation = stream(data).observation
        self.assertEqual((observation.status, observation.application_protocol, observation.scope), ("identified", protocol, scope), observation)
        found = {e.field: e.value for e in observation.evidence}
        for key, value in expected.items():
            self.assertEqual(found.get(key), value, (key, found))
        text = repr(observation)
        for leak in LEAKS:
            self.assertNotIn(leak, text)
        return observation

    def assert_rejected(self, data):
        observation = stream(data).observation
        self.assertNotEqual(observation.status, "identified", (data[:16].hex(), observation.reason))

    def test_modbus_responses_and_exceptions(self):
        self.assert_identified(MODBUS, "modbus", "request_header", modbus_pdu="request")
        self.assert_identified(MODBUS_RESPONSE, "modbus", "response_header", modbus_pdu="response")
        exception = self.assert_identified(MODBUS_EXCEPTION, "modbus", "response_header", modbus_pdu="exception", modbus_exception="illegal-data-address")
        self.assertEqual(classify(exception, "tcp", 502).risks, ("modbus-exception-response",))
        self.assertIn("modbus-exception-response", RISKS)
        verdict = session_verdict(stream(MODBUS).observation, stream(MODBUS_EXCEPTION).observation, "tcp", 502, 12, 9, True, None)
        self.assertEqual((verdict.app, verdict.risks), ("modbus", ("modbus-exception-response",)))
        for function, pdu in ((1, b"\x01\x05"), (2, b"\x02\x00\x01"), (4, b"\x02\x00\x01"), (7, b"\x40"), (11, b"\x00\x00\x00\x05"), (12, b"\x06" + bytes(6)), (17, b"\x03abc")):
            self.assert_identified(modbus_frame(function, pdu), "modbus", "response_header", modbus_pdu="response")
        for code in (1, 3, 4, 6, 10, 11):
            self.assert_identified(modbus_frame(0x81, bytes([code])), "modbus", "response_header", modbus_pdu="exception")
        self.assert_identified(modbus_frame(0x90, b"\x01"), "modbus", "response_header")   # exception for write multiple registers
        rejected = [
            modbus_frame(3, b"\x03\x00\x0a\x00"),            # odd register byte count
            modbus_frame(3, b"\x04\x00\x0a"),                # byte count beyond the PDU
            modbus_frame(1, b"\x00"),                        # zero byte count
            modbus_frame(7, b"\x40\x00"),                    # exception status with two bytes
            modbus_frame(11, b"\x00\x00\x00"),               # comm-event counter with three bytes
            modbus_frame(0x83, b""),                         # exception without a code
            modbus_frame(0x83, b"\x02\x00"),                 # exception with two bytes
            modbus_frame(0x83, b"\x00"),                     # exception code zero
            modbus_frame(0x83, b"\x0c"),                     # exception code 12
            modbus_frame(0x83, b"\x09"),                     # unassigned exception code 9
            modbus_frame(0xc8, b"\x01"),                     # exception for a function outside the public profile
            modbus_frame(0x80, b"\x01"),                     # function zero
        ]
        for data in rejected:
            self.assert_rejected(data)
        self.assertEqual(select(MODBUS_EXCEPTION[:24]), "modbus")

    def test_giop_replies(self):
        self.assert_identified(GIOP, "giop/1.2", "locate_request", giop_message="locate-request")
        self.assert_identified(GIOP_REPLY, "giop/1.2", "reply_header", giop_message="reply", giop_status="no-exception")
        self.assert_identified(GIOP_LOCATE_REPLY, "giop/1.2", "locate_reply", giop_message="locate-reply", giop_status="object-here")
        for status, label in ((1, "user-exception"), (2, "system-exception"), (3, "location-forward")):
            self.assert_identified(giop_message(1, struct.pack(">III", 7, status, 0) + bytes(4) + bytes(16)), "giop/1.2", "reply_header", giop_status=label)
        self.assert_identified(giop_message(1, struct.pack(">III", 7, 0, 1) + struct.pack(">II", 1, 4) + b"ctx!"), "giop/1.2", "reply_header")   # one service context, no body
        self.assert_identified(giop_message(4, struct.pack(">II", 7, 2) + bytes(16)), "giop/1.2", "locate_reply", giop_status="object-forward")
        self.assert_identified(giop_message(1, struct.pack("<III", 7, 0, 0) + bytes(4) + bytes(8), order="<"), "giop/1.2", "reply_header")
        verdict = session_verdict(stream(GIOP).observation, stream(GIOP_REPLY).observation, "tcp", 2809, 28, 36, True, None)
        self.assertEqual(verdict.app, "giop")
        rejected = [
            giop_message(1, struct.pack(">III", 7, 6, 0)),                                   # reply status 6
            giop_message(1, struct.pack(">III", 7, 0, 3) + bytes(8)),                        # context count beyond the message
            giop_message(1, struct.pack(">III", 7, 0, 1) + struct.pack(">II", 1, 1) + b"c" + bytes(7)),   # padding without a body
            giop_message(1, struct.pack(">II", 7, 0)),                                       # shorter than the reply header
            giop_message(4, struct.pack(">II", 7, 0) + b"x"),                                # UNKNOWN_OBJECT with a body
            giop_message(4, struct.pack(">II", 7, 6)),                                       # locate status 6
            giop_message(2, bytes(8)),                                                        # CancelRequest is outside the profile
            giop_message(1, struct.pack(">III", 7, 0, 200) + bytes(1600)),                   # context budget
        ]
        for data in rejected:
            self.assert_rejected(data)

    def test_tacacs_reply(self):
        self.assert_identified(TACACS, "tacacs-plus", "protocol_header", tacacs_packet="start", tacacs_type="authentication")
        self.assert_identified(TACACS_REPLY, "tacacs-plus", "negotiation_response", tacacs_packet="reply", tacacs_type="authentication")
        encrypted = b"\xc0\x01\x02\x00" + b"\x12\x34\x56\x78" + (16).to_bytes(4, "big") + bytes(range(16))
        self.assert_identified(encrypted, "tacacs-plus", "negotiation_response", tacacs_packet="reply")
        authorization = b"\xc0\x02\x02\x01" + b"\x12\x34\x56\x78" + (6 + 1 + 3).to_bytes(4, "big") + b"\x01\x01" + (0).to_bytes(2, "big") + (0).to_bytes(2, "big") + b"\x03" + b"a=b"
        self.assert_identified(authorization, "tacacs-plus", "negotiation_response", tacacs_type="authorization")
        accounting = b"\xc0\x03\x02\x01" + b"\x12\x34\x56\x78" + (5 + 2).to_bytes(4, "big") + (2).to_bytes(2, "big") + (0).to_bytes(2, "big") + b"\x01" + b"ok"
        self.assert_identified(accounting, "tacacs-plus", "negotiation_response", tacacs_type="accounting")
        verdict = session_verdict(stream(TACACS).observation, stream(TACACS_REPLY).observation, "tcp", 49, 24, 29, True, None)
        self.assertEqual(verdict.app, "tacacs-plus")
        rejected = [
            TACACS_REPLY[:12] + b"\x08" + TACACS_REPLY[13:],                                 # unknown authentication status
            TACACS_REPLY[:14] + (12).to_bytes(2, "big") + TACACS_REPLY[16:],                 # server_msg length disagrees
            b"\xc0\x01\x03\x01" + b"\x12\x34\x56\x78" + (8).to_bytes(4, "big") + bytes(8),  # seq_no 3
            accounting[:16] + b"\x04" + accounting[17:],                                     # accounting status 4
            authorization[:12] + b"\x03" + authorization[13:],                               # authorization status 3
        ]
        for data in rejected:
            self.assert_rejected(data)

    def test_smb1_negotiate_response(self):
        self.assert_identified(SMB1, "smb1", "negotiation_request", smb1_message="negotiate-request")
        self.assert_identified(SMB1_RESPONSE, "smb1", "negotiation_response", smb1_message="negotiate-response", smb1_dialect_layout="nt-lm-0.12")
        self.assert_identified(smb1_response(words=13), "smb1", "negotiation_response", smb1_dialect_layout="lan-manager")
        self.assert_identified(smb1_response(words=1), "smb1", "negotiation_response", smb1_dialect_layout="core")
        self.assert_identified(smb1_response(challenge=b"", domain=b""), "smb1", "negotiation_response")
        verdict = session_verdict(stream(SMB1).observation, stream(SMB1_RESPONSE).observation, "tcp", 445, 86, 93, True, None)
        self.assertEqual((verdict.app, verdict.risks), ("smb", ("desktop-or-file-sharing-session", "obsolete-protocol")))
        rejected = [
            smb1_response(words=12),                                                          # unknown layout
            smb1_response(dialect_index=40),                                                  # index beyond any request
            smb1_response(challenge=bytes(7)),                                                # challenge of seven bytes
            smb1_response(security_mode=0x10),                                                # reserved security bit
            SMB1_RESPONSE[:-1],                                                               # truncated
            SMB1_RESPONSE[:4 + 5] + b"\x01\x00\x00\x00" + SMB1_RESPONSE[4 + 9:],              # error status
        ]
        for data in rejected:
            self.assert_rejected(data)

    def test_amqp_connection_start(self):
        self.assert_identified(b"AMQP\x00\x00\x09\x01", "amqp/0-9-1", "protocol_header", amqp_message="protocol-header")
        self.assert_identified(AMQP_START, "amqp/0-9-1", "negotiation_response", amqp_message="connection-start")
        verdict = session_verdict(stream(b"AMQP\x00\x00\x09\x01").observation, stream(AMQP_START).observation, "tcp", 5672, 8, 69, True, None)
        self.assertEqual(verdict.app, "amqp")
        minimal = amqp_frame(b"\x00\x0a\x00\x0a\x00\x09" + bytes(4) + amqp_longstr(b"PLAIN") + amqp_longstr(b"en_US"))
        self.assert_identified(minimal, "amqp/0-9-1", "negotiation_response")
        rejected = [
            amqp_frame(b"\x00\x0a\x00\x0a\x00\x09" + bytes(4) + amqp_longstr(b"PLAIN") + amqp_longstr(b"en_US"))[:-1] + b"\x00",  # frame end
            amqp_frame(b"\x00\x0a\x00\x0b\x00\x09" + bytes(4) + amqp_longstr(b"PLAIN") + amqp_longstr(b"en_US")),            # Connection.Start-Ok
            amqp_frame(b"\x00\x0a\x00\x0a\x01\x00" + bytes(4) + amqp_longstr(b"PLAIN") + amqp_longstr(b"en_US")),            # version 1.0 in a 0-9 frame
            amqp_frame(b"\x00\x0a\x00\x0a\x00\x09" + (99).to_bytes(4, "big") + amqp_longstr(b"PLAIN") + amqp_longstr(b"en_US")),  # table beyond the frame
            amqp_frame(b"\x00\x0a\x00\x0a\x00\x09" + bytes(4) + amqp_longstr(b"") + amqp_longstr(b"en_US")),                 # empty mechanisms
            amqp_frame(b"\x00\x0a\x00\x0a\x00\x09" + bytes(4) + amqp_longstr(b"PLAIN") + amqp_longstr(b"en\x01")),           # non-printable locale
            amqp_frame(b"\x00\x0a\x00\x0a\x00\x09" + bytes(4) + amqp_longstr(b"PLAIN") + amqp_longstr(b"en_US") + b"\x00"),  # trailing byte
            amqp_frame(b"\x00\x0a\x00\x0a\x00\x09" + bytes(4) + amqp_longstr(b"PLAIN") + amqp_longstr(b"en_US"), channel=1),  # channel 1
            b"\x01\x00\x00\x00\x00\x20\x00" + bytes(20),                                                                         # size beyond the profile
        ]
        for data in rejected:
            self.assert_rejected(data)
        self.assertEqual(select(AMQP_START[:24]), "amqp")
        self.assertIsNone(select(AMQP_START[:10]))
        for split in range(1, len(AMQP_START)):
            inspector = Inspector()
            inspector.feed(AMQP_START[:split])
            inspector.feed(AMQP_START[split:])
            self.assertEqual(inspector.observation, stream(AMQP_START).observation, split)
            self.assertEqual(inspector.metrics.bytes_inspected, len(AMQP_START), split)

    def test_mutations_never_raise_or_leak(self):
        generator = random.Random(47)
        for base in (MODBUS_RESPONSE, MODBUS_EXCEPTION, GIOP_REPLY, GIOP_LOCATE_REPLY, TACACS_REPLY, SMB1_RESPONSE, AMQP_START):
            for _ in range(250):
                data = bytearray(base)
                data[generator.randrange(len(data))] = generator.randrange(256)
                inspector = stream(bytes(data), config=Config(max_bytes=4096))
                self.assertIn(inspector.observation.status, ("identified", "unknown", "malformed", "detecting", "budget_exhausted"))
                for leak in LEAKS:
                    self.assertNotIn(leak, repr(inspector.observation))


if __name__ == "__main__":
    unittest.main()
