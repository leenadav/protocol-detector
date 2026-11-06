"""v0.32: S7comm after the ISO-TSAP connection (cotp-connect shift) and the X.224 connection confirm."""
import random
import unittest

from protocol_engine import Inspector
from protocol_engine.appid import session_verdict
from protocol_fixtures import ISO_TSAP, ISO_TSAP_CONFIRM, RDP, RDP_CONFIRM, S7COMM, S7COMM_ACK


def run(data, hint=None):
    inspector = Inspector(protocol_hint=hint)
    events = inspector.feed(data)
    return inspector, events


def fields(observation, *names):
    return {e.field: e.value for e in observation.evidence if e.field in names}


def pdu(rosctr=1, parameters=b"\xf0\x00\x00\x01\x00\x01\x01\xe0", data=b"", error=b"\x00\x00", protocol=0x32, reserved=b"\x00\x00"):
    header = bytes([protocol, rosctr]) + reserved + b"\x00\x01" + len(parameters).to_bytes(2, "big") + len(data).to_bytes(2, "big")
    if rosctr in (2, 3):
        header += error
    body = header + parameters + data
    return b"\x03\x00" + (7 + len(body)).to_bytes(2, "big") + b"\x02\xf0\x80" + body


class S7Tests(unittest.TestCase):
    def test_connection_request_and_confirm_shift_to_s7(self):
        for data, carrier_scope, rosctr in ((ISO_TSAP + S7COMM, "negotiation_request", "job"), (ISO_TSAP_CONFIRM + S7COMM_ACK, "negotiation_response", "ack_data")):
            inspector, events = run(data)
            self.assertEqual([e.kind for e in events], ["updated", "shifted"])
            carrier, final = events[0].observation, events[1].observation
            self.assertEqual((carrier.application_protocol, carrier.scope), ("iso-tsap", carrier_scope))
            self.assertEqual((final.status, final.application_protocol), ("identified", "s7comm"))
            self.assertEqual(fields(final, "shift", "shift_from", "s7_rosctr", "s7_function"),
                             {"shift": "cotp-connect", "shift_from": "iso-tsap", "s7_rosctr": rosctr, "s7_function": "setup_communication"})
            self.assertEqual(inspector.metrics.bytes_inspected, len(data))
            for split in range(len(data) + 1):
                other = Inspector()
                other.feed(data[:split])
                other.feed(data[split:])
                self.assertEqual(other.observation, final, split)
        verdict = session_verdict(run(ISO_TSAP + S7COMM)[0].observation, run(ISO_TSAP_CONFIRM + S7COMM_ACK)[0].observation, "tcp", 102, 60, 60, True, None)
        self.assertEqual((verdict.app, verdict.shifted_from, verdict.port_usage, verdict.category, verdict.subcategory), ("s7comm", "iso-tsap", "standard", "business-systems", "ics-protocol"))
        self.assertIn("iso-tsap", verdict.implicitly_uses)
        pending = run(ISO_TSAP)[0]
        self.assertEqual((pending.observation.application_protocol, pending._terminal), ("iso-tsap", False))
        pending.end()
        self.assertEqual(fields(pending.observation, "shifted_payload"), {"shifted_payload": "incomplete"})

    def test_s7_profile_rejections_keep_the_carrier(self):
        self.assertEqual(run(S7COMM, "s7comm")[0].observation.application_protocol, "s7comm")
        self.assertEqual(run(pdu(rosctr=7, parameters=bytes(8)), "s7comm")[0].observation.application_protocol, "s7comm")
        self.assertEqual(run(pdu(parameters=b"\x04\x01" + bytes(12)), "s7comm")[0].observation.application_protocol, "s7comm")
        self.assertEqual(run(pdu(rosctr=2, parameters=b""), "s7comm")[0].observation.application_protocol, "s7comm")
        rejected = (pdu(protocol=0x31), pdu(rosctr=4), pdu(reserved=b"\x00\x01"), pdu(parameters=b"\x99" + bytes(7)),
                    pdu(parameters=b"\xf0\x00\x00\x01\x00\x01\x01\xe1"), pdu(parameters=b"\xf0\x00\x00\x00\x00\x01\x01\xe0"),
                    pdu(parameters=b"\xf0\x00\x00\x01\x00\x01"), pdu(rosctr=1, parameters=b""), pdu(rosctr=7, parameters=bytes(4)),
                    pdu(rosctr=3, error=b"\xff\x00"), S7COMM[:4] + b"\x02\xf0\x00" + S7COMM[7:], S7COMM[:2] + b"\x00\x10" + S7COMM[4:],
                    S7COMM[:-1])
        trailing = run(S7COMM + b"\x00", "s7comm")[0]  # the byte after a complete PDU is the next message, not inspected
        self.assertEqual((trailing.observation.application_protocol, trailing.metrics.bytes_inspected), ("s7comm", len(S7COMM)))
        for data in rejected:
            inspector = run(data, "s7comm")[0]
            inspector.end()
            self.assertNotEqual(inspector.observation.status, "identified", data)
            shifted = run(ISO_TSAP + data)[0]
            shifted.end()
            self.assertEqual(shifted.observation.application_protocol, "iso-tsap", data)
            self.assertIn(fields(shifted.observation, "shifted_payload")["shifted_payload"], ("unknown", "malformed", "incomplete"))
        self.assertEqual(run(S7COMM)[0].observation.status, "malformed")  # never selected from a bare TPKT prefix
        rng = random.Random(32)
        for _ in range(200):
            changed = bytearray(ISO_TSAP + S7COMM)
            changed[rng.randrange(len(changed))] = rng.randrange(256)
            whole, parts = Inspector(), Inspector()
            whole.feed(bytes(changed))
            for pos in range(0, len(changed), 3):
                parts.feed(bytes(changed[pos:pos + 3]))
            whole.end()
            parts.end()
            self.assertEqual(whole.observation, parts.observation, bytes(changed))

    def test_tpkt_route_distinguishes_rdp_and_cotp_confirms(self):
        self.assertEqual(run(RDP_CONFIRM)[0].observation.application_protocol, "rdp")
        self.assertEqual(run(RDP)[0].observation.application_protocol, "rdp")
        confirm = run(ISO_TSAP_CONFIRM)[0].observation
        self.assertEqual((confirm.application_protocol, confirm.scope), ("iso-tsap", "negotiation_response"))
        zero_dst = ISO_TSAP_CONFIRM[:6] + b"\x00\x00" + ISO_TSAP_CONFIRM[8:]
        self.assertEqual(run(zero_dst)[0].observation.status, "malformed")
        nonzero_dst_request = ISO_TSAP[:6] + b"\x00\x01" + ISO_TSAP[8:]
        self.assertEqual(run(nonzero_dst_request)[0].observation.status, "malformed")
        bare_confirm = b"\x03\x00\x00\x0b\x06\xd0\x00\x01\x00\x02\x00"
        self.assertEqual(run(bare_confirm)[0].observation.status, "unknown")
        self.assertEqual(run(ISO_TSAP_CONFIRM[:-2])[0].observation.status, "detecting")


if __name__ == "__main__":
    unittest.main()
