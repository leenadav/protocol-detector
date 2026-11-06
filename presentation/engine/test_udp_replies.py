"""v0.46: datagram server replies: DTLS server flight, RADIUS responses, OpenVPN server reset, IKEv2 responder."""
import random
import unittest

from protocol_engine import Config, DatagramInspector, Inspector
from protocol_engine.appid import classify, session_verdict
from protocol_engine.risks import RISKS
from protocol_fixtures import (DTLS, DTLS_HELLO_VERIFY, DTLS_SERVER_HELLO, IKEV2, IKEV2_RESPONSE, OPENVPN, OPENVPN_SERVER, OPENVPN_SERVER_TCP,
                               OPENVPN_TCP, RADIUS, RADIUS_ACCEPT, RADIUS_CHALLENGE, RADIUS_REJECT, dtls_record, radius_attr, radius_packet)

LEAKS = ("placeholder", "Welcome", "denied")


def datagram(data, hint=None, config=None):
    return DatagramInspector(config).inspect(data, hint)


def fields(observation, *names):
    return {e.field: e.value for e in observation.evidence if e.field in names}


def ike_response(flags=0x20, responder_spi=bytes.fromhex("2122232425262728"), body=None, exchange=34):
    body = IKEV2_RESPONSE[28:] if body is None else body
    header = IKEV2_RESPONSE[:8] + responder_spi + bytes([IKEV2_RESPONSE[16], 0x20, exchange, flags]) + bytes(4) + (28 + len(body)).to_bytes(4, "big")
    return header + body


class DatagramReplyTests(unittest.TestCase):
    def assert_identified(self, data, label, hint=None, **expected):
        observation = datagram(data, hint)
        self.assertEqual((observation.status, observation.application_protocol or observation.encryption), ("identified", label), observation)
        found = {e.field: e.value for e in observation.evidence}
        for key, value in expected.items():
            self.assertEqual(found.get(key), value, (key, found))
        for leak in LEAKS:
            self.assertNotIn(leak, repr(observation))
        return observation

    def assert_rejected(self, data, hint=None):
        observation = datagram(data, hint)
        self.assertNotEqual(observation.status, "identified", (data[:16].hex(), observation.reason))

    def test_dtls_server_flight(self):
        self.assert_identified(DTLS, "dtls", handshake="client_hello")
        self.assert_identified(DTLS_HELLO_VERIFY, "dtls", handshake="hello_verify_request")
        server = self.assert_identified(DTLS_SERVER_HELLO, "dtls", handshake="server_hello", selected_dtls_version="1.2", selected_cipher="0xc02f")
        self.assertNotIn("ja4s", fields(server, "ja4s"))
        self.assertNotIn("tls_handshake", {e.field for e in server.evidence})
        with_fingerprints = datagram(DTLS_SERVER_HELLO, config=Config(fingerprints=True))
        self.assertEqual({e.field for e in with_fingerprints.evidence if e.strength == "derived"}, set())   # TLS-prefixed JA4S does not describe DTLS
        verdict = session_verdict(datagram(DTLS), server, "udp", 4433, 67, 70, True, None)
        self.assertEqual((verdict.app, verdict.encryption), ("dtls", "dtls"))
        self.assert_identified(dtls_record(3, b"\xfe\xfd" + bytes([1]) + b"\x00"), "dtls", handshake="hello_verify_request")
        self.assert_identified(dtls_record(2, b"\xfe\xfd" + bytes(32) + b"\x00" + b"\xc0\x2f" + b"\x00"), "dtls", handshake="server_hello")
        rejected = [
            dtls_record(3, b"\xfe\xfd" + bytes([0])),                                   # empty cookie
            dtls_record(3, b"\xfe\xfd" + bytes([33]) + bytes(33)),                      # cookie beyond 32 bytes
            dtls_record(3, b"\xfe\xfd" + bytes([4]) + bytes(5)),                        # cookie length disagrees
            dtls_record(3, b"\x03\x03" + bytes([4]) + bytes(4)),                        # TLS version in a DTLS message
            dtls_record(2, b"\xfe\xff" + bytes(32) + b"\x00" + b"\xc0\x2f" + b"\x00"),  # DTLS 1.0 ServerHello
            dtls_record(2, b"\xfe\xfd" + bytes(32) + b"\x00" + b"\x13\x01" + b"\x00"),  # TLS 1.3 cipher without supported_versions
            dtls_record(2, b"\xfe\xfd" + bytes(32) + b"\x00" + b"\xc0\x2f" + b"\x01"),  # compression
            dtls_record(2, b"\xfe\xfd" + bytes(32) + b"\x21" + bytes(33) + b"\xc0\x2f" + b"\x00"),  # session id beyond 32
            dtls_record(4, bytes(40)),                                                   # NewSessionTicket is outside the profile
            DTLS_SERVER_HELLO[:3] + b"\x00\x01" + DTLS_SERVER_HELLO[5:],                # epoch 1
        ]
        for data in rejected:
            self.assert_rejected(data)
            self.assert_rejected(data, hint="dtls")

    def test_radius_responses_require_the_hint_and_match_their_code(self):
        self.assert_identified(RADIUS, "radius", hint="radius", radius_code="access-request")
        self.assert_identified(RADIUS_ACCEPT, "radius", hint="radius", radius_code="access-accept")
        self.assert_identified(RADIUS_REJECT, "radius", hint="radius", radius_code="access-reject")
        self.assert_identified(RADIUS_CHALLENGE, "radius", hint="radius", radius_code="access-challenge")
        for data in (RADIUS_ACCEPT, RADIUS_REJECT, RADIUS_CHALLENGE):
            self.assertNotEqual(datagram(data).application_protocol, "radius")   # still hint-only
        self.assertEqual(classify(datagram(RADIUS_REJECT, "radius"), "udp", 1812).risks, ("radius-access-reject",))
        self.assertEqual(classify(datagram(RADIUS_ACCEPT, "radius"), "udp", 1812).risks, ())
        self.assertIn("radius-access-reject", RISKS)
        verdict = session_verdict(datagram(RADIUS, "radius"), datagram(RADIUS_REJECT, "radius"), "udp", 1812, 56, 58, True, None)
        self.assertEqual((verdict.app, verdict.risks), ("radius", ("radius-access-reject",)))
        self.assert_identified(radius_packet(2, b""), "radius", hint="radius", radius_code="access-accept")   # bare Accept
        self.assert_identified(radius_packet(2, radius_attr(26, b"\x00\x00\x00\x09\x01\x03\x01") + radius_attr(26, b"\x00\x00\x00\x09\x02\x03\x02")),
                               "radius", hint="radius")
        rejected = [
            radius_packet(3, radius_attr(6, b"\x00\x00\x00\x02")),                     # Service-Type is not allowed in a Reject
            radius_packet(11, radius_attr(18, b"enter code")),                         # Challenge without State
            radius_packet(2, radius_attr(27, b"\x00\x01")),                            # Session-Timeout of two bytes
            radius_packet(2, radius_attr(18, b"")),                                    # empty Reply-Message
            radius_packet(2, radius_attr(80, bytes(15))),                              # Message-Authenticator length
            radius_packet(2, radius_attr(2, b"x" * 16)),                               # User-Password in a response
            radius_packet(2, radius_attr(24, b"a") + radius_attr(24, b"b")),           # duplicate State
            radius_packet(4, b""),                                                      # Accounting-Request outside the profile
            radius_packet(2, b"") + b"\x00",                                            # trailing padding
            radius_packet(2, radius_attr(26, b"\x01\x00\x00\x09\x01\x03\x01")),         # vendor id high byte nonzero
        ]
        for data in rejected:
            self.assert_rejected(data, hint="radius")

    def test_openvpn_server_reset(self):
        self.assert_identified(OPENVPN, "openvpn", openvpn_control="client-hard-reset")
        self.assert_identified(OPENVPN_SERVER, "openvpn", openvpn_control="server-hard-reset", tls_auth="absent")
        tls_auth = OPENVPN_SERVER[:9] + bytes(20) + bytes(8) + OPENVPN_SERVER[9:]
        self.assert_identified(tls_auth, "openvpn", openvpn_control="server-hard-reset", tls_auth="present")
        two_acks = OPENVPN_SERVER[:9] + b"\x02" + bytes(8) + OPENVPN_SERVER[14:]
        self.assert_identified(two_acks, "openvpn", openvpn_control="server-hard-reset")
        for data in (OPENVPN_TCP, OPENVPN_SERVER_TCP):
            inspector = Inspector()
            inspector.feed(data)
            self.assertEqual(inspector.observation.application_protocol, "openvpn")
        tcp = Inspector()
        tcp.feed(OPENVPN_SERVER_TCP)
        self.assertEqual((tcp.observation.scope, fields(tcp.observation, "openvpn_control")), ("negotiation_response", {"openvpn_control": "server-hard-reset"}))
        verdict = session_verdict(datagram(OPENVPN), datagram(OPENVPN_SERVER), "udp", 1194, 14, 26, True, None)
        self.assertEqual(verdict.app, "openvpn")
        rejected = [
            OPENVPN_SERVER[:9] + b"\x00" + OPENVPN_SERVER[10:],                        # server reset without acknowledgements
            OPENVPN_SERVER[:9] + b"\x09" + bytes(36) + OPENVPN_SERVER[14:],            # nine acknowledgements
            OPENVPN_SERVER[:14] + bytes(8) + OPENVPN_SERVER[22:],                      # remote session id zero
            OPENVPN_SERVER + b"\x00",                                                   # trailing byte
            OPENVPN_SERVER[:-1],                                                        # truncated packet id
            b"\x41" + OPENVPN_SERVER[1:],                                               # key id one
            b"\x48" + OPENVPN_SERVER[1:],                                               # opcode 9 (soft reset) outside the profile
        ]
        for data in rejected:
            self.assert_rejected(data)
            self.assert_rejected(data, hint="openvpn")

    def test_ikev2_responder(self):
        self.assert_identified(IKEV2, "ikev2", exchange="ike_sa_init_request", offered_dh_group="14")
        response = self.assert_identified(IKEV2_RESPONSE, "ikev2", exchange="ike_sa_init_response", selected_dh_group="14")
        self.assertNotIn("offered_dh_group", {e.field for e in response.evidence})
        verdict = session_verdict(datagram(IKEV2), response, "udp", 500, 376, 376, True, None)
        self.assertEqual((verdict.app, verdict.client_protocol, verdict.server_protocol), ("ike", "ikev2", "ikev2"))
        body = IKEV2_RESPONSE[28:]
        certreq = b"\x00\x00\x00\x19" + b"\x04" + bytes(20)
        with_certreq = ike_response(body=body[:body.index(b"\x28\x00\x01\x08")] .replace(b"\x22\x00", b"\x22\x00", 1) + body[body.index(b"\x28\x00\x01\x08"):])
        self.assert_identified(with_certreq, "ikev2", exchange="ike_sa_init_response")
        nonce_then_certreq = ike_response(body=body[:-36] + b"\x26" + body[-35:] + certreq)   # nonce now points at CERTREQ (38)
        self.assert_identified(nonce_then_certreq, "ikev2", exchange="ike_sa_init_response")
        two_proposals = IKEV2[28:]
        rejected = [
            ike_response(responder_spi=bytes(8)),                                     # responder SPI zero
            ike_response(flags=0x28),                                                 # both I and R bits
            ike_response(flags=0x00),                                                 # no direction flag
            ike_response(exchange=35),                                                # IKE_AUTH
            IKEV2_RESPONSE[:19] + b"\x08" + IKEV2_RESPONSE[20:],                      # initiator flag with a responder SPI
            ike_response(body=body[:-36] + b"\x26" + body[-35:] + b"\x00\x00\x00\x05" + b"\x05"),   # CERTREQ encoding 5
            ike_response(body=body[:-36] + b"\x26" + body[-35:] + b"\x00\x00\x00\x19" + b"\x04" + bytes(19)),  # hash list not a multiple of 20
            IKEV2_RESPONSE[:-1],                                                      # truncated
            ike_response(body=body.replace(b"\x00\x00\x00\x24", b"\x00\x00\x00\x23", 1) + b"\x00"),  # length mismatch
        ]
        for data in rejected:
            self.assert_rejected(data)
        # A responder SA with two transforms of one type is a request shape, not a selection.
        doubled = body.replace(b"\x00\x00\x00\x2c\x01\x01\x00\x04", b"\x00\x00\x00\x34\x01\x01\x00\x05", 1)
        doubled = doubled[:8 + 4 + 8 + 12] + b"\x03\x00\x00\x08\x02\x00\x00\x07" + doubled[8 + 4 + 8 + 12:]
        self.assert_rejected(ike_response(body=doubled.replace(b"\x22\x00\x00\x30", b"\x22\x00\x00\x38", 1)))
        self.assert_rejected(ike_response(body=two_proposals.replace(two_proposals[:0], b"", 1)) if False else ike_response(body=body[:4] + b"\x00\x38" + body[6:]))

    def test_mutations_never_raise_or_leak(self):
        generator = random.Random(46)
        for base, hint in ((DTLS_HELLO_VERIFY, None), (DTLS_SERVER_HELLO, None), (RADIUS_ACCEPT, "radius"), (RADIUS_CHALLENGE, "radius"),
                           (OPENVPN_SERVER, None), (IKEV2_RESPONSE, None)):
            for _ in range(250):
                data = bytearray(base)
                data[generator.randrange(len(data))] = generator.randrange(256)
                observation = datagram(bytes(data), hint)
                self.assertIn(observation.status, ("identified", "unknown", "malformed", "budget_exhausted"))
                for leak in LEAKS:
                    self.assertNotIn(leak, repr(observation))


if __name__ == "__main__":
    unittest.main()
