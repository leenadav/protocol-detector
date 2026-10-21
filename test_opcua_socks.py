"""v0.41: OPC UA connection messages and the SOCKS5 server direction.

Endpoint URLs, server URIs, error reasons and bound addresses are framing only
and never appear in observations.
"""
import ipaddress
import random
import struct
import unittest

from protocol_engine import Config, Inspector
from protocol_engine.appid import classify, session_verdict
from protocol_engine.dispatch import select
from protocol_engine.opcua import MAX_MESSAGE, opcua_probe
from protocol_demo import SOCKS5
from protocol_fixtures import (DCERPC, OPCUA_ACK, OPCUA_ERROR, OPCUA_HELLO, OPCUA_REVERSE_HELLO, OPCUA_URL, SOCKS5_SERVER,
                               SOCKS5_SERVER_AUTH, opcua_message, opcua_string)

LEAKS = ("placeholder", "urn:")


def inspect(data, config=None, hint=None):
    inspector = Inspector(config, protocol_hint=hint)
    inspector.feed(data)
    return inspector


def fields(observation, prefix):
    return {e.field: e.value for e in observation.evidence if e.field.startswith(prefix)}


def hello(version=0, receive=65536, send=65536, url=OPCUA_URL):
    return opcua_message(b"HEL", struct.pack("<IIIII", version, receive, send, 0, 0) + opcua_string(url))


def socks_server(method=0, reply=0, atyp=1, address=bytes([10, 0, 0, 1]), port=b"\x04\x38", selection_version=5, reply_version=5, reserved=0):
    return bytes([selection_version, method, reply_version, reply, reserved, atyp]) + address + port


class OPCUASocksTests(unittest.TestCase):
    def assert_identified(self, data, protocol, scope, **expected):
        observation = inspect(data).observation
        self.assertEqual((observation.status, observation.application_protocol, observation.scope), ("identified", protocol, scope), observation)
        found = fields(observation, protocol.split("/")[0].replace("socks5", "socks") + "_")
        for key, value in expected.items():
            self.assertEqual(found.get(key), value, (key, found))
        text = repr(observation)
        for leak in LEAKS:
            self.assertNotIn(leak, text)
        return observation

    def assert_rejected(self, data, hint=None):
        observation = inspect(data, hint=hint).observation
        self.assertNotEqual(observation.status, "identified", (data[:16].hex(), observation))
        return observation

    def test_opcua_messages(self):
        client = self.assert_identified(OPCUA_HELLO, "opcua", "negotiation_request", opcua_message="hello", opcua_protocol_version="0")
        server = self.assert_identified(OPCUA_ACK, "opcua", "negotiation_response", opcua_message="acknowledge", opcua_protocol_version="0")
        self.assert_identified(OPCUA_ERROR, "opcua", "negotiation_response", opcua_message="error")
        self.assert_identified(OPCUA_REVERSE_HELLO, "opcua", "negotiation_request", opcua_message="reverse-hello")
        self.assertEqual(fields(inspect(OPCUA_ERROR).observation, "opcua_"), {"opcua_message": "error"})
        self.assert_identified(hello(version=1, receive=8192, send=8192), "opcua", "negotiation_request", opcua_protocol_version="1")
        self.assert_identified(opcua_message(b"ERR", struct.pack("<I", 0x80020000) + opcua_string(None)), "opcua", "negotiation_response")
        self.assert_identified(opcua_message(b"RHE", opcua_string(None) + opcua_string(b"opc.tcp://x")), "opcua", "negotiation_request")
        verdict = session_verdict(client, server, "tcp", 4840, 68, 28, True, None)
        self.assertEqual((verdict.app, verdict.category, verdict.subcategory, verdict.port_usage, verdict.risks), ("opc-ua", "business-systems", "ics-protocol", "standard", ()))
        self.assertEqual(classify(client, "tcp", 4841).risks, ("nonstandard-port",))
        self.assertEqual(inspect(OPCUA_HELLO, hint="opcua").observation.application_protocol, "opcua")
        self.assertEqual(inspect(OPCUA_HELLO, Config(max_bytes=64)).observation.status, "budget_exhausted")

    def test_opcua_rejections_and_text_neighbours(self):
        rejected = [
            hello(receive=8191), hello(send=4096),                                  # buffer minimums
            hello(url=b"http://placeholder"),                                       # scheme
            hello(url=b"opc.tcp://pl\x01ce"),                                       # not printable
            hello(url=None),                                                        # null endpoint URL
            hello(url=b"opc.tcp://" + b"x" * 4087),                                 # 4097-byte string
            OPCUA_HELLO[:-1] + b"\x00\x00",                                         # size disagrees with the fields
            OPCUA_HELLO[:4] + b"\x07\x00\x00\x00" + OPCUA_HELLO[8:],                # size below the header
            OPCUA_HELLO[:3] + b"C" + OPCUA_HELLO[4:],                                # chunk type other than F
            opcua_message(b"ACK", struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + b"\x00"),  # acknowledge with a tail
            opcua_message(b"ERR", struct.pack("<I", 0x00000000) + opcua_string(b"ok")),    # Good status in an error
            opcua_message(b"ERR", struct.pack("<I", 0x80020000)),                   # missing reason string
            opcua_message(b"RHE", opcua_string(b"urn:x") + opcua_string(b"tcp://x")),  # endpoint scheme
            opcua_message(b"OPN", bytes(20)),                                       # secure channel messages are outside the profile
            b"HELF" + (MAX_MESSAGE + 1).to_bytes(4, "little") + bytes(20),          # beyond the profile size
        ]
        for data in rejected:
            self.assert_rejected(data)
            self.assert_rejected(data, hint="opcua")
        for text in (b"HELO client.example.com\r\n", b"HEAD / HTTP/1.1\r\nHost: a\r\n\r\n", b"HELF / HTTP/1.1\r\nHost: a\r\n\r\n",
                     b"ACKF / HTTP/1.1\r\nHost: a\r\n\r\n", b"RHEF / HTTP/1.1\r\nHost: a\r\n\r\n", b"ERRF / HTTP/1.1\r\nHost: a\r\n\r\n"):
            observation = inspect(text).observation
            self.assertEqual(observation.status, "identified", text)
            self.assertIn(observation.application_protocol, ("smtp", "http/1.1"), text)
        self.assertEqual(inspect(b"AMQP\x00\x00\x09\x01").observation.application_protocol, "amqp/0-9-1")
        for prefix in (b"H", b"HE", b"HEL", b"HELF", b"HELF\x44\x00", b"A", b"AC", b"R", b"RH", b"E", b"ER"):
            self.assertIsNone(select(prefix), prefix)
        self.assertEqual(select(b"HELO"), "text")
        self.assertEqual(select(b"HELF\x44\x00\x00\x00"), "opcua")
        self.assertEqual(select(b"HELF / HT"), "text")
        self.assertEqual(select(b"AMQP\x00\x00\x09\x01"), "amqp")
        self.assertEqual(select(b"RFB 003.008\n"), "rfb")
        self.assertFalse(opcua_probe(b"HELF\x44\x00\x00"))
        self.assertFalse(opcua_probe(b"HELF\x44\x00\x01\x00"))

    def test_socks5_server_direction(self):
        self.assert_identified(SOCKS5_SERVER, "socks5", "negotiation_response", socks_method="no-authentication", socks_reply="succeeded")
        self.assert_identified(SOCKS5_SERVER_AUTH, "socks5", "negotiation_response", socks_method="username-password", socks_reply="succeeded")
        self.assertNotIn("10.0.0.1", repr(inspect(SOCKS5_SERVER).observation))
        for reply, label in ((1, "general-failure"), (5, "connection-refused"), (8, "address-type-not-supported")):
            self.assert_identified(socks_server(reply=reply), "socks5", "negotiation_response", socks_reply=label)
        self.assert_identified(socks_server(atyp=4, address=ipaddress.IPv6Address("2001:db8::1").packed), "socks5", "negotiation_response")
        self.assert_identified(socks_server(atyp=3, address=b"\x03a.b"), "socks5", "negotiation_response")
        client = inspect(SOCKS5).observation
        server = inspect(SOCKS5_SERVER).observation
        self.assertEqual((client.scope, fields(client, "socks_")["socks_target"]), ("initial_message", "example.com"))
        verdict = session_verdict(client, server, "tcp", 1080, 21, 12, True, None)
        self.assertEqual((verdict.app, verdict.client_protocol, verdict.server_protocol, verdict.port_usage), ("socks", "socks5", "socks5", "standard"))
        # A client offering two methods, one of them 0x05, is still a client: the request version at byte 4 decides.
        two_methods = b"\x05\x02\x05\x00" + SOCKS5[3:]
        self.assertEqual(fields(inspect(two_methods).observation, "socks_")["socks_command"], "CONNECT")
        self.assertEqual(inspect(b"\x05\x00").observation.status, "detecting")
        self.assertEqual(inspect(b"\x05\x02\x05\x00").observation.status, "detecting")
        self.assertEqual(inspect(b"\x05\x00", hint="socks5").observation.status, "detecting")
        ended = inspect(b"\x05\x00")
        ended.end()
        self.assertEqual(ended.observation.status, "incomplete")
        for data in (SOCKS5_SERVER, SOCKS5_SERVER_AUTH, SOCKS5, two_methods):
            whole = inspect(data).observation
            for split in range(1, len(data)):
                inspector = Inspector()
                inspector.feed(data[:split])
                inspector.feed(data[split:])
                self.assertEqual(inspector.observation, whole, (data.hex(), split))
                self.assertEqual(inspector.metrics.bytes_inspected, len(data))
        trailing = inspect(SOCKS5_SERVER + b"\x16\x03")
        self.assertEqual((trailing.observation.application_protocol, trailing.metrics.bytes_inspected), ("socks5", len(SOCKS5_SERVER)))

    def test_socks5_server_rejections_and_dcerpc_neighbour(self):
        rejected = [
            socks_server(reply_version=4),                       # reply version
            socks_server(reply=9),                               # reply code outside RFC 1928
            socks_server(reserved=1),
            socks_server(atyp=2),                                # address type
            socks_server(atyp=3, address=b"\x00"),               # empty bound name
            socks_server(atyp=3, address=b"\x03a b"),            # invalid name
            socks_server(method=1),                              # GSSAPI selection is a client greeting with one method, then malformed
            b"\x05\xff",                                         # no acceptable methods alone never identifies
        ]
        for data in rejected:
            self.assert_rejected(data)
        self.assertEqual(inspect(DCERPC).observation.application_protocol, "dcerpc/5.0")
        self.assertEqual(select(DCERPC[:24]), "dcerpc")
        self.assertEqual(select(SOCKS5_SERVER[:6]), "socks5")
        self.assertIsNone(select(b"\x05\x00\x05\x00\x00"))
        self.assertEqual(select(b"\x05\x00\x05\x00\x00\x02"), "dcerpc")
        self.assertIn(inspect(b"\x05\x00" + b"\xff" * 16).observation.status, ("unknown", "malformed"))   # DCE/RPC route rejects it

    def test_mutations_never_raise_or_leak(self):
        generator = random.Random(41)
        for base in (OPCUA_HELLO, OPCUA_ACK, OPCUA_ERROR, OPCUA_REVERSE_HELLO, SOCKS5_SERVER, SOCKS5_SERVER_AUTH, SOCKS5):
            for _ in range(300):
                data = bytearray(base)
                for _ in range(generator.randint(1, 2)):
                    data[generator.randrange(len(data))] = generator.randrange(256)
                inspector = inspect(bytes(data))
                self.assertIn(inspector.observation.status, ("identified", "unknown", "malformed", "detecting", "budget_exhausted"))
                self.assertLessEqual(inspector.metrics.bytes_inspected, len(data))
                self.assertNotIn("placeholder", repr(inspector.observation))


if __name__ == "__main__":
    unittest.main()
