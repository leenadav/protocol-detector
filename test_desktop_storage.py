"""X11, SPICE, AFP over DSI, Omron FINS/TCP, RIP and RTCP profiles, isolation and mutations."""
import random
import unittest

from protocol_engine import Config, DatagramInspector, Inspector
from protocol_engine.appid import classify, session_verdict
from protocol_engine.datagram import VALIDATORS
from protocol_fixtures import (AFP_GET_STATUS, AFP_OPEN_REPLY, AFP_OPEN_SESSION, DATAGRAM_CASES, FINS_FRAME, FINS_NODE_REPLY, FINS_NODE_REQUEST,
                               RIP_REQUEST, RIP_RESPONSE, RIP_V1, RTCP_SR, SPICE_LINK, SPICE_REPLY, STREAM_CASES, X11_REPLY, X11_SETUP,
                               X11_SETUP_MSB, dsi, fins, le16, le32, rip_entry, spice_header)


def values(observation):
    return {e.field: e.value for e in observation.evidence}


def stream(data, hint=None, config=None):
    inspector = Inspector(config, protocol_hint=hint)
    inspector.feed(data)
    return inspector


def datagram(data, hint=None, config=None):
    return DatagramInspector(config).inspect(data, hint)


def splits_agree(test, data, hint=None):
    expected = stream(data, hint).observation
    test.assertEqual(expected.status, "identified", data[:8])
    for split in range(len(data) + 1):
        inspector = Inspector(protocol_hint=hint)
        inspector.feed(data[:split])
        inspector.feed(data[split:])
        test.assertEqual(inspector.observation, expected, split)
    for end in range(len(data)):
        test.assertEqual(stream(data[:end], hint).observation.status, "detecting", end)
    inspector = stream(data + b"\x00" * 7, hint)
    test.assertEqual(inspector.metrics.bytes_inspected, len(data))


class X11Tests(unittest.TestCase):
    def test_setup_request_and_reply(self):
        request = stream(X11_SETUP).observation
        self.assertEqual((request.application_protocol, values(request)["x11_byte_order"], values(request)["x11_authorization"]), ("x11", "lsb", "mit-magic-cookie-1"))
        self.assertEqual({e.field: e.strength for e in request.evidence}["x11_authorization"], "asserted")
        self.assertNotIn("\\x0f", repr(request))
        self.assertEqual((values(stream(X11_SETUP_MSB).observation)["x11_byte_order"], values(stream(X11_SETUP_MSB).observation)["x11_authorization"]), ("msb", "none"))
        reply = stream(X11_REPLY, "x11-server").observation
        self.assertEqual((reply.scope, values(reply)["x11_message"]), ("negotiation_response", "setup-success"))
        self.assertNotIn("vendor-x", repr(reply))
        self.assertNotEqual(stream(X11_REPLY).observation.status, "identified")      # first byte 1 never selects X11 alone
        verdict = session_verdict(request, reply, "tcp", 6000)
        self.assertEqual((verdict.app, verdict.port_usage), ("x11", "standard"))
        self.assertEqual(classify(request, "tcp", 6063).port_usage, "standard")
        self.assertEqual(classify(request, "tcp", 6064).port_usage, "nonstandard")
        for data, hint in ((X11_SETUP, None), (X11_SETUP_MSB, None), (X11_REPLY, "x11-server")):
            splits_agree(self, data, hint)

    def test_setup_rules(self):
        head = b"l\x00" + le16(11) + le16(0)
        for bad, status in ((b"l\x01" + X11_SETUP[2:], "malformed"), (b"l\x00" + le16(12) + X11_SETUP[4:], "unknown"),
                            (b"l\x00" + le16(11) + le16(1) + X11_SETUP[6:], "unknown"), (head + le16(65) + le16(0) + bytes(2) + bytes(68), "malformed"),
                            (head + le16(0) + le16(4) + bytes(2) + bytes(4), "malformed"), (head + le16(4) + le16(1025) + bytes(2), "malformed"),
                            (head + le16(4) + le16(0) + bytes(2) + b"a\x01bc", "malformed")):
            self.assertEqual(stream(bad).observation.status, status, bad[:8])
        self.assertEqual(stream(b"lOGIN user\r\n").candidate, "text")
        self.assertEqual(stream(b"BREW / HTTP/1.1\r\n").candidate, "text")
        other = head + le16(5) + le16(0) + bytes(2) + b"OTHER" + bytes(3)
        self.assertEqual(values(stream(other).observation)["x11_authorization"], "other")
        self.assertEqual(stream(X11_SETUP, config=Config(max_bytes=64)).observation.status, "identified")
        failed = b"\x00\x05" + le16(11) + le16(0) + le16(2) + b"nope!" + bytes(3)
        self.assertEqual(values(stream(failed, "x11-server").observation)["x11_message"], "setup-failed")
        self.assertEqual(stream(b"\x00\x09" + le16(11) + le16(0) + le16(2) + bytes(8), "x11-server").observation.status, "malformed")
        self.assertEqual(values(stream(b"\x02\x00" + le16(11) + le16(0) + le16(1) + b"auth", "x11-server").observation)["x11_message"], "setup-authenticate")
        self.assertEqual(stream(b"\x03\x00" + le16(11) + le16(0) + le16(0), "x11-server").observation.status, "unknown")
        self.assertEqual(stream(b"\x01\x00" + le16(11) + le16(0) + le16(2) + bytes(8), "x11-server").observation.status, "malformed")
        broken = bytearray(X11_REPLY)
        broken[30] = 2                                       # image byte order
        self.assertEqual(stream(bytes(broken), "x11-server").observation.status, "malformed")
        broken = bytearray(X11_REPLY)
        broken[28] = 3                                       # three screens do not fit the reply
        self.assertEqual(stream(bytes(broken), "x11-server").observation.status, "malformed")
        big = b"B\x00" + (11).to_bytes(2, "big") + bytes(2) + (11).to_bytes(2, "big") + (0).to_bytes(2, "big") + b"\x00\x00" + b"XDM-AUTHORIZATION-1".ljust(12, b"\x00")[:12]
        self.assertEqual(stream(big).observation.status, "identified")


class SPICETests(unittest.TestCase):
    def test_link_message_and_reply(self):
        link = stream(SPICE_LINK).observation
        self.assertEqual((link.application_protocol, values(link)["spice_message"], values(link)["spice_channel"]), ("spice", "link-message", "main"))
        reply = stream(SPICE_REPLY).observation
        self.assertEqual((reply.scope, values(reply)["spice_message"], values(reply)["spice_link_error"]), ("negotiation_response", "link-reply", "ok"))
        self.assertEqual(session_verdict(link, reply, "tcp", 5900).app, "spice")
        for data in (SPICE_LINK, SPICE_REPLY):
            splits_agree(self, data)
        body = le32(7) + bytes((2, 0)) + le32(0) + le32(0) + le32(18)
        self.assertEqual(values(stream(spice_header(len(body)) + body).observation)["spice_channel"], "display")
        body = le32(7) + bytes((12, 0)) + le32(0) + le32(0) + le32(18)
        self.assertEqual(values(stream(spice_header(len(body)) + body).observation)["spice_channel"], "other")
        error = le32(5) + bytes(162) + le32(0) + le32(0) + le32(178)
        self.assertEqual(values(stream(spice_header(len(error)) + error).observation)["spice_link_error"], "need-secured")

    def test_link_rules(self):
        body = SPICE_LINK[16:]
        cases = ((b"REDQ" + le32(1) + le32(0) + le32(len(body)) + body, "unknown"), (b"REDQ" + le32(2) + le32(3) + le32(len(body)) + body, "unknown"),
                 (b"REDQ" + le32(2) + le32(2) + le32(17) + body[:17], "malformed"), (spice_header(len(body) + 4) + body + bytes(4), "malformed"),
                 (spice_header(len(body)) + le32(0) + bytes((0, 0)) + body[6:], "malformed"),              # channel type 0
                 (spice_header(len(body)) + le32(0) + bytes((2, 0)) + body[6:], "malformed"),              # display channel without connection id
                 (spice_header(len(body)) + body[:14] + le32(19) + body[18:], "malformed"),                # caps offset
                 (spice_header(len(body)) + body[:6] + le32(33) + body[10:], "malformed"),                 # caps count
                 (spice_header(len(SPICE_REPLY) - 16 + 4) + SPICE_REPLY[16:] + bytes(4), "malformed"),
                 (spice_header(len(SPICE_REPLY) - 16) + le32(10) + SPICE_REPLY[20:], "malformed"),         # link error 10
                 (b"RED", "detecting"))
        for data, status in cases:
            self.assertEqual(stream(data).observation.status, status, data[:20])
        self.assertEqual(stream(b"RFB 003.008\n").observation.application_protocol, "rfb")
        self.assertEqual(stream(b"REDX" + SPICE_LINK[4:]).candidate, "text")
        self.assertEqual(stream(b"R\x00\x00\x00\x08\x00").candidate, "postgresql")
        self.assertEqual(stream(SPICE_LINK, config=Config(max_bytes=64)).observation.status, "identified")
        self.assertEqual(stream(SPICE_REPLY, config=Config(max_bytes=100)).observation.status, "budget_exhausted")


class DSITests(unittest.TestCase):
    def test_requests_and_reply(self):
        open_session = stream(AFP_OPEN_SESSION).observation
        self.assertEqual((open_session.application_protocol, values(open_session)["dsi_message"], values(open_session)["afp_command"]), ("afp", "request", "open-session"))
        self.assertEqual(values(stream(AFP_GET_STATUS).observation)["afp_command"], "get-status")
        reply = stream(AFP_OPEN_REPLY).observation
        self.assertEqual((reply.scope, values(reply)["dsi_message"]), ("negotiation_response", "reply"))
        verdict = session_verdict(open_session, reply, "tcp", 548)
        self.assertEqual((verdict.app, verdict.port_usage, verdict.subcategory), ("afp", "standard", "storage-backup"))
        for data in (AFP_OPEN_SESSION, AFP_GET_STATUS, AFP_OPEN_REPLY):
            splits_agree(self, data)
        status_reply = dsi(1, 3, 2, bytes(300))
        self.assertEqual(values(stream(status_reply).observation)["afp_command"], "get-status")
        self.assertEqual(stream(dsi(1, 3, 2, error=-5019)).observation.status, "identified")       # error reply without data

    def test_dsi_rules(self):
        self.assertNotEqual(stream(dsi(0, 2, 1, bytes(8))).observation.status, "identified")   # DSICommand first: never routed
        cases = ((dsi(2, 4, 1), "unknown"), (dsi(0, 4, 1, b"\x03\x04" + bytes(4)), "malformed"),
                 (dsi(0, 4, 1, b"\x01\x02" + bytes(2)), "malformed"), (dsi(0, 4, 1, b"\x01"), "malformed"), (dsi(0, 3, 1, bytes(4)), "malformed"),
                 (dsi(0, 4, 1, bytes(70)), "malformed"), (dsi(1, 3, 2), "malformed"))
        for data, status in cases:
            self.assertEqual(stream(data).observation.status, status, data[:16])
        # Headers the dispatcher never routes (reserved bytes, data offset, length or error code outside the profile)
        # are rejected by the parser when forced with the afp hint.
        for data in (dsi(1, 3, 2, bytes(4097)), AFP_OPEN_SESSION[:12] + b"\x00\x00\x00\x01",
                     AFP_OPEN_SESSION[:4] + b"\x00\x00\x00\x08" + AFP_OPEN_SESSION[8:], AFP_OPEN_REPLY[:4] + b"\x00\x00\x01\x00" + AFP_OPEN_REPLY[8:]):
            self.assertNotEqual(stream(data).observation.status, "identified", data[:16])
            self.assertEqual(stream(data, "afp").observation.status, "malformed", data[:16])
        from protocol_fixtures import KAFKA
        self.assertEqual(stream(KAFKA).observation.application_protocol, "kafka")


class FINSTests(unittest.TestCase):
    def test_messages(self):
        request = stream(FINS_NODE_REQUEST).observation
        self.assertEqual((request.application_protocol, values(request)["fins_message"], classify(request, "tcp", 9600).app), ("fins", "node-address-request", "omron-fins"))
        reply = stream(FINS_NODE_REPLY).observation
        self.assertEqual((reply.scope, values(reply)["fins_message"]), ("negotiation_response", "node-address-reply"))
        frame = stream(FINS_FRAME).observation
        self.assertEqual((values(frame)["fins_message"], values(frame)["fins_frame"]), ("frame", "command"))
        response = fins(2, bytes((0xc0, 0, 2, 0, 1, 0, 0, 11, 0, 5)) + b"\x01\x01" + b"\x00\x00" + b"\x12\x34")
        observation = stream(response).observation
        self.assertEqual((observation.scope, values(observation)["fins_frame"]), ("response_header", "response"))
        self.assertEqual(session_verdict(request, reply, "tcp", 9600).app, "omron-fins")
        for data in (FINS_NODE_REQUEST, FINS_NODE_REPLY, FINS_FRAME):
            splits_agree(self, data)

    def test_rules(self):
        cases = ((fins(3, bytes(4)), "unknown"), (fins(0, bytes(8)), "malformed"), (fins(0, bytes(4), error=1), "malformed"),
                 (fins(1, bytes(4)), "malformed"), (fins(0, (255).to_bytes(4, "big")), "malformed"), (fins(2, bytes(10)), "malformed"),
                 (fins(2, bytes((0x81, 0, 2, 0, 1, 0, 0, 11, 0, 5)) + bytes(2)), "malformed"), (fins(2, bytes((0x80, 1, 2, 0, 1, 0, 0, 11, 0, 5)) + bytes(2)), "malformed"),
                 (fins(2, bytes((0x80, 0, 8, 0, 1, 0, 0, 11, 0, 5)) + bytes(2)), "malformed"), (fins(2, bytes((0x80, 0, 2, 128, 1, 0, 0, 11, 0, 5)) + bytes(2)), "malformed"),
                 (fins(2, bytes((0xc0, 0, 2, 0, 1, 0, 0, 11, 0, 5)) + bytes(2)), "malformed"), (fins(0, bytes(4), error=0x20), "malformed"),
                 (b"FINS" + (3000).to_bytes(4, "big") + (2).to_bytes(4, "big") + bytes(4), "malformed"), (b"FINSx", "detecting"), (b"FINS ", "detecting"))
        for data, status in cases:
            self.assertEqual(stream(data).observation.status, status, data[:16])
        self.assertEqual(stream(b"FINS ").candidate, "text")
        self.assertEqual(stream(b"FIN").candidate, None)


class RIPTests(unittest.TestCase):
    def test_versions_commands_and_authentication(self):
        for data, protocol, command in ((RIP_REQUEST, "rip/2", "request"), (RIP_RESPONSE, "rip/2", "response"), (RIP_V1, "rip/1", "response")):
            observation = datagram(data)
            self.assertEqual((observation.status, observation.application_protocol, values(observation)["rip_command"]), ("identified", protocol, command))
            self.assertEqual(classify(observation, "udp", 520).port_usage, "standard")
            self.assertNotIn("cleartext-credential-protocol", classify(observation).risks)
        password = b"\x02\x02\x00\x00" + b"\xff\xff\x00\x02" + b"secret-pw".ljust(16, b"\x00") + rip_entry(bytes((10, 0, 0, 0)), 1)
        observation = datagram(password)
        self.assertEqual(values(observation)["rip_authentication"], "simple-password")
        self.assertIn("cleartext-credential-protocol", classify(observation).risks)
        self.assertNotIn("secret-pw", repr(observation))
        entry = rip_entry(bytes((10, 0, 0, 0)), 1)
        md5 = b"\x02\x02\x00\x00" + b"\xff\xff\x00\x03" + (4 + 20 + 20).to_bytes(2, "big") + bytes((1, 16)) + bytes(12) + entry + b"\xff\xff\x00\x01" + bytes(16)
        observation = datagram(md5)
        self.assertEqual(values(observation)["rip_authentication"], "md5")
        self.assertNotIn("cleartext-credential-protocol", classify(observation).risks)

    def test_rules_and_isolation(self):
        entry = rip_entry(bytes((10, 0, 0, 0)), 1)
        cases = ((b"\x03\x02\x00\x00" + entry, "unknown"), (b"\x02\x03\x00\x00" + entry, "unknown"), (b"\x02\x02\x00\x01" + entry, "unknown"),
                 (b"\x02\x02\x00\x00" + entry[:19], "unknown"), (b"\x02\x02\x00\x00" + rip_entry(bytes(4), 0), "malformed"),
                 (b"\x02\x02\x00\x00" + rip_entry(bytes(4), 17), "malformed"), (b"\x02\x02\x00\x00" + rip_entry(bytes(4), 1, family=3), "malformed"),
                 (b"\x02\x01\x00\x00" + rip_entry(bytes(4), 1, tag=1), "malformed"), (b"\x02\x01\x00\x00" + rip_entry(bytes(4), 1, mask=bytes((255, 0, 0, 0))), "malformed"),
                 (b"\x01\x02\x00\x00" + rip_entry(bytes(4), 15, family=0), "malformed"), (b"\x02\x02\x00\x00" + b"\xff\xff\x00\x04" + bytes(16) + entry, "malformed"),
                 (b"\x02\x02\x00\x00" + b"\xff\xff\x00\x02" + bytes(16), "malformed"), (b"\x02\x02\x00\x00" + b"\xff\xff\x00\x03" + bytes(16) + entry, "malformed"),
                 (b"\x02\x02\x00\x00" + entry * 26, "malformed"))
        for data, status in cases:
            self.assertEqual(datagram(data).status, status, data[:8])
        for data, family in DATAGRAM_CASES:
            if not family.startswith("rip"):
                self.assertNotEqual(datagram(data, hint="rip").status, "identified", family)
        for family in VALIDATORS:
            self.assertEqual(datagram(RIP_RESPONSE, hint=family).status == "identified", family == "rip", family)


class RTCPTests(unittest.TestCase):
    def test_hinted_compound_packets(self):
        observation = datagram(RTCP_SR, "rtcp")
        self.assertEqual((observation.status, values(observation)["rtcp_packet"], values(observation)["rtcp_packets"]), ("identified", "sr", "2"))
        self.assertNotIn("demo", repr(observation))
        self.assertEqual(classify(observation).app, "rtcp")
        self.assertNotEqual(datagram(RTCP_SR).status, "identified")
        rr = b"\x80\xc9\x00\x01" + bytes(4)
        self.assertEqual(values(datagram(rr, "rtcp"))["rtcp_packet"], "rr")
        self.assertEqual(datagram(b"\x81\xc8\x00\x0c" + bytes(48), "rtcp").status, "identified")   # one SR with one report block
        for bad in (b"\x41\xc8\x00\x0c" + bytes(48), b"\x81\xca\x00\x03" + bytes(12), b"\x81\xc8\x00\x0b" + bytes(44), b"\x81\xc8\x00\x0c" + bytes(44),
                    b"\x80\xc9\x00\x01" + bytes(4) + b"\x80\xd0\x00\x00", RTCP_SR + b"\x80\xc9\x00\x02" + bytes(4), b"\x80\xc9\x00\x01" + bytes(3),
                    b"\x80\xc9\x00\x01" + bytes(4) + (b"\x80\xc9\x00\x01" + bytes(4)) * 8):
            self.assertNotEqual(datagram(bad, "rtcp").status, "identified", bad[:4])
        self.assertEqual(datagram(b"\x80\xc9\x00\x01" + bytes(4) + (b"\x80\xc9\x00\x01" + bytes(4)) * 7, "rtcp").status, "identified")


class MutationTests(unittest.TestCase):
    def test_streams_and_datagrams_bounded(self):
        rng = random.Random(5353)
        for base in (X11_SETUP, SPICE_LINK, SPICE_REPLY, AFP_OPEN_SESSION, FINS_FRAME):
            for _ in range(400):
                data = bytearray(base)
                for _ in range(rng.randrange(1, 4)):
                    data[rng.randrange(len(data))] = rng.randrange(256)
                inspector = Inspector()
                inspector.feed(bytes(data))
                inspector.end()
                self.assertIn(inspector.observation.status, ("identified", "unknown", "malformed", "incomplete", "budget_exhausted"))
                self.assertLessEqual(inspector.metrics.bytes_inspected, len(data))
        for base in (RIP_RESPONSE, RTCP_SR):
            for _ in range(400):
                data = bytearray(base)
                for _ in range(rng.randrange(1, 4)):
                    data[rng.randrange(len(data))] = rng.randrange(256)
                inspector = DatagramInspector()
                inspector.inspect(bytes(data), "rtcp" if base is RTCP_SR else None)
                self.assertLessEqual(inspector.metrics.parser_calls, 3)
        for data, protocol in STREAM_CASES:
            if protocol not in ("x11", "spice", "afp", "fins"):
                for hint in ("x11", "x11-server", "spice", "afp", "fins"):
                    self.assertNotEqual(stream(data, hint).observation.status, "identified", (protocol, hint))


if __name__ == "__main__":
    unittest.main()
