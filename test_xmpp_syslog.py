"""XMPP stream headers (both directions) and syslog RFC 6587 TCP framing."""
import random
import unittest

from protocol_engine import Config, Inspector
from protocol_engine.appid import classify, session_verdict
from protocol_fixtures import SYSLOG, SYSLOG_OCTET, SYSLOG_TCP, XMPP_CLIENT, XMPP_S2S, XMPP_SERVER

STREAMS = b"http://etherx.jabber.org/streams"


def values(observation):
    return {e.field: e.value for e in observation.evidence}


def inspect(data, config=None, hint=None):
    inspector = Inspector(config, protocol_hint=hint)
    inspector.feed(data)
    return inspector


def header(attributes, prolog=b"", tag=b"<stream:stream"):
    return prolog + tag + b"".join(b" " + name + b"='" + value + b"'" for name, value in attributes) + b">"


CLIENT = ((b"to", b"chat.example"), (b"xmlns", b"jabber:client"), (b"xmlns:stream", STREAMS), (b"version", b"1.0"))


class XMPPTests(unittest.TestCase):
    def test_fixtures_directions_and_hostnames(self):
        client = inspect(XMPP_CLIENT).observation
        self.assertEqual((client.status, client.application_protocol, client.scope, client.hostname), ("identified", "xmpp", "initial_message", "chat.example"))
        self.assertEqual((values(client)["xmpp_stream"], values(client)["xmpp_namespace"], values(client)["xmpp_version"]), ("initiating", "client", "1.0"))
        self.assertEqual({e.field: (e.source, e.strength) for e in client.evidence}["hostname"], ("wire:xmpp_stream", "asserted"))
        server = inspect(XMPP_SERVER).observation
        self.assertEqual((server.scope, server.hostname, values(server)["xmpp_stream"]), ("negotiation_response", "chat.example", "response"))
        self.assertNotIn("c2s-0001", repr(server))
        s2s = inspect(XMPP_S2S).observation
        self.assertEqual((values(s2s)["xmpp_namespace"], values(s2s)["xmpp_version"], s2s.hostname), ("server", "legacy", "b.example"))
        self.assertNotIn("a.example", repr(s2s))
        verdict = session_verdict(client, server, "tcp", 5222)
        self.assertEqual((verdict.app, verdict.category, verdict.port_usage), ("xmpp", "collaboration", "standard"))
        self.assertEqual(classify(client, "tcp", 5223).port_usage, "standard")
        for data in (XMPP_CLIENT, XMPP_SERVER, XMPP_S2S):
            expected = inspect(data).observation
            for split in range(len(data) + 1):
                inspector = Inspector()
                inspector.feed(data[:split])
                inspector.feed(data[split:])
                self.assertEqual(inspector.observation, expected, split)
            for end in range(len(data)):
                self.assertEqual(inspect(data[:end]).observation.status, "detecting", end)
            inspector = inspect(data + b"<stream:features/>")
            self.assertEqual(inspector.metrics.bytes_inspected, len(data))

    def test_header_variants(self):
        good = (header(CLIENT), header(CLIENT, b'<?xml version="1.0" encoding="UTF-8"?>'), header(CLIENT, b"<?xml version='1.0' encoding='utf-8' standalone='no' ?>\r\n"),
                header(CLIENT, b"<?xml version='1.0'?>  \r\n"), header(((b"xmlns", b"jabber:component:accept"), (b"xmlns:stream", STREAMS), (b"to", b"gw.example"))),
                b"<stream:stream\n\tto='chat.example'\n\txmlns='jabber:client' xmlns:stream=\"http://etherx.jabber.org/streams\"\n>",
                header(CLIENT + ((b"xml:lang", b"en"), (b"from", b"user@chat.example"))))
        for data in good:
            observation = inspect(data).observation
            self.assertEqual((observation.status, observation.application_protocol), ("identified", "xmpp"), data)
            self.assertNotIn("user@", repr(observation))
        component = inspect(good[4]).observation
        self.assertEqual((values(component)["xmpp_namespace"], values(component)["xmpp_version"], component.hostname), ("component", "legacy", "gw.example"))
        self.assertIsNone(inspect(header(((b"xmlns", b"jabber:client"), (b"xmlns:stream", STREAMS)))).observation.hostname)
        self.assertIsNone(inspect(header(((b"to", b"192.0.2.1"), (b"xmlns", b"jabber:client"), (b"xmlns:stream", STREAMS)))).observation.hostname)

    def test_header_rules(self):
        cases = (
            (header(((b"xmlns", b"jabber:other"), (b"xmlns:stream", STREAMS))), "unknown"),
            (header(((b"xmlns:stream", STREAMS),)), "unknown"),                                         # no content namespace
            (header(((b"xmlns", b"jabber:client"), (b"xmlns:stream", b"urn:other"))), "malformed"),
            (header(((b"xmlns", b"jabber:client"),)), "malformed"),
            (header(CLIENT + ((b"to", b"again.example"),)), "malformed"),                                   # duplicate attribute
            (header(((b"to", b"chat.example"), (b"xmlns", b"jabber:client"), (b"xmlns:stream", STREAMS), (b"version", b"x.1"))), "malformed"),
            (header(((b"to", b"bad host"), (b"xmlns", b"jabber:client"), (b"xmlns:stream", STREAMS))), "malformed"),
            (header(((b"to", b"b\xfccher.example"), (b"xmlns", b"jabber:client"), (b"xmlns:stream", STREAMS))), "malformed"),
            (header(((b"id", b""), (b"xmlns", b"jabber:client"), (b"xmlns:stream", STREAMS))), "malformed"),
            (header(CLIENT)[:-1] + b"/>", "malformed"),
            (b"<stream:stream to=chat.example xmlns='jabber:client'>", "malformed"),                        # unquoted value
            (b"<stream:stream to='a<b' xmlns='jabber:client' xmlns:stream='" + STREAMS + b"'>", "malformed"),
            (b"<?xml version='2.0'?><stream:stream xmlns='jabber:client'>", "unknown"),
            (b"<?xml version='1.0'?><soap:Envelope xmlns:soap='x'>", "unknown"),
            (b"<stream:stream" + b" a1='1'" * 17 + b" xmlns='jabber:client' xmlns:stream='" + STREAMS + b"'>", "malformed"),
            (b"<stream:stream" + b"".join(b" a%d='1'" % i for i in range(17)) + b" xmlns='jabber:client'>", "budget_exhausted"),
            (b"<stream:streamx xmlns='jabber:client'>", "unknown"),
            (b"<html><body>", "unknown"),
        )
        for data, status in cases:
            self.assertEqual(inspect(data).observation.status, status, data[:40])
        long = b"<stream:stream to='chat.example' xmlns='jabber:client' xmlns:stream='" + STREAMS + b"' x='" + b"y" * 1100 + b"'>"
        self.assertEqual(inspect(long).observation.status, "malformed")        # attribute value over 1023 bytes
        self.assertEqual(inspect(long, Config(max_line=1024)).observation.status, "budget_exhausted")
        self.assertEqual(inspect(b"<?xml version='1.0'?>" + b" " * 5000).observation.status, "budget_exhausted")

    def test_seeded_mutations(self):
        rng = random.Random(5252)
        for base in (XMPP_CLIENT, XMPP_SERVER):
            for _ in range(500):
                data = bytearray(base)
                for _ in range(rng.randrange(1, 4)):
                    data[rng.randrange(len(data))] = rng.randrange(256)
                inspector = Inspector()
                inspector.feed(bytes(data))
                inspector.end()
                self.assertIn(inspector.observation.status, ("identified", "unknown", "malformed", "incomplete", "budget_exhausted"))
                self.assertLessEqual(inspector.metrics.bytes_inspected, len(data))
                self.assertNotIn("c2s-0001", repr(inspector.observation))


class SyslogStreamTests(unittest.TestCase):
    def test_both_framings(self):
        plain = inspect(SYSLOG_TCP).observation
        counted = inspect(SYSLOG_OCTET).observation
        self.assertEqual((plain.status, plain.application_protocol, values(plain)["syslog_framing"]), ("identified", "syslog/5424", "non-transparent"))
        self.assertEqual((counted.status, counted.application_protocol, values(counted)["syslog_framing"]), ("identified", "syslog/5424", "octet-counting"))
        for observation in (plain, counted):
            self.assertEqual(classify(observation, "tcp", 514).port_usage, "standard")
            self.assertEqual(classify(observation).app, "syslog")
            self.assertNotIn("synthetic", repr(observation))
        self.assertEqual(inspect(SYSLOG + b"\r\n").observation.status, "identified")
        inspector = inspect(SYSLOG_TCP + SYSLOG_TCP)
        self.assertEqual(inspector.metrics.bytes_inspected, len(SYSLOG_TCP))
        inspector = inspect(SYSLOG_OCTET + SYSLOG_OCTET)
        self.assertEqual(inspector.metrics.bytes_inspected, len(SYSLOG_OCTET))
        for data in (SYSLOG_TCP, SYSLOG_OCTET):
            expected = inspect(data).observation
            for split in range(len(data) + 1):
                inspector = Inspector()
                inspector.feed(data[:split])
                inspector.feed(data[split:])
                self.assertEqual(inspector.observation, expected, split)
            for end in range(len(data)):
                self.assertEqual(inspect(data[:end]).observation.status, "detecting", end)

    def test_framing_rules(self):
        self.assertNotEqual(inspect(b"0" + SYSLOG_OCTET).observation.status, "identified")          # leading zero: never routed
        self.assertEqual(inspect(b"0" + SYSLOG_OCTET, hint="syslog").observation.status, "malformed")
        self.assertEqual(inspect(b"15 " + SYSLOG[:15]).observation.status, "malformed")             # below the shortest header
        self.assertEqual(inspect(b"12345 " + SYSLOG).observation.status, "budget_exhausted")        # over the line budget
        self.assertEqual(inspect(str(len(SYSLOG) + 1).encode() + b" " + SYSLOG + b"x").observation.status, "identified")   # free-form MSG
        self.assertEqual(inspect(b"20 " + SYSLOG).observation.status, "malformed")                     # count cuts the header
        self.assertEqual(inspect(b"<34>1 - - - - - -\n").observation.status, "identified")
        self.assertEqual(inspect(b"<34>0 - - - - - -\n").observation.status, "malformed")
        self.assertEqual(inspect(b"<192>1 - - - - - -\n").observation.status, "malformed")
        self.assertEqual(inspect(b"<34>1 broken\n").observation.status, "malformed")
        self.assertEqual(inspect(b"<34>1 " + b"x" * 9000, Config(max_line=8192)).observation.status, "budget_exhausted")
        self.assertEqual(inspect(b"220 mail.example ESMTP\r\n").candidate, "text")
        self.assertEqual(inspect(b"123456 <34>1 - - - - - -\n").candidate, "text")
        self.assertEqual(inspect(b"<a>").observation.status, "unknown")
        self.assertEqual(inspect(b"<").observation.status, "detecting")

    def test_seeded_mutations(self):
        rng = random.Random(5253)
        for base in (SYSLOG_TCP, SYSLOG_OCTET):
            for _ in range(500):
                data = bytearray(base)
                for _ in range(rng.randrange(1, 4)):
                    data[rng.randrange(len(data))] = rng.randrange(256)
                inspector = Inspector()
                inspector.feed(bytes(data))
                inspector.end()
                self.assertIn(inspector.observation.status, ("identified", "unknown", "malformed", "incomplete", "budget_exhausted"))
                self.assertLessEqual(inspector.metrics.bytes_inspected, len(data))


if __name__ == "__main__":
    unittest.main()
