"""ZMTP 3.x greeting and Neo4j Bolt handshake profiles, dispatch isolation and risks."""
import random
import unittest

from protocol_engine import Config, Inspector
from protocol_engine.appid import classify, session_verdict
from protocol_fixtures import BOLT_HANDSHAKE, BOLT_RESPONSE, STREAM_CASES, ZMTP_GREETING, ZMTP_SERVER_GREETING, zmtp_greeting


def values(observation):
    return {e.field: e.value for e in observation.evidence}


def inspect(data, hint=None, config=None):
    inspector = Inspector(config, protocol_hint=hint)
    inspector.feed(data)
    return inspector


class ZMTPTests(unittest.TestCase):
    def test_greetings_mechanisms_roles_and_risks(self):
        client = inspect(ZMTP_GREETING).observation
        self.assertEqual((client.status, client.application_protocol, values(client)["zmtp_mechanism"], values(client)["zmtp_role"]), ("identified", "zmtp/3", "null", "client"))
        server = inspect(ZMTP_SERVER_GREETING).observation
        self.assertEqual((values(server)["zmtp_mechanism"], values(server)["zmtp_role"]), ("curve", "server"))
        for mechanism, label in ((b"NULL", "null"), (b"PLAIN", "plain"), (b"CURVE", "curve"), (b"GSSAPI", "gssapi"), (b"CUSTOM-1", "other")):
            observation = inspect(zmtp_greeting(mechanism)).observation
            self.assertEqual(values(observation)["zmtp_mechanism"], label)
            verdict = classify(observation)
            self.assertEqual(verdict.app, "zeromq")
            self.assertEqual("cleartext-credential-protocol" in verdict.risks, label == "plain", label)
        verdict = session_verdict(inspect(zmtp_greeting(b"PLAIN")).observation, inspect(zmtp_greeting(b"PLAIN", as_server=1)).observation)
        self.assertIn("cleartext-credential-protocol", verdict.risks)

    def test_greeting_rules_and_boundaries(self):
        for bad, status in ((zmtp_greeting(minor=2), "unknown"), (b"\xff" + bytes(7) + b"\x01\x7e" + ZMTP_GREETING[10:], "unknown"),
                            (ZMTP_GREETING[:10] + b"\x02" + ZMTP_GREETING[11:], "unknown"),
                            (zmtp_greeting(b"null"), "malformed"), (zmtp_greeting(b""), "malformed"), (zmtp_greeting(b"NU LL"), "malformed"),
                            (zmtp_greeting(b"NULL\x00X"), "malformed"), (zmtp_greeting(as_server=2), "malformed"),
                            (ZMTP_GREETING[:40] + b"\x01" + ZMTP_GREETING[41:], "malformed")):
            self.assertEqual(inspect(bad).observation.status, status, bad[:12])
        for end in range(len(ZMTP_GREETING)):
            self.assertEqual(inspect(ZMTP_GREETING[:end]).observation.status, "detecting", end)
        inspector = inspect(ZMTP_GREETING + b"\x04\x19\x05READY")
        self.assertEqual((inspector.observation.status, inspector.metrics.bytes_inspected), ("identified", 64))
        self.assertEqual(inspect(ZMTP_GREETING, config=Config(max_bytes=64)).observation.status, "identified")
        self.assertEqual(inspect(b"\xff\xff" + bytes(20)).observation.application_protocol, None)        # BGP marker route
        self.assertEqual(inspect(b"\xff\xfb\x01").candidate, "telnet")
        self.assertEqual(inspect(b"\xff" + bytes(8) + b"\x7f\x01" + bytes(53)).observation.status, "unknown")   # ZMTP 2 revision byte


class BoltTests(unittest.TestCase):
    def test_handshake_and_hinted_response(self):
        observation = inspect(BOLT_HANDSHAKE).observation
        self.assertEqual((observation.status, observation.application_protocol, values(observation)["bolt_message"], values(observation)["bolt_version"]),
                         ("identified", "bolt", "handshake", "5.4"))
        self.assertEqual({e.field: e.strength for e in observation.evidence}["bolt_version"], "offered")
        verdict = classify(observation, "tcp", 7687)
        self.assertEqual((verdict.app, verdict.port_usage, verdict.subcategory), ("neo4j", "standard", "database"))
        response = inspect(BOLT_RESPONSE, hint="bolt").observation
        self.assertEqual((response.status, response.scope, values(response)["bolt_message"], values(response)["bolt_version"]),
                         ("identified", "negotiation_response", "version-response", "5.4"))
        self.assertEqual(values(inspect(b"\x00\x00\x00\x00", hint="bolt").observation)["bolt_version"], "none")
        self.assertNotEqual(inspect(BOLT_RESPONSE).observation.status, "identified")      # four bytes never select Bolt alone
        self.assertEqual(session_verdict(observation, response, "tcp", 7687).app, "neo4j")

    def test_handshake_rules(self):
        magic = BOLT_HANDSHAKE[:4]
        for versions, status in ((((0, 0, 4, 4), (0, 0, 0, 0), (0, 0, 0, 0), (0, 0, 0, 0)), "identified"),
                                 (((0, 0, 0, 0),) * 4, "malformed"),
                                 (((0, 0, 4, 4), (0, 0, 0, 0), (0, 0, 3, 5), (0, 0, 0, 0)), "malformed"),     # version after an empty slot
                                 (((1, 0, 4, 4),) + ((0, 0, 0, 0),) * 3, "malformed"),                       # reserved byte
                                 (((0, 5, 4, 4),) + ((0, 0, 0, 0),) * 3, "malformed"),                       # range above minor
                                 (((0, 0, 5, 4),) + ((0, 0, 0, 0),) * 3, "malformed"),                       # 4.5 was never published
                                 (((0, 0, 1, 3),) + ((0, 0, 0, 0),) * 3, "malformed"),
                                 (((0, 0, 0, 6),) + ((0, 0, 0, 0),) * 3, "malformed"),
                                 (((0, 0, 0, 3), (0, 0, 0, 2), (0, 0, 0, 1), (0, 0, 0, 0)), "identified"),
                                 (((0, 1, 0, 0),) + ((0, 0, 0, 0),) * 3, "malformed")):
            data = magic + b"".join(bytes(v) for v in versions)
            self.assertEqual(inspect(data).observation.status, status, versions)
        for end in range(len(BOLT_HANDSHAKE)):
            self.assertEqual(inspect(BOLT_HANDSHAKE[:end]).observation.status, "detecting", end)
        self.assertNotEqual(inspect(b"\x60\x60\xb0\x18" + bytes(16)).observation.status, "identified")
        self.assertEqual(inspect(b"`GET / HTTP/1.1\r\n").candidate, "text")                 # back to the text route
        self.assertEqual(inspect(b"\x00\x00\x10\x05", hint="bolt").observation.status, "malformed")
        self.assertEqual(inspect(b"\x00\x00\x00\x08", hint="bolt").observation.status, "malformed")   # PostgreSQL SSLRequest length word
        self.assertEqual(inspect(b"\x01\x00\x04\x05", hint="bolt").observation.status, "unknown")
        inspector = inspect(BOLT_HANDSHAKE + b"\xb1\x01")
        self.assertEqual(inspector.metrics.bytes_inspected, len(BOLT_HANDSHAKE))

    def test_isolation_and_mutations(self):
        for data, protocol in STREAM_CASES:
            if protocol not in ("zmtp/3", "bolt"):
                for hint in ("zmtp", "bolt"):
                    self.assertNotEqual(inspect(data, hint=hint).observation.status, "identified", (protocol, hint))
        rng = random.Random(5153)
        for base in (ZMTP_GREETING, BOLT_HANDSHAKE):
            for _ in range(600):
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
