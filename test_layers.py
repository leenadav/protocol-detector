"""Stage 5 (A05, A13): the layered App-ID view and the one effective answer per session."""
import json
import sys
import unittest
from pathlib import Path

from protocol_adapters.events import EventLog, reduce, session_identity
from protocol_adapters.layers import BASES, layered_view, split_observation
from protocol_engine import Inspector
from protocol_engine.model import ApplicationRule, RuleIndex

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
import schema_check  # noqa: E402

CLIENT, SERVER = ("192.0.2.10", 52000), ("198.51.100.20", 443)
REQUEST = b"PROPFIND /documents HTTP/1.1\r\nHost: demo.invalid\r\nDepth: 0\r\n\r\n"
RESPONSE = b"HTTP/1.1 207 Multi-Status\r\nContent-Length: 0\r\n\r\n"


def client_hello(host=b"demo.invalid", alpn=(b"h2", b"http/1.1")):
    from protocol_adapters.protocol_fixtures import client_hello_with
    name = b"\x00" + len(host).to_bytes(2, "big") + host
    sni = (len(name)).to_bytes(2, "big") + name
    protocols = b"".join(bytes([len(p)]) + p for p in alpn)
    return client_hello_with(((0, sni), (16, len(protocols).to_bytes(2, "big") + protocols), (43, b"\x02\x03\x04")))


def server_hello():
    from protocol_adapters.protocol_fixtures import TLS_SERVER13
    return TLS_SERVER13


def validate(layers):
    schema = schema_check.load("session")
    errors = schema_check.validate(json.loads(json.dumps(layers)), {"$ref": "#/$defs/layers", "$defs": schema["$defs"]})
    return errors


class LayeredViewTests(unittest.TestCase):
    def test_plain_http_webdav_is_structural(self):
        client, server = Inspector(), Inspector()
        client.feed(REQUEST)
        server.feed(RESPONSE)
        layers, effective = layered_view("tcp", client.observation, server.observation, None, 80, len(REQUEST), len(RESPONSE))
        self.assertEqual(layers["chain"], ["http/1.1", "webdav"])
        self.assertEqual((layers["application"]["name"], layers["application"]["basis"]), ("webdav", "structural"))
        self.assertIsNone(layers["encryption"])
        self.assertIsNone(layers["inner"])
        self.assertEqual(effective.app, "webdav")
        self.assertEqual(validate(layers), [])

    def test_tls_only_lists_sni_and_alpn_as_claims_not_identity(self):
        client, server = Inspector(), Inspector()
        client.feed(client_hello())
        server.feed(server_hello())
        layers, effective = layered_view("tcp", client.observation, server.observation, None, 443)
        self.assertEqual(layers["chain"], ["tls", "ssl"])
        self.assertEqual(layers["application"]["basis"], "structural")
        self.assertEqual(layers["encryption"]["offered_alpn"], ["h2", "http/1.1"])
        self.assertTrue(layers["encryption"]["server_name_asserted"])
        claimed = {(c["field"], c["strength"]) for c in layers["claims"]}
        self.assertIn(("hostname", "asserted"), claimed)
        self.assertNotIn("demo.invalid", json.dumps(layers))          # claims carry provenance, never values
        self.assertEqual(validate(layers), [])

    def test_decrypted_webdav_chain_without_rewriting_observations(self):
        client, server = Inspector(), Inspector()
        client.feed(client_hello())
        server.feed(server_hello())
        client.feed_decrypted(REQUEST)
        server.feed_decrypted(RESPONSE)
        outer, inner = split_observation(client.observation)
        self.assertEqual((outer.encryption, outer.application_protocol), ("tls", None))
        self.assertEqual((inner.encryption, inner.application_protocol), (None, "http/1.1"))
        self.assertTrue(all(e.source.startswith("decrypted") for e in inner.evidence))
        self.assertTrue(all(not e.source.startswith("decrypted") for e in outer.evidence))
        decryption = {"state": "complete", "reason_code": None, "authenticated_records": 6, "version": "TLS 1.3"}
        layers, effective = layered_view("tcp", client.observation, server.observation, None, 443, len(REQUEST), len(RESPONSE),
                                         decryption=decryption)
        self.assertEqual(layers["chain"], ["tls", "http/1.1", "webdav"])
        self.assertEqual(layers["application"]["basis"], "authenticated_plaintext")
        self.assertEqual((layers["outer"]["app"], layers["inner"]["app"], effective.app), ("ssl", "webdav", "webdav"))
        self.assertTrue(layers["inner"]["authenticated"])
        self.assertIn("not peer identity", layers["note"])
        self.assertEqual(layers["encryption"]["version"], "TLS 1.3")
        self.assertEqual(validate(layers), [])

    def test_authentication_failure_withdraws_inner_but_keeps_tls(self):
        client, server = Inspector(), Inspector()
        client.feed(client_hello())
        server.feed(server_hello())
        client.feed_decrypted(REQUEST)                                   # plaintext that was later contradicted
        failed = {"state": "failed", "reason_code": "authentication_failed", "authenticated_records": 2}
        layers, effective = layered_view("tcp", client.observation, server.observation, None, 443, decryption=failed)
        self.assertEqual(layers["chain"], ["tls", "ssl"])
        self.assertEqual((effective.app, layers["application"]["basis"]), ("ssl", "structural"))
        self.assertFalse(layers["inner"]["authenticated"])
        self.assertEqual(layers["decryption"]["reason_code"], "authentication_failed")
        self.assertEqual(validate(layers), [])

    def test_host_catalog_and_configured_rules_are_named_as_such(self):
        client, server = Inspector(), Inspector()
        client.feed(client_hello(host=b"www.google.com"))
        server.feed(server_hello())
        layers, effective = layered_view("tcp", client.observation, server.observation, None, 443)
        self.assertEqual(layers["application"]["basis"], "client_assertion")
        self.assertNotEqual(effective.app, "ssl")
        rules = RuleIndex([ApplicationRule("demo.invalid", "demo-app", "tls_sni")])
        configured = Inspector(rules=rules)
        configured.feed(client_hello())
        layers, effective = layered_view("tcp", configured.observation, server.observation, None, 443)
        self.assertEqual((effective.app, layers["application"]["basis"]), ("demo-app", "configured_rule"))
        self.assertTrue(set(BASES) >= {"client_assertion", "configured_rule"})


class EffectiveViewTests(unittest.TestCase):
    def test_session_and_decoder_row_agree_on_one_answer(self):
        log = EventLog("cap")
        sid = session_identity("tcp", CLIENT, SERVER)
        session = {"type": "session", "transport": "tcp", "client": CLIENT, "server": SERVER, "app": "ssl",
                   "engine_status": "identified", "encryption": "tls", "client_protocol": None, "server_protocol": None,
                   "reasons": [], "layers": {"chain": ["tls", "ssl"], "application": {"name": "ssl", "basis": "structural", "status": "identified"}}}
        log.wrap_and_append(session)
        state = reduce(log.snapshot()["events"])
        self.assertEqual(state["sessions"][sid]["effective"], {"app": "ssl", "basis": "structural", "chain": ["tls", "ssl"],
                                                               "status": "identified", "from": "layers"})
        row = {"client": list(CLIENT), "server": list(SERVER), "status": "decrypted", "session_id": sid, "generation": 0,
               "application": "webdav", "layers": {"chain": ["tls", "http/1.1", "webdav"],
                                                   "application": {"name": "webdav", "basis": "authenticated_plaintext", "status": "identified"}}}
        log.wrap_and_append({"type": "decryption", "report": {"connections": [row], "decrypted": 1, "frames": 9}, "provisional": False})
        reduce(log.snapshot()["events"][-1:], state)
        view = state["sessions"][sid]
        self.assertEqual(view["decryption"]["application"], "webdav")
        self.assertEqual(view["effective"]["chain"], ["tls", "http/1.1", "webdav"])
        self.assertEqual(view["effective"]["basis"], "authenticated_plaintext")
        log.wrap_and_append({"type": "capture_gap", "reason": "Capture truncation", "scope": "active_connections", "session_ids": [sid]})
        reduce(log.snapshot()["events"][-1:], state)
        self.assertEqual((view["status"], view["decryption"]), ("retracted", None))
        self.assertEqual(view["effective"]["chain"], ["tls", "ssl"])    # the wire layer outlives the retraction
        self.assertEqual(reduce(json.loads(json.dumps(log.snapshot()["events"])))["sessions"][sid]["effective"], view["effective"])

    def test_flat_session_without_layers_still_gets_an_effective_answer(self):
        log = EventLog("cap")
        log.wrap_and_append({"type": "session", "transport": "tcp", "client": CLIENT, "server": SERVER, "app": "ssh",
                             "engine_status": "identified", "client_protocol": "ssh", "reasons": []})
        view = next(iter(reduce(log.snapshot()["events"])["sessions"].values()))
        self.assertEqual(view["effective"], {"app": "ssh", "basis": None, "chain": ["ssh"], "status": "identified", "from": "session"})


if __name__ == "__main__":
    unittest.main()
