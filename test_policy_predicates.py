"""D04: typed policy predicates over identity basis, activity, affiliation, decryption state and capture quality."""
import json
import unittest

from protocol_engine import Inspector
from protocol_engine.appid import classify, session_verdict
from protocol_engine.policy import Policy, PolicyError, policy_context
from protocol_adapters.layers import layered_view
from protocol_adapters.protocol_fixtures import TLS_SERVER13, client_hello_with
from test_v065 import http, sni, tls

REQUEST = b"PROPFIND /documents HTTP/1.1\r\nHost: demo.invalid\r\nDepth: 0\r\n\r\n"


def policy(*rules, default="deny"):
    return Policy.from_json(json.dumps({"default": default, "rules": list(rules)}))


def decrypted_pair(host="api.openai.com", state="complete"):
    client, server = Inspector(), Inspector()
    client.feed(client_hello_with((sni(host), (43, b"\x02\x03\x04"))))
    server.feed(TLS_SERVER13)
    if state in ("complete", "decrypting"):
        client.feed_decrypted(REQUEST)
    decryption = {"state": state, "reason_code": None if state in ("complete", "decrypting") else state, "authenticated_records": 4}
    layers, effective = layered_view("tcp", client.observation, server.observation, None, 443, 100, 200, decryption=decryption)
    return layers, effective


class PredicateTests(unittest.TestCase):
    def test_client_assertion_never_satisfies_a_stronger_identity_requirement(self):
        strict = policy({"name": "allow-structural-or-plaintext", "action": "allow",
                         "match": {"identity_basis": ["structural", "authenticated_plaintext"]}})
        asserted = classify(tls("chatgpt.com"), "tcp", 443)             # named by SNI only
        decision = strict.evaluate(asserted, "tcp", 443)
        self.assertEqual((decision.action, decision.rule, decision.predicates["identity_basis"]), ("deny", None, "client_assertion"))
        self.assertTrue(any("evidence requirements are not met" in r and "identity_basis is client_assertion" in r for r in decision.reasons))
        structural = strict.evaluate(classify(http("example.org"), "tcp", 80), "tcp", 80)
        self.assertEqual((structural.action, structural.predicates["identity_basis"]), ("allow", "structural"))
        lenient = policy({"name": "allow-asserted", "action": "allow", "match": {"identity_basis": ["client_assertion"]}})
        self.assertEqual(lenient.evaluate(asserted, "tcp", 443).action, "allow")
        self.assertNotIn("confidence", json.dumps(decision.fields()))             # no invented confidence numbers

    def test_decryption_state_missing_keys_and_failures(self):
        rule = {"name": "allow-decrypted", "action": "allow", "match": {"identity_basis": ["authenticated_plaintext"], "decryption": ["complete"]}}
        pol = policy(rule)
        layers, effective = decrypted_pair(state="complete")
        decision = pol.evaluate(effective, "tcp", 443, layers=layers)
        self.assertEqual((decision.action, decision.predicates["identity_basis"], decision.predicates["decryption"]), ("allow", "authenticated_plaintext", "complete"))
        self.assertEqual(decision.predicates["activity"], "authenticated-plaintext")
        for state in ("awaiting_keys", "failed"):
            layers, effective = decrypted_pair(state=state)
            decision = pol.evaluate(effective, "tcp", 443, layers=layers)
            self.assertEqual(decision.action, "deny", state)
            self.assertEqual(decision.predicates["decryption"], state)
            self.assertNotEqual(decision.predicates["identity_basis"], "authenticated_plaintext", state)
        # Authenticated plaintext is record authentication; there is no "verified identity" predicate to claim more.
        with self.assertRaises(PolicyError):
            policy({"name": "x", "action": "allow", "match": {"identity_basis": ["verified"]}})
        with self.assertRaises(PolicyError):
            policy({"name": "x", "action": "allow", "match": {"confidence_min": 90}})

    def test_degraded_capture_unknown_budget_and_conflicting_directions(self):
        pol = policy({"name": "allow-intact-web", "action": "allow", "match": {"apps": ["web-browsing"], "capture_quality": ["intact"]}},
                     {"name": "alert-exhausted", "action": "alert", "match": {"engine_status": ["budget_exhausted", "invalidated"]}},
                     {"name": "alert-conflict", "action": "alert", "match": {"directions": ["conflicting"]}})
        web = classify(http("example.org"), "tcp", 80)
        self.assertEqual(pol.evaluate(web, "tcp", 80).action, "allow")
        degraded = pol.evaluate(web, "tcp", 80, capture_quality="degraded")
        self.assertEqual((degraded.action, degraded.predicates["capture_quality"]), ("deny", "degraded"))
        exhausted = Inspector()
        from protocol_engine import Config
        exhausted = Inspector(Config(max_bytes=64))
        exhausted.feed(b"X" * 100)
        verdict = classify(exhausted.observation, "tcp", 9999)
        decision = pol.evaluate(verdict, "tcp", 9999)
        self.assertEqual((verdict.app, decision.predicates["engine_status"]), ("unknown-tcp", verdict.status))
        self.assertIn(decision.predicates["engine_status"], ("budget_exhausted", "unknown"))
        if decision.predicates["engine_status"] == "budget_exhausted":
            self.assertEqual(decision.action, "alert")
        client, server = Inspector(), Inspector()
        client.feed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")
        server.feed(b"SSH-2.0-OpenSSH_9.6\r\n")
        conflict = session_verdict(client.observation, server.observation, "tcp", 80, 10, 10)
        decision = pol.evaluate(conflict, "tcp", 80)
        self.assertEqual((decision.predicates["directions"], decision.rule), ("conflicting", "allow-intact-web"))   # order: the web rule still comes first
        reordered = policy({"name": "alert-conflict", "action": "alert", "match": {"directions": ["conflicting"]}},
                           {"name": "allow-intact-web", "action": "allow", "match": {"apps": ["web-browsing"], "capture_quality": ["intact"]}})
        self.assertEqual(reordered.evaluate(conflict, "tcp", 80).rule, "alert-conflict")
        one_sided = session_verdict(client.observation, None, "tcp", 80, 10, 0)
        self.assertEqual(policy_context(one_sided)["directions"], "one-direction")

    def test_affiliation_and_activity_predicates(self):
        pol = policy({"name": "alert-asserted-remote-access", "action": "alert",
                      "match": {"subcategories": ["remote-access"], "identity_basis": ["client_assertion"], "activity": ["unobserved"]}},
                     {"name": "allow-provider-web", "action": "allow", "match": {"affiliation": ["provider-web"]}})
        remote = classify(tls("router17.teamviewer.com"), "tcp", 5938)
        decision = pol.evaluate(remote, "tcp", 5938)
        self.assertEqual((decision.action, decision.rule), ("alert", "alert-asserted-remote-access"))
        web_front = classify(tls("www.teamviewer.com"), "tcp", 443)
        decision = pol.evaluate(web_front, "tcp", 443)
        self.assertEqual((decision.action, decision.rule, decision.predicates["affiliation"]), ("allow", "allow-provider-web", "provider-web"))
        example = Policy.from_path("policy-example.json")
        self.assertEqual(example.evaluate(remote, "tcp", 5938).rule, "alert-asserted-remote-access")
        self.assertEqual(example.lint(), ())


if __name__ == "__main__":
    unittest.main()
