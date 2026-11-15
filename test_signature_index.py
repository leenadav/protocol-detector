"""Stage 7 (A11): the signature indexes give exactly the linear first-match result, with fewer evaluations."""
import json
import random
import unittest

from protocol_engine import Inspector, SignatureSet
from protocol_engine.signatures import CONTEXTS

TEXT = [name for name, (kind, family) in CONTEXTS.items() if kind == "text"]
HOSTS = ["a.example", "b.example", "portal.example.com", "intranet.example.com", "x.test"]


def condition(context, operator="equal-to", value=None, **extra):
    data = {"context": context, "operator": operator}
    if operator == "pattern-match":
        data["pattern"] = value
    else:
        data["value"] = value
    data.update(extra)
    return data


def random_signature(rng, index):
    """A random signature mixing indexable and non-indexable shapes, all within one or two families."""
    host_context = rng.choice(["http-req-host-header", "ssl-req-chello-sni", "dns-req-query-name"])
    shape = rng.randrange(6)
    host = rng.choice(HOSTS)
    if shape == 0:      # indexable: top-level AND with a case-sensitive equal-to
        conditions = [condition(host_context, value=host)]
    elif shape == 1:    # indexable with extra members
        conditions = [condition(host_context, value=host), condition("http-req-method", "pattern-match", "^GET$")]
    elif shape == 2:    # not indexable: case-insensitive equal-to
        conditions = [condition(host_context, value=host.upper(), case_insensitive=True)]
    elif shape == 3:    # not indexable: negated equal-to plus a positive pattern
        conditions = [condition(host_context, value=host, negate=True), condition("http-req-uri-path", "pattern-match", "^/api/")]
    elif shape == 4:    # not indexable: OR root
        conditions = {"or": [condition(host_context, value=host), condition("http-req-uri-path", "pattern-match", "^/login")]}
    else:               # pattern only
        conditions = [condition(host_context, "pattern-match", "(^|\\.)" + host.replace(".", "\\.") + "$")]
    return {"name": "sig-%04d" % index, "conditions": conditions}


def random_contexts(rng):
    contexts = {}
    if rng.random() < 0.9:
        contexts[rng.choice(["http-req-host-header", "ssl-req-chello-sni", "dns-req-query-name"])] = rng.choice(HOSTS + ["other.example", "PORTAL.EXAMPLE.COM"]).encode()
    if rng.random() < 0.7:
        contexts["http-req-method"] = rng.choice([b"GET", b"POST", b"PUT"])
    if rng.random() < 0.7:
        contexts["http-req-uri-path"] = rng.choice([b"/", b"/api/x", b"/login", b"/static/a.js"])
    return contexts


class IndexEquivalenceTests(unittest.TestCase):
    def test_indexed_match_equals_linear_match_on_seeded_sets(self):
        rng = random.Random(7)
        for size in (1, 7, 50, 300):
            signatures = SignatureSet([random_signature(rng, i) for i in range(size)])
            self.assertEqual(signatures.stats["indexed"] + signatures.stats["scanned"],
                             sum(len(signatures._by_family[f]) for f in signatures.families))
            for _ in range(400):
                contexts = random_contexts(rng)
                for family in ("http", "tls", "dns"):
                    expected = signatures.match_linear(family, contexts)
                    found, evaluated = signatures.match_counted(family, contexts)
                    self.assertIs(found, expected, (size, family, contexts))
                    self.assertLessEqual(evaluated, len(signatures._by_family.get(family, ())))

    def test_indexed_lookup_evaluates_fewer_candidates_and_keeps_priority(self):
        hosts = ["host-%05d.example" % i for i in range(1000)]
        documents = [{"name": "exact-%05d" % i, "conditions": [condition("http-req-host-header", value=h)]} for i, h in enumerate(hosts)]
        documents.append({"name": "catch-all-pattern", "conditions": [condition("http-req-host-header", "pattern-match", "example$")]})
        documents.insert(0, {"name": "first-priority", "conditions": [condition("http-req-host-header", value="host-00500.example"),
                                                                       condition("http-req-method", value="GET")]})
        signatures = SignatureSet(documents)
        found, evaluated = signatures.match_counted("http", {"http-req-host-header": b"host-00500.example", "http-req-method": b"GET"})
        self.assertEqual(found.name, "first-priority")            # definition order wins over the index
        self.assertLessEqual(evaluated, 3)                        # scan list (1) + the two exact hits at most
        found, evaluated = signatures.match_counted("http", {"http-req-host-header": b"host-00500.example", "http-req-method": b"POST"})
        self.assertEqual(found.name, "exact-00500")
        found, evaluated = signatures.match_counted("http", {"http-req-host-header": b"nobody.example"})
        self.assertEqual((found.name, evaluated), ("catch-all-pattern", 1))
        found, evaluated = signatures.match_counted("http", {"http-req-host-header": b"nobody.test"})
        self.assertEqual((found, evaluated), (None, 1))
        self.assertEqual(signatures.match_linear("http", {"http-req-host-header": b"nobody.test"}), None)

    def test_name_index_digest_and_version_pin(self):
        document = {"version": 1, "signatures": [{"name": "a", "conditions": [condition("ssh-req-banner", "pattern-match", "^SSH-2\\.0-Deploy")]},
                                                 {"name": "b", "conditions": [condition("dns-req-query-name", value="corp.example")]}]}
        one = SignatureSet.from_json(json.dumps(document))
        two = SignatureSet.from_json(json.dumps(document))
        self.assertEqual(one.digest, two.digest)
        self.assertEqual(len(one.digest), 16)
        self.assertIs(one.get("b"), one._by_family["dns"][0])
        self.assertIsNone(one.get("nope"))
        self.assertIn("a", one)
        document["signatures"][1]["conditions"][0]["value"] = "other.example"
        self.assertNotEqual(SignatureSet.from_json(json.dumps(document)).digest, one.digest)

    def test_adversarial_shapes_never_bypass_evaluation(self):
        # The index only short-lists; every candidate is still fully evaluated, so a signature whose
        # indexed value matches but whose other members do not never matches.
        signatures = SignatureSet([{"name": "strict", "conditions": [condition("ssl-req-chello-sni", value="portal.example.com"),
                                                                      condition("ssl-req-version", "greater-than", 0x0303)]}])
        self.assertIsNone(signatures.match("tls", {"ssl-req-chello-sni": b"portal.example.com", "ssl-req-version": 0x0303}))
        self.assertIsNotNone(signatures.match("tls", {"ssl-req-chello-sni": b"portal.example.com", "ssl-req-version": 0x0304}))
        self.assertIsNone(signatures.match("tls", {"ssl-req-chello-sni": b"PORTAL.example.com", "ssl-req-version": 0x0304}))
        self.assertIsNone(signatures.match("tls", {"ssl-req-version": 0x0304}))        # absent context: never a match

    def test_inspector_reports_candidates_evaluated(self):
        from protocol_engine import Config
        signatures = SignatureSet([{"name": "corp", "conditions": [condition("http-req-host-header", value="intranet.example.com")]},
                                   {"name": "pattern", "conditions": [condition("http-req-uri-path", "pattern-match", "^/never/")]}])
        inspector = Inspector(Config(retain_contexts=True), signatures=signatures)
        inspector.feed(b"GET / HTTP/1.1\r\nHost: intranet.example.com\r\n\r\n")
        self.assertEqual(inspector.observation.application, "corp")
        self.assertEqual(inspector.metrics.signature_candidates, 1)     # the exact hit comes first and matches
        other = Inspector(Config(retain_contexts=True), signatures=signatures)
        other.feed(b"GET / HTTP/1.1\r\nHost: elsewhere.example\r\n\r\n")
        self.assertIsNone(other.observation.application)
        self.assertEqual(other.metrics.signature_candidates, 1)         # only the scan-list pattern was evaluated


if __name__ == "__main__":
    unittest.main()
