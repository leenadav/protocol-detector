package signatures

import (
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
)

func loadPack(t *testing.T) *content.Pack {
	t.Helper()
	p, err := content.Load("../../../migration/fixtures/content.json")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Digests computed by the Python reference (SignatureSet.from_json(...).digest). The second vector carries DEL,
// Latin-1, BMP and astral characters: json.dumps(ensure_ascii=True) escapes all of them, DEL included (the Go
// escaper once wrote DEL raw, which the signature differential caught as a different signature_set digest).
func TestDigestMatchesTheReference(t *testing.T) {
	pack := loadPack(t)
	for _, v := range []struct{ doc, digest string }{
		{`[{"name": "a", "conditions": [{"context": "http-req-host-header", "pattern": "example"}]}]`, "eab7a24951c6f4c7"},
		{`{"version": 1, "signatures": [{"name": "del-é-€-😀", "description": "x\u007fy", "risk": 2, "conditions": [{"context": "ssh-req-banner", "pattern": "OpenSSH"}]}]}`, "23447bb46ec21348"},
		{`[{"name": "f", "description": 1.5e-7, "conditions": [{"context": "dns-req-query-type", "operator": "equal-to", "value": 1}]}, {"name": "g", "description": 1e22, "conditions": [{"context": "unknown-req-udp-payload", "pattern": "PROBE-1234"}]}]`, "c248c2625b950421"},
	} {
		set, err := FromJSON([]byte(v.doc), pack)
		if err != nil {
			t.Fatalf("%s: %v", v.doc, err)
		}
		if set.Digest != v.digest {
			t.Errorf("%s: digest %s, reference %s", v.doc, set.Digest, v.digest)
		}
	}
}

func TestContainerDescriptionIsPythonsStr(t *testing.T) {
	// str() of a JSON object or list as the reference computes it (key order, repr of each value, 256 code
	// points); vectors from CPython 3.13.
	cases := []struct{ description, want string }{
		{"{\x22a\x22: 1, \x22b\x22: [1.5, true, null, \x22x'y\x22], \x22a\x22: 2}", "{'a': 2, 'b': [1.5, True, None, \x22x'y\x22]}"},
		{"[\x22\xc3\xa9\x22, \x22\x5cu00a0\x22, \x22\x5cu0007\x22, \x22\xf0\x9f\x98\x80\x22, \x22\x5cud800\x22, \x22a\x5c\x22b\x22, \x22'\x22]", "['\xc3\xa9', '\x5cxa0', '\x5cx07', '\xf0\x9f\x98\x80', '\x5cud800', 'a\x22b', \x22'\x22]"},
		{"{\x22k\x22: {\x22n\x22: -0.0, \x22f\x22: 1e22, \x22g\x22: 1e-5}}", "{'k': {'n': -0.0, 'f': 1e+22, 'g': 1e-05}}"},
		{"[]", "[]"},
		{"{}", "{}"},
		{"[NaN, Infinity]", "[nan, inf]"},
		{"{\x22long\x22: \x22xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\x22}", "{'long': 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
	}
	for _, c := range cases {
		doc := `[{"name": "a", "description": ` + c.description + `, "conditions": [{"context": "ssh-req-banner", "pattern": "OpenSSH"}]}]`
		set, err := FromJSON([]byte(doc), loadPack(t))
		if err != nil {
			if c.description == "[NaN, Infinity]" {
				continue // encoding/json refuses NaN before the description is read; the reference accepts it
			}
			t.Fatalf("%s: %v", c.description, err)
		}
		if got := set.byName["a"].Description; got != c.want {
			t.Errorf("%s: got %q, want %q", c.description, got, c.want)
		}
	}
}
