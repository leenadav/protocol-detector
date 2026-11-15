package signatures

import (
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/parsing"
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

func TestContainerDescriptionIsRefusedNotGuessed(t *testing.T) {
	// Python's str() of a JSON object depends on key order, which the Go decoder does not keep: refused explicitly.
	_, err := FromJSON([]byte(`[{"name": "a", "description": {"k": 1}, "conditions": [{"context": "ssh-req-banner", "pattern": "OpenSSH"}]}]`), loadPack(t))
	if _, ok := err.(*parsing.NotPorted); !ok {
		t.Fatalf("container description: %v", err)
	}
}
