package content

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// Integration work item #16, the pinned pack digest. The contract and its vectors are
// migration/CONTENT-DIGEST.md; the values for this branch's pack (release 2026.11.0) were computed with
// Python's json and hashlib from migration/fixtures/content.json, independently of this package.
const (
	branchReleaseVersion = "2026.11.0"
	branchReleaseDigest  = "991c007668d263d1"
	branchPackDigest     = "02620ad2606202de99beac0035ded3a2983824eaeb268a1a0c747fc6d34f7f17"
)

// The published vectors of the contract: the canonical encoding, its hash, and the pack digest rule.
func TestContractVectors(t *testing.T) {
	document := []byte("{\"n\": 9999999999999999, \"b\": [1, -2, 0, true, false, null],\n" +
		" \"a\": {\"z\": \"\", \"Z\": \"q\\\"\\\\/\\n\\t\\u0001\\u007f\", \"é\": \"€ 𝄞\", \"aa\": []}}")
	want := `{"a": {"Z": "q\"\\/\n\t\u0001\u007f", "aa": [], "z": "", "\u00e9": "\u20ac \ud834\udd1e"}, "b": [1, -2, 0, true, false, null], "n": 9999999999999999}`
	got, err := Canonical(document)
	if err != nil || string(got) != want {
		t.Fatalf("CJ1: %q %v", got, err)
	}
	plain := sha256.Sum256(got)
	if hex.EncodeToString(plain[:]) != "2919fccc2c9c5488f568daf7ada444f3b38fbd0c1de80a970d2d6a48f162e172" {
		t.Errorf("SHA-256 of CJ1: %x", plain)
	}
	prefixed := sha256.Sum256(append([]byte(PackDigestPrefix), got...))
	if hex.EncodeToString(prefixed[:]) != "bfe5d9552aa34d72ac55d185ed3f79afccbe8991c0a73ab6528feba5ce170377" {
		t.Errorf("pack digest rule: %x", prefixed)
	}
	if len(PackDigestPrefix) != 28 || !strings.HasSuffix(PackDigestPrefix, "\n") {
		t.Errorf("prefix %q", PackDigestPrefix)
	}
}

// The correct pin: the built-in pack has the digest the build pins, and it is the independently computed one.
func TestEmbeddedPackHasThePinnedDigest(t *testing.T) {
	if EmbeddedPackDigest != branchPackDigest {
		t.Fatalf("the build pins %s; the fixture's pack digest is %s", EmbeddedPackDigest, branchPackDigest)
	}
	p, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if p.Digests.Pack != branchPackDigest || p.Digests.Release != branchReleaseDigest ||
		p.Release.Digest != branchReleaseDigest || p.Release.Version != branchReleaseVersion {
		t.Fatalf("digests %+v, release %+v", p.Digests, p.Release)
	}
	if !reflect.DeepEqual(p.Digests.Recomputed, []string{"application_catalog", "host_catalog", "risks"}) {
		t.Errorf("recomputed components: %v", p.Digests.Recomputed)
	}
}

// edited returns the built-in pack re-encoded after edit changed its document.
func edited(t *testing.T, edit func(document map[string]interface{})) []byte {
	t.Helper()
	var document map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(packJSONBytes))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		t.Fatal(err)
	}
	edit(document)
	out, err := json.MarshalIndent(document, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The pin is on the contents, not on the file's form: another encoding of the same document is accepted.
func TestPinAcceptsAnotherEncodingOfTheSameDocument(t *testing.T) {
	other := edited(t, func(map[string]interface{}) {})
	if bytes.Equal(other, packJSONBytes) {
		t.Fatal("the re-encoding is the same bytes")
	}
	p, err := ParsePinned(other, EmbeddedPackDigest)
	if err != nil || p.Digests.Pack != EmbeddedPackDigest {
		t.Fatalf("%v", err)
	}
}

const pinMismatch = "content pack does not have the pinned digest"

// A mismatch is refused, no pack is returned, and the refusal comes before the pack's contents are
// interpreted: a pack that Parse would refuse for its structure is refused for its digest instead.
func TestPinMismatchIsRefusedBeforeUse(t *testing.T) {
	otherPin := strings.Repeat("0", 64)
	label := edited(t, func(d map[string]interface{}) { // outside the release digest: only the pin sees it
		d["protocol_names"].(map[string]interface{})["tls"] = "Not TLS"
	})
	if _, err := ParseSupplied(label); err != nil {
		t.Fatalf("the label edit should be self-consistent: %v", err)
	}
	unknown := edited(t, func(d map[string]interface{}) { d["extra"] = "x" })
	structural := edited(t, func(d map[string]interface{}) { d["schema"] = json.Number("2") })
	if _, err := Parse(structural); err == nil || strings.Contains(err.Error(), "pinned") {
		t.Fatalf("Parse of the structurally invalid pack: %v", err)
	}
	for name, c := range map[string]struct {
		data []byte
		pin  string
	}{
		"good pack, another pin":           {packJSONBytes, otherPin},
		"edited label, the build's pin":    {label, EmbeddedPackDigest},
		"added field, the build's pin":     {unknown, EmbeddedPackDigest},
		"invalid structure, the build pin": {structural, EmbeddedPackDigest},
	} {
		p, err := ParsePinned(c.data, c.pin)
		if p != nil || err == nil || !strings.Contains(err.Error(), pinMismatch) {
			t.Errorf("%s: pack %v, error %v", name, p != nil, err)
		}
	}
	// A pin that is not a digest never matches anything, and an absent or oversized pack is not hashed.
	for name, pin := range map[string]string{"empty": "", "short": EmbeddedPackDigest[:63], "uppercase": strings.ToUpper(EmbeddedPackDigest),
		"release digest": branchReleaseDigest, "padded": EmbeddedPackDigest + " "} {
		if p, err := ParsePinned(packJSONBytes, pin); p != nil || err == nil {
			t.Errorf("pin %s accepted", name)
		}
	}
	for name, data := range map[string][]byte{"empty": nil, "oversize": make([]byte, MaxPackBytes+1), "not json": []byte("{"),
		"repeated key": []byte(`{"a": 1, "a": 1}`)} {
		if p, err := ParsePinned(data, EmbeddedPackDigest); p != nil || err == nil {
			t.Errorf("data %s accepted", name)
		}
	}
}

// What the immutability of validated content rests on: the pack keeps no reference to the bytes it was
// parsed from, the built-in bytes are not handed out, and every load builds its own tables.
func TestValidatedPackDoesNotShareItsInput(t *testing.T) {
	data := EmbeddedBytes()
	p, err := ParsePinned(data, EmbeddedPackDigest)
	if err != nil {
		t.Fatal(err)
	}
	for i := range data {
		data[i] = 'x'
	}
	fresh, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p, fresh) {
		t.Fatal("overwriting the supplied bytes changed the validated pack")
	}
	// A holder that writes to one pack's exported tables changes neither the built-in bytes nor a later load.
	for name := range p.Applications {
		delete(p.Applications, name)
	}
	p.ProtocolNames["tls"], p.Digests.Components["risks"] = "changed", "changed"
	again, err := Embedded()
	if err != nil || !reflect.DeepEqual(again, fresh) || len(again.Applications) == 0 {
		t.Fatalf("a later load differs: %v", err)
	}
}
