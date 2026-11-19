package content

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/errs"
)

// The vectors below were computed outside Go, with Python's json.dumps(value, sort_keys=True) and hashlib
// (migration/CONTENT-DIGEST.md, "Test vectors").
const (
	vectorDocument  = "{\"n\": 9999999999999999, \"b\": [1, -2, 0, true, false, null],\n \"a\": {\"z\": \"\", \"Z\": \"q\\\"\\\\/\\n\\t\\u0001\\u007f\", \"é\": \"€ \U0001d11e\", \"aa\": []}}"
	vectorCanonical = `{"a": {"Z": "q\"\\/\n\t\u0001\u007f", "aa": [], "z": "", "\u00e9": "\u20ac \ud834\udd1e"}, "b": [1, -2, 0, true, false, null], "n": 9999999999999999}`
	vectorSHA256    = "2919fccc2c9c5488f568daf7ada444f3b38fbd0c1de80a970d2d6a48f162e172"
	vectorPack      = "bfe5d9552aa34d72ac55d185ed3f79afccbe8991c0a73ab6528feba5ce170377"
	vectorChain     = "77cd6b4c4e0c482824748218f10725708199c628e96dc1c99a9b28804251cc7b"

	// Release 2026.11.2 (migration/fixtures/content.json).
	releaseVersion    = "2026.11.7"
	releaseDigest     = "b2ccbc7842dcffcc"
	releasePackDigest = "b2250e213c8d7a61e3585d3969a58c42a0fad242bcbb0fe94e2576f803082e24"
)

func TestCanonicalEncodingVectors(t *testing.T) {
	canonical, err := Canonical([]byte(vectorDocument))
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != vectorCanonical {
		t.Fatalf("canonical encoding:\n got %s\nwant %s", canonical, vectorCanonical)
	}
	sum := sha256.Sum256(canonical)
	if hex.EncodeToString(sum[:]) != vectorSHA256 {
		t.Errorf("SHA-256 of the canonical encoding: %x", sum)
	}
	sum = sha256.Sum256(append([]byte(PackDigestPrefix), canonical...))
	if hex.EncodeToString(sum[:]) != vectorPack {
		t.Errorf("pack digest of the vector document: %x", sum)
	}
	// The encoding is a fixed point: encoding it again changes nothing.
	again, err := Canonical(canonical)
	if err != nil || string(again) != vectorCanonical {
		t.Errorf("canonical encoding is not idempotent: %s (%v)", again, err)
	}
	parts := []interface{}{"x", []interface{}{"y", []interface{}{integer("1"), nil}}, map[string]interface{}{"k": "v"}}
	if got := chain(parts); got != vectorChain {
		t.Errorf("component hash: %s", got)
	}
}

func TestCanonicalEncodingRefusesWhatItCannotEncodeUnambiguously(t *testing.T) {
	for name, document := range map[string]string{
		"repeated key":        `{"a": 1, "a": 2}`,
		"nested repeated key": `{"a": [{"b": 1, "b": 1}]}`,
		"fraction":            `{"a": 1.0}`,
		"exponent":            `{"a": 1e3}`,
		"negative zero":       `{"a": -0}`,
		"seventeen digits":    `{"a": 12345678901234567}`,
		"lone surrogate":      `{"a": "\ud800"}`,
		"replacement char":    "{\"a\": \"�\"}",
		"trailing document":   `{"a": 1} {"b": 2}`,
		"trailing text":       `{"a": 1} x`,
		"truncated":           `{"a": [1, 2`,
		"empty":               ``,
		"too deep":            strings.Repeat("[", maxDigestDepth+2) + strings.Repeat("]", maxDigestDepth+2),
	} {
		if _, err := Canonical([]byte(document)); !errors.Is(err, errs.Invalid.Err()) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
	if _, err := Canonical([]byte(strings.Repeat("[", maxDigestDepth) + strings.Repeat("]", maxDigestDepth))); err != nil {
		t.Errorf("nesting at the bound refused: %v", err)
	}
}

func TestReleaseAndPackDigestsOfTheCommittedPack(t *testing.T) {
	data, err := os.ReadFile(packPath)
	if err != nil {
		t.Fatal(err)
	}
	pack, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	d := pack.Digests
	if pack.Release.Version != releaseVersion || d.Release != releaseDigest || pack.Release.Digest != releaseDigest {
		t.Errorf("release %s digest %s (stated %s)", pack.Release.Version, d.Release, pack.Release.Digest)
	}
	if d.Pack != releasePackDigest {
		t.Errorf("pack digest %s", d.Pack)
	}
	if strings.Join(d.Recomputed, ",") != "application_catalog,host_catalog,risks" {
		t.Errorf("recomputed components: %v", d.Recomputed)
	}
	for name, value := range pack.Release.Components {
		if d.Components[name] != value {
			t.Errorf("component %s: %s, stated %s", name, d.Components[name], value)
		}
	}
	embedded, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if embedded.Digests.Pack != releasePackDigest || embedded.Digests.Release != releaseDigest {
		t.Errorf("embedded pack digests: %+v", embedded.Digests)
	}
}

// reencode writes the pack with other whitespace and Go's own key order and escaping; edit may change it first.
func reencode(t *testing.T, edit func(document map[string]interface{})) []byte {
	t.Helper()
	data, err := os.ReadFile(packPath)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	var document map[string]interface{}
	if err := decoder.Decode(&document); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(document)
	}
	out, err := json.MarshalIndent(document, "", "\t\t")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPackDigestDependsOnContentNotOnTheFileForm(t *testing.T) {
	other := reencode(t, nil)
	original, _ := os.ReadFile(packPath)
	if string(other) == string(original) {
		t.Fatal("the re-encoded pack is the same file")
	}
	digests, err := ComputeDigests(other)
	if err != nil {
		t.Fatal(err)
	}
	if digests.Pack != releasePackDigest || digests.Release != releaseDigest {
		t.Errorf("digests changed with the file form: %+v", digests)
	}
}

func TestPackDigestCoversWhatTheReleaseDigestDoesNot(t *testing.T) {
	// The reference's release digest is over the host entries, the applications, the risks and the family
	// inventory. The label map, the vocabularies and the derived host tables are outside it; the pack digest
	// is over the whole document.
	for name, edit := range map[string]func(map[string]interface{}){
		"protocol name map": func(d map[string]interface{}) { d["protocol_names"].(map[string]interface{})["bolt"] = "ssh" },
		"vocabulary": func(d map[string]interface{}) {
			v := d["vocabulary"].(map[string]interface{})
			v["outcomes"] = append(v["outcomes"].([]interface{}), "ssh")
		},
		"derived web fronts": func(d map[string]interface{}) {
			d["host_catalog"].(map[string]interface{})["web_fronts"].(map[string]interface{})["www.example.invalid"] = "ssh"
		},
		"release date": func(d map[string]interface{}) { d["release"].(map[string]interface{})["reviewed"] = "2001-01-01" },
		"extra field":  func(d map[string]interface{}) { d["note"] = "x" },
	} {
		digests, err := ComputeDigests(reencode(t, edit))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if digests.Release != releaseDigest {
			t.Errorf("%s: the release digest moved to %s", name, digests.Release)
		}
		if digests.Pack == releasePackDigest {
			t.Errorf("%s: the pack digest did not change", name)
		}
	}
}

func TestStatedDigestsAreVerified(t *testing.T) {
	applications := func(d map[string]interface{}) []interface{} { return d["applications"].([]interface{}) }
	release := func(d map[string]interface{}) map[string]interface{} { return d["release"].(map[string]interface{}) }
	components := func(d map[string]interface{}) map[string]interface{} {
		return release(d)["components"].(map[string]interface{})
	}
	for name, c := range map[string]struct {
		edit func(map[string]interface{})
		want string
	}{
		"application description": {func(d map[string]interface{}) { applications(d)[0].(map[string]interface{})["description"] = "changed" },
			"component application_catalog"},
		"application risk": {func(d map[string]interface{}) { applications(d)[3].(map[string]interface{})["risk"] = json.Number("5") },
			"component application_catalog"},
		"host entry": {func(d map[string]interface{}) {
			entries := d["host_catalog"].(map[string]interface{})["entries"].([]interface{})
			entries[0].(map[string]interface{})["risk"] = json.Number("5")
		}, "component host_catalog"},
		"host entry order": {func(d map[string]interface{}) {
			entries := d["host_catalog"].(map[string]interface{})["entries"].([]interface{})
			entries[0], entries[1] = entries[1], entries[0]
		}, "component host_catalog"},
		"risk text": {func(d map[string]interface{}) {
			for _, risk := range d["risks"].(map[string]interface{}) {
				risk.(map[string]interface{})["description"] = "changed"
				return
			}
		}, "component risks"},
		"stated component": {func(d map[string]interface{}) { components(d)["risks"] = strings.Repeat("0", 64) }, "component risks"},
		"stated families":  {func(d map[string]interface{}) { components(d)["families"] = strings.Repeat("0", 64) }, "release digest"},
		"stated digest":    {func(d map[string]interface{}) { release(d)["digest"] = "0000000000000000" }, "release digest"},
		"short component":  {func(d map[string]interface{}) { components(d)["families"] = "abc" }, "not a SHA-256 value"},
		"extra component":  {func(d map[string]interface{}) { components(d)["extra"] = strings.Repeat("0", 64) }, "outside the digest contract"},
		"extra application field": {func(d map[string]interface{}) { applications(d)[0].(map[string]interface{})["vendor"] = "x" },
			"outside the digest contract"},
		"missing application field": {func(d map[string]interface{}) { delete(applications(d)[0].(map[string]interface{}), "aliases") },
			"outside the digest contract"},
	} {
		_, err := ComputeDigests(reencode(t, c.edit))
		if !errors.Is(err, errs.Invalid.Err()) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
		if _, err := Parse(reencode(t, c.edit)); err == nil {
			t.Errorf("%s: the loader accepted the pack", name)
		}
	}
	// The application list's own order is not part of the contract: the component sorts by name.
	digests, err := ComputeDigests(reencode(t, func(d map[string]interface{}) {
		list := applications(d)
		list[0], list[len(list)-1] = list[len(list)-1], list[0]
	}))
	if err != nil || digests.Release != releaseDigest {
		t.Errorf("reordered application list: %v", err)
	}
}

func FuzzCanonicalIsAFixedPoint(f *testing.F) {
	f.Add([]byte(vectorDocument))
	f.Add([]byte(`{"a": [1, {"b": null}], "c": "é"}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			return
		}
		canonical, err := Canonical(data)
		if err != nil {
			return
		}
		again, err := Canonical(canonical)
		if err != nil || string(again) != string(canonical) {
			t.Fatalf("not a fixed point: %q -> %q (%v)", canonical, again, err)
		}
		if !json.Valid(canonical) {
			t.Fatalf("not JSON: %q", canonical)
		}
		if _, err := ComputeDigests(data); err == nil {
			t.Fatalf("an arbitrary document passed as a pack: %q", data)
		}
	})
}
