package content

import "testing"

// Every earlier release parses (its digests are recomputed and must equal the stated ones) and pins the
// reference's version and digest (protocol_engine.content.digest(version)).
func TestEarlierReleasesParseWithTheReferenceDigests(t *testing.T) {
	want := map[string]struct {
		digest string
		hosts  int
	}{
		"2025.10.0": {"5d38359bcadf2419", 53}, "2026.11.0": {"e4ba10037ef25ee7", 54},
		"2026.11.1": {"45ad7b6b7d7a027e", 169}, "2026.11.2": {"e0d6e39533a6ae9c", 431},
	}
	releases := Releases()
	if len(releases) != len(want) || releases[len(releases)-1] != "2026.11.2" {
		t.Fatalf("releases %v", releases)
	}
	for _, v := range releases {
		pack, err := EmbeddedRelease(v)
		if err != nil {
			t.Fatalf("%s: %v", v, err)
		}
		if pack.Release.Version != v || pack.Release.Digest != want[v].digest {
			t.Errorf("%s: pack pins %s %s", v, pack.Release.Version, pack.Release.Digest)
		}
	}
	if _, err := EmbeddedRelease("1999.01.0"); err == nil {
		t.Fatal("an unknown version was accepted")
	}
}
