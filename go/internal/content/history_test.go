package content

import (
	"encoding/json"
	"strings"
	"testing"
)

// published are the releases published before the content moved to the Go side (PRO-411), with the digests the
// reference published them with (protocol_engine.content.digest(version)) and their host-entry counts. They never
// change: a later release is added with tools/content_pack.py and recorded in lock.json, never by editing these.
var published = map[string]struct {
	digest string
	hosts  int
}{
	"2025.10.0": {"9f8791749a940f5b", 53}, "2026.11.0": {"991c007668d263d1", 54},
	"2026.11.1": {"c4020c2437f3de8d", 169}, "2026.11.2": {"e0d6e39533a6ae9c", 431},
	"2026.11.3": {"fef8f709d5615a85", 434}, "2026.11.4": {"c13a842d11873db6", 434},
	"2026.11.5": {"39150de086799d99", 438},
	"2026.11.6": {"d425b8adc87db36d", 438},
	"2026.11.7": {"b2ccbc7842dcffcc", 441},
	"2026.11.8": {"804f727352bc61e0", 441},
	"2026.11.9": {"cdaa5993077d101a", 442},
}

// Every release this binary can run (history.json and pack.json) parses (an earlier one's host catalog must
// reproduce the stated host component, and the release digest is recomputed) and is exactly the lock's entry for
// it, in the lock's order; the releases published before PRO-411 keep the digests they were published with. C11
// (2026-11-18): those digests are unchanged by later applications.
func TestEveryReleaseParsesAndMatchesTheLock(t *testing.T) {
	releases, lock := Releases(), readLock(t)
	if len(releases) != len(lock) {
		t.Fatalf("binary runs %d releases %v, lock.json lists %d", len(releases), releases, len(lock))
	}
	for k, v := range releases {
		entry := lock[k]
		if entry.Version != v {
			t.Fatalf("release %d: binary %s, lock %s", k, v, entry.Version)
		}
		pack, err := EmbeddedRelease(v)
		if err != nil {
			t.Fatalf("%s: %v", v, err)
		}
		if pack.Release.Version != v || pack.Release.Digest != entry.Digest || pack.Release.Released != entry.Released ||
			pack.Release.Reviewed != entry.Reviewed || len(pack.AppDomains) != entry.HostEntries {
			t.Errorf("%s: pack %s %s %s %s (%d hosts), lock %+v", v, pack.Release.Version, pack.Release.Digest,
				pack.Release.Released, pack.Release.Reviewed, len(pack.AppDomains), entry)
		}
		for name, value := range entry.Components {
			if pack.Release.Components[name] != value {
				t.Errorf("%s: component %s differs from the lock", v, name)
			}
		}
		if strings.TrimSpace(entry.Note) == "" || strings.TrimSpace(entry.Review) == "" {
			t.Errorf("%s: the lock entry needs a note and a review", v)
		}
		if k > 0 && (CompareVersions(lock[k-1].Version, v) >= 0 || lock[k-1].Released > entry.Released) {
			t.Errorf("%s: not after %s", v, lock[k-1].Version)
		}
	}
	for v, want := range published {
		pack, err := EmbeddedRelease(v)
		if err != nil {
			t.Fatalf("published release %s is gone: %v", v, err)
		}
		if pack.Release.Digest != want.digest || len(pack.AppDomains) != want.hosts {
			t.Errorf("%s: pins %s with %d hosts, published %s with %d", v, pack.Release.Digest, len(pack.AppDomains),
				want.digest, want.hosts)
		}
	}
	current, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if last := lock[len(lock)-1]; last.Version != current.Release.Version || last.Digest != current.Release.Digest {
		t.Fatalf("the lock's last release %s %s is not the pack's %s %s", last.Version, last.Digest,
			current.Release.Version, current.Release.Digest)
	}
	if _, err := EmbeddedRelease("1999.01.0"); err == nil {
		t.Fatal("an unknown version was accepted")
	}
}

// C11: an earlier release is accepted with the components it was published with (they differ from the current
// pack's application catalog), but its server-name catalog must reproduce its host component, and the current
// pack's own validation is unchanged.
func TestEarlierReleaseMustReproduceItsHostCatalog(t *testing.T) {
	var doc struct {
		Releases map[string]struct {
			Release     map[string]interface{} `json:"release"`
			HostCatalog map[string]interface{} `json:"host_catalog"`
		} `json:"releases"`
	}
	if err := json.Unmarshal(embeddedHistory, &doc); err != nil {
		t.Fatal(err)
	}
	earlier := doc.Releases["2026.11.1"]
	current, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	components := earlier.Release["components"].(map[string]interface{})
	if components["application_catalog"] == current.Digests.Components["application_catalog"] {
		t.Fatal("the test needs an earlier release published with another application catalog")
	}
	compose := func(hosts map[string]interface{}) []byte {
		var pack map[string]interface{}
		if err := json.Unmarshal(embedded, &pack); err != nil {
			t.Fatal(err)
		}
		pack["release"], pack["host_catalog"] = earlier.Release, hosts
		data, err := json.Marshal(pack)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	if _, err := parse(compose(earlier.HostCatalog), true); err != nil {
		t.Fatalf("the earlier release as published: %v", err)
	}
	if _, err := Parse(compose(earlier.HostCatalog)); err == nil {
		t.Fatal("a pack stating an application catalog its tables do not hold was accepted as a current pack")
	}
	entries := earlier.HostCatalog["entries"].([]interface{})
	changed := map[string]interface{}{}
	for k, v := range earlier.HostCatalog {
		changed[k] = v
	}
	changed["entries"] = entries[1:]
	if _, err := parse(compose(changed), true); err == nil || !strings.Contains(err.Error(), "host_catalog") {
		t.Fatalf("an earlier release whose host catalog changed: %v", err)
	}
}
