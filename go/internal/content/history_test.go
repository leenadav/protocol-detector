package content

import (
	"encoding/json"
	"strings"
	"testing"
)

// Every earlier release parses (its host catalog must reproduce the stated host component, and the release digest
// is recomputed) and pins the reference's version and digest (protocol_engine.content.digest(version)). C11
// (2026-11-18): the digests are the ones each release was published with, unchanged by later applications.
func TestEarlierReleasesParseWithTheReferenceDigests(t *testing.T) {
	want := map[string]struct {
		digest string
		hosts  int
	}{
		"2025.10.0": {"9f8791749a940f5b", 53}, "2026.11.0": {"991c007668d263d1", 54},
		"2026.11.1": {"c4020c2437f3de8d", 169}, "2026.11.2": {"e0d6e39533a6ae9c", 431},
		"2026.11.3": {"fef8f709d5615a85", 434}, "2026.11.4": {"c13a842d11873db6", 434},
		"2026.11.5": {"39150de086799d99", 438},
		"2026.11.6": {"d425b8adc87db36d", 438},
		"2026.11.7": {"b2ccbc7842dcffcc", 441},
	}
	releases := Releases()
	if len(releases) != len(want) || releases[len(releases)-1] != "2026.11.7" {
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
