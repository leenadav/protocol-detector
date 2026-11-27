package content

import (
	"strings"
	"testing"
)

// restate edits the committed pack and restates its host_catalog component and release digest over the edited
// tables, so the digest gate passes and only the table validation is left to refuse the pack.
func restate(t *testing.T, edit func(entries []interface{})) []byte {
	t.Helper()
	apply := func(d map[string]interface{}) {
		if edit != nil {
			edit(d["host_catalog"].(map[string]interface{})["entries"].([]interface{}))
		}
	}
	// The component is computed the way the loader computes it: over the strictly parsed edited tables.
	value, err := parseStrict(reencode(t, apply))
	if err != nil {
		t.Fatal(err)
	}
	entries := value.(map[string]interface{})["host_catalog"].(map[string]interface{})["entries"].([]interface{})
	host := chain(entries)
	return reencode(t, func(d map[string]interface{}) {
		apply(d)
		release := d["release"].(map[string]interface{})
		components := release["components"].(map[string]interface{})
		components["host_catalog"] = host
		parts := make([]interface{}, 0, len(ComponentNames))
		for _, name := range ComponentNames {
			parts = append(parts, components[name].(string))
		}
		release["digest"] = chain(parts)[:16]
	})
}

// SR-66: a server-name catalog that would map one domain (or one web front) to two applications never builds,
// even with digests restated to match it, as the current pack or as a rolled-back earlier release; an unknown
// release is refused rather than replaced by the current one.
func TestSecurityDuplicateDomainsNeverBuild(t *testing.T) {
	if _, err := Parse(restate(t, nil)); err != nil {
		t.Fatalf("the restated, unedited pack: %v", err)
	}
	duplicate := func(entries []interface{}) {
		first := entries[0].(map[string]interface{})["domains"].([]interface{})
		second := entries[1].(map[string]interface{})
		second["domains"] = append(append([]interface{}{}, second["domains"].([]interface{})...), first[0])
	}
	data := restate(t, duplicate)
	for _, earlier := range []bool{false, true} {
		if _, err := parse(data, earlier); err == nil || !strings.Contains(err.Error(), "Duplicate host-catalog domain") {
			t.Fatalf("a duplicate domain (earlier %v): %v", earlier, err)
		}
	}
	var front string
	var owner int
	fronts := func(entries []interface{}) {
		for i, e := range entries {
			if list, ok := e.(map[string]interface{})["web_fronts"].([]interface{}); ok && len(list) > 0 {
				front, owner = list[0].(string), i
				break
			}
		}
		other := entries[(owner+1)%len(entries)].(map[string]interface{})
		list, _ := other["web_fronts"].([]interface{})
		other["web_fronts"] = append(append([]interface{}{}, list...), front)
	}
	if _, err := Parse(restate(t, fronts)); front == "" || err == nil || !strings.Contains(err.Error(), "Duplicate host-catalog web front") {
		t.Fatalf("a duplicate web front %q: %v", front, err)
	}
	for _, v := range []string{"2030.01.0", "2026.11", "", "2026.11.09x"} {
		if p, err := EmbeddedRelease(v); err == nil {
			t.Fatalf("unknown release %q selected %s", v, p.Release.Version)
		}
	}
	earlier, err := EmbeddedRelease("2025.10.0")
	if err != nil || earlier.Release.Version != "2025.10.0" {
		t.Fatalf("the earliest release: %v", err)
	}
	current, _ := Embedded()
	if earlier.Release.Digest == current.Release.Digest {
		t.Fatal("the earlier release reports the current digest")
	}
}
