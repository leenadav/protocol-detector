package replay

// PRO-428: TestPortedFamiliesMatchThePythonReference replays cases.json on the release it was recorded at
// (frozenPack). This test replays the same cases on the current release (migration/fixtures/content.json, the copy
// of the embedded pack.json) to show what a new release changes: every case keeps its recorded answer, except the
// release stamp every record carries, unless the answer names an application the frozen release does not have.
// On a tree whose current release is the frozen one it is the same comparison; tools/content_pack.py --self-test
// --e2e runs it with the example batch added.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/parity"
)

const currentPack = "../../../migration/fixtures/content.json"

// stripContent removes the release stamp (content.version and content.digest) from every session record.
func stripContent(value interface{}) {
	m, ok := value.(map[string]interface{})
	if !ok {
		return
	}
	records, _ := m["records"].([]interface{})
	for _, r := range records {
		if rec, ok := r.(map[string]interface{}); ok {
			delete(rec, "content")
		}
	}
}

// recordVersions lists the content.version of every session record of an answer.
func recordVersions(value interface{}) []interface{} {
	var out []interface{}
	m, _ := value.(map[string]interface{})
	records, _ := m["records"].([]interface{})
	for _, r := range records {
		rec, _ := r.(map[string]interface{})
		c, _ := rec["content"].(map[string]interface{})
		out = append(out, c["version"])
	}
	return out
}

// names reports whether any string in the value is one of the given application names.
func names(value interface{}, added map[string]bool) bool {
	switch v := value.(type) {
	case string:
		return added[v]
	case []interface{}:
		for _, item := range v {
			if names(item, added) {
				return true
			}
		}
	case map[string]interface{}:
		for _, item := range v {
			if names(item, added) {
				return true
			}
		}
	}
	return false
}

func TestCurrentContentKeepsEveryCaseThatNamesNoNewRecord(t *testing.T) {
	frozen, err := content.Load(frozenPack)
	if err != nil {
		t.Fatal(err)
	}
	current, err := content.Load(currentPack)
	if err != nil {
		t.Fatal(err)
	}
	added := map[string]bool{}
	for name := range current.Applications {
		if _, ok := frozen.Applications[name]; !ok {
			added[name] = true
		}
	}
	doc, err := parity.Load(context.Background(), "../../../migration/fixtures/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	SetPackPath(currentPack)
	defer SetPackPath("")
	results, err := Run(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	pinned := loadPinned(t)
	kept, changed, stamped := 0, 0, 0
	var failures []string
	for i := range doc.Cases {
		c := &doc.Cases[i]
		raw := results.Results[c.ID]
		var marker Unsupported
		if json.Unmarshal(raw, &marker) == nil && marker.Unsupported != "" {
			continue // gaps.json is checked by TestPortedFamiliesMatchThePythonReference
		}
		var want, got interface{}
		json.Unmarshal(c.Expected, &want)
		json.Unmarshal(raw, &got)
		if items, ok := pinned[c.ID]; ok {
			if want, err = expectPinned(want, items); err != nil {
				failures = append(failures, c.ID+": "+err.Error())
				continue
			}
		}
		for _, version := range recordVersions(got) {
			stamped++
			if version != current.Release.Version {
				failures = append(failures, c.ID+": a record states content release "+toString(version)+", not the current "+current.Release.Version)
			}
		}
		stripContent(want)
		stripContent(got)
		if d := diff("$", want, got); d != "" {
			if names(got, added) {
				changed++ // the answer names an application this release added: expected to differ
				continue
			}
			failures = append(failures, c.ID+": changed on release "+current.Release.Version+" without naming an added application: "+d)
			continue
		}
		kept++
	}
	t.Logf("release %s (%d applications added since %s): %d cases kept, %d changed by added applications, %d records stamped",
		current.Release.Version, len(added), frozen.Release.Version, kept, changed, stamped)
	if len(failures) > 0 {
		limit := 25
		if len(failures) < limit {
			limit = len(failures)
		}
		t.Fatalf("%d failures, first %d:\n%v", len(failures), limit, failures[:limit])
	}
	if kept < 1000 || stamped < 1000 {
		t.Fatalf("too few cases compared: %d kept, %d records stamped", kept, stamped)
	}
}

func toString(v interface{}) string {
	s, _ := v.(string)
	return s
}
