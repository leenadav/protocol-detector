package replay

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/engine"
	"github.com/leenadav/protocol-detector/go/internal/parity"
)

func family(label string) string {
	if i := strings.IndexByte(label, '/'); i >= 0 {
		return label[:i]
	}
	return label
}

func ported(label string) bool {
	for _, f := range engine.Families {
		if family(label) == f {
			return true
		}
	}
	return false
}

// diff returns the first differing path between two decoded JSON values ("" when equal).
func diff(path string, want, got interface{}) string {
	switch w := want.(type) {
	case map[string]interface{}:
		g, ok := got.(map[string]interface{})
		if !ok {
			return path + ": type"
		}
		keys := map[string]bool{}
		for k := range w {
			keys[k] = true
		}
		for k := range g {
			keys[k] = true
		}
		sorted := make([]string, 0, len(keys))
		for k := range keys {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		for _, k := range sorted {
			if d := diff(path+"."+k, w[k], g[k]); d != "" {
				return d
			}
		}
	case []interface{}:
		g, ok := got.([]interface{})
		if !ok {
			return path + ": type"
		}
		if len(w) != len(g) {
			return fmt.Sprintf("%s.length: want %d got %d", path, len(w), len(g))
		}
		for i := range w {
			if d := diff(fmt.Sprintf("%s[%d]", path, i), w[i], g[i]); d != "" {
				return d
			}
		}
	default:
		if !reflect.DeepEqual(want, got) {
			return fmt.Sprintf("%s: want %v got %v", path, want, got)
		}
	}
	return ""
}

// canonicalizeRecords applies the harness rule to a Go result: content.digest is not compared (cases.py record_dict).
func canonicalizeRecords(got interface{}) {
	m, ok := got.(map[string]interface{})
	if !ok {
		return
	}
	records, _ := m["records"].([]interface{})
	for _, r := range records {
		if rec, ok := r.(map[string]interface{}); ok {
			if c, ok := rec["content"].(map[string]interface{}); ok {
				rec["content"] = map[string]interface{}{"version": c["version"]}
			}
		}
	}
}

// The Go backend's results must equal the Python expectations on every case of a ported family that
// uses only ported options; cases it cannot answer are reported as unsupported, never as a different
// result. Session cases are compared without their records (M6).
func TestPortedFamiliesMatchThePythonReference(t *testing.T) {
	doc, err := parity.Load(context.Background(), "../../../migration/fixtures/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	results, err := Run(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	var failures []string
	for i := range doc.Cases {
		c := &doc.Cases[i]
		raw := results.Results[c.ID]
		var marker Unsupported
		if json.Unmarshal(raw, &marker) == nil && marker.Unsupported != "" {
			if ported(c.Label) && !strings.Contains(marker.Unsupported, "option ") && !strings.Contains(marker.Unsupported, "datagram candidate") &&
				!strings.Contains(marker.Unsupported, "UDP flows in sessions") && !strings.Contains(marker.Unsupported, "text family") &&
				!strings.Contains(marker.Unsupported, "shift to") && !strings.Contains(marker.Unsupported, "family ") {
				failures = append(failures, c.ID+": unsupported without a named gap: "+marker.Unsupported)
			}
			counts["unsupported/"+c.Kind]++
			continue
		}
		if !ported(c.Label) {
			// A result for an unported family is still a claim: it must be exactly right or absent.
			counts["result-unported/"+c.Kind]++
		}
		var want, got interface{}
		json.Unmarshal(c.Expected, &want)
		json.Unmarshal(raw, &got)
		if c.Kind == "session" {
			canonicalizeRecords(got)
		}
		if d := diff("$", want, got); d != "" {
			failures = append(failures, c.ID+": "+d)
			counts["mismatch/"+c.Kind]++
			continue
		}
		counts["matched/"+c.Kind]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("%-26s %d", k, counts[k])
	}
	if len(failures) > 0 {
		limit := 25
		if len(failures) < limit {
			limit = len(failures)
		}
		t.Fatalf("%d failures, first %d:\n%s", len(failures), limit, strings.Join(failures[:limit], "\n"))
	}
	if counts["matched/stream"] < 100 || counts["matched/datagram"] < 20 || counts["matched/session"] < 10 {
		t.Fatalf("too few matched cases: %v", counts)
	}
}
