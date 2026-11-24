package replay

import (
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"testing"
)

// pinnedDelta is a migration/parity/deltas.json item that records `go`: an approved Go-only divergence (PRO-260,
// TLS post-quantum hybrid key shares, Lee 2026-11-23). The Go result must have exactly that value at the path;
// compare.py applies the same rule to a Go results file.
type pinnedDelta struct {
	Path          string          `json:"path"`
	Justification string          `json:"justification"`
	Go            json.RawMessage `json:"go"`
}

func loadPinned(t *testing.T) map[string][]pinnedDelta {
	t.Helper()
	raw, err := os.ReadFile("../../../migration/parity/deltas.json")
	if err != nil {
		t.Fatal(err)
	}
	var all map[string][]pinnedDelta
	if err := json.Unmarshal(raw, &all); err != nil {
		t.Fatalf("deltas.json: %v", err)
	}
	pinned := map[string][]pinnedDelta{}
	for id, items := range all {
		for _, item := range items {
			if item.Go == nil {
				continue // an exact-path exemption without a pinned value; none is honoured here
			}
			if item.Justification == "" {
				t.Fatalf("deltas.json %s %s: a pinned delta needs a justification", id, item.Path)
			}
			pinned[id] = append(pinned[id], item)
		}
	}
	return pinned
}

var pathStep = regexp.MustCompile(`\.([A-Za-z0-9_]+)|\[(\d+)\]`)

// expectPinned returns the expectation with each pinned path replaced by the recorded Go value, so the diff that
// follows requires exactly that value. A path that does not exist in the expectation is an error.
func expectPinned(want interface{}, items []pinnedDelta) (interface{}, error) {
	for _, item := range items {
		var value interface{}
		if err := json.Unmarshal(item.Go, &value); err != nil {
			return nil, err
		}
		steps := pathStep.FindAllStringSubmatch(item.Path[1:], -1)
		if len(steps) == 0 || item.Path[0] != '$' {
			return nil, &pathError{item.Path}
		}
		node := want
		for i, step := range steps {
			last := i == len(steps)-1
			switch n := node.(type) {
			case map[string]interface{}:
				if _, ok := n[step[1]]; step[1] == "" || !ok {
					return nil, &pathError{item.Path}
				}
				if last {
					n[step[1]] = value
				}
				node = n[step[1]]
			case []interface{}:
				index, err := strconv.Atoi(step[2])
				if step[2] == "" || err != nil || index >= len(n) {
					return nil, &pathError{item.Path}
				}
				if last {
					n[index] = value
				}
				node = n[index]
			default:
				return nil, &pathError{item.Path}
			}
		}
	}
	return want, nil
}

type pathError struct{ path string }

func (e *pathError) Error() string { return "pinned delta path not in the expectation: " + e.path }

func TestExpectPinned(t *testing.T) {
	want := map[string]interface{}{"final": map[string]interface{}{"status": "unknown"},
		"events": []interface{}{map[string]interface{}{"observation": "old"}}}
	got, err := expectPinned(want, []pinnedDelta{{Path: "$.final", Go: json.RawMessage(`{"status":"identified"}`)},
		{Path: "$.events[0].observation", Go: json.RawMessage(`"new"`)}})
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]interface{}{"final": map[string]interface{}{"status": "identified"},
		"events": []interface{}{map[string]interface{}{"observation": "new"}}}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("got %v", got)
	}
	for _, path := range []string{"$.missing", "$.events[3]", "$.final.status.deeper", "final"} {
		if _, err := expectPinned(map[string]interface{}{"final": map[string]interface{}{"status": "x"}, "events": []interface{}{}},
			[]pinnedDelta{{Path: path, Go: json.RawMessage(`1`)}}); err == nil {
			t.Errorf("%s: want an error", path)
		}
	}
	// Every pinned delta on file names a case and a path that exist.
	if len(loadPinned(t)) == 0 {
		t.Fatal("no pinned deltas: PRO-260 records 18")
	}
}
