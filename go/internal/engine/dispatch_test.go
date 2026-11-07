package engine

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestSelectMatchesThePythonDecisionTable(t *testing.T) {
	data, err := os.ReadFile("../../../migration/fixtures/dispatch.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Lookahead int                `json:"lookahead"`
		Decisions map[string]*string `json:"decisions"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Lookahead != Lookahead || len(doc.Decisions) < 5000 {
		t.Fatalf("table: lookahead %d, %d decisions", doc.Lookahead, len(doc.Decisions))
	}
	mismatches := 0
	for prefixHex, want := range doc.Decisions {
		prefix, _ := hex.DecodeString(prefixHex)
		got := Select(prefix)
		expected := Wait
		if want != nil {
			expected = *want
		}
		if got != expected {
			mismatches++
			if mismatches <= 10 {
				t.Errorf("prefix %s: got %q want %q", prefixHex, got, expected)
			}
		}
	}
	if mismatches > 0 {
		t.Fatalf("%d of %d decisions differ", mismatches, len(doc.Decisions))
	}
}

func FuzzSelectNeverPanics(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\n"))
	f.Add([]byte{0x16, 0x03, 0x01})
	f.Fuzz(func(t *testing.T, prefix []byte) {
		if len(prefix) == 0 || len(prefix) > Lookahead {
			return
		}
		Select(prefix)
	})
}
