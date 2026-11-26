package engine

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand"
	"os"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// PRO-119 (audit A3, PRO-48): a validator error that is not a *parsing.Error is a malformed candidate, not a panic.
func TestDatagramFailureToleratesAForeignErrorType(t *testing.T) {
	for _, tc := range []struct {
		err            error
		status, reason string
	}{
		{parsing.Budget("over"), "budget_exhausted", "over"},
		{parsing.Unsupported("no"), "unknown", "no"},
		{parsing.Malformed("bad"), "malformed", "bad"},
		{errors.New("a future validator's own error"), "malformed", "a future validator's own error"},
	} {
		if status, reason := datagramFailure(tc.err); status != tc.status || reason != tc.reason {
			t.Errorf("%v: %s %q", tc.err, status, reason)
		}
	}
}

// PRO-119 (audit A3, PRO-48): Select never answers Wait for a full Lookahead probe. The inspector relies on it
// (inspector.go, the Wait branch of Feed): it keeps the whole chunk in its prefix only on Wait, which then implies
// a probe shorter than Lookahead, so the retained prefix stays under Lookahead bytes. Every waiting prefix of the
// reference's decision table, and random prefixes for every first byte, are completed to Lookahead bytes here.
func TestSelectNeverWaitsOnAFullLookahead(t *testing.T) {
	data, err := os.ReadFile("../../../migration/fixtures/dispatch.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Decisions map[string]*string `json:"decisions"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(119))
	complete := func(prefix []byte) []byte {
		full := append(append(make([]byte, 0, Lookahead), prefix...), make([]byte, Lookahead-len(prefix))...)
		rng.Read(full[len(prefix):])
		return full
	}
	check := func(probe []byte) {
		if Select(probe) == Wait {
			t.Fatalf("Select waits on a %d-byte probe %x", len(probe), probe)
		}
	}
	waiting := 0
	for prefixHex, decision := range doc.Decisions {
		prefix, _ := hex.DecodeString(prefixHex)
		if decision != nil || len(prefix) >= Lookahead {
			continue
		}
		waiting++
		check(append(append([]byte{}, prefix...), make([]byte, Lookahead-len(prefix))...)) // zero-filled
		for i := 0; i < 64; i++ {
			check(complete(prefix))
		}
	}
	if waiting < 100 {
		t.Fatalf("only %d waiting prefixes in the decision table", waiting)
	}
	for first := 0; first < 256; first++ {
		for i := 0; i < 256; i++ {
			check(complete([]byte{byte(first)}))
		}
	}
}
