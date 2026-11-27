package appid

import (
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
)

// SR-15: a session outcome never upgrades its evidence. A direction that ran out of budget, was malformed or
// unknown is an unmatched outcome named by its own status (never insufficient-data, never identified), and it
// outranks an invalidated or incomplete peer; ambiguity needs exactly one shared candidate. Ported from
// test_appid.py test_outcomes_for_unknown_malformed_budget_incomplete_invalidated.
func TestSessionOutcomesFollowStatusPrecedenceAndNeverUpgrade(t *testing.T) {
	p := pack(t)
	for _, c := range []struct {
		name           string
		client, server *contracts.Observation
		app, status    string
	}{
		{"budget", status(contracts.BudgetExhausted, "Byte budget exhausted"), nil, "unknown-tcp", "budget_exhausted"},
		{"budget over invalidated", status(contracts.BudgetExhausted, "Byte budget exhausted"), status(contracts.Invalidated, "conflict"), "unknown-tcp", "budget_exhausted"},
		{"budget over incomplete", status(contracts.Incomplete, "fin"), status(contracts.BudgetExhausted, "Byte budget exhausted"), "unknown-tcp", "budget_exhausted"},
		{"malformed over incomplete", status(contracts.Incomplete, "fin"), status(contracts.Malformed, "bad"), "unknown-tcp", "malformed"},
		{"invalidated over incomplete", status(contracts.Incomplete, "fin"), status(contracts.Invalidated, "conflict"), "not-applicable", "invalidated"},
	} {
		v := SessionVerdict(p, c.client, c.server, "tcp", 80, true, Bytes{5, true}, Bytes{5, true}, true)
		if v.App != c.app || v.Status != c.status || v.Identified(p) {
			t.Fatalf("%s: got %s/%s (identified %v), want %s/%s", c.name, v.App, v.Status, v.Identified(p), c.app, c.status)
		}
	}
	amb := func(cands string) *contracts.Observation {
		o := status(contracts.Unknown, "ambiguous")
		o.Evidence = []contracts.Evidence{{Field: "ambiguous_candidates", Value: cands, Source: "wire", Strength: "context"}}
		return o
	}
	if v := SessionVerdict(p, amb("ftp,pop3"), amb("pop3,ftp"), "tcp", 21, true, Bytes{5, true}, Bytes{5, true}, true); v.Status == "correlated" || v.Identified(p) {
		t.Fatalf("two shared candidates were resolved: %+v", v)
	}
}
