package detector

import (
	"crypto/tls"
	"testing"
)

// Integration work item #18: what one flow costs, per profile family. A flow here is NewFlow, the client's first
// flight, the server's first flight and Close, on a shared Engine, as a proxy would drive it.
//
// The benchmarks report time and allocations on the machine they run on; they are not a production latency
// figure. TestFlowAllocationBudget turns the allocation counts into a regression gate: a change that makes a
// flow allocate more than the ceiling must either be fixed or raise the ceiling on purpose.

type flowCase struct {
	name           string
	client, server []byte
	ceiling        float64 // allocations per flow that the gate allows
	group          string  // TLS only: the selected_group the server direction must report
}

func flowCases(t testing.TB) []flowCase {
	// PRO-596: the TLS flow is two explicit cases. Until then it was one "tls" case on Go's default groups, which
	// negotiate X25519MLKEM768; before PRO-260 the engine refused that ServerHello at once ("Server key share group
	// outside supported profile"), so the old 67-allocation baseline never parsed the server direction at all, and
	// the full parse PRO-260 brought read as a regression. Each case now names its group, and the budget test below
	// checks that the server direction is identified with it, so a benchmark can never again measure a refusal.
	classicalHello, classicalReply := tlsFlights(t, "bench.example.test", []string{"h2", "http/1.1"}, []tls.CurveID{tls.X25519})
	hybridHello, hybridReply := tlsFlights(t, "bench.example.test", []string{"h2", "http/1.1"},
		[]tls.CurveID{tls.X25519MLKEM768, tls.X25519}) // the shares Go's default configuration sends
	return []flowCase{
		{"tls-classical", classicalHello, classicalReply, 75, "29"}, // 59 (63 under -race); 92 before PRO-596
		{"tls-hybrid", hybridHello, hybridReply, 75, "4588"},        // 60 (64); 93 before PRO-596, 191 before PRO-148
		{"http", httpRequest, httpResponse, 80, ""},                 // 61 (69); 73 before PRO-596, 128 before PRO-148
		{"ssh", sshBanner, sshBanner, 60, ""},                       // 45 (47); 51 before PRO-596, 89 before PRO-148
		{"unknown", junk, junk, 15, ""},                             // 11 (11), 15 before
	}
}

func runFlow(e *Engine, c flowCase) Snapshot {
	f, err := e.NewFlow("bench")
	if err != nil {
		panic(err)
	}
	_, _ = f.Feed(ClientToServer, c.client)
	_, _ = f.Feed(ServerToClient, c.server)
	return f.Close()
}

func BenchmarkFlow(b *testing.B) {
	e := mustEngine(b, allFamilies())
	for _, c := range flowCases(b) {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(c.client) + len(c.server)))
			for i := 0; i < b.N; i++ {
				runFlow(e, c)
			}
		})
	}
}

// BenchmarkFlowBytewise is the adversarial shape: the same streams delivered one byte per Feed, up to the feed
// budget. It shows what a slow or hostile peer can make a flow cost.
func BenchmarkFlowBytewise(b *testing.B) {
	c := allFamilies()
	c.MaxFeedsPerDirection = 4096
	e := mustEngine(b, c)
	for _, fc := range flowCases(b) {
		b.Run(fc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				f, _ := e.NewFlow("bench")
				for j := range fc.client {
					_, _ = f.Feed(ClientToServer, fc.client[j:j+1])
				}
				for j := range fc.server {
					_, _ = f.Feed(ServerToClient, fc.server[j:j+1])
				}
				f.Close()
			}
		})
	}
}

func TestFlowAllocationBudget(t *testing.T) {
	e := mustEngine(t, allFamilies())
	for _, c := range flowCases(t) {
		s := runFlow(e, c)
		if c.name != "unknown" && s.Direction(ClientToServer).Outcome != OutcomeIdentified {
			t.Fatalf("%s: the benchmark flow is not identified: %+v", c.name, s.Direction(ClientToServer))
		}
		if c.group != "" {
			srv, group := s.Direction(ServerToClient), ""
			for _, ev := range srv.Evidence {
				if ev.Field == "selected_group" {
					group = ev.Value
				}
			}
			if srv.Outcome != OutcomeIdentified || group != c.group {
				t.Fatalf("%s: the server direction must be identified with group %s, got %s with group %q (%s)",
					c.name, c.group, srv.Outcome, group, srv.Detail)
			}
		}
		got := testing.AllocsPerRun(200, func() { runFlow(e, c) })
		t.Logf("%s: %.0f allocations per flow (ceiling %.0f)", c.name, got, c.ceiling)
		if got > c.ceiling {
			t.Errorf("%s: %.0f allocations per flow, over the ceiling of %.0f", c.name, got, c.ceiling)
		}
	}
}
