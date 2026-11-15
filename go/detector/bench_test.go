package detector

import (
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
}

func flowCases(t testing.TB) []flowCase {
	hello, reply := tlsFlights(t, "bench.example.test", []string{"h2", "http/1.1"}, nil)
	return []flowCase{
		{"tls", hello, reply, 240},
		{"http", httpRequest, httpResponse, 160},
		{"ssh", sshBanner, sshBanner, 115},
		{"unknown", junk, junk, 25},
	}
}

func runFlow(e *Engine, c flowCase) Snapshot {
	f, err := e.NewFlow("bench")
	if err != nil {
		panic(err)
	}
	f.Feed(ClientToServer, c.client)
	f.Feed(ServerToClient, c.server)
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
					f.Feed(ClientToServer, fc.client[j:j+1])
				}
				for j := range fc.server {
					f.Feed(ServerToClient, fc.server[j:j+1])
				}
				f.Close()
			}
		})
	}
}

func TestFlowAllocationBudget(t *testing.T) {
	e := mustEngine(t, allFamilies())
	for _, c := range flowCases(t) {
		if s := runFlow(e, c); c.name != "unknown" && s.Direction(ClientToServer).Outcome != OutcomeIdentified {
			t.Fatalf("%s: the benchmark flow is not identified: %+v", c.name, s.Direction(ClientToServer))
		}
		got := testing.AllocsPerRun(200, func() { runFlow(e, c) })
		t.Logf("%s: %.0f allocations per flow (ceiling %.0f)", c.name, got, c.ceiling)
		if got > c.ceiling {
			t.Errorf("%s: %.0f allocations per flow, over the ceiling of %.0f", c.name, got, c.ceiling)
		}
	}
}
