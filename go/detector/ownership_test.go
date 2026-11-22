package detector

import (
	"runtime"
	"strings"
	"testing"
)

// Review of work item #14, finding R1: RetainedBytes must cover the whole allocation each retained buffer
// keeps alive. The HTTP parser kept the request target as a subslice of its copy of the request line, so a
// long extension method with a one-byte target kept about 6 KiB alive that the figure did not count.
//
// These tests do not trust RetainedBytes on its own word. They measure the live heap that a batch of flows
// holds and require it to stay within a fixed overhead of what the flows report.

// heapPerFlow builds n flows with build, keeps them alive across a garbage collection and returns the
// live-heap bytes per flow together with the flows.
func heapPerFlow(n int, build func(i int) *Flow) (float64, []*Flow) {
	flows := make([]*Flow, n)
	runtime.GC()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := range flows {
		flows[i] = build(i)
	}
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&after)
	return (float64(after.HeapAlloc) - float64(before.HeapAlloc)) / float64(n), flows
}

// unaccountedCeiling is the live heap one flow may hold beyond its reported retained buffers: the Flow, its
// two inspectors and parsers, snapshots and strings. Measured at about 1.7 KiB for one direction with state;
// the R1 defects added 6 KiB (the request-line copy behind the target) and another 6 KiB (the method string).
const unaccountedCeiling = 3072

func tightEngine(t testing.TB) *Engine {
	c := allFamilies()
	c.MaxBytesPerDirection, c.MaxFeedsPerDirection, c.MaxRetainedPerFlow, c.MaxFlows = 8192, 1<<14, 8192, 512
	return mustEngine(t, c)
}

// longMethod is a request line with a 6000-byte extension method and a one-byte target, headers not finished.
var longMethod = []byte(strings.Repeat("X", 6000) + " / HTTP/1.1\r\n")

func feedIn(f *Flow, d Direction, data []byte, step int) {
	for pos := 0; pos < len(data); pos += step {
		_, _ = f.Feed(d, data[pos:minInt(pos+step, len(data))])
	}
}

func TestRetainedCoversTheBackingAllocations(t *testing.T) {
	for _, tc := range []struct {
		name string
		step int
		dirs []Direction
	}{
		{"whole, client", len(longMethod), []Direction{ClientToServer}},
		{"whole, server", len(longMethod), []Direction{ServerToClient}},
		{"fragmented, client", 97, []Direction{ClientToServer}},
		{"byte by byte, server", 1, []Direction{ServerToClient}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := tightEngine(t)
			per, flows := heapPerFlow(200, func(i int) *Flow {
				f := mustFlow(t, e)
				for _, d := range tc.dirs {
					feedIn(f, d, longMethod, tc.step)
				}
				return f
			})
			s := flows[0].Snapshot()
			d := tc.dirs[0]
			if got := s.Direction(d); got.Done || got.Outcome != OutcomeDetecting {
				t.Fatalf("the flow fits its allowance once the target is a compact copy, but it ended: %+v", got)
			}
			if s.RetainedBytes < 6000 || s.RetainedBytes > 8192 {
				t.Fatalf("reported retained %d, want the line accumulator plus a small target copy", s.RetainedBytes)
			}
			if extra := per - float64(s.RetainedBytes); extra > unaccountedCeiling {
				t.Fatalf("each flow keeps %.0f bytes of heap alive but reports %d retained: %.0f unaccounted (ceiling %d)",
					per, s.RetainedBytes, extra, unaccountedCeiling)
			}
			t.Logf("heap per flow %.0f, reported retained %d", per, s.RetainedBytes)
			// Terminal release: finishing the headers decides the direction and frees the buffers.
			f := flows[0]
			_, _ = f.Feed(d, []byte("Host: a.example\r\n\r\n"))
			if s := f.Snapshot(); s.Direction(d).Outcome != OutcomeIdentified || s.RetainedBytes != 0 {
				t.Fatalf("after the headers: outcome %s, retained %d", s.Direction(d).Outcome, s.RetainedBytes)
			}
			for _, f := range flows {
				f.Close()
			}
			if st := e.Stats(); st.RetainedBytes != 0 || st.ReservedBytes != 0 || st.Active != 0 {
				t.Fatalf("after close: %+v", st)
			}
			runtime.KeepAlive(flows)
		})
	}
}

// With the same line in both directions the flow really does hold more than its allowance, and now says so:
// the second direction ends with memory_budget, and the heap the flow keeps afterwards is inside the allowance.
func TestBothDirectionsOverTheAllowanceEndWithMemoryBudget(t *testing.T) {
	for _, step := range []int{len(longMethod), 61} {
		e := tightEngine(t)
		per, flows := heapPerFlow(200, func(i int) *Flow {
			f := mustFlow(t, e)
			feedIn(f, ClientToServer, longMethod, step)
			feedIn(f, ServerToClient, longMethod, step)
			return f
		})
		s := flows[0].Snapshot()
		if got := s.Direction(ServerToClient); got.Outcome != OutcomeBudgetExhausted || got.Reason != ReasonMemory {
			t.Fatalf("step %d: second direction %+v", step, got)
		}
		if got := s.Direction(ClientToServer); got.Done {
			t.Fatalf("step %d: first direction was ended too: %+v", step, got)
		}
		if s.RetainedBytes > 8192 || per-float64(s.RetainedBytes) > unaccountedCeiling {
			t.Fatalf("step %d: heap per flow %.0f, reported retained %d", step, per, s.RetainedBytes)
		}
		for _, f := range flows {
			f.Close()
			f.Close()
		}
		if st := e.Stats(); st.RetainedBytes != 0 || st.ReservedBytes != 0 {
			t.Fatalf("step %d: after close: %+v", step, st)
		}
		runtime.KeepAlive(flows)
	}
}

// After Close the flows keep no buffer alive at all.
func TestClosedFlowsKeepNoBuffers(t *testing.T) {
	e := tightEngine(t)
	per, flows := heapPerFlow(200, func(i int) *Flow {
		f := mustFlow(t, e)
		feedIn(f, ClientToServer, longMethod, 500)
		feedIn(f, ServerToClient, longMethod[:3000], 500)
		f.Close()
		return f
	})
	if per > unaccountedCeiling {
		t.Fatalf("a closed flow keeps %.0f bytes of heap alive", per)
	}
	runtime.KeepAlive(flows)
}

// The same independent check for the other states the covered parsers can be left in: a long request target,
// a pending long header line after an Upgrade header, half a TLS ClientHello, and an SSH banner followed by
// part of a KEXINIT. Each must report what it keeps alive.
func TestOtherRetainedStatesAreCovered(t *testing.T) {
	hello, _ := tlsFlights(t, "own.example.test", []string{"h2", "http/1.1"}, nil)
	kex := append([]byte{0, 0, 0x10, 0, 4, 20}, make([]byte, 3000)...) // a 4096-byte KEXINIT packet, 3000 bytes of it
	states := map[string][]byte{
		"long target":    []byte("GET /" + strings.Repeat("a", 6000) + " HTTP/1.1\r\nHost: a.example\r\n"),
		"upgrade header": []byte("GET / HTTP/1.1\r\nUpgrade: websocket\r\nX-Pending: " + strings.Repeat("p", 3000)),
		"host header":    []byte("GET / HTTP/1.1\r\nHost: " + strings.Repeat("h", 60) + ".example\r\nX-Pending: " + strings.Repeat("p", 1000)),
		"half a hello":   hello[:len(hello)/2],
		"ssh kexinit":    append(append([]byte{}, sshBanner...), kex...),
	}
	for name, data := range states {
		for _, step := range []int{len(data), 53} {
			c := allFamilies()
			c.MaxFeedsPerDirection, c.MaxFlows = 1<<14, 512
			e := mustEngine(t, c)
			per, flows := heapPerFlow(200, func(i int) *Flow {
				f := mustFlow(t, e)
				feedIn(f, Direction(i%2), data, step) // alternate the direction that holds the state
				return f
			})
			s := flows[0].Snapshot()
			if s.Direction(ClientToServer).Done && s.Direction(ClientToServer).Outcome != OutcomeIdentified {
				t.Fatalf("%s (step %d): the state was not reached: %+v", name, step, s.Direction(ClientToServer))
			}
			if s.RetainedBytes == 0 {
				t.Fatalf("%s (step %d): nothing reported retained", name, step)
			}
			if extra := per - float64(s.RetainedBytes); extra > unaccountedCeiling {
				t.Errorf("%s (step %d): heap per flow %.0f, reported retained %d: %.0f unaccounted (ceiling %d)",
					name, step, per, s.RetainedBytes, extra, unaccountedCeiling)
			} else {
				t.Logf("%s (step %d): heap per flow %.0f, reported retained %d", name, step, per, s.RetainedBytes)
			}
			for _, f := range flows {
				f.Close()
			}
			if st := e.Stats(); st.RetainedBytes != 0 || st.ReservedBytes != 0 {
				t.Fatalf("%s: after close: %+v", name, st)
			}
			runtime.KeepAlive(flows)
		}
	}
}
