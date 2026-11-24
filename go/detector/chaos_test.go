package detector

// PRO-101: chaos tests of the facade, after Culvert's CI standard. Each drives many goroutines against one engine
// with hostile traffic or injected faults and checks the limits a proxy host depends on: the flow limit and the
// memory allowance are never exceeded at any instant, a hostile flow ends with a budget outcome instead of holding
// state, a panic stays inside the flow that caused it, the breaker opens exactly at PanicLimit, and closing every
// flow returns every counter to zero. They run under `go test -race` in make go-check-race.

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

// watchStats samples e.Stats() while work runs and fails if an instant ever broke the limits.
func watchStats(t *testing.T, e *Engine, maxFlows int64) (stop func()) {
	t.Helper()
	done, finished := make(chan struct{}), make(chan string, 1)
	go func() {
		for {
			st := e.Stats()
			switch {
			case st.Active < 0 || st.Active > maxFlows:
				finished <- fmt.Sprintf("active flows %d outside 0..%d", st.Active, maxFlows)
				return
			case st.ReservedBytes > st.EngineAllowance:
				finished <- fmt.Sprintf("reserved %d bytes over the engine allowance %d", st.ReservedBytes, st.EngineAllowance)
				return
			case st.RetainedBytes < 0 || st.RetainedBytes > st.EngineAllowance:
				finished <- fmt.Sprintf("retained %d bytes outside 0..%d", st.RetainedBytes, st.EngineAllowance)
				return
			}
			select {
			case <-done:
				finished <- ""
				return
			default:
			}
		}
	}()
	return func() {
		close(done)
		if msg := <-finished; msg != "" {
			t.Fatal(msg)
		}
	}
}

// requireDrained checks that no flow, reservation or retained byte is left once every flow closed.
func requireDrained(t *testing.T, e *Engine) {
	t.Helper()
	if st := e.Stats(); st.Active != 0 || st.ReservedBytes != 0 || st.RetainedBytes != 0 {
		t.Fatalf("after every flow closed: %+v", st)
	}
}

// Max flows: 32 goroutines race for 16 slots, holding what they get, while others close. Admission never
// over-commits, every attempt is counted once, and the slots all come back.
func TestChaosAdmissionStormNeverExceedsMaxFlows(t *testing.T) {
	c := allFamilies()
	c.MaxFlows = 16
	e := mustEngine(t, c)
	stop := watchStats(t, e, int64(c.MaxFlows))
	var wg sync.WaitGroup
	var attempts, admitted, refused atomic.Int64
	// Every goroutine holds its first admission until all 32 have made one, so 32 concurrent attempts meet a
	// 16-flow limit whatever the scheduler does. Without this barrier a slow run (coverage instrumentation on
	// CI) could serialise the goroutines and never refuse anything.
	var first sync.WaitGroup
	first.Add(32)
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			var held []*Flow
			for i := 0; i < 200; i++ {
				attempts.Add(1)
				f, err := e.NewFlow(fmt.Sprintf("storm-%d-%d", g, i))
				switch {
				case err == nil:
					admitted.Add(1)
					_, _ = f.Feed(ClientToServer, httpRequest[:1+i%len(httpRequest)])
					held = append(held, f)
				case errors.Is(err, ErrAdmission):
					refused.Add(1)
				default:
					t.Errorf("admission error %v", err)
					if i == 0 {
						first.Done()
					}
					return
				}
				if i == 0 {
					first.Done()
					first.Wait()
				}
				if len(held) > 2 || (err != nil && len(held) > 0) {
					held[0].Close()
					held = held[1:]
				}
			}
			for _, f := range held {
				f.Close()
			}
		}(g)
	}
	wg.Wait()
	stop()
	st := e.Stats()
	if st.Admitted != admitted.Load() || st.Refused != refused.Load() || admitted.Load()+refused.Load() != attempts.Load() {
		t.Fatalf("stats %+v, admitted %d refused %d of %d attempts", st, admitted.Load(), refused.Load(), attempts.Load())
	}
	if refused.Load() == 0 {
		t.Fatal("no admission was refused: the storm did not reach the flow limit")
	}
	requireDrained(t, e)
	if _, err := e.NewFlow("after"); err != nil {
		t.Fatalf("admission after the storm: %v", err)
	}
}

// Memory exhaustion: the engine allowance holds 4 flow allowances, so concurrent admission beyond it is refused
// with ErrMemory (counted in RefusedMemory), never by over-committing.
func TestChaosMemoryAllowanceRefusesInsteadOfOvercommitting(t *testing.T) {
	c := allFamilies()
	c.MaxFlows, c.MaxRetainedPerFlow = 64, 16384
	c.MaxRetainedTotal = 4 * c.MaxRetainedPerFlow
	e := mustEngine(t, c)
	stop := watchStats(t, e, int64(c.MaxFlows))
	var wg sync.WaitGroup
	var memory atomic.Int64
	start := make(chan struct{})
	flows := make(chan *Flow, 64)
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			f, err := e.NewFlow("memory")
			switch {
			case err == nil:
				flows <- f
			case errors.Is(err, ErrMemory):
				memory.Add(1)
			default:
				t.Errorf("admission error %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(flows)
	n := 0
	for f := range flows {
		n++
		_, _ = f.Feed(ClientToServer, bytes.Repeat([]byte("A"), 40000)) // past the flow allowance
		if s := f.Snapshot(); s.RetainedBytes > f.reserved {
			t.Errorf("flow retains %d over its allowance %d", s.RetainedBytes, f.reserved)
		}
		f.Close()
	}
	stop()
	if st := e.Stats(); n != 4 || memory.Load() != 12 || st.RefusedMemory != 12 {
		t.Fatalf("admitted %d (want 4), refused for memory %d (want 12), stats %+v", n, memory.Load(), st)
	}
	requireDrained(t, e)
}

// Huge headers: one request with a 1 MiB header, fed whole and in 64 KiB pieces, and a TLS record header that
// claims the largest length. Each direction stops at MaxBytesPerDirection with a final outcome and never holds
// more than its allowance, whatever the claimed or real size.
func TestChaosHugeHeadersStopAtTheByteBudget(t *testing.T) {
	c := allFamilies()
	c.MaxFeedsPerDirection = 4096
	e := mustEngine(t, c)
	huge := append([]byte("GET / HTTP/1.1\r\nHost: huge.example.test\r\nX-Pad: "), bytes.Repeat([]byte("a"), 1<<20)...)
	many := append([]byte("GET / HTTP/1.1\r\nHost: many.example.test\r\n"), bytes.Repeat([]byte("X-A: b\r\n"), 1<<16)...)
	tlsClaim := append([]byte{0x16, 0x03, 0x01, 0xff, 0xff, 0x01, 0xff, 0xff, 0xfb, 0x03, 0x03}, bytes.Repeat([]byte{0x41}, 1<<20)...)
	// an in-profile 16 KiB record whose ClientHello claims 16 MiB, followed by records that never complete it
	tlsHello := []byte{0x16, 0x03, 0x01, 0x40, 0x00, 0x01, 0xff, 0xff, 0xff, 0x03, 0x03}
	for len(tlsHello) < 1<<20 {
		tlsHello = append(tlsHello, bytes.Repeat([]byte{0x42}, 0x4000-6)...)
		tlsHello = append(tlsHello, 0x16, 0x03, 0x01, 0x40, 0x00)
	}
	for _, tc := range []struct {
		name    string
		input   []byte
		outcome Outcome
	}{
		{"http header line", huge, OutcomeBudgetExhausted},
		{"http header count", many, OutcomeBudgetExhausted},
		{"tls record length", tlsClaim, OutcomeMalformed},
		{"tls handshake length", tlsHello, OutcomeBudgetExhausted},
	} {
		name, input := tc.name, tc.input
		for _, piece := range []int{len(input), 1 << 16, 1500} {
			f := mustFlow(t, e)
			for pos := 0; pos < len(input); pos += piece {
				_, _ = f.Feed(ClientToServer, input[pos:minInt(pos+piece, len(input))])
				s := f.Snapshot()
				if s.RetainedBytes > f.reserved {
					t.Fatalf("%s in %d-byte pieces: retains %d over the allowance %d", name, piece, s.RetainedBytes, f.reserved)
				}
				if s.Direction(ClientToServer).Done {
					break
				}
			}
			ds := f.Snapshot().Direction(ClientToServer)
			if !ds.Done || ds.Outcome != tc.outcome {
				t.Fatalf("%s in %d-byte pieces: %s %s done=%v (%q)", name, piece, ds.Outcome, ds.Reason, ds.Done, ds.Detail)
			}
			if ds.BytesInspected > c.MaxBytesPerDirection {
				t.Fatalf("%s in %d-byte pieces: inspected %d of a %d budget", name, piece, ds.BytesInspected, c.MaxBytesPerDirection)
			}
			f.Close()
		}
	}
	requireDrained(t, e)
}

// Slowloris: every slot is held by a flow that sends one byte per call of a request that never ends. Each
// direction ends as budget_exhausted after MaxFeedsPerDirection calls and then ignores further bytes; the engine
// keeps refusing new flows while the slots are held (it never grows state for them) and admits again once the
// host closes them.
func TestChaosSlowlorisFlowsEndAtTheFeedBudget(t *testing.T) {
	c := allFamilies()
	c.MaxFlows, c.MaxFeedsPerDirection = 128, 32
	e := mustEngine(t, c)
	stop := watchStats(t, e, int64(c.MaxFlows))
	slow := []byte("GET / HTTP/1.1\r\nHost: slow.example.test\r\nX-Keep: " + string(bytes.Repeat([]byte("z"), 200)))
	flows := make([]*Flow, c.MaxFlows)
	for i := range flows {
		flows[i] = mustFlow(t, e)
	}
	if _, err := e.NewFlow("one too many"); !errors.Is(err, ErrAdmission) {
		t.Fatalf("admission with every slot held: %v", err)
	}
	var wg sync.WaitGroup
	for i, f := range flows {
		wg.Add(1)
		go func(i int, f *Flow) {
			defer wg.Done()
			for n := 0; n < len(slow); n++ {
				u, err := f.Feed(ServerToClient-Direction(i%2), slow[n:n+1])
				if err != nil {
					t.Errorf("flow %d byte %d: %v", i, n, err)
					return
				}
				if n > c.MaxFeedsPerDirection && u.Changed { // call MaxFeeds+1 is the one that ends the direction
					t.Errorf("flow %d: byte %d changed a direction past its feed budget", i, n)
					return
				}
			}
			ds := f.Snapshot().Direction(ServerToClient - Direction(i%2))
			if !ds.Done || ds.Outcome != OutcomeBudgetExhausted || ds.Reason != ReasonEngine || ds.BytesFed != len(slow) {
				t.Errorf("flow %d: %s %s done=%v fed %d", i, ds.Outcome, ds.Reason, ds.Done, ds.BytesFed)
			}
		}(i, f)
	}
	wg.Wait()
	if st := e.Stats(); st.RetainedBytes != 0 {
		t.Errorf("every direction is done, yet %d bytes are retained", st.RetainedBytes)
	}
	for _, f := range flows {
		f.Close()
	}
	stop()
	requireDrained(t, e)
	if _, err := e.NewFlow("after"); err != nil {
		t.Fatalf("admission after the slow flows closed: %v", err)
	}
}

// Panic boundary and breaker: 16 goroutines run flows while one operation in 7 panics inside the engine. No panic
// escapes, the flow that panicked (and only it) is quarantined, the count of quarantined flows equals Stats.Panics,
// the breaker refuses new flows from the PanicLimit-th panic on, flows admitted before it keep working, and closing
// everything drains the engine.
func TestChaosPanicStormOpensTheBreakerAtTheLimit(t *testing.T) {
	c := allFamilies()
	c.MaxFlows, c.PanicLimit = 256, 6
	e := mustEngine(t, c)
	survivor := mustFlow(t, e) // admitted before the storm; it must still work after the breaker opens
	var ops atomic.Int64
	e.testHook = func(op string, d Direction) {
		if op != "snapshot" && op != "close" && ops.Add(1)%7 == 0 {
			panic("injected engine fault")
		}
	}
	stop := watchStats(t, e, int64(c.MaxFlows))
	var wg sync.WaitGroup
	var quarantined, disabled atomic.Int64
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				f, err := e.NewFlow(fmt.Sprintf("p-%d-%d", g, i))
				if errors.Is(err, ErrDisabled) {
					disabled.Add(1)
					continue
				}
				if err != nil {
					t.Errorf("admission: %v", err)
					return
				}
				hit := false
				for _, piece := range [][]byte{httpRequest[:10], httpRequest[10:]} {
					if _, err := f.Feed(ClientToServer, piece); errors.Is(err, ErrQuarantined) {
						hit = true
					}
				}
				if _, err := f.EndDirection(ServerToClient, EndEOF); errors.Is(err, ErrQuarantined) {
					hit = true
				}
				s := f.Close()
				if s.Quarantined != hit && !s.Quarantined {
					t.Errorf("flow %d-%d: quarantine %v, reported %v", g, i, s.Quarantined, hit)
				}
				if s.Quarantined {
					quarantined.Add(1)
					for _, ds := range s.Directions {
						if ds.Outcome != OutcomeFailed || ds.Reason != ReasonPanic || !ds.Done || ds.Evidence != nil || ds.Detail != "" {
							t.Errorf("quarantined direction %+v", ds)
						}
					}
				}
			}
		}(g)
	}
	wg.Wait()
	stop()
	st := e.Stats()
	if st.Panics != quarantined.Load() || st.Panics < int64(c.PanicLimit) || !st.Disabled || disabled.Load() == 0 {
		t.Fatalf("panics %d, quarantined flows %d, disabled refusals %d, stats %+v", st.Panics, quarantined.Load(), disabled.Load(), st)
	}
	if _, err := e.NewFlow("late"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("admission after the breaker opened: %v", err)
	}
	e.testHook = nil
	if _, err := survivor.Feed(ClientToServer, httpRequest); err != nil {
		t.Fatalf("a flow admitted before the breaker opened: %v", err)
	}
	if ds := survivor.Close().Direction(ClientToServer); ds.Outcome != OutcomeIdentified || ds.Family != "http" {
		t.Fatalf("a flow admitted before the breaker opened: %+v", ds)
	}
	requireDrained(t, e)
}

// PanicLimit 0 disables the breaker: the same storm quarantines flows but never refuses admission.
func TestChaosPanicsWithoutABreakerOnlyQuarantine(t *testing.T) {
	c := allFamilies()
	c.PanicLimit = 0
	e := mustEngine(t, c)
	var ops atomic.Int64
	e.testHook = func(op string, d Direction) {
		if op == "feed" && ops.Add(1)%3 == 0 {
			panic("injected engine fault")
		}
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				f, err := e.NewFlow("no-breaker")
				if err != nil {
					t.Errorf("admission without a breaker: %v", err)
					return
				}
				_, _ = f.Feed(ClientToServer, httpRequest)
				f.Close()
			}
		}()
	}
	wg.Wait()
	if st := e.Stats(); st.Disabled || st.Panics != 80 || st.Admitted != 240 {
		t.Fatalf("stats %+v (want 80 panics of 240 feeds, never disabled)", st)
	}
	requireDrained(t, e)
}
