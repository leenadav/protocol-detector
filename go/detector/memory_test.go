package detector

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/parity"
)

// Integration work item #14: the memory budget. Two quantities are kept apart throughout: the reservation
// (one flow allowance per admitted flow, held from NewFlow to Close) and the retained figure (the buffer
// capacity the parsers hold right now, always inside the reservation between calls).

func TestMemoryLimitsAreValidatedNotClamped(t *testing.T) {
	base := allFamilies()
	defaults := mustEngine(t, base).Stats()
	if defaults.FlowAllowance != 32768 || defaults.EngineAllowance != 32768*1024 {
		t.Fatalf("defaults: flow %d, engine %d", defaults.FlowAllowance, defaults.EngineAllowance)
	}
	for name, change := range map[string]func(*Config){
		"negative per flow":             func(c *Config) { c.MaxRetainedPerFlow = -1 },
		"negative total":                func(c *Config) { c.MaxRetainedTotal = -1 },
		"per flow under the byte limit": func(c *Config) { c.MaxRetainedPerFlow = c.MaxBytesPerDirection - 1 },
		"per flow over the ceiling":     func(c *Config) { c.MaxRetainedPerFlow = MaxRetainedCeiling + 1 },
		"total under one allowance":     func(c *Config) { c.MaxRetainedTotal = 32767 },
		"total over the ceiling":        func(c *Config) { c.MaxRetainedTotal = MaxRetainedCeiling + 1 },
		"derived total over ceiling":    func(c *Config) { c.MaxFlows = 1 << 20 },
		"derived total, big per flow":   func(c *Config) { c.MaxRetainedPerFlow = MaxRetainedCeiling; c.MaxFlows = 2 },
	} {
		c := base
		change(&c)
		if _, err := New(c); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A large flow count is fine once the engine allowance is stated; memory then binds before the count.
	c := base
	c.MaxFlows, c.MaxRetainedTotal = 1<<20, MaxRetainedCeiling
	if st := mustEngine(t, c).Stats(); st.EngineAllowance != MaxRetainedCeiling {
		t.Errorf("explicit total: %+v", st)
	}
	c = base
	c.MaxBytesPerDirection = 4096
	if st := mustEngine(t, c).Stats(); st.FlowAllowance != 8192 {
		t.Errorf("derived flow allowance follows the byte limit: %+v", st)
	}
}

func TestReservationLifecycle(t *testing.T) {
	c := allFamilies()
	c.MaxFlows, c.MaxRetainedTotal = 8, 2*32768 // memory admits two flows, the count eight
	e := mustEngine(t, c)
	a, b := mustFlow(t, e), mustFlow(t, e)
	if st := e.Stats(); st.ReservedBytes != 2*32768 || st.Active != 2 {
		t.Fatalf("after two admissions: %+v", st)
	}
	if _, err := e.NewFlow("c"); !errors.Is(err, ErrMemory) || errors.Is(err, ErrAdmission) {
		t.Fatalf("third flow: %v", err)
	}
	if st := e.Stats(); st.ReservedBytes != 2*32768 || st.Active != 2 || st.Refused != 1 || st.RefusedMemory != 1 {
		t.Fatalf("a refusal leaked a slot or a reservation: %+v", st)
	}
	a.Close()
	a.Close() // idempotent: the reservation is returned once
	if st := e.Stats(); st.ReservedBytes != 32768 || st.Active != 1 {
		t.Fatalf("after close and repeat close: %+v", st)
	}
	d := mustFlow(t, e) // the returned allowance is usable again
	b.Close()
	d.Close()
	if st := e.Stats(); st.ReservedBytes != 0 || st.RetainedBytes != 0 || st.Active != 0 {
		t.Fatalf("after all closed: %+v", st)
	}
}

func TestQuarantinedFlowKeepsItsReservationUntilClose(t *testing.T) {
	e := mustEngine(t, allFamilies())
	f := mustFlow(t, e)
	f.Feed(ClientToServer, httpRequest[:10]) // buffers something first
	if e.Stats().RetainedBytes == 0 {
		t.Fatal("nothing retained before the panic")
	}
	e.testHook = func(op string, d Direction) { panic("injected") }
	if _, err := f.Feed(ClientToServer, httpRequest[10:]); !errors.Is(err, ErrQuarantined) {
		t.Fatalf("feed: %v", err)
	}
	e.testHook = nil
	if st := e.Stats(); st.RetainedBytes != 0 || st.ReservedBytes != int64(st.FlowAllowance) {
		t.Fatalf("quarantine: %+v", st)
	}
	f.Close()
	f.Close()
	if st := e.Stats(); st.ReservedBytes != 0 || st.Active != 0 {
		t.Fatalf("close after quarantine: %+v", st)
	}
}

func TestRetainedFollowsTheParsers(t *testing.T) {
	e := mustEngine(t, allFamilies())
	hello, _ := tlsFlights(t, "mem.example.test", []string{"h2"}, nil)
	f := mustFlow(t, e)
	f.Feed(ClientToServer, hello[:len(hello)/2])
	mid := f.Snapshot().RetainedBytes
	if mid < len(hello)/2-5 || int64(mid) != e.Stats().RetainedBytes {
		t.Fatalf("half a hello retains %d bytes (engine %d)", mid, e.Stats().RetainedBytes)
	}
	f.Feed(ClientToServer, hello[len(hello)/2:])
	if s := f.Snapshot(); s.Direction(ClientToServer).Outcome != OutcomeIdentified || s.RetainedBytes != 0 || e.Stats().RetainedBytes != 0 {
		t.Fatalf("a decided direction still retains: %+v engine %+v", s.RetainedBytes, e.Stats())
	}
	// Early terminal paths release too: expiry and end of direction.
	for name, finish := range map[string]func(*Flow){
		"expire": func(f *Flow) { f.Expire() },
		"end":    func(f *Flow) { f.EndDirection(ClientToServer, EndEOF) },
		"close":  func(f *Flow) { f.Close() },
	} {
		g := mustFlow(t, e)
		g.Feed(ClientToServer, hello[:100])
		if e.Stats().RetainedBytes == 0 {
			t.Fatalf("%s: nothing retained", name)
		}
		finish(g)
		if e.Stats().RetainedBytes != 0 || g.Snapshot().RetainedBytes != 0 {
			t.Fatalf("%s: retained %d after the direction ended", name, e.Stats().RetainedBytes)
		}
		g.Close()
	}
	f.Close()
	if st := e.Stats(); st.ReservedBytes != 0 || st.Active != 0 {
		t.Fatalf("end state: %+v", st)
	}
}

// A flow that would hold more than its allowance loses the direction that grew, explicitly; the other
// direction and other flows are untouched.
func TestFlowAllowanceIsEnforced(t *testing.T) {
	c := allFamilies()
	c.MaxBytesPerDirection, c.MaxFeedsPerDirection, c.MaxRetainedPerFlow = 8192, 4096, 8192
	e := mustEngine(t, c)
	other := mustFlow(t, e)
	other.Feed(ClientToServer, httpRequest[:20])
	f := mustFlow(t, e)
	// An unfinished request line the parser must keep: 3,005 bytes in a 3,072-byte accumulator. Finishing it
	// later also copies the 3,001-byte target, 6,144 bytes in all, inside the 8,192-byte allowance. (A 6,000-byte
	// target would need 12,288 bytes while the request completes; that is refused now, see
	// TestGrowthIsChargedBeforeItIsAllocated.)
	line := []byte("GET /" + strings.Repeat("a", 3000))
	f.Feed(ClientToServer, line)
	if s := f.Snapshot(); s.Direction(ClientToServer).Done || s.RetainedBytes == 0 || s.RetainedBytes > 8192 {
		t.Fatalf("first direction: retained %d, %+v", s.RetainedBytes, s.Direction(ClientToServer).Outcome)
	}
	u, err := f.Feed(ServerToClient, []byte("HTTP/1.1 200 "+strings.Repeat("b", 6000)))
	if err != nil || !u.Done || u.Outcome != OutcomeBudgetExhausted {
		t.Fatalf("second direction: %+v %v", u, err)
	}
	s := f.Snapshot()
	if got := s.Direction(ServerToClient); got.Reason != ReasonMemory || !strings.Contains(got.Detail, "allowance") {
		t.Fatalf("second direction snapshot: %+v", got)
	}
	if s.Direction(ClientToServer).Done || s.RetainedBytes > 8192 || s.RetainedBytes == 0 {
		t.Fatalf("the first direction was disturbed or the flow is still over: retained %d, %+v", s.RetainedBytes, s.Direction(ClientToServer))
	}
	if other.Snapshot().Direction(ClientToServer).Done {
		t.Fatal("another flow was affected")
	}
	// The surviving direction still completes.
	f.Feed(ClientToServer, []byte(" HTTP/1.1\r\nHost: a.example\r\n\r\n"))
	if got := f.Snapshot().Direction(ClientToServer); got.Outcome != OutcomeIdentified {
		t.Fatalf("surviving direction: %+v", got)
	}
	f.Close()
	other.Close()
	if st := e.Stats(); st.RetainedBytes != 0 || st.ReservedBytes != 0 {
		t.Fatalf("end state: %+v", st)
	}
}

func TestConcurrentAdmissionFeedAndCloseBalance(t *testing.T) {
	c := allFamilies()
	c.MaxFlows, c.MaxRetainedTotal = 64, 16*32768 // memory is the tighter limit: refusals are expected
	e := mustEngine(t, c)
	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				f, err := e.NewFlow("c")
				if err != nil {
					if !errors.Is(err, ErrMemory) && !errors.Is(err, ErrAdmission) {
						t.Errorf("admission: %v", err)
					}
					continue
				}
				var inner sync.WaitGroup
				inner.Add(2)
				go func() { defer inner.Done(); f.Feed(ClientToServer, httpRequest[:len(httpRequest)-i%7-1]) }()
				go func() { defer inner.Done(); f.Feed(ServerToClient, httpResponse[:10+i%20]) }()
				if i%3 == 0 {
					f.Expire()
				}
				inner.Wait()
				if st := e.Stats(); st.RetainedBytes > st.ReservedBytes || st.ReservedBytes > st.EngineAllowance {
					t.Errorf("retained %d over reserved %d (allowance %d)", st.RetainedBytes, st.ReservedBytes, st.EngineAllowance)
				}
				f.Close()
				f.Close()
			}
		}(w)
	}
	wg.Wait()
	if st := e.Stats(); st.Active != 0 || st.ReservedBytes != 0 || st.RetainedBytes != 0 || st.Admitted+st.Refused != 16*200 {
		t.Fatalf("end state: %+v", st)
	}
}

// With the default budgets no profile fixture is cut short by the memory allowance, whole or byte by byte,
// and the largest retained figure is reported so a change that needs more memory is visible.
func TestFixturesFitTheDefaultFlowAllowance(t *testing.T) {
	doc, err := parity.Load(context.Background(), "../../migration/fixtures/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	c := DefaultConfig()
	c.Families = ProfileFamilies()
	c.MaxFeedsPerDirection = 1 << 16 // so that byte-by-byte delivery is not cut by the feed budget
	e := mustEngine(t, c)
	peak, peakID, streams := 0, "", 0
	for i := range doc.Cases {
		cs := &doc.Cases[i]
		if cs.Kind != "stream" || cs.Hint != nil {
			continue
		}
		data, err := hex.DecodeString(strings.Join(cs.Chunks, ""))
		if err != nil {
			t.Fatal(err)
		}
		streams++
		for _, step := range []int{len(data), 1} {
			f := mustFlow(t, e)
			for pos := 0; pos < len(data) && step > 0; pos += step {
				f.Feed(ClientToServer, data[pos:minInt(pos+step, len(data))])
				f.Feed(ServerToClient, data[pos:minInt(pos+step, len(data))]) // both directions hold state at once
				if r := f.Snapshot().RetainedBytes; r > peak {
					peak, peakID = r, cs.ID
				}
			}
			s := f.Close()
			for _, d := range AllDirections() {
				if s.Direction(d).Reason == ReasonMemory {
					t.Errorf("%s (step %d, %s): cut by the memory allowance", cs.ID, step, d)
				}
			}
		}
	}
	t.Logf("%d streams, both directions at once: peak retained %d bytes of a %d-byte allowance (%s)", streams, peak, e.Stats().FlowAllowance, peakID)
	if streams < 1000 || peak == 0 {
		t.Fatalf("the fixtures were not exercised: %d streams, peak %d", streams, peak)
	}
	if st := e.Stats(); st.ReservedBytes != 0 || st.RetainedBytes != 0 {
		t.Fatalf("end state: %+v", st)
	}
}
