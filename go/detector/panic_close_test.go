package detector

import (
	"errors"
	"testing"
)

// Working plan item #10 covers Snapshot and Close as well as Feed, EndDirection and Expire, and asks what
// happens when cleanup itself fails. A panic in either is contained: the caller gets the quarantined flow's
// snapshot, never the panic, and Close still returns the flow's reservation and admission slot, exactly once.
func TestPanicInSnapshotOrCloseIsContained(t *testing.T) {
	for _, op := range []string{"snapshot", "close"} {
		c := allFamilies()
		c.MaxFlows, c.PanicLimit = 1, 0 // one slot: a leaked slot would refuse the next flow
		e := mustEngine(t, c)
		f := mustFlow(t, e)
		f.Feed(ClientToServer, httpRequest[:20]) // an unfinished request: the parser holds buffers
		if f.Snapshot().RetainedBytes == 0 {
			t.Fatalf("%s: the flow retains nothing, the release would go unchecked", op)
		}
		e.testHook = func(o string, d Direction) {
			if o == op {
				panic("injected " + string(httpRequest)) // a panic value that quotes input
			}
		}
		var s Snapshot
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s: the panic reached the caller", op)
				}
			}()
			if op == "snapshot" {
				s = f.Snapshot()
			} else {
				s = f.Close()
			}
		}()
		e.testHook = nil
		if !s.Quarantined || s.RetainedBytes != 0 {
			t.Fatalf("%s: snapshot %+v", op, s)
		}
		for _, d := range AllDirections() {
			if ds := s.Direction(d); ds.Outcome != OutcomeFailed || ds.Reason != ReasonPanic || !ds.Done || ds.Detail != "" || len(ds.Evidence) != 0 {
				t.Fatalf("%s: %s %+v", op, d, ds)
			}
		}
		if _, err := f.Feed(ClientToServer, httpRequest); !errors.Is(err, ErrQuarantined) {
			t.Fatalf("%s: a quarantined flow was fed: %v", op, err)
		}
		f.Close()
		f.Close() // idempotent: nothing is returned twice
		st := e.Stats()
		if st.Active != 0 || st.ReservedBytes != 0 || st.RetainedBytes != 0 || st.Panics != 1 {
			t.Fatalf("%s: after close %+v", op, st)
		}
		g, err := e.NewFlow("next") // the slot and the reservation are back
		if err != nil {
			t.Fatalf("%s: the next flow was refused: %v", op, err)
		}
		g.Close()
	}
}
