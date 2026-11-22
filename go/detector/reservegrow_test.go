package detector

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/parity"
)

// Review of work item #14 at 6842e0f (Codex, issue #2 comment 6899752738): the allowance was checked after a
// call, so one call could grow a buffer past it, and a direction that finished in that same call dropped its
// buffers before anything was measured. The reviewer's case: the server line was refused when it arrived in
// two reads and accepted when it arrived in one. Every covered buffer is now charged before it grows, so the
// response is refused either way and the flow never holds more than its allowance.
func TestGrowthIsChargedBeforeItIsAllocated(t *testing.T) {
	for _, split := range []bool{false, true} {
		c := allFamilies()
		c.MaxBytesPerDirection, c.MaxFeedsPerDirection, c.MaxRetainedPerFlow = 8192, 4096, 8192
		e := mustEngine(t, c)
		f := mustFlow(t, e)
		_, _ = f.Feed(ClientToServer, []byte("GET /"+strings.Repeat("a", 6000))) // the client keeps a 6,144-byte line
		response := []byte("HTTP/1.1 200 " + strings.Repeat("b", 6000) + "\r\nContent-Length: 0\r\n\r\n")
		if split {
			_, _ = f.Feed(ServerToClient, response[:6000])
			_, _ = f.Feed(ServerToClient, response[6000:])
		} else {
			_, _ = f.Feed(ServerToClient, response)
		}
		s := f.Snapshot()
		if got := s.Direction(ServerToClient); got.Outcome != OutcomeBudgetExhausted || got.Reason != ReasonMemory {
			t.Errorf("split %v: server direction %s/%s, want budget_exhausted/memory_budget", split, got.Outcome, got.Reason)
		}
		if got := s.Direction(ClientToServer); got.Done || got.Outcome != OutcomeDetecting {
			t.Errorf("split %v: the client direction was disturbed: %+v", split, got)
		}
		if f.credit.Peak() > f.reserved || s.RetainedBytes > f.reserved {
			t.Errorf("split %v: charged at most %d, retained %d, against an allowance of %d", split, f.credit.Peak(), s.RetainedBytes, f.reserved)
		}
		f.Close()
		if st := e.Stats(); st.RetainedBytes != 0 || st.ReservedBytes != 0 {
			t.Fatalf("split %v: end state %+v", split, st)
		}
	}
}

// Over every unhinted fixture stream, fed to both directions at once, whole, byte by byte and in 7-byte
// reads, under allowances from tight to the default: the most the flow's buffers were ever charged never
// exceeds the allowance, at any point inside or between calls, and a refusal is always the explicit memory
// outcome.
func TestTheAllowanceIsNeverExceededInsideACall(t *testing.T) {
	doc, err := parity.Load(context.Background(), "../../migration/fixtures/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	refused := 0
	// (bytes per direction, allowance): the allowance may not be below the per-direction byte budget.
	for _, budget := range [][2]int{{256, 256}, {1024, 1024}, {4096, 8192}, {0, 0}} {
		c := allFamilies()
		if budget[0] > 0 {
			c.MaxBytesPerDirection = budget[0]
		}
		allowance := budget[1]
		c.MaxFeedsPerDirection, c.MaxRetainedPerFlow = 1<<16, allowance
		e := mustEngine(t, c)
		for i := range doc.Cases {
			cs := &doc.Cases[i]
			if cs.Kind != "stream" || cs.Hint != nil {
				continue
			}
			data, err := hex.DecodeString(strings.Join(cs.Chunks, ""))
			if err != nil {
				t.Fatal(err)
			}
			for _, step := range []int{len(data), 1, 7} {
				f := mustFlow(t, e)
				for pos := 0; pos < len(data) && step > 0; pos += step {
					piece := data[pos:minInt(pos+step, len(data))]
					_, _ = f.Feed(ClientToServer, piece)
					_, _ = f.Feed(ServerToClient, piece)
					if f.credit.Peak() > f.reserved {
						t.Fatalf("%s (allowance %d, step %d): charged %d of %d", cs.ID, allowance, step, f.credit.Peak(), f.reserved)
					}
				}
				s := f.Close()
				for _, d := range AllDirections() {
					if ds := s.Direction(d); ds.Reason == ReasonMemory {
						refused++
						if ds.Outcome != OutcomeBudgetExhausted || ds.Detail != memoryDetail {
							t.Fatalf("%s: memory refusal reported as %+v", cs.ID, ds)
						}
					}
				}
			}
		}
		if st := e.Stats(); st.RetainedBytes != 0 || st.ReservedBytes != 0 || st.Active != 0 {
			t.Fatalf("allowance %d: end state %+v", allowance, st)
		}
	}
	if refused == 0 {
		t.Fatal("no allowance refused anything: the tight cases exercised nothing")
	}
}
