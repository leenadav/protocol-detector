package detector

import (
	"math"
	"runtime"
	"testing"
)

// Round 2 of the review of work item #14, finding P3. The HTTP parser normalized the Host authority by
// slicing a string copy of the whole value: for "a.:65535" the retained host "a" kept the 8-byte copy alive
// while the accounting charged one byte. The host is now an owned compact copy.
//
// The reported figure is the same before and after the fix (it always charged the normalized length), so the
// check is on the heap: flows whose Host is "a.:65535" must keep the same live heap as flows whose Host is
// already "a". Before the fix they kept about 7 bytes more each.
func TestNormalizedHostKeepsNoLargerBacking(t *testing.T) {
	c := DefaultConfig()
	c.MaxBytesPerDirection, c.MaxRetainedPerFlow, c.MaxFlows = 64, 73, 1<<16 // the reviewer's tight case
	e := mustEngine(t, c)
	const n = 20000
	build := func(host string) func(int) *Flow {
		request := []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n") // headers unfinished: the parser holds the host
		return func(int) *Flow {
			f := mustFlow(t, e)
			f.Feed(ClientToServer, request)
			return f
		}
	}
	plain, plainFlows := heapPerFlow(n, build("a"))
	authority, authorityFlows := heapPerFlow(n, build("a.:65535"))
	for name, flows := range map[string][]*Flow{"a": plainFlows, "a.:65535": authorityFlows} {
		s := flows[0].Snapshot()
		if got := s.Direction(ClientToServer); got.Done || got.Outcome != OutcomeDetecting {
			t.Fatalf("Host %s: %+v", name, got)
		}
		if s.RetainedBytes != 25 { // the 16-byte line accumulator, the 8-byte target copy and the one-byte host
			t.Fatalf("Host %s: reported retained %d, want 25", name, s.RetainedBytes)
		}
	}
	if diff := authority - plain; math.Abs(diff) > 3 {
		t.Errorf("a flow with Host a.:65535 keeps %.1f bytes more heap than one with Host a (%.1f against %.1f)", diff, authority, plain)
	}
	// The normalized host is what the flow reports, and the flow stays inside the tight allowance.
	f := authorityFlows[0]
	u, err := f.Feed(ClientToServer, []byte("\r\n"))
	if err != nil || u.Outcome != OutcomeIdentified {
		t.Fatalf("finishing the headers: %+v %v", u, err)
	}
	if s := f.Snapshot(); s.Direction(ClientToServer).Hostname != "a" || s.RetainedBytes != 0 {
		t.Fatalf("hostname %q, retained %d", s.Direction(ClientToServer).Hostname, s.RetainedBytes)
	}
	for _, flows := range [][]*Flow{plainFlows, authorityFlows} {
		for _, f := range flows {
			f.Close()
		}
	}
	if st := e.Stats(); st.RetainedBytes != 0 || st.ReservedBytes != 0 || st.Active != 0 {
		t.Fatalf("after close: %+v", st)
	}
	runtime.KeepAlive(plainFlows)
	runtime.KeepAlive(authorityFlows)
}
