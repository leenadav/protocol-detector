package engine

import (
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
)

// SEC-INSP-1: every HTTP CONNECT in a shifted phase opened another nested phase, so a stream of N CONNECT
// requests built a chain N deep, each segment walked the chain and every level rebuilt the evidence of the
// levels below it: O(n^2) evidence and O(n^3) work per direction. Parser-driven shift nesting is capped at
// maxShiftDepth, and the published evidence stays bounded however many CONNECTs follow.
func TestRepeatedConnectDoesNotNestWithoutBound(t *testing.T) {
	cfg := contracts.DefaultConfig()
	in, err := New(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	request := "CONNECT a.example.test:443 HTTP/1.1\r\nHost: a.example.test:443\r\n\r\n"
	requests := cfg.MaxBytes / len(request) // as many as the byte budget admits
	events := 0
	for i := 0; i < requests; i++ {
		events += len(in.Feed([]byte(request)))
	}
	depth := 0
	for p := in; p.next != nil; p = p.next {
		depth++
	}
	if depth > maxShiftDepth {
		t.Fatalf("%d CONNECT requests opened %d nested shift phases (limit %d)", requests, depth, maxShiftDepth)
	}
	if n := len(in.Observation.Evidence); n > 16 {
		t.Fatalf("the published observation carries %d evidence items after %d CONNECT requests", n, requests)
	}
	shifts := 0
	for _, e := range in.Observation.Evidence {
		if e.Field == "shift" {
			shifts++
		}
	}
	// Two tunnels are followed, as a CONNECT carrying TLS or an Upgrade inside the tunnel needs; the third
	// CONNECT identifies its phase, names the limit, and nothing below it is inspected.
	if shifts != 2 { // the documented limit, written out so a changed constant fails here
		t.Fatalf("%d shift markers, want %d: %v", shifts, maxShiftDepth, in.Observation.Evidence)
	}
	if !strings.Contains(in.Observation.Reason, "http-connect boundary was not followed (shift nesting limit)") {
		t.Fatalf("reason %q", in.Observation.Reason)
	}
	if !in.terminal {
		t.Fatal("the capped stream should be terminal: later bytes are not inspected")
	}
	t.Logf("%d requests, %d events, depth %d, %d evidence items", requests, events, depth, len(in.Observation.Evidence))
}
