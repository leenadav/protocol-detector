package engine

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
)

// PRO-189 (Codex PRO-12, P2): after dispatch fails, the unknown-payload buffer collects up to heuristic_bytes for
// the heuristics. When max_bytes is smaller than that buffer, the byte budget ran out first and the buffer never
// filled, so the stream stayed "detecting" for every later byte and only End gave the verdict. Exhausting the
// byte budget must finalize, with the verdict End would give for the same bytes.
func TestUnknownBufferFinalizesWhenTheByteBudgetIsExhausted(t *testing.T) {
	cfg := contracts.DefaultConfig()
	cfg.MaxBytes, cfg.Heuristics, cfg.HeuristicBytes = 64, true, 512
	payload := bytes.Repeat([]byte{0xde, 0xad, 0x00, 0x7f}, 40) // 160 bytes no family profile claims
	for _, c := range []struct {
		name   string
		chunks [][]byte
	}{
		{"one segment past the budget", [][]byte{payload}},
		{"the budget runs out in the buffering phase", [][]byte{payload[:30], payload[30:60], payload[60:90], payload[90:]}},
		{"the budget ends exactly at a segment", [][]byte{payload[:64], payload[64:]}},
	} {
		t.Run(c.name, func(t *testing.T) {
			in, err := New(cfg, "")
			if err != nil {
				t.Fatal(err)
			}
			for _, chunk := range c.chunks {
				in.Feed(chunk)
			}
			if !in.terminal || in.Observation.Status != contracts.Unknown {
				t.Fatalf("after %d bytes (max_bytes %d): status %q, terminal %v; want a terminal unknown verdict",
					in.Metrics.BytesInspected, cfg.MaxBytes, in.Observation.Status, in.terminal)
			}
			if in.Metrics.BytesInspected != cfg.MaxBytes {
				t.Fatalf("inspected %d bytes, want the whole budget %d", in.Metrics.BytesInspected, cfg.MaxBytes)
			}
			// The verdict End gives when a stream closes after the same 64 bytes, under a budget that never ran out.
			large := cfg
			large.MaxBytes = 1024
			want, err := New(large, "")
			if err != nil {
				t.Fatal(err)
			}
			want.Feed(payload[:cfg.MaxBytes])
			if want.terminal {
				t.Fatal("the reference stream finalized before End")
			}
			want.End("closed")
			if in.Observation.Reason != want.Observation.Reason || !reflect.DeepEqual(in.Observation.Evidence, want.Observation.Evidence) {
				t.Fatalf("budget verdict %q %v differs from the close verdict %q %v",
					in.Observation.Reason, in.Observation.Evidence, want.Observation.Reason, want.Observation.Evidence)
			}
			if len(want.Observation.Evidence) == 0 {
				t.Fatal("the heuristics produced no evidence; the comparison proves nothing")
			}
			// No later byte changes it.
			if events := in.Feed(payload); len(events) != 0 {
				t.Fatalf("a terminal stream emitted %d events", len(events))
			}
		})
	}
}
