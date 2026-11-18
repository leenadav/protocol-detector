//go:build benchgate

package bench

// Performance gates for the engine on a proxy's hot path, in Culvert's benchgate convention
// (go test -tags benchgate -run 'TestBenchGate_'): outside the default suite, keyed on quantities that are
// deterministic and hardware independent (allocations per flow, retained bytes per finished flow), never on
// ns/op. Bounds come from the Culvert integration plan's starting budgets (docs/integration/
// PROTODETECT-CULVERT-WORKING-PLAN.md §9, branch claude/culvert-integration-prep): "engine CPU and
// allocations per flow: p99 ≤ 50 µs, ≤ 64 allocations"; "retained after observation ≤ 4 KiB per relay".
// CPU time is measured and reported by `protodetect bench` (migration/STATUS.md), not gated here, because a
// timing bound on a shared runner gates the machine, not the change.

import (
	"encoding/hex"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/engine"
)

const (
	maxAllocsPerFlow    = 64   // plan §9: the integration budget
	maxRetainedPerFlow  = 4096 // bytes, plan §9
	retainedSampleFlows = 2000
)

// regressionCeiling is, per workload, a bound a little above the count measured on go1.27.4 when the gate was
// written (2026-11-16): measured + 4, the headroom Culvert's benchgates leave for standard-library churn (their
// proxy_emptybody gate: 69 measured, bound 73). The plan's budget says what is acceptable; this says the
// count did not grow. A deliberate change that adds allocations raises the ceiling in the same commit.
var regressionCeiling = map[string]int64{
	"http_small":                30, // measured 26
	"http_fragmented":           42, // 38
	"tls_whole":                 37, // 33
	"tls_fragmented":            41, // 37
	"http_after_identification": 30, // 26
	"ssh_banner_kexinit":        38, // 34 (90 before the KEXINIT scan rewrite)
	"unknown_16x1KiB":           14, // 10
}

// loadWorkloads are the shared benchmark workloads plus two the shared file lacks: an SSH flow (the plan's
// item #18 names TLS, HTTP and SSH) and the adversarial case, a flow that never identifies and is fed its
// observation budget in the plan's 16 feed calls of 1 KiB (§9: 16 KiB, 16 feeds per direction).
func loadWorkloads(t *testing.T) []Workload {
	t.Helper()
	workloads, err := Load("../../../migration/benchmarks/workloads.json")
	if err != nil {
		t.Fatal(err)
	}
	ssh := sshKexinit()
	workloads = append(workloads, Workload{Name: "ssh_banner_kexinit", Chunks: []string{hex.EncodeToString(ssh[:21]), hex.EncodeToString(ssh[21:])},
		Expected: "ssh"})
	noise := Workload{Name: "unknown_16x1KiB"}
	for i := 0; i < 16; i++ {
		chunk := make([]byte, 1024)
		for j := range chunk {
			chunk[j] = byte(0x80 + (i*31+j*7)%127) // high bytes: no text route, no framed prefix
		}
		noise.Chunks = append(noise.Chunks, hex.EncodeToString(chunk))
	}
	return append(workloads, noise)
}

func decode(t *testing.T, w *Workload) [][]byte {
	t.Helper()
	chunks := make([][]byte, len(w.Chunks))
	for i, h := range w.Chunks {
		b, err := hex.DecodeString(h)
		if err != nil {
			t.Fatal(err)
		}
		chunks[i] = b
	}
	return chunks
}

// oneFlow is a whole flow as a proxy would run it: construct, feed every chunk, end.
func oneFlow(chunks [][]byte) *engine.Inspector {
	in, _ := engine.New(contracts.DefaultConfig(), "")
	for _, c := range chunks {
		in.Feed(c)
	}
	in.End("relay finished")
	return in
}

func TestBenchGate_AllocationsPerFlow(t *testing.T) {
	for _, w := range loadWorkloads(t) {
		w := w
		chunks := decode(t, &w)
		if w.Expected != "" {
			if _, _, err := flow(&w, chunks); err != nil { // the workload still classifies as expected
				t.Fatal(err)
			}
		} else if in := oneFlow(chunks); in.Observation.Status == contracts.Identified {
			t.Fatalf("%s: the adversarial flow was identified (%s)", w.Name, in.Observation.Reason)
		}
		result := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				oneFlow(chunks)
			}
		})
		allocs := result.AllocsPerOp()
		ceiling, known := regressionCeiling[w.Name]
		t.Logf("%-28s %3d allocs/flow %6d B/flow (ceiling %d, budget %d)", w.Name, allocs, result.AllocedBytesPerOp(), ceiling, maxAllocsPerFlow)
		switch {
		case !known:
			t.Errorf("%s: no regression ceiling recorded for this workload", w.Name)
		case allocs > maxAllocsPerFlow:
			t.Errorf("%s: %d allocations per flow, budget %d", w.Name, allocs, maxAllocsPerFlow)
		case allocs > ceiling:
			t.Errorf("%s: %d allocations per flow, above its regression ceiling %d", w.Name, allocs, ceiling)
		}
	}
}

func TestBenchGate_RetainedBytesPerFinishedFlow(t *testing.T) {
	for _, w := range loadWorkloads(t) {
		chunks := decode(t, &w)
		keep := make([]*engine.Inspector, retainedSampleFlows)
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		for i := range keep {
			keep[i] = oneFlow(chunks)
		}
		runtime.GC()
		runtime.ReadMemStats(&after)
		var delta uint64
		if after.HeapAlloc > before.HeapAlloc {
			delta = after.HeapAlloc - before.HeapAlloc
		}
		perFlow := delta / retainedSampleFlows
		runtime.KeepAlive(keep)
		t.Logf("%-28s %5d bytes retained per finished flow (bound %d)", w.Name, perFlow, maxRetainedPerFlow)
		if perFlow > maxRetainedPerFlow {
			t.Errorf("%s: %d bytes retained per finished flow, budget %d", w.Name, perFlow, maxRetainedPerFlow)
		}
	}
}

// TestBenchGate_ReportLatencyPerFlow measures wall time per whole flow (construct, feed, end) and reports
// p50/p99 against the plan's p99 ≤ 50 µs. It reports, it does not fail: per Culvert's practice a timing bound
// is judged by interleaved comparisons (benchstat) on a pinned machine, not by one shared runner's clock.
func TestBenchGate_ReportLatencyPerFlow(t *testing.T) {
	const flows = 20000
	for _, w := range loadWorkloads(t) {
		chunks := decode(t, &w)
		for i := 0; i < 500; i++ {
			oneFlow(chunks)
		}
		samples := make([]int64, flows)
		for i := range samples {
			start := time.Now()
			oneFlow(chunks)
			samples[i] = time.Since(start).Nanoseconds()
		}
		sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
		p50, p99 := float64(samples[flows/2])/1000, float64(samples[flows*99/100])/1000
		verdict := "within"
		if p99 > 50 {
			verdict = "OVER"
		}
		t.Logf("%-28s p50 %7.2f µs  p99 %7.2f µs  (%s the 50 µs hypothesis)", w.Name, p50, p99, verdict)
	}
}
