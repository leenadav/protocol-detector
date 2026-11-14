// Package bench times the Go engine on the shared benchmark workloads (migration/benchmarks/workloads.json,
// written by migration/benchmarks/bench_compare.py from the same bytes benchmark_engine.py uses). It
// reports per-flow latency distributions and allocation counts for the feed loop only: no capture, no
// reassembly, no output. Correctness is asserted on every flow outside the timed region's purpose
// (an unexpected outcome aborts the run) so a fast wrong engine never produces a number.
package bench

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"time"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/engine"
)

// Workload is one benchmark case.
type Workload struct {
	Name     string   `json:"name"`
	Chunks   []string `json:"chunks"` // hex
	Expected string   `json:"expected"`
}

// Distribution mirrors benchmark_engine.distribution (microseconds).
type Distribution struct {
	P50 float64 `json:"p50_us"`
	P95 float64 `json:"p95_us"`
	P99 float64 `json:"p99_us"`
}

// Result is one workload's measurement.
type Result struct {
	Flow          Distribution      `json:"flow"`
	RoundP50      []float64         `json:"round_p50_us"`
	AllocsPerFlow float64           `json:"allocs_per_flow"`
	BytesPerFlow  float64           `json:"alloc_bytes_per_flow"`
	Metrics       contracts.Metrics `json:"metrics"`
	InputBytes    int               `json:"input_bytes"`
	Chunks        int               `json:"chunks"`
}

func distribution(samples []int64) Distribution {
	sorted := append([]int64{}, samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	pick := func(q float64) float64 { return float64(sorted[int(float64(len(sorted)-1)*q)]) / 1000 }
	median := float64(sorted[len(sorted)/2])
	if len(sorted)%2 == 0 {
		median = float64(sorted[len(sorted)/2-1]+sorted[len(sorted)/2]) / 2
	}
	return Distribution{P50: round3(median / 1000), P95: round3(pick(.95)), P99: round3(pick(.99))}
}

func round3(v float64) float64 { return float64(int64(v*1000+0.5)) / 1000 }

func flow(w *Workload, chunks [][]byte) (int64, contracts.Metrics, error) {
	cfg := contracts.DefaultConfig()
	in, err := engine.New(cfg, "")
	if err != nil {
		return 0, contracts.Metrics{}, err
	}
	start := time.Now()
	for _, c := range chunks {
		in.Feed(c)
	}
	elapsed := time.Since(start).Nanoseconds()
	if in.NotPorted != nil {
		return 0, in.Metrics, fmt.Errorf("%s: %v", w.Name, in.NotPorted)
	}
	got := ""
	if in.Observation.ApplicationProtocol != nil {
		got = *in.Observation.ApplicationProtocol
	} else if in.Observation.Encryption != nil {
		got = *in.Observation.Encryption
	}
	if in.Observation.Status != contracts.Identified || got != w.Expected {
		return 0, in.Metrics, fmt.Errorf("%s: correctness assertion failed: %s %q", w.Name, in.Observation.Status, in.Observation.Reason)
	}
	return elapsed, in.Metrics, nil
}

// Run measures every workload: warmup flows, then rounds × iterations timed flows.
func Run(workloads []Workload, iterations, rounds, warmup int) (map[string]Result, error) {
	out := map[string]Result{}
	for i := range workloads {
		w := &workloads[i]
		chunks := make([][]byte, len(w.Chunks))
		total := 0
		for j, h := range w.Chunks {
			b, err := hex.DecodeString(h)
			if err != nil {
				return nil, err
			}
			chunks[j] = b
			total += len(b)
		}
		for n := 0; n < warmup; n++ {
			if _, _, err := flow(w, chunks); err != nil {
				return nil, err
			}
		}
		var samples []int64
		var roundP50 []float64
		var metrics contracts.Metrics
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		for r := 0; r < rounds; r++ {
			var roundSamples []int64
			for n := 0; n < iterations; n++ {
				elapsed, m, err := flow(w, chunks)
				if err != nil {
					return nil, err
				}
				metrics = m
				roundSamples = append(roundSamples, elapsed)
			}
			samples = append(samples, roundSamples...)
			roundP50 = append(roundP50, distribution(roundSamples).P50)
		}
		runtime.ReadMemStats(&after)
		flows := float64(rounds * iterations)
		out[w.Name] = Result{Flow: distribution(samples), RoundP50: roundP50,
			AllocsPerFlow: round3(float64(after.Mallocs-before.Mallocs) / flows),
			BytesPerFlow:  round3(float64(after.TotalAlloc-before.TotalAlloc) / flows),
			Metrics:       metrics, InputBytes: total, Chunks: len(chunks)}
	}
	return out, nil
}

// Load reads the workloads file.
func Load(path string) ([]Workload, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Workloads []Workload `json:"workloads"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return doc.Workloads, nil
}
