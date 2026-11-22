// Package telemetry is protocol_adapters/observability.py: integer counters and fixed-bucket histograms for the
// boundaries between components, rendered to a JSON-friendly value. Nothing here records payload, names or
// keys: values are counts, byte totals and durations. Series keep their first-use order, as the reference's do.
package telemetry

import (
	"math"
	"time"

	"github.com/leenadav/protocol-detector/go/internal/pyjson"
)

// Buckets are the default upper bounds; MaxSeries bounds counters and histograms each.
var Buckets = []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 60.0}

const MaxSeries = 64

// Histogram keeps bucket counts, count, sum, minimum and maximum; no samples.
type Histogram struct {
	counts   []int // one per bucket, then +inf
	count    int
	total    float64
	min, max float64
}

func (h *Histogram) observe(value float64) {
	index := len(Buckets)
	for i, bound := range Buckets {
		if value <= bound {
			index = i
			break
		}
	}
	h.counts[index]++
	if h.count == 0 || value < h.min {
		h.min = value
	}
	if h.count == 0 || value > h.max {
		h.max = value
	}
	h.count++
	h.total += value
}

// quantile is the upper bound of the bucket holding the q-quantile (nil when empty or in the +inf bucket).
func (h *Histogram) quantile(q float64) interface{} {
	if h.count == 0 {
		return nil
	}
	target := int(math.RoundToEven(q * float64(h.count)))
	if target < 1 {
		target = 1
	}
	seen := 0
	for i, bound := range Buckets {
		seen += h.counts[i]
		if seen >= target {
			return bound
		}
	}
	return nil
}

func (h *Histogram) render() map[string]interface{} {
	buckets := make([]interface{}, 0, len(h.counts))
	for i, bound := range Buckets {
		buckets = append(buckets, []interface{}{bound, h.counts[i]})
	}
	buckets = append(buckets, []interface{}{"+inf", h.counts[len(Buckets)]})
	var minimum, maximum interface{}
	if h.count > 0 {
		minimum, maximum = h.min, h.max
	}
	return map[string]interface{}{"count": h.count, "sum": pyjson.Round(h.total, 6), "min": minimum, "max": maximum,
		"p50": h.quantile(0.5), "p95": h.quantile(0.95), "p99": h.quantile(0.99), "buckets": buckets}
}

// HistogramKeys is the key order of a rendered histogram.
var HistogramKeys = []string{"count", "sum", "min", "max", "p50", "p95", "p99", "buckets"}

// Telemetry is one registry per capture path.
type Telemetry struct {
	counters       map[string]int
	counterOrder   []string
	histograms     map[string]*Histogram
	histogramOrder []string
	// Clock times work stages (seconds); nil uses the process's monotonic clock.
	Clock func() float64
	began time.Time
}

func New() *Telemetry {
	return &Telemetry{counters: map[string]int{}, histograms: map[string]*Histogram{}, began: time.Now()}
}

func (t *Telemetry) series(name string) bool {
	if _, seen := t.counters[name]; seen {
		return true
	}
	if len(t.counters) >= MaxSeries {
		return false // the reference raises; every name here is fixed, so the bound cannot be reached
	}
	t.counterOrder = append(t.counterOrder, name)
	return true
}

// Add increases a counter; Set replaces its value.
func (t *Telemetry) Add(name string, value int) {
	if t.series(name) {
		t.counters[name] += value
	}
}

func (t *Telemetry) Set(name string, value int) {
	if t.series(name) {
		t.counters[name] = value
	}
}

// Observe adds one value to a histogram.
func (t *Telemetry) Observe(name string, value float64) {
	h := t.histograms[name]
	if h == nil {
		if len(t.histograms) >= MaxSeries {
			return
		}
		h = &Histogram{counts: make([]int, len(Buckets)+1)}
		t.histograms[name] = h
		t.histogramOrder = append(t.histogramOrder, name)
	}
	h.observe(value)
}

func (t *Telemetry) now() float64 {
	if t.Clock != nil {
		return t.Clock()
	}
	return time.Since(t.began).Seconds()
}

// Stage times one bounded unit of work into stage_seconds.<name>; call the returned function when it ends.
func (t *Telemetry) Stage(name string) func() {
	started := t.now()
	return func() { t.Observe("stage_seconds."+name, t.now()-started) }
}

// Render is Telemetry.render() with the key orders of its maps: orders maps a path below the value
// ("counters", "histograms") to that map's keys in first-use order.
func (t *Telemetry) Render() (map[string]interface{}, map[string][]string) {
	counters := make(map[string]interface{}, len(t.counters))
	for name, value := range t.counters {
		counters[name] = value
	}
	histograms := make(map[string]interface{}, len(t.histograms))
	for name, h := range t.histograms {
		histograms[name] = h.render()
	}
	return map[string]interface{}{"counters": counters, "histograms": histograms},
		map[string][]string{"counters": append([]string{}, t.counterOrder...), "histograms": append([]string{}, t.histogramOrder...)}
}
