// Lab-only measurement hook for the PRO-516 child-app load test. It is copied into the local Culvert clone
// before the build and is NOT part of culvert-lab-ef94311-childapp.patch. The same binary runs both arms
// (child-app lab off and on), so the hook cannot bias the comparison.
//
// With CULVERT_LAB_METRICS_ADDR set to a loopback address it serves, on that address only:
//   /lab/metrics   runtime/metrics counters as JSON (heap allocations: objects and bytes; GC cycles)
//   /debug/pprof/  the standard net/http/pprof handlers (CPU, allocation, mutex and block profiles)
// CULVERT_LAB_PROFILE_LOCKS=1 also turns on mutex and block profiling (runtime.SetMutexProfileFraction(10),
// runtime.SetBlockProfileRate(10000 ns)); it is set only for the profile passes, never for the measured steps.
// Unset (the default), it does nothing. Never shipped, never proposed upstream.

package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"runtime/metrics"
	"time"
)

func init() {
	addr := os.Getenv("CULVERT_LAB_METRICS_ADDR")
	if addr == "" {
		return
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return // loopback only
	}
	if os.Getenv("CULVERT_LAB_PROFILE_LOCKS") == "1" {
		runtime.SetMutexProfileFraction(10)
		runtime.SetBlockProfileRate(10000)
	}
	names := []string{"/gc/heap/allocs:objects", "/gc/heap/allocs:bytes", "/gc/cycles/total:gc-cycles",
		"/cpu/classes/total:cpu-seconds", "/cpu/classes/gc/total:cpu-seconds"}
	mux := http.NewServeMux()
	mux.HandleFunc("/lab/metrics", func(w http.ResponseWriter, _ *http.Request) {
		samples := make([]metrics.Sample, len(names))
		for i, n := range names {
			samples[i].Name = n
		}
		metrics.Read(samples)
		out := map[string]float64{}
		for _, s := range samples {
			switch s.Value.Kind() {
			case metrics.KindUint64:
				out[s.Name] = float64(s.Value.Uint64())
			case metrics.KindFloat64:
				out[s.Name] = s.Value.Float64()
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.ListenAndServe() }()
}
