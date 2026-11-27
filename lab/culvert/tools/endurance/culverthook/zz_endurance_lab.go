// Lab-only measurement hook for the PRO-540 endurance run (lab/culvert/ENDURANCE.md). It is copied into the
// local Culvert clone, next to main.go, before the build; it is NOT part of any lab patch, never shipped and
// never proposed upstream. Unset (the default), it does nothing.
//
// With CULVERT_LAB_METRICS_ADDR set to a loopback address it serves, on that address only:
//
//	/lab/endurance        one JSON sample: goroutines, heap (runtime.MemStats and runtime/metrics), open fds,
//	                      the lab observer's engine counters (admission, refusals, reservations, retained bytes)
//	                      and the handoff counter
//	/lab/endurance?gc=1   the same after runtime.GC(), used only for the baseline and recovery samples, so the
//	                      heap figure is the live heap rather than garbage waiting for the next cycle
//	/debug/pprof/heap     the standard heap profile, to attribute retained memory (goroutine profile too)
//
// It reads counters only; it changes no relay, observation or policy behaviour.
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

	"github.com/KidCarmi/Culvert/internal/protodetect"
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
	start := time.Now()
	mux := http.NewServeMux()
	mux.HandleFunc("/lab/endurance", func(w http.ResponseWriter, r *http.Request) {
		forced := r.URL.Query().Get("gc") == "1"
		if forced {
			runtime.GC()
		}
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		live := []metrics.Sample{{Name: "/gc/heap/live:bytes"}, {Name: "/sched/goroutines:goroutines"}}
		metrics.Read(live)
		fds := -1
		if ents, err := os.ReadDir("/proc/self/fd"); err == nil {
			fds = len(ents)
		}
		out := map[string]any{
			"uptime_s":      time.Since(start).Seconds(),
			"forced_gc":     forced,
			"goroutines":    runtime.NumGoroutine(),
			"heap_inuse":    ms.HeapInuse,
			"heap_alloc":    ms.HeapAlloc,
			"heap_objects":  ms.HeapObjects,
			"heap_sys":      ms.HeapSys,
			"heap_released": ms.HeapReleased,
			"heap_live":     live[0].Value.Uint64(),
			"stack_inuse":   ms.StackInuse,
			"sys":           ms.Sys,
			"num_gc":        ms.NumGC,
			"open_fds":      fds,
			"pd_handoffs":   labHandoffs.Load(),
		}
		if obs := labObs(); obs != nil {
			out["pd_engine"] = obs.Name()
			s := obs.Stats()
			out["pd_stats"] = s
			if real, ok := obs.(*protodetect.Real); ok {
				out["pd_engine_stats"] = real.EnduranceStats()
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
	mux.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.ListenAndServe() }()
}
