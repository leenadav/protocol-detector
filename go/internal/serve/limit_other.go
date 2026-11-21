//go:build !unix

package serve

// limitCPU: no RLIMIT_CPU or SIGXCPU on this platform (the release builds for Windows; the reference's
// limit_worker_cpu is a no-op where the resource module is missing).
func limitCPU(seconds uint64) {}
