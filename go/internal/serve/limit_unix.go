//go:build unix

package serve

import (
	"os"
	"os/signal"
	"syscall"
)

// limitCPU is limit_worker_cpu(resource, 22): a CPU budget that never raises an inherited hard limit. The
// reference dies of SIGXCPU at the soft limit (its default action); the Go runtime ignores that signal
// unless asked, so it is caught and re-raised with the default action to end the same way (status -24).
func limitCPU(seconds uint64) {
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CPU, &limit); err != nil {
		return
	}
	capped := func(v uint64) uint64 {
		if limit.Max != ^uint64(0) && v > limit.Max {
			return limit.Max
		}
		return v
	}
	_ = syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{Cur: capped(seconds), Max: capped(seconds + 1)})
	xcpu := make(chan os.Signal, 1)
	signal.Notify(xcpu, syscall.SIGXCPU)
	go func() {
		<-xcpu
		signal.Reset(syscall.SIGXCPU)
		_ = syscall.Kill(os.Getpid(), syscall.SIGXCPU)
	}()
}
