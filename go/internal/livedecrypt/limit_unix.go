//go:build unix

package livedecrypt

import (
	"math"
	"syscall"
)

// limitCPU gives the worker a CPU budget; it only ever lowers the limit.
func limitCPU(seconds uint64) {
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CPU, &limit); err != nil {
		return
	}
	capped := func(value uint64) uint64 {
		if limit.Max != math.MaxUint64 && value > limit.Max {
			return limit.Max
		}
		return value
	}
	_ = syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{Cur: capped(seconds), Max: capped(seconds + 5)})
}
