// Package clock separates wall-clock reads from the components that need time, so that tests and the
// differential harness run deterministically (migration/CONTRACTS.md: capture timestamps are inputs,
// never read from the host clock inside the engine).
package clock

import (
	"sync"
	"time"
)

// Clock is the only time source components may hold.
type Clock interface {
	Now() time.Time
}

// Real reads the host clock; used by the live adapters only.
type Real struct{}

func (Real) Now() time.Time { return time.Now() }

// Fake is a settable clock for tests and replay; it never moves on its own.
type Fake struct {
	mu  sync.Mutex
	now time.Time
}

// NewFake starts at the given instant.
func NewFake(start time.Time) *Fake { return &Fake{now: start} }

func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Advance moves the clock forward; a negative step is ignored (time never runs backwards in replay).
func (f *Fake) Advance(d time.Duration) time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	if d > 0 {
		f.now = f.now.Add(d)
	}
	return f.now
}

// Set jumps to an instant no earlier than the current one.
func (f *Fake) Set(t time.Time) time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	if t.After(f.now) {
		f.now = t
	}
	return f.now
}
