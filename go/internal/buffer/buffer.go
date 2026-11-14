// Package buffer holds the bounded byte primitives the engine and the adapters build on.
//
// Ownership contract (migration/adr/0001-ownership-and-resources.md): a caller's input slice may be
// reused the moment a call returns; anything a component keeps is copied into memory it owns. A view
// returned by Bytes is valid only until the next mutating call on the same buffer. Every buffer is
// created against an Account that bounds aggregate retained memory for a stated scope, so a per-buffer
// limit is never the only limit.
//
// Two limits, two units (review R3, 2026-11-14). The per-buffer limit counts logical bytes (Len). The
// Account counts allocated capacity (Cap): a buffer is charged for its whole backing array from the
// moment it is allocated until it is freed or replaced by a smaller one, so bytes a parser has consumed
// keep their charge for as long as their memory is still reachable. Charging the logical length only
// let any number of buffers each fill, discard and keep a full backing array under one account.
package buffer

import (
	"sync"

	"github.com/leenadav/protocol-detector/go/internal/errs"
)

// Account bounds the bytes retained across many buffers of one scope (flow table, capture, worker).
type Account struct {
	mu    sync.Mutex
	scope string
	limit int
	used  int
}

// NewAccount creates an aggregate budget; limit <= 0 is rejected at construction, not at use.
func NewAccount(scope string, limit int) (*Account, error) {
	if limit <= 0 || scope == "" {
		return nil, errs.New(errs.Invalid, errs.ScopeProcess, "aggregate byte limit needs a positive limit and a scope")
	}
	return &Account{scope: scope, limit: limit}, nil
}

// Used reports the capacity currently allocated under the account, in bytes.
func (a *Account) Used() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.used
}

func (a *Account) reserve(n int) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if n < 0 || a.used+n > a.limit {
		return errs.Exceeded(a.scope, a.limit, "aggregate retained bytes")
	}
	a.used += n
	return nil
}

func (a *Account) release(n int) {
	a.mu.Lock()
	a.used -= n
	if a.used < 0 {
		a.used = 0
	}
	a.mu.Unlock()
}

// Bounded accumulates bytes up to a per-buffer limit while charging the account.
type Bounded struct {
	account *Account
	limit   int
	data    []byte
	closed  bool
}

// NewBounded creates an empty buffer that may hold at most limit bytes (limit > 0).
func NewBounded(account *Account, limit int) (*Bounded, error) {
	if account == nil || limit <= 0 {
		return nil, errs.New(errs.Invalid, errs.ScopeProcess, "bounded buffer needs an account and a positive limit")
	}
	return &Bounded{account: account, limit: limit}, nil
}

// Append copies p into the buffer. It accepts the bytes that fit under both limits and returns how
// many were taken; a Budget error (scoped to the direction for the per-buffer limit, or to the
// account's scope) accompanies a short count. The caller keeps ownership of p.
//
// Growth is charged before it is allocated: the buffer asks the account for a doubled capacity (never
// above the per-buffer limit), falls back to exactly the capacity it needs, and takes nothing when the
// account cannot cover even that.
func (b *Bounded) Append(p []byte) (int, error) {
	if b.closed {
		return 0, errs.New(errs.Invalid, errs.ScopeDirection, "append after release")
	}
	room := b.limit - len(b.data)
	if room <= 0 && len(p) > 0 {
		return 0, errs.Exceeded(errs.ScopeDirection, b.limit, "buffer byte limit")
	}
	take := len(p)
	var limitErr error
	if take > room {
		take, limitErr = room, errs.Exceeded(errs.ScopeDirection, b.limit, "buffer byte limit")
	}
	if need := len(b.data) + take; need > cap(b.data) {
		target := 2 * cap(b.data)
		if target < need {
			target = need
		}
		if target > b.limit {
			target = b.limit
		}
		if err := b.resize(target); err != nil {
			if target == need {
				return 0, err
			}
			if err := b.resize(need); err != nil {
				return 0, err
			}
		}
	}
	b.data = append(b.data, p[:take]...)
	return take, limitErr
}

// resize moves the retained bytes into a backing array of exactly capacity bytes (capacity >= Len),
// charging the account for growth before allocating and returning the difference after shrinking. The
// old array is zeroed. Capacity 0 frees the array.
func (b *Bounded) resize(capacity int) error {
	old := b.data
	if grow := capacity - cap(old); grow > 0 {
		if err := b.account.reserve(grow); err != nil {
			return err
		}
	}
	if capacity == 0 {
		b.data = nil
	} else {
		b.data = make([]byte, len(old), capacity)
		copy(b.data, old)
	}
	full := old[:cap(old)]
	for i := range full {
		full[i] = 0
	}
	if shrink := cap(old) - capacity; shrink > 0 {
		b.account.release(shrink)
	}
	return nil
}

// Len is the number of retained bytes.
func (b *Bounded) Len() int { return len(b.data) }

// Cap is the allocated capacity the account is charged for.
func (b *Bounded) Cap() int { return cap(b.data) }

// Bytes returns a view of the retained bytes; it must not be kept across Append, Discard or Release.
func (b *Bounded) Bytes() []byte { return b.data }

// Discard drops the first n bytes (a parser consumed them). The charge follows the memory, not the
// length: when at most half of the capacity is still in use the remainder moves to an array of exactly
// its size (none when nothing remains) and the difference is returned to the account; otherwise the
// array and its charge are kept.
func (b *Bounded) Discard(n int) {
	if n <= 0 || b.closed {
		return
	}
	if n > len(b.data) {
		n = len(b.data)
	}
	copy(b.data, b.data[n:])
	tail := b.data[len(b.data)-n:]
	for i := range tail {
		tail[i] = 0
	}
	b.data = b.data[:len(b.data)-n]
	if len(b.data) <= cap(b.data)/2 {
		_ = b.resize(len(b.data)) // shrinking never asks the account for more
	}
}

// Release zeroes and frees everything and returns the charge; the buffer cannot be used again.
func (b *Bounded) Release() {
	if b.closed {
		return
	}
	_ = b.resize(0)
	b.closed = true
}
