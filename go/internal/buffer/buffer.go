// Package buffer holds the bounded byte primitives the engine and the adapters build on.
//
// Ownership contract (migration/adr/0001-ownership-and-resources.md): a caller's input slice may be
// reused the moment a call returns; anything a component keeps is copied into memory it owns. A view
// returned by Bytes is valid only until the next mutating call on the same buffer. Every buffer is
// created against an Account that bounds aggregate retained bytes for a stated scope, so a per-buffer
// limit is never the only limit.
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

// Used reports the bytes currently retained under the account.
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
	if err := b.account.reserve(take); err != nil {
		return 0, err
	}
	b.data = append(b.data, p[:take]...)
	return take, limitErr
}

// Len is the number of retained bytes.
func (b *Bounded) Len() int { return len(b.data) }

// Bytes returns a view of the retained bytes; it must not be kept across Append, Discard or Release.
func (b *Bounded) Bytes() []byte { return b.data }

// Discard drops the first n bytes (a parser consumed them), releasing their account charge.
func (b *Bounded) Discard(n int) {
	if n <= 0 {
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
	b.account.release(n)
}

// Release zeroes and frees everything and returns the charge; the buffer cannot be used again.
func (b *Bounded) Release() {
	if b.closed {
		return
	}
	for i := range b.data {
		b.data[i] = 0
	}
	b.account.release(len(b.data))
	b.data, b.closed = nil, true
}
