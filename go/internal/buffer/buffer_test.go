package buffer

import (
	"bytes"
	"errors"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/errs"
)

func account(t *testing.T, limit int) *Account {
	t.Helper()
	a, err := NewAccount(errs.ScopeFlow, limit)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestInputIsCopiedNotRetained(t *testing.T) {
	b, _ := NewBounded(account(t, 100), 50)
	in := []byte("GET / HTTP/1.1")
	if n, err := b.Append(in); n != len(in) || err != nil {
		t.Fatalf("append %d %v", n, err)
	}
	for i := range in {
		in[i] = 'x' // the caller reuses its buffer immediately
	}
	if !bytes.Equal(b.Bytes(), []byte("GET / HTTP/1.1")) {
		t.Fatalf("retained bytes changed with the input: %q", b.Bytes())
	}
}

func TestPerBufferLimitIsExplicitAndScoped(t *testing.T) {
	b, _ := NewBounded(account(t, 100), 8)
	n, err := b.Append([]byte("0123456789"))
	if n != 8 || !errors.Is(err, errs.Budget.Err()) {
		t.Fatalf("n=%d err=%v", n, err)
	}
	var e *errs.Error
	if !errors.As(err, &e) || e.Scope != errs.ScopeDirection || e.Limit != 8 {
		t.Fatalf("limit not stated: %v", err)
	}
	if n, err := b.Append([]byte("a")); n != 0 || err == nil {
		t.Fatalf("full buffer accepted bytes: %d %v", n, err)
	}
}

func TestAggregateAccountBoundsManyBuffers(t *testing.T) {
	a := account(t, 10)
	one, _ := NewBounded(a, 8)
	two, _ := NewBounded(a, 8)
	if n, err := one.Append([]byte("12345678")); n != 8 || err != nil {
		t.Fatal(n, err)
	}
	n, err := two.Append([]byte("abc"))
	if n != 0 || !errors.Is(err, &errs.Error{Code: errs.Budget, Scope: errs.ScopeFlow}) {
		t.Fatalf("aggregate limit not enforced: n=%d err=%v", n, err)
	}
	one.Discard(5) // three of eight bytes remain: the remainder moves to a three-byte array
	if a.Used() != 3 || one.Cap() != 3 {
		t.Fatalf("used after discard = %d, cap %d", a.Used(), one.Cap())
	}
	if n, err := two.Append([]byte("abc")); n != 3 || err != nil {
		t.Fatal(n, err)
	}
	one.Release()
	two.Release()
	if a.Used() != 0 {
		t.Fatalf("used after release = %d", a.Used())
	}
	if _, err := one.Append([]byte("z")); !errors.Is(err, errs.Invalid.Err()) {
		t.Fatalf("append after release: %v", err)
	}
}

func TestDiscardKeepsTheRemainderAndZeroesTheTail(t *testing.T) {
	b, _ := NewBounded(account(t, 100), 50)
	b.Append([]byte("headerbody"))
	backing := b.Bytes()[:10]
	b.Discard(6)
	if !bytes.Equal(b.Bytes(), []byte("body")) {
		t.Fatalf("remainder = %q", b.Bytes())
	}
	if !bytes.Equal(backing[4:10], make([]byte, 6)) {
		t.Fatalf("discarded bytes still readable: %q", backing)
	}
}

// Review R3 (2026-11-14): the account released a buffer's charge on Discard while its backing array stayed
// allocated, so 100 retained buffers under a 1,024-byte account held 102,400 bytes with Used() == 0.
func TestAccountFollowsAllocatedCapacity(t *testing.T) {
	a := account(t, 1024)
	payload := bytes.Repeat([]byte{7}, 1024)
	var kept []*Bounded
	for i := 0; i < 100; i++ {
		b, _ := NewBounded(a, 1024)
		if n, err := b.Append(payload); n != 1024 || err != nil {
			t.Fatalf("buffer %d: %d %v", i, n, err)
		}
		b.Discard(1024)
		kept = append(kept, b)
		total := 0
		for _, k := range kept {
			total += k.Cap()
		}
		if total != a.Used() || total > 1024 {
			t.Fatalf("after %d buffers: allocated %d, charged %d", i+1, total, a.Used())
		}
	}
	// A buffer that keeps more than half of its array keeps the charge, and the next buffer is refused.
	first, _ := NewBounded(a, 1024)
	first.Append(payload)
	first.Discard(400)
	if first.Len() != 624 || first.Cap() != 1024 || a.Used() != 1024 {
		t.Fatalf("len %d cap %d used %d", first.Len(), first.Cap(), a.Used())
	}
	second, _ := NewBounded(a, 1024)
	if n, err := second.Append([]byte("x")); n != 0 || !errors.Is(err, &errs.Error{Code: errs.Budget, Scope: errs.ScopeFlow}) {
		t.Fatalf("append beyond the allocated total: %d %v", n, err)
	}
	// Reuse inside the kept capacity costs nothing; dropping below half returns the difference.
	if n, err := first.Append(bytes.Repeat([]byte{1}, 400)); n != 400 || err != nil || a.Used() != 1024 {
		t.Fatalf("reuse: %d %v used %d", n, err, a.Used())
	}
	first.Discard(900)
	if first.Len() != 124 || first.Cap() != 124 || a.Used() != 124 {
		t.Fatalf("after shrink: len %d cap %d used %d", first.Len(), first.Cap(), a.Used())
	}
	if n, err := second.Append(bytes.Repeat([]byte{2}, 900)); n != 900 || err != nil || a.Used() != 1024 {
		t.Fatalf("second after shrink: %d %v used %d", n, err, a.Used())
	}
	first.Release()
	second.Release()
	if a.Used() != 0 || first.Cap() != 0 || second.Cap() != 0 {
		t.Fatalf("after release: used %d", a.Used())
	}
}

// Growth is charged as capacity: doubling when the account allows it, the exact need when it does not, nothing
// when even that does not fit; the per-buffer limit caps the capacity as well as the length.
func TestGrowthIsChargedBeforeItIsAllocated(t *testing.T) {
	a := account(t, 100)
	b, _ := NewBounded(a, 64)
	b.Append(make([]byte, 10))
	if b.Cap() != 10 || a.Used() != 10 {
		t.Fatalf("cap %d used %d", b.Cap(), a.Used())
	}
	b.Append(make([]byte, 1)) // doubles to 20
	if b.Len() != 11 || b.Cap() != 20 || a.Used() != 20 {
		t.Fatalf("len %d cap %d used %d", b.Len(), b.Cap(), a.Used())
	}
	b.Append(make([]byte, 40)) // needs 51; doubling would give 40, the limit caps growth at 64
	if b.Len() != 51 || b.Cap() != 51 || a.Used() != 51 {
		t.Fatalf("len %d cap %d used %d", b.Len(), b.Cap(), a.Used())
	}
	other, _ := NewBounded(a, 64)
	other.Append(make([]byte, 45)) // 96 of 100 charged
	if n, err := b.Append(make([]byte, 3)); n != 3 || err != nil || b.Cap() != 54 || a.Used() != 99 {
		t.Fatalf("exact fallback: %d %v cap %d used %d", n, err, b.Cap(), a.Used())
	}
	if n, err := b.Append(make([]byte, 5)); n != 0 || err == nil || b.Len() != 54 || a.Used() != 99 {
		t.Fatalf("refused growth changed state: %d %v len %d used %d", n, err, b.Len(), a.Used())
	}
}

func TestInvalidConstruction(t *testing.T) {
	if _, err := NewAccount("", 1); !errors.Is(err, errs.Invalid.Err()) {
		t.Fatal(err)
	}
	if _, err := NewAccount(errs.ScopeFlow, 0); !errors.Is(err, errs.Invalid.Err()) {
		t.Fatal(err)
	}
	if _, err := NewBounded(nil, 1); !errors.Is(err, errs.Invalid.Err()) {
		t.Fatal(err)
	}
}

func FuzzAppendNeverExceedsLimits(f *testing.F) {
	f.Add([]byte("abc"), 4, 3)
	f.Add([]byte(""), 1, 1)
	f.Fuzz(func(t *testing.T, p []byte, limit, aggregate int) {
		if limit <= 0 || aggregate <= 0 || limit > 1<<16 || aggregate > 1<<16 {
			return
		}
		a, _ := NewAccount(errs.ScopeFlow, aggregate)
		b, _ := NewBounded(a, limit)
		total := 0
		for i := 0; i < 4; i++ {
			n, _ := b.Append(p)
			total += n
			if b.Len() > limit || a.Used() > aggregate || b.Len() != total || b.Cap() != a.Used() || b.Cap() > limit || b.Cap() < b.Len() {
				t.Fatalf("limits broken: len=%d cap=%d limit=%d used=%d aggregate=%d", b.Len(), b.Cap(), limit, a.Used(), aggregate)
			}
		}
		b.Discard(len(p) / 2)
		if b.Cap() != a.Used() || b.Cap() < b.Len() || !bytes.Equal(b.Bytes(), expected(p, total)[min(len(p)/2, total):]) {
			t.Fatalf("after discard: len=%d cap=%d used=%d", b.Len(), b.Cap(), a.Used())
		}
		b.Release()
		if a.Used() != 0 {
			t.Fatalf("charge leaked: %d", a.Used())
		}
	})
}

// expected is the first total bytes of p repeated (what four Appends of p retain).
func expected(p []byte, total int) []byte {
	out := make([]byte, 0, total)
	for len(out) < total {
		n := total - len(out)
		if n > len(p) {
			n = len(p)
		}
		out = append(out, p[:n]...)
	}
	return out
}
