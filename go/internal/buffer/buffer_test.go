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
	one.Discard(5)
	if a.Used() != 3 {
		t.Fatalf("used after discard = %d", a.Used())
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
			if b.Len() > limit || a.Used() > aggregate || b.Len() != total {
				t.Fatalf("limits broken: len=%d limit=%d used=%d aggregate=%d", b.Len(), limit, a.Used(), aggregate)
			}
		}
		b.Discard(len(p) / 2)
		b.Release()
		if a.Used() != 0 {
			t.Fatalf("charge leaked: %d", a.Used())
		}
	})
}
