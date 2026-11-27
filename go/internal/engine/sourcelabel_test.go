package engine

import (
	"fmt"
	"sync"
	"testing"
)

// PRO-596: sourceLabel is a + ":" + b, without a fresh string per evidence row once the pair has been seen.
func TestSourceLabelEqualsConcatenation(t *testing.T) {
	for _, c := range [][2]string{{"wire", "client_hello"}, {"wire", "server_hello"}, {"decrypted", "request_line"},
		{"", ""}, {"wire", ""}, {"", "x"}, {"wire", "client_hello"}} {
		if got, want := sourceLabel(c[0], c[1]), c[0]+":"+c[1]; got != want {
			t.Fatalf("sourceLabel(%q, %q) = %q, want %q", c[0], c[1], got, want)
		}
	}
}

func TestSourceLabelAllocatesOnlyOnFirstUse(t *testing.T) {
	_ = sourceLabel("wire", "pro596_probe")
	if n := testing.AllocsPerRun(100, func() { _ = sourceLabel("wire", "pro596_probe") }); n != 0 {
		t.Fatalf("a known source label allocates %.0f times, want 0", n)
	}
}

// The cache is bounded: past maxSourceLabels distinct pairs a label is still correct, just not cached.
func TestSourceLabelBoundedAndConcurrent(t *testing.T) {
	saved := sourceLabels.Load()
	defer sourceLabels.Store(saved) // a full cache would only slow the other tests of this package down
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 2*maxSourceLabels; i++ {
				p := fmt.Sprintf("p%d", i)
				if got := sourceLabel("wire", p); got != "wire:"+p {
					t.Errorf("goroutine %d: sourceLabel(wire, %s) = %q", g, p, got)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	if n := len(*sourceLabels.Load()); n > maxSourceLabels {
		t.Fatalf("source label cache holds %d entries, over the bound of %d", n, maxSourceLabels)
	}
}
