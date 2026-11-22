//go:build linux

package textroute

import (
	"runtime/debug"
	"syscall"
	"testing"
)

// guardedInput returns a slice whose first len(head) bytes are readable and whose remaining extra bytes lie on a
// page mapped PROT_NONE: reading any byte past head faults instead of returning data.
func guardedInput(t *testing.T, head []byte, extra int) []byte {
	t.Helper()
	page := syscall.Getpagesize()
	if len(head) > page || extra > page {
		t.Fatal("guarded input larger than a page")
	}
	mem, err := syscall.Mmap(-1, 0, 2*page, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("mmap: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Munmap(mem) })
	if err := syscall.Mprotect(mem[page:], syscall.PROT_NONE); err != nil {
		t.Fatalf("mprotect: %v", err)
	}
	start := page - len(head)
	copy(mem[start:page], head)
	return mem[start : page+extra]
}

// Codex PRO-16 (P2): the chunked continuation looked for the next newline across all remaining input, although
// it can take at most its remaining byte budget, so each call scanned bytes the budget never admits. With the
// bytes past the budget on a guard page, an unbounded search faults; a bounded one never reads them.
func TestChunkedContinuationSearchStaysInsideItsBudget(t *testing.T) {
	defer debug.SetPanicOnFault(debug.SetPanicOnFault(true))
	for name, head := range map[string]string{"size line without a newline": "1f4a", "trailer without a newline": "X-A:"} {
		c := &httpContinuation{opts: Options{MaxLine: 8192}, budget: len(head), chunked: true, chunkState: chunkSize}
		if name == "trailer without a newline" {
			c.chunkState = chunkTrailers
		}
		data := guardedInput(t, []byte(head), 64)
		pos := func() (pos int) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s: read past the continuation budget: %v", name, r)
				}
			}()
			return c.feed(data)
		}()
		if pos != len(head) || c.budget != 0 || string(c.chunkLine) != head {
			t.Fatalf("%s: pos %d budget %d line %q", name, pos, c.budget, c.chunkLine)
		}
		// The budget is spent, so the continuation has ended and a later feed takes nothing.
		if n := c.feed(data[pos:]); n != 0 || !c.done || c.ended != "budget" {
			t.Fatalf("%s: continuation not ended on its budget: done %v ended %q", name, c.done, c.ended)
		}
	}
}
