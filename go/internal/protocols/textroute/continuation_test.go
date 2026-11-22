package textroute

import (
	"bytes"
	"testing"
)

// Codex PRO-16: a chunk-size, data-CRLF or trailer line was searched for its newline through all of the input,
// although at most the remaining continuation budget can be consumed. The search stops at the budget; what is
// consumed, and how the continuation ends, is unchanged (the reference's data.find is unbounded, with the same
// result).
func TestChunkedLineSearchStopsAtTheBudget(t *testing.T) {
	data := []byte("xx5\r\nhello\r\n0\r\n\r\n")
	for _, c := range []struct{ pos, budget, want int }{
		{2, 3, 4},  // "5\r\n": the newline is the last byte the budget covers
		{2, 2, -1}, // one byte short: the newline is beyond the budget, so it is not looked for
		{2, 100, 4},
		{5, 6, -1}, // "hello\r" fits, the newline does not
		{5, 7, 11},
		{len(data), 5, -1},
	} {
		if got := lineEnd(data, c.pos, c.budget); got != c.want {
			t.Errorf("lineEnd(pos %d, budget %d) = %d, want %d", c.pos, c.budget, got, c.want)
		}
	}
}

// The bounded search keeps every outcome: a chunked body fed with each budget ends, consumes and records the
// same as the unbounded search did.
func TestChunkedContinuationOutcomeAtEveryBudget(t *testing.T) {
	body := []byte("5\r\nhello\r\n3;ext=1\r\nabc\r\n0\r\nTrailer: x\r\n\r\n")
	for budget := 1; budget <= len(body)+1; budget++ {
		c := &httpContinuation{opts: Options{MaxLine: 8192}, budget: budget, limit: 10, messages: 1,
			chunked: true, chunkState: chunkSize}
		consumed := c.feed(body)
		wantConsumed := min(budget, len(body))
		if consumed != wantConsumed {
			t.Errorf("budget %d: consumed %d, want %d", budget, consumed, wantConsumed)
		}
		if budget >= len(body) && (c.chunked || c.ended != "") {
			t.Errorf("budget %d: chunked %v ended %q, want the body complete", budget, c.chunked, c.ended)
		}
		if budget < len(body) && !c.chunked {
			t.Errorf("budget %d: the body completed before its last byte", budget)
		}
	}
	// A line longer than the budget is consumed up to the budget and ends the continuation on the budget, not as
	// framing.
	long := append(bytes.Repeat([]byte{'a'}, 64), '\r', '\n')
	c := &httpContinuation{opts: Options{MaxLine: 8192}, budget: 10, limit: 10, messages: 1, chunked: true, chunkState: chunkSize}
	if consumed := c.feed(long); consumed != 10 || c.ended != "budget" || len(c.chunkLine) != 10 {
		t.Errorf("long line: consumed %d ended %q line %d", consumed, c.ended, len(c.chunkLine))
	}
}
