package parsing

import (
	"sort"
	"strings"
	"sync"
)

// Credit is the memory allowance that the retained buffers of one flow draw from (integration work item #14,
// review round 1 of 6842e0f: reserve before growing). A buffer that grows through a Credit is charged for
// the capacity it will have before that capacity is allocated, so the buffers it covers never hold more than
// the allowance, not even inside a call. A denied growth allocates nothing; the caller returns Denied() and
// the flow ends that direction with an explicit memory outcome.
//
// The charge counts what stays allocated after the operation: the replaced buffer's capacity is credited back
// and the new capacity is charged, because a buffer that grows replaces its old array, which it alone held.
// A charge is an upper bound of the allocation (Go rounds a request up to a size class); once the buffer
// exists, the exact capacity replaces the bound. Frees the Credit does not see (a parser that resets a buffer
// to nil, an inspector that is dropped) are taken into account when the owner calls Settle between calls
// with the measured figure; until then the Credit only over-counts.
//
// A nil *Credit is valid and unlimited: every method then behaves like the plain operation it replaces, so
// the engine's own callers (the parity harness, the command line) are unchanged.
//
// A Credit is not safe for concurrent use; a flow serializes its calls.
type Credit struct {
	limit, used, peak int
	denied            bool
}

// NewCredit returns a Credit for an allowance of limit bytes.
func NewCredit(limit int) *Credit { return &Credit{limit: limit} }

// Reset makes c a fresh Credit for an allowance of limit bytes, so an owner can hold one by value.
func (c *Credit) Reset(limit int) { *c = Credit{limit: limit} }

// deniedMessage is the reason sentence of a denied growth. It is distinct from every parser budget sentence,
// so the owner can tell a memory denial from a parser's own byte or line budget.
const deniedMessage = "Retained parser memory exceeds the flow allowance"

// deniedError is the one error value of a refused growth: returning it allocates nothing. No code writes to a
// parser error after it is made.
var deniedError = &Error{Kind: "budget", Message: deniedMessage}

// Denied is the parser error for a growth the allowance cannot cover (a budget error).
func Denied() error { return deniedError }

// IsDenied reports whether err is the error Denied returns.
func IsDenied(err error) bool {
	e, ok := err.(*Error)
	return ok && e.Kind == "budget" && e.Message == deniedMessage
}

// Limit is the allowance. Used is what is charged now, Peak the most that was ever charged; both are at most
// Limit. Denied reports whether a growth was refused since the last Settle.
func (c *Credit) Limit() int   { return c.limit }
func (c *Credit) Used() int    { return c.used }
func (c *Credit) Peak() int    { return c.peak }
func (c *Credit) Denied() bool { return c != nil && c.denied }

// Settle replaces the charged figure with measured, the capacity the covered buffers hold after a call, and
// clears the denial. measured above Limit means a buffer grew outside the Credit; it is recorded as charged
// so Peak shows it.
func (c *Credit) Settle(measured int) {
	if c == nil {
		return
	}
	c.used, c.denied = measured, false
	if measured > c.peak {
		c.peak = measured
	}
}

// smallLimit is the largest allocation Go serves from a size class; a larger one takes whole pages.
const (
	smallLimit = 32768
	pageSize   = 8192
)

var (
	classesOnce sync.Once
	classes     []int // ascending size classes up to smallLimit, as this process's allocator rounds
)

// sizeClasses probes the allocator once: each probe asks for one byte more than the last class and records
// the capacity it gets, so the table is the allocator's own rounding, about seventy small allocations in all.
func sizeClasses() []int {
	classesOnce.Do(func() {
		for n := 1; n <= smallLimit; {
			c := cap(append([]byte(nil), make([]byte, n)...))
			classes = append(classes, c)
			n = c + 1
		}
	})
	return classes
}

// allocationBound is the capacity Go gives a fresh byte allocation of n bytes: the size class n rounds up to,
// or whole pages above smallLimit (TestAllocationBoundCoversTheAllocator checks it against the allocator).
func allocationBound(n int) int {
	if n <= 0 {
		return 0
	}
	if n > smallLimit {
		return (n + pageSize - 1) / pageSize * pageSize
	}
	table := sizeClasses()
	return table[sort.SearchInts(table, n)]
}

// reserve charges a buffer of capacity old growing to a new allocation of n bytes, before it is allocated.
func (c *Credit) reserve(old, n int) bool {
	if c.used-old+allocationBound(n) > c.limit {
		c.denied = true
		return false
	}
	c.used += allocationBound(n) - old
	if c.used > c.peak {
		c.peak = c.used
	}
	return true
}

// settleAllocation replaces the bound charged for a new buffer with its exact capacity.
func (c *Credit) settleAllocation(n, capacity int) { c.used -= allocationBound(n) - capacity }

// next is the capacity a buffer of capacity old grows to when it must hold need bytes: double while small,
// then by a quarter, never less than need (the shape of Go's append, which an exact-fit retry falls back from).
func next(old, need int) int {
	grown := 2 * old
	if old >= 256 {
		grown = old + old/4
	}
	if grown < need {
		return need
	}
	return grown
}

// Append is append(buf, data...) for a buffer the flow retains. When buf has room, nothing is allocated or
// charged. Otherwise the new capacity is charged first: the usual growth when it fits, else an exact fit,
// else nothing is allocated, buf is returned unchanged and the error is Denied().
func (c *Credit) Append(buf, data []byte) ([]byte, error) {
	need := len(buf) + len(data)
	if c == nil || need <= cap(buf) {
		return append(buf, data...), nil
	}
	size := next(cap(buf), need)
	if !c.reserve(cap(buf), size) {
		if size == need {
			return buf, Denied()
		}
		c.denied = false
		if size = need; !c.reserve(cap(buf), size) {
			return buf, Denied()
		}
	}
	grown := append([]byte(nil), make([]byte, size)...)[:len(buf)] // one allocation, rounded to its size class
	copy(grown, buf)
	grown = append(grown, data...)
	c.settleAllocation(size, cap(grown))
	return grown, nil
}

// Copy is an owned exact copy of data that the flow retains (nil for empty data, as append([]byte(nil), ...)).
func (c *Credit) Copy(data []byte) ([]byte, error) {
	if c == nil || len(data) == 0 {
		return append([]byte(nil), data...), nil
	}
	if !c.reserve(0, len(data)) {
		return nil, Denied()
	}
	out := append([]byte(nil), data...)
	c.settleAllocation(len(data), cap(out))
	return out, nil
}

// String is an owned copy of s that the flow retains. It is charged by its length, which is how a retained
// string is measured.
func (c *Credit) String(s string) (string, error) {
	if c == nil || len(s) == 0 {
		return strings.Clone(s), nil
	}
	if !c.reserve(0, len(s)) {
		return "", Denied()
	}
	out := strings.Clone(s)
	c.settleAllocation(len(s), len(out))
	return out, nil
}

// Credited is implemented by a parser whose retained buffers grow through a Credit. The inspector hands its
// Credit to the parser it creates.
type Credited interface {
	SetCredit(*Credit)
}
