package parsing

import (
	"bytes"
	"testing"
)

var sink []byte

// The charge is the capacity the allocator really gives: checked for every size up to 40,000 bytes and on a
// sample above, against fresh allocations of this process.
func TestAllocationBoundCoversTheAllocator(t *testing.T) {
	check := func(n int) {
		sink = append([]byte(nil), make([]byte, n)...)
		if got, want := allocationBound(n), cap(sink); got != want {
			t.Fatalf("allocation of %d bytes: bound %d, allocator gives %d", n, got, want)
		}
	}
	for n := 1; n <= 40000; n++ {
		check(n)
	}
	for n := 40000; n <= 1<<21; n += 4093 {
		check(n)
	}
	if allocationBound(0) != 0 || allocationBound(-1) != 0 {
		t.Fatal("empty allocations are charged")
	}
}

func TestAppendChargesBeforeGrowing(t *testing.T) {
	c := NewCredit(100)
	buf, err := c.Append(nil, []byte("0123456789"))
	if err != nil || string(buf) != "0123456789" || c.Used() != cap(buf) || c.Used() != allocationBound(10) {
		t.Fatalf("first growth: %q %v, used %d, cap %d", buf, err, c.Used(), cap(buf))
	}
	// Room left in the buffer: nothing is allocated or charged.
	used := c.Used()
	if buf, err = c.Append(buf, []byte("ab")); err != nil || c.Used() != used || string(buf) != "0123456789ab" {
		t.Fatalf("append within capacity: %q %v, used %d", buf, err, c.Used())
	}
	// Growth replaces the old array: the old capacity is credited back, the new one charged.
	if buf, err = c.Append(buf, bytes.Repeat([]byte("x"), 40)); err != nil || c.Used() != cap(buf) {
		t.Fatalf("growth: %v, used %d, cap %d", err, c.Used(), cap(buf))
	}
	// A growth the allowance cannot cover even as an exact fit is refused, allocates nothing and leaves the
	// buffer and the charge as they were.
	before, beforeCap, beforeUsed := string(buf), cap(buf), c.Used()
	big := bytes.Repeat([]byte("y"), 200)
	allocs := testing.AllocsPerRun(20, func() {
		c.Settle(beforeUsed)
		if _, err := c.Append(buf, big); !IsDenied(err) {
			t.Fatalf("over the allowance: %v", err)
		}
	})
	if allocs != 0 {
		t.Errorf("a refused growth allocated %.0f times", allocs)
	}
	if string(buf) != before || cap(buf) != beforeCap || c.Used() != beforeUsed || !c.Denied() || c.Peak() > c.Limit() {
		t.Fatalf("after the refusal: used %d, denied %v, peak %d", c.Used(), c.Denied(), c.Peak())
	}
	c.Settle(beforeUsed)
	if c.Denied() {
		t.Fatal("Settle keeps the denial")
	}
}

// When the usual doubling does not fit but the exact size does, the exact size is taken.
func TestAppendFallsBackToAnExactFit(t *testing.T) {
	c := NewCredit(allocationBound(600))
	buf, _ := c.Append(nil, bytes.Repeat([]byte("a"), 300))
	c.Settle(cap(buf))
	buf, err := c.Append(buf, bytes.Repeat([]byte("b"), 300))
	if err != nil || len(buf) != 600 || cap(buf) != allocationBound(600) || c.Denied() || c.Used() > c.Limit() {
		t.Fatalf("exact fit: %v len %d cap %d used %d denied %v", err, len(buf), cap(buf), c.Used(), c.Denied())
	}
}

func TestCopyAndStringAreCharged(t *testing.T) {
	c := NewCredit(64)
	data := []byte("some header value")
	out, err := c.Copy(data)
	if err != nil || !bytes.Equal(out, data) || &out[0] == &data[0] || c.Used() != cap(out) {
		t.Fatalf("copy: %q %v used %d", out, err, c.Used())
	}
	if empty, err := c.Copy(nil); err != nil || empty != nil {
		t.Fatalf("empty copy: %v %v", empty, err)
	}
	used := c.Used()
	s, err := c.String("host.example")
	if err != nil || s != "host.example" || c.Used() != used+len(s) {
		t.Fatalf("string: %q %v used %d", s, err, c.Used())
	}
	if _, err := c.String(string(make([]byte, 64))); !IsDenied(err) || !c.Denied() {
		t.Fatalf("an oversized string was accepted: %v", err)
	}
	if _, err := c.Copy(make([]byte, 64)); !IsDenied(err) {
		t.Fatalf("an oversized copy was accepted: %v", err)
	}
}

// A nil Credit is the plain operation: what the engine's own callers use.
func TestNilCreditIsUnlimited(t *testing.T) {
	var c *Credit
	buf, err := c.Append([]byte("a"), make([]byte, 1<<20))
	if err != nil || len(buf) != 1<<20+1 || c.Denied() {
		t.Fatalf("nil append: %v", err)
	}
	if out, err := c.Copy([]byte("x")); err != nil || string(out) != "x" {
		t.Fatal("nil copy")
	}
	if s, err := c.String("x"); err != nil || s != "x" {
		t.Fatal("nil string")
	}
	c.Settle(10)
}

func TestDeniedIsDistinctFromParserBudgets(t *testing.T) {
	if !IsDenied(Denied()) || IsDenied(Budget("Line length budget exceeded")) || IsDenied(Malformed(deniedMessage)) || IsDenied(nil) {
		t.Fatal("IsDenied does not identify exactly the memory refusal")
	}
}
