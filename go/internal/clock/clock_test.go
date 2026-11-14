package clock

import (
	"testing"
	"time"
)

func TestFakeClockIsDeterministicAndMonotonic(t *testing.T) {
	start := time.Unix(1_700_000_000, 0).UTC()
	c := NewFake(start)
	if !c.Now().Equal(start) || !c.Now().Equal(start) {
		t.Fatal("fake clock moved on its own")
	}
	c.Advance(2 * time.Second)
	c.Advance(-time.Hour)
	if got := c.Now(); !got.Equal(start.Add(2 * time.Second)) {
		t.Fatalf("Now = %v", got)
	}
	c.Set(start)
	if !c.Now().Equal(start.Add(2 * time.Second)) {
		t.Fatal("Set moved the clock backwards")
	}
	var _ Clock = Real{}
}
