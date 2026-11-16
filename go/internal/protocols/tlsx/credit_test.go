package tlsx_test

import (
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/parsertest"
)

// Integration work item #14, reserve before growing: the record-header and handshake accumulators grow only
// from the flow's Credit, over every fixture stream and several splits, and a tight allowance refuses
// explicitly without ever being exceeded.
func TestRetainedBuffersGrowOnlyFromTheCredit(t *testing.T) {
	streams, err := parsertest.Streams(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	refused := 0
	for i, data := range streams {
		for _, step := range []int{0, 1, 5, 100} {
			if failure, _ := parsertest.CheckCredit(fresh(t), data, step, 1<<30); failure != "" {
				t.Fatalf("stream %d, step %d: %s", i, step, failure)
			}
			for _, limit := range []int{8, 64, 256, 1024} {
				failure, denied := parsertest.CheckCredit(fresh(t), data, step, limit)
				if failure != "" {
					t.Fatalf("stream %d, step %d, limit %d: %s", i, step, limit, failure)
				}
				if denied {
					refused++
				}
			}
		}
	}
	if refused == 0 {
		t.Fatal("no tight allowance refused a growth: the check exercised nothing")
	}
}
