package textroute_test

import (
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/parsertest"
	"github.com/leenadav/protocol-detector/go/internal/parsing"
	"github.com/leenadav/protocol-detector/go/internal/protocols/textroute"
)

// Integration work item #14, reserve before growing: every buffer the text-route parsers retain grows from
// the flow's Credit. Over every fixture stream and several splits, nothing they retain grows uncharged, and
// with tight allowances a refused growth ends the run explicitly and never exceeds the allowance.
func TestRetainedBuffersGrowOnlyFromTheCredit(t *testing.T) {
	streams, err := parsertest.Streams(parsertest.Cases(fixtures))
	if err != nil {
		t.Fatal(err)
	}
	irc := func(testing.TB) parsing.Parser { return textroute.NewIRC(512) }
	refused := 0
	for _, build := range []func(testing.TB) parsing.Parser{fresh, irc} {
		for i, data := range streams {
			for _, step := range []int{0, 1, 3, 17, 64} {
				if failure, _ := parsertest.CheckCredit(build(t), data, step, 1<<30); failure != "" {
					t.Fatalf("stream %d, step %d: %s", i, step, failure)
				}
				for _, limit := range []int{16, 40, 100, 300, 1000} {
					failure, denied := parsertest.CheckCredit(build(t), data, step, limit)
					if failure != "" {
						t.Fatalf("stream %d, step %d, limit %d: %s", i, step, limit, failure)
					}
					if denied {
						refused++
					}
				}
			}
		}
	}
	if refused == 0 {
		t.Fatal("no tight allowance refused a growth: the check exercised nothing")
	}
}
