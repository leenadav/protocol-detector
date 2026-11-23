package detector

// PRO-101: property tests of the facade a host embeds. Both directions of a flow are fed in arbitrary chunk splits,
// interleaved, and the final snapshot must equal the one of feeding each direction whole (split invariance) while
// the feed budget allows the split; past it the direction ends as budget_exhausted, never as another outcome. The
// same input and split give the same snapshot twice (determinism), and after every call the flow retains no more
// than its allowance and inspects no more than MaxBytesPerDirection. rapid shrinks a failure to a minimal
// counterexample; FuzzFlowIsSplitInvariant runs the same check under `go test -fuzz` and replays its checked-in
// corpus (testdata/fuzz/FuzzFlowIsSplitInvariant) on every `go test`.

import (
	"reflect"
	"sort"
	"sync"
	"testing"

	"pgregory.net/rapid"

	"github.com/leenadav/protocol-detector/go/internal/parsertest"
)

const propertyFeeds = 24 // the feed budget of the property engine: small, so the generated splits cross it

var (
	propertyOnce    sync.Once
	propertyEngine  *Engine
	propertySeeds   [][]byte
	propertySeedErr error
)

// property returns one engine shared by every check (flows are independent; sharing it also checks that nothing
// leaks between them) and every unhinted stream fixture.
func property(t failer) (*Engine, [][]byte) {
	propertyOnce.Do(func() {
		c := allFamilies()
		c.MaxBytesPerDirection, c.MaxFeedsPerDirection, c.MaxFlows = 4096, propertyFeeds, 64
		propertyEngine, propertySeedErr = New(c)
		if propertySeedErr == nil {
			propertySeeds, propertySeedErr = parsertest.Streams("../../migration/fixtures/cases.json")
		}
	})
	if propertySeedErr != nil {
		t.Fatal(propertySeedErr)
	}
	return propertyEngine, propertySeeds
}

// failer is what the check needs of a *testing.T or a *rapid.T.
type failer interface {
	Helper()
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

// flowRun feeds the two directions in the pieces their cuts delimit, alternating client and server pieces, then
// closes the flow and returns its final snapshot. The budgets are checked after every call.
func flowRun(t failer, e *Engine, client, server []byte, clientCuts, serverCuts []int) Snapshot {
	t.Helper()
	f, err := e.NewFlow("property")
	if err != nil {
		t.Fatal(err)
	}
	pieces := [2][][]byte{parsertest.Pieces(client, clientCuts), parsertest.Pieces(server, serverCuts)}
	check := func() {
		s := f.Snapshot()
		if s.RetainedBytes < 0 || s.RetainedBytes > f.reserved {
			t.Fatalf("the flow retains %d bytes, allowance %d", s.RetainedBytes, f.reserved)
		}
		for _, d := range AllDirections() {
			if ds := s.Direction(d); ds.BytesInspected > e.cfg.MaxBytes || !ds.Outcome.Valid() || !ds.Reason.Valid() {
				t.Fatalf("%s: inspected %d of a %d budget, outcome %q reason %q", d, ds.BytesInspected, e.cfg.MaxBytes, ds.Outcome, ds.Reason)
			}
		}
	}
	for i := 0; i < len(pieces[0]) || i < len(pieces[1]); i++ {
		for _, d := range AllDirections() {
			if i < len(pieces[d]) {
				if _, err := f.Feed(d, pieces[d][i]); err != nil {
					t.Fatalf("%s feed %d: %v", d, i, err)
				}
				check()
			}
		}
	}
	for _, d := range AllDirections() {
		if _, err := f.EndDirection(d, EndEOF); err != nil {
			t.Fatal(err)
		}
	}
	return f.Close()
}

// checkFlowSplit is the property, for one input pair and one split of each direction.
func checkFlowSplit(t failer, client, server []byte, clientCuts, serverCuts []int) {
	t.Helper()
	e, _ := property(t)
	whole := flowRun(t, e, client, server, nil, nil)
	if again := flowRun(t, e, client, server, nil, nil); !reflect.DeepEqual(again, whole) {
		t.Fatalf("not deterministic on %x / %x:\n first  %+v\n second %+v", client, server, whole, again)
	}
	split := flowRun(t, e, client, server, clientCuts, serverCuts)
	for _, d := range AllDirections() {
		w, s := whole.Direction(d), split.Direction(d)
		pieces := len(parsertest.Pieces([][]byte{client, server}[d], [][]int{clientCuts, serverCuts}[d]))
		switch {
		case reflect.DeepEqual(stable(s), stable(w)):
		case pieces > propertyFeeds && s.Outcome == OutcomeBudgetExhausted && s.Reason == ReasonEngine:
			// the split spent the feed budget before the direction was decided: the documented outcome
		default:
			t.Fatalf("%s is not split invariant (%d pieces, budget %d) on %x / %x at %v / %v:\n whole %+v\n split %+v",
				d, pieces, propertyFeeds, client, server, clientCuts, serverCuts, w, s)
		}
	}
	if st := e.Stats(); st.RetainedBytes != 0 || st.Active != 0 {
		t.Fatalf("closed flows left %d bytes retained and %d flows active", st.RetainedBytes, st.Active)
	}
}

func genFlowStream(t *rapid.T, seeds [][]byte, label string) []byte {
	if rapid.IntRange(0, 4).Draw(t, label+" kind") == 0 {
		return rapid.SliceOfN(rapid.Byte(), 0, 300).Draw(t, label+" bytes")
	}
	data := append([]byte(nil), rapid.SampledFrom(seeds).Draw(t, label+" fixture")...)
	if len(data) > 0 && rapid.Bool().Draw(t, label+" mutate") {
		at := rapid.IntRange(0, len(data)-1).Draw(t, label+" at")
		data[at] ^= rapid.ByteRange(1, 255).Draw(t, label+" xor")
	}
	return data
}

func genFlowCuts(t *rapid.T, data []byte, label string) []int {
	if len(data) < 2 {
		return nil
	}
	cuts := rapid.SliceOfNDistinct(rapid.IntRange(1, len(data)-1), 0, 2*propertyFeeds, rapid.ID[int]).Draw(t, label+" cuts")
	sort.Ints(cuts)
	return cuts
}

func TestFlowIsSplitInvariantAndBounded(t *testing.T) {
	_, seeds := property(t)
	rapid.Check(t, func(rt *rapid.T) {
		client, server := genFlowStream(rt, seeds, "client"), genFlowStream(rt, seeds, "server")
		checkFlowSplit(rt, client, server, genFlowCuts(rt, client, "client"), genFlowCuts(rt, server, "server"))
	})
}

// cutsOf turns piece lengths (one byte each, a piece of 1..256 bytes, repeated until data is covered) into cuts.
func cutsOf(data, lengths []byte) []int {
	if len(lengths) == 0 {
		return nil
	}
	var cuts []int
	for pos, i := 0, 0; ; i++ {
		pos += int(lengths[i%len(lengths)]) + 1
		if pos >= len(data) {
			return cuts
		}
		cuts = append(cuts, pos)
	}
}

func FuzzFlowIsSplitInvariant(f *testing.F) {
	_, seeds := property(f)
	for i := 0; i < len(seeds); i += 9 {
		f.Add(seeds[i], seeds[(i+1)%len(seeds)], []byte{byte(i % 5)}, []byte{byte(i % 3), 40})
	}
	f.Add(httpRequest, httpResponse, []byte{0}, []byte{0}) // byte by byte: past the feed budget
	f.Fuzz(func(t *testing.T, client, server, clientLengths, serverLengths []byte) {
		checkFlowSplit(t, client, server, cutsOf(client, clientLengths), cutsOf(server, serverLengths))
	})
}
