package engine

// PRO-101: property tests over every parser in the registry and over the inspector that drives them. Four
// properties, each checked by pgregory.net/rapid (which shrinks a failure to a minimal counterexample) and by a
// native fuzz target with the same check, so a counterexample found by either is replayed by `go test` from
// testdata/fuzz/<Target>/ (the checked-in seed corpus):
//
//   - no panic, and no parser that consumes more than it was given or stalls without being done;
//   - the per-direction budgets hold: the inspector inspects at most MaxBytes, counts every byte it was given,
//     and a credited parser never retains more than its Credit allows;
//   - split invariance: feeding a stream in any chunk split gives the outcome of feeding it whole;
//   - determinism: the same input and split give the same outcome on a fresh parser.

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"

	"pgregory.net/rapid"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/parsertest"
)

const propertyFixtures = "../../../migration/fixtures/cases.json"

var (
	propertyStreamsOnce sync.Once
	propertyStreams     [][]byte
	propertyStreamsErr  error
)

// streamSeeds is every unhinted stream fixture: the generators start from real messages of every family so
// mutations reach past the first length check of each parser, not only random noise.
func streamSeeds(t testing.TB) [][]byte {
	propertyStreamsOnce.Do(func() { propertyStreams, propertyStreamsErr = parsertest.Streams(propertyFixtures) })
	if propertyStreamsErr != nil {
		t.Fatal(propertyStreamsErr)
	}
	if len(propertyStreams) < 100 {
		t.Fatalf("only %d stream fixtures; the fixture path changed", len(propertyStreams))
	}
	return propertyStreams
}

// failer is what the checks need of a *testing.T, *testing.F's fuzz T or a *rapid.T.
type failer interface {
	Helper()
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

// registry is every candidate the factory registry builds, in a fixed order.
func registry() []string {
	names := make([]string, 0, len(factories))
	for name := range factories {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// propertyConfig is the default configuration with a small byte budget, so the generated inputs reach it.
func propertyConfig() contracts.Config {
	cfg := contracts.DefaultConfig()
	cfg.MaxBytes = 2048
	return cfg
}

// cutsFrom turns piece lengths (each byte one piece of 1..256 bytes, repeated until data is covered) into the
// offsets parsertest.Pieces splits at. The fuzz targets take their split in this form.
func cutsFrom(data, lengths []byte) []int {
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

var consumedField = regexp.MustCompile(` consumed=[0-9]+`)

// comparable drops the consumed count from the rendering of a run that failed before identification: the
// inspector discards it with the parser (Inspector.failed), and a parser may report the whole call's input or
// only what it read up to the fault, so it depends on the split without changing any outcome.
func comparable(rendering string) string {
	if strings.HasPrefix(rendering, `error=""`) {
		return rendering
	}
	return consumedField.ReplaceAllString(rendering, "")
}

// continuationConsumedVaries names the parsers whose consumed count after identification depends on the split,
// with the finding that records why. Only the consumed field is relaxed for them: the error, done, the result and
// every other field must still match.
var continuationConsumedVaries = map[string]string{
	// PRO-101 F1: the SMB watch of one more frame reports each byte of the next frame's 8-byte header as consumed
	// when it arrives in its own call, but returns 0 for the whole header when it arrives in one call and is not
	// an SMB frame. The reference does the same (protocol_engine/windows.py _next_frame, `return start`), so
	// only bytes_inspected moves (by at most 7); changing it is a parity delta (migration/STATUS.md, PRO-101).
	// Tracked in https://github.com/leenadav/protocol-detector/issues/103; the decision (accept or fix) is Lee's.
	"smb1": "PRO-101 F1, issue #103",
	"smb2": "PRO-101 F1, issue #103",
}

// checkParserSplit is the parser-level property: one registry parser, the whole stream against the given split,
// twice each on fresh parsers.
func checkParserSplit(t failer, family string, data []byte, cuts []int) {
	t.Helper()
	cfg := propertyConfig()
	drive := func(cuts []int) string {
		p, err := factory(family, cfg)
		if err != nil {
			t.Fatalf("%s: %v", family, err)
		}
		out := comparable(parsertest.DriveCuts(p, data, cuts))
		if continuationConsumedVaries[family] != "" {
			out = consumedField.ReplaceAllString(out, "")
		}
		return out
	}
	whole := drive(nil)
	if strings.HasPrefix(whole, "BROKEN") {
		t.Fatalf("%s whole on %x: %s", family, data, whole)
	}
	if again := drive(nil); again != whole {
		t.Fatalf("%s is not deterministic on %x:\n first  %s\n second %s", family, data, whole, again)
	}
	if split := drive(cuts); split != whole {
		t.Fatalf("%s is not split invariant on %x at %v:\n whole %s\n split %s", family, data, cuts, whole, split)
	}
	if p, err := factory(family, cfg); err == nil {
		step := 1
		if len(cuts) > 0 {
			step = cuts[0]
		}
		if failure, _ := parsertest.CheckCredit(p, data, step, 512); failure != "" && !strings.Contains(failure, "does not take a Credit") {
			t.Fatalf("%s on %x in %d-byte pieces: %s", family, data, step, failure)
		}
	}
}

// inspectorOutcome feeds data to a fresh inspector in the pieces cuts delimit, ends it, and renders what a host
// sees at the end: the final observation, whether it is terminal and the message boundary. The budget
// invariants are checked on the way. bytes_inspected is checked against the budget but not compared across
// splits: like the reference (engine.py), the inspector counts the whole chunk in which a parser fails, so it
// is chunk-granular by contract. That is the reference contract, not finding F1 (issue #103 names both).
func inspectorOutcome(t failer, cfg contracts.Config, data []byte, cuts []int) string {
	t.Helper()
	in, err := New(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, piece := range parsertest.Pieces(data, cuts) {
		in.Feed(piece)
		if in.NotPorted != nil {
			return "not-ported " + in.NotPorted.Error()
		}
		if in.Metrics.BytesInspected > cfg.MaxBytes {
			t.Fatalf("inspected %d bytes over the %d budget", in.Metrics.BytesInspected, cfg.MaxBytes)
		}
		if retained, _ := in.RetainedBytes(); retained < 0 || retained > cfg.MaxBytes+cfg.MaxLine+cfg.HeuristicBytes+cfg.SignatureBytes {
			t.Fatalf("retains %d bytes with a %d-byte budget", retained, cfg.MaxBytes)
		}
	}
	in.End("fin")
	if in.Metrics.BytesReceived != len(data) || in.Metrics.BytesInspected > cfg.MaxBytes {
		t.Fatalf("metrics out of bounds for %d bytes: %+v", len(data), in.Metrics)
	}
	obs, err := json.Marshal(in.Observation)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%s terminal=%v boundary=%d/%v", obs, in.Terminal(), in.Boundary, in.hasBoundary)
}

// checkInspectorSplit is the inspector-level property: dispatch, the chosen parser, shifts and the unknown
// buffer together give the same final outcome whole and split, and the same outcome twice.
func checkInspectorSplit(t failer, data []byte, cuts []int) {
	t.Helper()
	cfg := propertyConfig()
	whole := inspectorOutcome(t, cfg, data, nil)
	if again := inspectorOutcome(t, cfg, data, nil); again != whole {
		t.Fatalf("not deterministic on %x:\n first  %s\n second %s", data, whole, again)
	}
	if split := inspectorOutcome(t, cfg, data, cuts); split != whole {
		t.Fatalf("not split invariant on %x at %v:\n whole %s\n split %s", data, cuts, whole, split)
	}
}

// genStream draws a stream: a fixture, random bytes, or a fixture mutated by truncation, byte flips, insertions
// and duplication. rapid shrinks towards the unmutated fixture and short inputs.
func genStream(t *rapid.T, seeds [][]byte) []byte {
	var data []byte
	if rapid.Bool().Draw(t, "random") {
		data = rapid.SliceOfN(rapid.Byte(), 0, 600).Draw(t, "bytes")
	} else {
		data = append([]byte(nil), rapid.SampledFrom(seeds).Draw(t, "fixture")...)
	}
	for i, n := 0, rapid.IntRange(0, 4).Draw(t, "mutations"); i < n && len(data) > 0; i++ {
		at := rapid.IntRange(0, len(data)-1).Draw(t, "at")
		switch rapid.IntRange(0, 3).Draw(t, "op") {
		case 0:
			data = data[:at]
		case 1:
			data[at] ^= rapid.ByteRange(1, 255).Draw(t, "xor")
		case 2:
			extra := rapid.SliceOfN(rapid.Byte(), 1, 32).Draw(t, "insert")
			data = append(data[:at:at], append(extra, data[at:]...)...)
		case 3:
			data = append(data, data[at:]...)
		}
	}
	return data
}

// genCuts draws a split of data: sorted distinct offsets strictly inside it, from none to one at every byte.
func genCuts(t *rapid.T, data []byte) []int {
	if len(data) < 2 {
		return nil
	}
	if rapid.IntRange(0, 9).Draw(t, "bytewise") == 0 {
		cuts := make([]int, 0, len(data)-1)
		for i := 1; i < len(data); i++ {
			cuts = append(cuts, i)
		}
		return cuts
	}
	cuts := rapid.SliceOfNDistinct(rapid.IntRange(1, len(data)-1), 0, 24, rapid.ID[int]).Draw(t, "cuts")
	sort.Ints(cuts)
	return cuts
}

// ownSeeds is the fixtures that family's parser identifies whole: half of each family's draws start there, so
// the mutations exercise its parser past the first fields instead of failing at the first byte.
func ownSeeds(t testing.TB, family string, seeds [][]byte) [][]byte {
	var own [][]byte
	for _, data := range seeds {
		p, err := factory(family, propertyConfig())
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(parsertest.Drive(p, data, 0), `error="" done=true`) {
			own = append(own, data)
		}
	}
	return own
}

func TestEveryParserIsSplitInvariantAndBounded(t *testing.T) {
	seeds := streamSeeds(t)
	names := registry()
	if len(names) < 59 {
		t.Fatalf("the registry has %d parsers; it shrank", len(names))
	}
	covered := 0
	for _, family := range names {
		own := ownSeeds(t, family, seeds)
		if len(own) > 0 {
			covered++
		}
		t.Run(family, func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				pool := seeds
				if len(own) > 0 && rapid.Bool().Draw(rt, "own") {
					pool = own
				}
				data := genStream(rt, pool)
				checkParserSplit(rt, family, data, genCuts(rt, data))
			})
		})
	}
	// Some registry parsers have only datagram or hinted fixtures; the rest must be reached by a real message.
	if covered < 40 {
		t.Fatalf("only %d of %d parsers identify any stream fixture; the generators would mostly test the first byte", covered, len(names))
	}
	t.Logf("%d of %d parsers start from fixtures they identify", covered, len(names))
}

func TestInspectorIsSplitInvariantAndBounded(t *testing.T) {
	seeds := streamSeeds(t)
	rapid.Check(t, func(rt *rapid.T) {
		data := genStream(rt, seeds)
		checkInspectorSplit(rt, data, genCuts(rt, data))
	})
}

// Datagrams are not split, so their property is determinism and no panic on every hint, with the budget.
func TestDatagramIsDeterministicOnEveryHint(t *testing.T) {
	seeds := streamSeeds(t)
	hints := []string{""}
	for hint := range DatagramHints {
		hints = append(hints, hint)
	}
	sort.Strings(hints)
	rapid.Check(t, func(rt *rapid.T) {
		data := genStream(rt, seeds)
		hint := rapid.SampledFrom(hints).Draw(rt, "hint")
		checkDatagram(rt, data, hint)
	})
}

func checkDatagram(t failer, data []byte, hint string) {
	t.Helper()
	render := func() string {
		d, err := NewDatagram(propertyConfig())
		if err != nil {
			t.Fatal(err)
		}
		obs, err := d.Inspect(data, hint)
		out, _ := json.Marshal(obs)
		return fmt.Sprintf("%s err=%v", out, err)
	}
	first := render()
	if second := render(); second != first {
		t.Fatalf("datagram hint %q not deterministic on %x:\n first  %s\n second %s", hint, data, first, second)
	}
}

// The native fuzz targets run the same checks; their checked-in corpora (testdata/fuzz/) hold one seed per
// registry family and every shrunk counterexample found so far, which `go test` replays on every run.

func FuzzEveryParserIsSplitInvariant(f *testing.F) {
	names := registry()
	seeds := streamSeeds(f)
	for i, family := range names {
		f.Add(family, seeds[i%len(seeds)], []byte{byte(i % 7)})
	}
	f.Fuzz(func(t *testing.T, family string, data, lengths []byte) {
		if _, ok := factories[family]; !ok {
			family = names[len(family)%len(names)]
		}
		checkParserSplit(t, family, data, cutsFrom(data, lengths))
	})
}

func FuzzInspectorIsSplitInvariant(f *testing.F) {
	for i, data := range streamSeeds(f) {
		if i%8 == 0 {
			f.Add(data, []byte{byte(i % 5)})
		}
	}
	f.Fuzz(func(t *testing.T, data, lengths []byte) {
		checkInspectorSplit(t, data, cutsFrom(data, lengths))
	})
}

func FuzzDatagramIsDeterministic(f *testing.F) {
	hints := []string{""}
	for hint := range DatagramHints {
		hints = append(hints, hint)
	}
	sort.Strings(hints)
	for i, data := range streamSeeds(f) {
		if i%8 == 0 {
			f.Add(data, uint8(i))
		}
	}
	f.Fuzz(func(t *testing.T, data []byte, hint uint8) {
		checkDatagram(t, data, hints[int(hint)%len(hints)])
	})
}
