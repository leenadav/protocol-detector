package signatures

import (
	"errors"
	"fmt"
	"os"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

const unlimited = 1 << 30 // fits a 32-bit int: the tests also run on GOARCH=386

// programInsts compiles the expression compileTree writes for pattern exactly as regexp.Compile does (Perl
// syntax, Simplify, Compile) and returns its instruction count with the estimate, or ok=false when the pattern is
// rejected or refused before compilation.
func programInsts(t testing.TB, pattern string, ignorecase bool) (actual, estimate int, ok bool) {
	t.Helper()
	tree, err := parsePattern(pattern)
	if err != nil {
		return 0, 0, false
	}
	var runs [][]int
	if literalRuns(tree, false, &runs) != nil || latin1Error([]rune(pattern)) != "" {
		return 0, 0, false
	}
	var b strings.Builder
	if compileTree(&b, tree, ignorecase, true) != nil {
		return 0, 0, false
	}
	re, err := syntax.Parse(b.String(), syntax.Perl)
	if err != nil {
		return 0, 0, false
	}
	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		return 0, 0, false
	}
	return len(prog.Inst), estimateInsts(tree, unlimited), true
}

// estimateCorpus is every signature pattern the repository holds: the reference vectors, the repeat-split tests,
// the document fuzz seeds, the shipped example, the analyze-differential set and shapes chosen to stress each
// rule of the model (nested repeats inside groups, alternation inside repeats, unbounded and split repeats,
// $ at the end, empty groups and branches, and the PRO-170 hostile shapes).
func estimateCorpus(t testing.TB) []string {
	out := []string{}
	for _, v := range patternVectors {
		out = append(out, v.pattern)
	}
	out = append(out,
		`abcx{1500}`, `head(?:cd){1001,2002}tail`, `start[a-c]{2000,}end`, `mark{0,4000}stop`, `gate(xy){0,1001}z`,
		`keyz{1000,1001}v`, `lit(?:q|rs){1200,1200}end`, `begin.{0,3000}finish`, `(?:ab){0,1500}stamp`,
		`abcx{4096}`, `abcx{1,4096}`, `abcx{4096,}`, `example`, `\.example$`, `[\x00-\xff]{0,8}\x00\x00`,
		`\.example`, `OpenSSH_[0-9]`, `\x00\x00\x00\x00\x00\x00\x00`, `[\x00-\xff]{0,8}\x00\x00\x00\x00\x00\x00\x00`,
		`abcdefg.{0,4096}`, `abc.{0,4096}def`, `abc.{4096}`, `abc.{4096,}`, `abc(?:.|x){0,4096}`, `abc(?:){0,4096}`,
		`abc(?:|x){0,100}`, `abc(?:x|){5,}`, `abc(?:a|b|c|d){0,50}$`, `abc((x)|(y(z)))*`, `abc(?:(?:x)(?:y)){2,4}`,
		`abc[^\x00-\xff]{0,10}`, `abc$`, `^abc\b\B\Z`, `abc(?:x{0,3}|y)`, `abc(?:ab|ac|ad){1,300}`,
		`(?:abcdefgh|abcdefgi|abcdefgj){0,900}xyz`, `abc.{1000,}`, `abc.{999,1001}`, `abc(?:\d\w\s){0,1000}`,
		`(?:abc){0,1}`, `abc(?:x+|y)`, `abc(x*)`, `abc(?:)`, `abc(|)`, `abc(?:x?){3}`)
	if text, err := os.ReadFile("../../../signatures-example.json"); err == nil {
		for _, line := range strings.Split(string(text), `"pattern": "`)[1:] {
			raw := line[:strings.Index(line, `"`)]
			out = append(out, strings.ReplaceAll(raw, `\\`, `\`))
		}
	} else {
		t.Fatalf("signatures-example.json: %v", err)
	}
	return out
}

// TestEstimateBoundsTheCompiledProgram: the estimate is an upper bound of the real program size on every pattern
// of the corpus, with and without IGNORECASE (SEC-SIG-2 acceptance).
func TestEstimateBoundsTheCompiledProgram(t *testing.T) {
	checked := 0
	for _, pattern := range estimateCorpus(t) {
		for _, ci := range []bool{false, true} {
			actual, estimate, ok := programInsts(t, pattern, ci)
			if !ok {
				continue
			}
			checked++
			if estimate < actual {
				t.Errorf("%q ci=%v: estimate %d below the compiled program's %d instructions", pattern, ci, estimate, actual)
			}
		}
	}
	if checked < 100 {
		t.Fatalf("only %d patterns compiled; the corpus lost its coverage", checked)
	}
}

// FuzzEstimateBoundsProgram: for any pattern the port compiles, the estimate is at least the real program size.
func FuzzEstimateBoundsProgram(f *testing.F) {
	for _, p := range estimateCorpus(f) {
		f.Add(p, false)
	}
	f.Fuzz(func(t *testing.T, pattern string, ci bool) {
		if len(pattern) > 4*maxPattern {
			return
		}
		actual, estimate, ok := programInsts(t, pattern, ci)
		if ok && estimate < actual {
			t.Fatalf("%q ci=%v: estimate %d below the compiled program's %d instructions", pattern, ci, estimate, actual)
		}
	})
}

// TestEstimateStopsEarly: the walk saturates just above the limit instead of computing a huge bound.
func TestEstimateStopsEarly(t *testing.T) {
	tree, err := parsePattern(`abc(?:(?:x|y){0,4096}|(?:x|y){0,4096}|(?:x|y){0,4096}){0,4096}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := estimateInsts(tree, maxPatternInsts); got != maxPatternInsts+1 {
		t.Fatalf("estimate %d, want the saturated %d", got, maxPatternInsts+1)
	}
	if satMul(1<<20, 1<<20, maxPatternInsts) != maxPatternInsts+1 || satAdd(maxPatternInsts, 1, maxPatternInsts) != maxPatternInsts+1 {
		t.Fatal("saturating arithmetic overflowed its limit")
	}
}

// The per-pattern cap: the PRO-170 shape (a 502-character pattern of 450,569 instructions) is refused as not
// ported, while the largest reference-legal single repeats stay compiled.
func TestPatternInstructionCap(t *testing.T) {
	for _, pattern := range []string{pro170Pattern(), `abc(?:abcd){0,4096}`, `abc.{0,4096}.{0,4096}`} {
		_, err := compilePattern(pattern, "text", false)
		var np *notPortedError
		if !errors.As(err, &np) || !strings.Contains(err.Error(), "10000 instructions") {
			t.Errorf("%q: %v, want the instruction-cap refusal", pattern, err)
		}
	}
	for _, pattern := range []string{`abcdefg.{0,4096}`, `abcx{1,4096}`, `abc.{4096,}`} {
		if _, err := compilePattern(pattern, "text", false); err != nil {
			t.Errorf("%q: %v", pattern, err)
		}
	}
	// A reference rule still wins over the cap: Python's error, not a refusal.
	if _, err := compilePattern(`a{5000}bcdefgh`, "raw", false); err == nil || err.Error() != "Repeat count exceeds 4096" {
		t.Errorf("rule order: %v", err)
	}
}

// pro170Pattern is a pattern of the PRO-170 measurement's size class: 36 two-byte alternatives repeated up to
// 4096 times compile to about 438,000 instructions (the parser cannot merge them into a class).
func pro170Pattern() string {
	alts := make([]string, 36)
	for i := range alts {
		alts[i] = string(rune('a'+i%26)) + string(rune('0'+i/26))
	}
	return "abcdefg(?:" + strings.Join(alts, "|") + "){0,4096}"
}

// hostileDocument is the PRO-170 load attack: many signatures of many patterns over the raw unknown payload.
func hostileDocument(signatures, conditions int, pattern string) []byte {
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < signatures; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"name": "s` + strings.Repeat("x", i%7) + itoa(i) + `", "conditions": [`)
		for j := 0; j < conditions; j++ {
			if j > 0 {
				b.WriteString(",")
			}
			b.WriteString(`{"context": "unknown-req-tcp-payload", "pattern": "` + pattern + `"}`)
		}
		b.WriteString("]}")
	}
	b.WriteString("]")
	return []byte(b.String())
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var d []byte
	for ; i > 0; i /= 10 {
		d = append([]byte{byte('0' + i%10)}, d...)
	}
	return string(d)
}

// The set cap: cumulative over the document, checked before each compile, refusing the set as not ported.
func TestSetInstructionCap(t *testing.T) {
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	// `abcdefg.{0,4096}` is 8,202 instructions by the estimate: 12 fit in 100,000, the 13th does not.
	if _, err := FromJSON(hostileDocument(1, 12, `abcdefg.{0,4096}`), pack); err != nil {
		t.Fatalf("12 patterns within the set cap: %v", err)
	}
	_, err = FromJSON(hostileDocument(1, 13, `abcdefg.{0,4096}`), pack)
	var np *parsing.NotPorted
	if !errors.As(err, &np) || !strings.Contains(err.Error(), "100000 instructions") {
		t.Fatalf("13 patterns: %v, want the set-cap refusal", err)
	}
	// The cap is per set: two documents each within it both load.
	for i := 0; i < 2; i++ {
		if _, err := FromJSON(hostileDocument(4, 3, `abcdefg.{0,4096}`), pack); err != nil {
			t.Fatalf("document %d: %v", i, err)
		}
	}
}

// hostileLoads are the worst documents the caps allow or refuse (PRO-51 load target: under 50 ms).
var hostileLoads = []struct {
	name string
	doc  func() []byte
	ok   bool
}{
	{"PRO-170: 512 x 40 of a 438k-instruction pattern (4 MiB)", func() []byte { return hostileDocument(512, 40, pro170Pattern()) }, false},
	{"11,110 of the cheapest raw pattern (9 instructions each)", func() []byte { return hostileDocument(2222, 5, `abcdefg`) }, true},
	{"set cap filled by 12 patterns of 8,202", func() []byte { return hostileDocument(1, 12, `abcdefg.{0,4096}`) }, true},
	{"set cap filled by 600 patterns of 164", func() []byte { return hostileDocument(600, 1, `abcdefg.{0,77}`) }, true},
	{"set cap exceeded at the 13th pattern", func() []byte { return hostileDocument(1, 64, `abcdefg.{0,4096}`) }, false},
}

// TestHostileDocumentLoadIsBounded: each hostile document loads or is refused as the caps say, and the
// instruction total of a loaded set stays within maxSetInsts. Timing is measured by BenchmarkHostileDocumentLoad
// (wall-clock assertions are not made in tests: they fail under -race or on a loaded runner).
func TestHostileDocumentLoadIsBounded(t *testing.T) {
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range hostileLoads {
		set, err := FromJSON(c.doc(), pack)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if err != nil {
			var np *parsing.NotPorted
			if !errors.As(err, &np) || !strings.Contains(err.Error(), "SEC-SIG-2 cap") {
				t.Errorf("%s: %v, want a cap refusal", c.name, err)
			}
			continue
		}
		total := 0
		for _, s := range set.byName {
			var leaves []*condition
			s.root.leaves(&leaves)
			for _, c := range leaves {
				total += c.pattern.insts
			}
		}
		if total > maxSetInsts {
			t.Errorf("%s: %d instructions loaded", c.name, total)
		}
	}
}

// BenchmarkHostileDocumentLoad measures the load times reported in migration/STATUS.md.
func BenchmarkHostileDocumentLoad(b *testing.B) {
	pack, err := content.Embedded()
	if err != nil {
		b.Fatal(err)
	}
	for _, c := range hostileLoads {
		doc := c.doc()
		b.Run(strings.Fields(c.name)[0]+"-"+itoa(len(doc)), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				FromJSON(doc, pack) //nolint:errcheck // the outcome is checked by TestHostileDocumentLoadIsBounded
			}
		})
	}
}

// TestLiteralFastPathWritesTheSameExpression: the single-byte shortcut of compileTree and writeHexRune write
// exactly the text emitSet(literalSet(...)) wrote through fmt, for every byte with and without IGNORECASE.
func TestLiteralFastPathWritesTheSameExpression(t *testing.T) {
	for _, ci := range []bool{false, true} {
		for v := 0; v < 256; v++ {
			var fast, slow strings.Builder
			if err := compileTree(&fast, []node{{op: opLiteral, value: v}}, ci, false); err != nil {
				t.Fatal(err)
			}
			set := literalSet(v, false, ci)
			slow.WriteString("[")
			for c := 0; c < 256; c++ {
				if !set[c] {
					continue
				}
				start := c
				for c+1 < 256 && set[c+1] {
					c++
				}
				fmt.Fprintf(&slow, `\x{%x}`, start)
				if c > start {
					fmt.Fprintf(&slow, `-\x{%x}`, c)
				}
			}
			slow.WriteString("]")
			if fast.String() != slow.String() {
				t.Errorf("byte %#x ci=%v: %q, fmt wrote %q", v, ci, fast.String(), slow.String())
			}
		}
	}
}

// Work is charged before a condition runs; an exhausted budget stops the evaluation and is never a match.
func TestWorkStopsBeforeTheSearchAndNeverMatches(t *testing.T) {
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	set, err := FromJSON(hostileDocument(1, 1, `abcdefg.{0,100}`), pack)
	if err != nil {
		t.Fatal(err)
	}
	values := Values{"unknown-req-tcp-payload": []byte("abcdefg-tail"), "unknown-req-tcp-payload-length": int64(12)}
	perByte := set.WorkPerByte("unknown-tcp") // 1 + the pattern's estimate
	if perByte != 1+2+7+100*2+1 {
		t.Fatalf("per byte %d", perByte)
	}
	exact := 12*perByte + set.WorkPerEvaluation("unknown-tcp") // + the candidate slot and the condition
	if m, _ := set.MatchBudgeted("unknown-tcp", values, &Work{Limit: exact}); m == nil {
		t.Fatal("exact allowance: no match")
	}
	w := &Work{Limit: exact - 1}
	if m, _ := set.MatchBudgeted("unknown-tcp", values, w); m != nil || !w.Exhausted || w.Used != FixedWork+FixedWork+12 {
		t.Fatalf("one unit short: match %v, work %+v (only the anchor scan may be charged)", m, w)
	}
	if m, n := set.MatchBudgeted("unknown-tcp", values, w); m != nil || n != 0 {
		t.Fatalf("exhausted work evaluated %d candidates", n)
	}
	if m, _ := set.MatchCounted("unknown-tcp", values); m == nil {
		t.Fatal("unbudgeted match lost")
	}
}

// PRO-370 (Codex PRO-369, P2): length-only (integer) conditions and candidate preparation cost CPU on every
// update, so they are charged too. Each candidate slot and each condition costs FixedWork (a condition plus its bytes
// for a byte-valued one), before it runs; a document of integer-only conditions no longer evaluates for free.
func TestLengthOnlyConditionsAndCandidatesAreCharged(t *testing.T) {
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	doc := `[{"name": "len", "conditions": {"or": [
		{"context": "unknown-req-tcp-payload-length", "operator": "equal-to", "value": 1},
		{"context": "unknown-req-tcp-payload-length", "operator": "less-than", "value": 2},
		{"context": "unknown-req-tcp-payload-length", "operator": "greater-than", "value": 99}]}}]`
	set, err := FromJSON([]byte(doc), pack)
	if err != nil {
		t.Fatal(err)
	}
	values := Values{"unknown-req-tcp-payload": []byte("abcdefg-tail"), "unknown-req-tcp-payload-length": int64(12)}
	if got := set.WorkPerByte("unknown-tcp"); got != 0 {
		t.Fatalf("per byte %d: no byte-valued condition", got)
	}
	if got := set.WorkPerEvaluation("unknown-tcp"); got != FixedWork*(1+3) {
		t.Fatalf("per evaluation %d, want one candidate and three conditions", got)
	}
	w := &Work{Limit: 1 << 20}
	if m, n := set.MatchBudgeted("unknown-tcp", values, w); m != nil || n != 1 || w.Used != FixedWork*4 {
		t.Fatalf("match %v, %d candidates, work %+v: want 4 x FixedWork charged", m, n, w)
	}
	w = &Work{Limit: FixedWork * 3} // the candidate and two conditions: the third is not run
	if m, _ := set.MatchBudgeted("unknown-tcp", values, w); m != nil || !w.Exhausted || w.Used != FixedWork*3 {
		t.Fatalf("one unit short: match %v, work %+v", m, w)
	}
	w = &Work{Limit: 0} // not even the candidate list is prepared
	if m, n := set.MatchBudgeted("unknown-tcp", values, w); m != nil || n != 0 || !w.Exhausted || w.Used != 0 {
		t.Fatalf("empty allowance: match %v, %d candidates, work %+v", m, n, w)
	}
}
