package signatures

import (
	"bytes"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
)

// SR-18: evaluation is prefiltered by the pattern's literal anchor: a haystack without the anchor costs only the
// candidate slot, the condition and the anchor scan, never the regular-expression search.
func TestSecurityPatternSearchIsPrefilteredByItsLiteralAnchor(t *testing.T) {
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	set, err := FromJSON(hostileDocument(1, 1, `abcdefg.{0,100}`), pack)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("abcdef-"), 512) // every byte but the anchor's last one
	values := Values{"unknown-req-tcp-payload": payload, "unknown-req-tcp-payload-length": int64(len(payload))}
	w := &Work{Limit: 1 << 40}
	if m, _ := set.MatchBudgeted("unknown-tcp", values, w); m != nil {
		t.Fatalf("matched %s without its anchor", m.Name)
	}
	if want := int64(FixedWork + FixedWork + len(payload)); w.Used != want || w.Exhausted {
		t.Fatalf("work %+v, want exactly %d (the search must not run without the anchor)", w, want)
	}
	// The anchor present: the search runs and is charged per byte and instruction.
	values["unknown-req-tcp-payload"] = append(append([]byte{}, payload...), "abcdefg"...)
	w = &Work{Limit: 1 << 40}
	if m, _ := set.MatchBudgeted("unknown-tcp", values, w); m == nil || w.Used <= int64(FixedWork+FixedWork+len(payload)+7) {
		t.Fatalf("anchored payload: match %v, work %+v", m, w)
	}
}

// SR-18: the pattern rules refuse what has no literal anchor and every unsafe construct, with the reference messages.
func TestSecurityUnsafePatternsAreRefused(t *testing.T) {
	cases := []struct{ pattern, kind, want string }{
		{"ab", "text", "Pattern needs a literal run of at least 3 bytes"},
		{"a.c", "text", "Pattern needs a literal run of at least 3 bytes"},
		{"abcdef", "raw", "Pattern needs a literal run of at least 7 bytes"},
		{"(a+)+bcdefgh", "text", "Nested quantifiers are not allowed"},
		{"abc(?:x*)+", "text", "Nested quantifiers are not allowed"},
		{"(abc)\\1", "text", "Backreferences and lookaround are not allowed"},
		{"abc(?=d)ef", "text", "Backreferences and lookaround are not allowed"},
		{"abc(?<!x)ef", "text", "Backreferences and lookaround are not allowed"},
		{"abcx{4097}", "text", "Repeat count exceeds 4096"},
	}
	for _, c := range cases {
		_, err := compilePattern(c.pattern, c.kind, false)
		if err == nil || err.Error() != c.want {
			t.Errorf("%q (%s): got %v, want %q", c.pattern, c.kind, err, c.want)
		}
	}
	if _, err := compilePattern("abcx{4096}", "text", false); err != nil {
		t.Errorf("a repeat of 4096 is within the rules: %v", err)
	}
}
