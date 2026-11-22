package signatures

import (
	"errors"
	"strings"
	"testing"
)

// Repeat counts above RE2's 1000 (2026-11-18): split into pieces that denote the same language, so a signature's
// match existence equals Python's re.search. Expected values computed with CPython 3.13's re (DOTALL, bytes) on
// prefix + atom*k + suffix for each k in repeatCounts.
var repeatCounts = []int{0, 1, 999, 1000, 1001, 1199, 1200, 1201, 1499, 1500, 1501, 1999, 2000, 2002, 2003, 3000, 3001, 5000, 5001}

func TestRepeatCountsAbove1000MatchTheReference(t *testing.T) {
	for _, c := range []struct{ pattern, prefix, atom, suffix, want string }{
		{`abcx{1500}`, "abc", "x", "", "0000000001111111111"},
		{`head(?:cd){1001,2002}tail`, "head", "cd", "tail", "0000111111111100000"},
		{`start[a-c]{2000,}end`, "start", "b", "end", "0000000000001111111"},
		{`mark{0,4000}stop`, "mar", "k", "stop", "1111111111111111100"},
		{`gate(xy){0,1001}z`, "gate", "xy", "z", "1111100000000000000"},
		{`keyz{1000,1001}v`, "key", "z", "v", "0001100000000000000"},
		{`lit(?:q|rs){1200,1200}end`, "lit", "rs", "end", "0000001000000000000"},
		{`begin.{0,3000}finish`, "begin", "\x00", "finish", "1111111111111111000"},
		{`(?:ab){0,1500}stamp`, "", "ab", "stamp", "1111111111111111111"}} {
		p, err := compilePattern(c.pattern, "text", false)
		if err != nil {
			t.Fatalf("%s: %v", c.pattern, err)
		}
		for i, k := range repeatCounts {
			data := []byte(c.prefix + strings.Repeat(c.atom, k) + c.suffix)
			if got := p.search(data); got != (c.want[i] == '1') {
				t.Errorf("%s with %d repeats: got %v, Python %v", c.pattern, k, got, !got)
			}
		}
	}
}

// The signature rules cap a repeat at 4096 and refuse nested quantifiers (as the reference does), so the split
// opens counts 1001..4096 and needs at most five pieces; the rule errors are unchanged.
func TestRepeatLimitsStayTheReferenceRules(t *testing.T) {
	for _, pattern := range []string{`abcx{4096}`, `abcx{1,4096}`, `abcx{4096,}`} {
		if _, err := compilePattern(pattern, "text", false); err != nil {
			t.Errorf("%s: %v", pattern, err)
		}
	}
	for pattern, want := range map[string]string{`abcx{4097}`: "Repeat count exceeds 4096", `abc(?:x{2000}){2}`: "Nested quantifiers are not allowed"} {
		_, err := compilePattern(pattern, "text", false)
		var pe *patternError
		if !errors.As(err, &pe) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", pattern, err, want)
		}
	}
}
