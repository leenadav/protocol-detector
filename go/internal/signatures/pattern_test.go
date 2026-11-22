package signatures

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// patternVectors were produced by the Python reference (signatures.compile_pattern, then the anchor pre-check and
// re.search over each haystack): err is the SignatureError text, otherwise anchor (hex) and one match bit per
// haystack. The 20,000-pattern randomized differential that preceded this port agreed on all of them.
var patternVectors = []struct {
	pattern, kind      string
	ci                 bool
	err, anchor, match string
}{
	{"abc", "text", false, "", "616263", "110000000000000000011"},
	{"ab", "text", false, "Pattern needs a literal run of at least 3 bytes", "", ""},
	{"(?:abc|abd)x", "text", false, "Pattern needs a literal run of at least 3 bytes", "", ""},
	{"GET /api/v[0-9]+", "text", true, "", "676574202f6170692f76", "000011000000000000000"},
	{"^SSH-2\\.0-OpenSSH_[0-9.]+", "text", false, "", "5353482d322e302d4f70656e5353485f", "000000100000000000000"},
	{"(a+)+bcdefgh", "raw", false, "Nested quantifiers are not allowed", "", ""},
	{"abc(?=d)ef", "text", false, "Backreferences and lookaround are not allowed", "", ""},
	{"(abc)\\1", "text", false, "Backreferences and lookaround are not allowed", "", ""},
	{"a{5000}bcdefgh", "raw", false, "Repeat count exceeds 4096", "", ""},
	{"[", "text", false, "Invalid pattern: unterminated character set at position 0", "", ""},
	{"Āabc", "text", false, "Patterns must be Latin-1 encodable", "", ""},
	{"PROBE-v1", "raw", false, "", "50524f42452d7631", "000000010000000000000"},
	{"\\x00\\x01PROBE", "raw", false, "", "000150524f4245", "000000001000000000000"},
	{"hello\\s+world", "text", true, "", "68656c6c6f", "000000000110000000000"},
	{"café", "text", true, "", "636166e9", "000000000001000000000"},
	{"(?i)abc", "text", false, "", "616263", "110000000000000000011"},
	{"abc$", "text", false, "", "616263", "100000000000000000011"},
	{"ab$c", "text", false, "Pattern needs a literal run of at least 3 bytes", "", ""},
	{"x{2,3}yz.*end", "text", false, "", "656e64", "000000000000010000000"},
	{"\\bword\\b", "text", false, "", "776f7264", "000000000000001000000"},
	{"[A-Z]{2}-abc", "text", true, "", "2d616263", "000000000000000100000"},
	{"abc|def|ghi", "text", false, "Pattern needs a literal run of at least 3 bytes", "", ""},
	{"a.c", "text", false, "Pattern needs a literal run of at least 3 bytes", "", ""},
	{"(?:ab|ac)def", "text", false, "", "646566", "000000000000000000100"},
	{"\\d\\d\\dabc", "text", false, "", "616263", "000000000000000000010"},
	{"abc\n(def", "text", false, "Invalid pattern: missing ), unterminated subpattern at position 4 (line 2, column 1)", "", ""},
	{"(?P<n>a)(?P<n>b)xyz", "text", false, "Invalid pattern: redefinition of group name 'n' as group 2; was group 1 at position 12", "", ""},
	{"(?P<1a>x)abc", "text", false, "Invalid pattern: bad character in group name '1a' at position 4", "", ""},
	{"\\777abc", "text", false, "Invalid pattern: octal escape value \\777 outside of range 0-0o377 at position 0", "", ""},
	{"abc\\", "text", false, "Invalid pattern: bad escape (end of pattern) at position 3", "", ""},
	{"(?<x)abc", "text", false, "Invalid pattern: unknown extension ?<x at position 1", "", ""},
	{"x{3,1}abc", "text", false, "Invalid pattern: min repeat greater than max repeat at position 2", "", ""},
	{"abc**", "text", false, "Invalid pattern: multiple repeat at position 4", "", ""},
	{"abc(?P=zz)", "text", false, "Invalid pattern: unknown group name 'zz' at position 7", "", ""},
	{"(a\\1)bcd", "text", false, "Invalid pattern: cannot refer to an open group at position 2", "", ""},
	{"abcĀ(", "text", false, "Invalid pattern: missing ), unterminated subpattern at position 4", "", ""},
	{"abcĀāx", "text", false, "Patterns must be Latin-1 encodable", "", ""},
	{"[\\777]abc", "text", false, "Invalid pattern: octal escape value \\777 outside of range 0-0o377 at position 1", "", ""},
	{"(?P<n>abc)(?P=n)", "text", false, "Backreferences and lookaround are not allowed", "", ""},
	{"(?#unterminated abc", "text", false, "Invalid pattern: missing ), unterminated comment at position 0", "", ""},
	{"abc(?Px)", "text", false, "Invalid pattern: unknown extension ?Px at position 4", "", ""},
	{"abc(?<!)", "text", false, "", "616263", "000000000000000000000"},
	{"a++bcdefgh", "raw", false, "", "62636465666768", "000000000000000000000"},
	{"abc[Āā]", "text", false, "Pattern must be Latin-1 encodable: 'latin-1' codec can't encode characters in position 4-5: ordinal not in range(256)", "", ""},
	{"abc[😀z]", "text", false, "Pattern must be Latin-1 encodable: 'latin-1' codec can't encode character '\\U0001f600' in position 4: ordinal not in range(256)", "", ""},
}

var patternHaystacks = []string{"616263", "7861626378", "414243", "61626478", "474554202f6170692f763132", "676574202f4150492f5639", "5353482d322e302d4f70656e5353485f392e36", "50524f42452d7631", "000150524f4245", "68656c6c6f200920776f726c64", "48454c4c4f20574f524c44", "636166e9", "434146c9", "7878797a7a7a656e64", "6120776f72642068657265", "41422d414243", "676869", "610a63", "6163646566", "313233616263", "d9a3616263"}

func TestPatternsMatchTheReference(t *testing.T) {
	for _, v := range patternVectors {
		p, err := compilePattern(v.pattern, v.kind, v.ci)
		if _, refused := err.(*notPortedError); refused {
			if v.err != "" {
				t.Errorf("%q: Go refuses as not ported a pattern Python rejects (%s)", v.pattern, v.err)
			}
			continue // explicitly outside the ported subset (inline flags): refused, never guessed
		}
		if v.err != "" {
			if err == nil || err.Error() != v.err {
				t.Errorf("%q: error %v, reference %q", v.pattern, err, v.err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v; the reference accepts it", v.pattern, err)
			continue
		}
		if got := hex.EncodeToString(p.anchor); got != v.anchor {
			t.Errorf("%q: anchor %s, reference %s", v.pattern, got, v.anchor)
		}
		for i, h := range patternHaystacks {
			hay, _ := hex.DecodeString(h)
			probe := hay
			if v.ci {
				probe = lowerASCII(hay)
			}
			got := bytes.Contains(probe, p.anchor) && p.search(hay)
			if got != (v.match[i] == '1') {
				t.Errorf("%q ci=%v on %q: %v, reference %c", v.pattern, v.ci, hay, got, v.match[i])
			}
		}
	}
}

// FuzzPatternNeverPanics: any pattern is accepted, rejected or refused as not ported; an accepted one searches any
// input without panicking.
func FuzzPatternNeverPanics(f *testing.F) {
	for _, v := range patternVectors {
		f.Add(v.pattern, v.kind == "raw", v.ci, []byte("GET /api/v1 abcdefgh"))
	}
	f.Fuzz(func(t *testing.T, pattern string, raw, ci bool, hay []byte) {
		kind := "text"
		if raw {
			kind = "raw"
		}
		p, err := compilePattern(pattern, kind, ci)
		if err == nil {
			p.search(hay)
		}
	})
}
