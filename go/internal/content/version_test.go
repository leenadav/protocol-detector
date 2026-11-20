package content

import (
	"encoding/json"
	"reflect"
	"regexp"
	"sort"
	"testing"
)

// PRO-31: content release versions are ordered by their numeric components. 2026.11.10 comes after 2026.11.9;
// sort.Strings put it first, so the release list (and the --content-version choices) would have been out of order.
func TestCompareVersionsIsNumeric(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2026.11.9", "2026.11.10", -1},
		{"2026.11.10", "2026.11.9", 1},
		{"2026.11.10", "2026.11.10", 0},
		{"2026.11.1", "2026.11.10", -1},
		{"2026.11.10", "2026.11.11", -1},
		{"2026.11.99", "2026.11.100", -1},
		{"2026.9.0", "2026.10.0", -1},
		{"2025.10.0", "2026.11.0", -1},
		{"2026.11.9", "2026.12.1", -1},
		{"2026.12.0", "2027.1.0", -1},
		{"2026.11", "2026.11.0", -1},
		{"2026.11.x", "2026.11.y", -1},
		{"2026.11.09", "2026.11.9", -1}, // numerically equal spellings still have a fixed order
		// strconv.ParseUint: no sign, no underscore, no non-ASCII digit, at most 2**64 - 1 (test_content.py
		// VersionOrderTests.test_compare_versions_matches_go has the same table)
		{"2026.11.+9", "2026.11.10", -1},
		{"2026.11.1_0", "2026.11.9", -1},
		{"2026.11.\u0669", "2026.11.10", 1},
		{"2026.11.18446744073709551616", "2026.11.2", -1},
		{"2026.11.18446744073709551615", "2026.11.2", 1},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := CompareVersions(c.b, c.a); got != -c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}

// The release list of a history whose earlier releases run past N = 9 is in release order, the current
// release last, whatever the map order of history.json.
func TestReleasesOfOrdersPastNine(t *testing.T) {
	earlier := []string{"2025.10.0", "2026.11.0", "2026.11.1", "2026.11.2", "2026.11.9", "2026.11.10", "2026.11.11"}
	doc := map[string]interface{}{"current": "2026.12.1", "releases": map[string]interface{}{}}
	for _, v := range earlier {
		doc["releases"].(map[string]interface{})[v] = map[string]string{}
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]string{}, earlier...), "2026.12.1")
	for i := 0; i < 20; i++ { // Go map iteration order varies; the result must not
		if got := releasesOf(data); !reflect.DeepEqual(got, want) {
			t.Fatalf("releases %v, want %v", got, want)
		}
	}
}

// The embedded history is already in numeric order and agrees with the C11 rollback test's release list.
func TestEmbeddedReleasesAreNumericallyOrdered(t *testing.T) {
	releases := Releases()
	for i := 1; i < len(releases); i++ {
		if CompareVersions(releases[i-1], releases[i]) >= 0 {
			t.Fatalf("releases out of order at %d: %v", i, releases)
		}
	}
}

// PRO-31 numbering rule (Hermes, PRO-34): a content release is YYYY.MM.N with a two-digit month 01..12 and a
// single-digit N (0..9); when N is used up, numbering moves on to the next month segment at 0 (the version is a
// label; the real date is the release's `released` field). Under this rule string order and numeric order agree,
// so the frozen Python reference (string comparison) and this loader (numeric comparison) order every release the
// same way. This test reads the embedded pack and history and stops anyone who breaks the rule.
var numberingRule = regexp.MustCompile(`^[0-9]{4}\.(0[1-9]|1[0-2])\.[0-9]$`)

func TestEmbeddedReleasesFollowTheNumberingRule(t *testing.T) {
	pack, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Current  string                     `json:"current"`
		Releases map[string]json.RawMessage `json:"releases"`
	}
	if err := json.Unmarshal(embeddedHistory, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Current != pack.Release.Version {
		t.Fatalf("history.json current %q, pack.json release %q", doc.Current, pack.Release.Version)
	}
	versions := []string{doc.Current}
	for v := range doc.Releases {
		versions = append(versions, v)
	}
	for _, v := range versions {
		if !numberingRule.MatchString(v) {
			t.Errorf("content release %q breaks the numbering rule YYYY.MM.N (month 01..12, N 0..9)", v)
		}
	}
	numeric := append([]string{}, versions...)
	sort.SliceStable(numeric, func(i, j int) bool { return CompareVersions(numeric[i], numeric[j]) < 0 })
	lexical := append([]string{}, versions...)
	sort.Strings(lexical)
	if !reflect.DeepEqual(numeric, lexical) {
		t.Errorf("string order %v differs from numeric order %v", lexical, numeric)
	}
	if numeric[len(numeric)-1] != doc.Current {
		t.Errorf("current release %q is not the newest of %v", doc.Current, numeric)
	}
}

// The rule check itself rejects the versions that would split the two orders.
func TestNumberingRuleRejectsTenAndUnpaddedMonths(t *testing.T) {
	for _, v := range []string{"2026.11.10", "2026.9.0", "2026.13.0", "2026.00.1", "2026.11", "2026.11.x"} {
		if numberingRule.MatchString(v) {
			t.Errorf("%q passes the numbering rule", v)
		}
	}
	for _, v := range []string{"2025.10.0", "2026.11.9", "2026.12.1", "2027.01.0"} {
		if !numberingRule.MatchString(v) {
			t.Errorf("%q fails the numbering rule", v)
		}
	}
}
