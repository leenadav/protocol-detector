package content

import (
	"encoding/json"
	"reflect"
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
