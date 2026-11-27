package textroute

import (
	"strings"
	"testing"
)

// SR-54: an HTTP challenge list is split outside quoted strings and read for at most 32 elements per header.
func TestSecurityChallengeListIsSplitOutsideQuotesAndBoundedTo32Elements(t *testing.T) {
	alone := challengeSchemeClasses([]byte("Negotiate"))
	if len(alone) != 1 || alone[0] == "other" {
		t.Fatalf("Negotiate alone: %v", alone)
	}
	label := alone[0]
	has := func(list []string) bool {
		for _, l := range list {
			if l == label {
				return true
			}
		}
		return false
	}
	if got := challengeSchemeClasses([]byte(strings.Repeat("X-Other, ", 31) + "Negotiate")); !has(got) {
		t.Fatalf("the 32nd element was not read: %v", got)
	}
	if got := challengeSchemeClasses([]byte(strings.Repeat("X-Other, ", 32) + "Negotiate")); has(got) {
		t.Fatalf("an element beyond the 32nd was read: %v", got)
	}
	if got := challengeSchemeClasses([]byte(`Basic realm="a, Negotiate"`)); has(got) {
		t.Fatalf("a scheme inside a quoted string was read: %v", got)
	}
}
