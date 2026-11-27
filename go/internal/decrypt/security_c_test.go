package decrypt

import (
	"fmt"
	"strings"
	"testing"
)

// SR-58: the key provider's printed forms carry counts only. fmt's %v, %+v and %s use String; the secret bytes,
// the client random and the label never appear in them, before or after Release.
func TestKeyProviderPrintsCountsOnly(t *testing.T) {
	p := NewKeyProvider()
	random, secret := strings.Repeat("ab", 32), strings.Repeat("5c", 48)
	if _, err := p.Append("CLIENT_RANDOM " + random + " " + secret + "\n"); err != nil {
		t.Fatal(err)
	}
	for _, release := range []bool{false, true} {
		if release {
			p.Release()
		}
		for _, verb := range []string{"%v", "%+v", "%s"} {
			text := fmt.Sprintf(verb, p)
			if !strings.HasPrefix(text, "<KeyProvider entries=") || strings.Contains(text, "5c5c") || strings.Contains(text, "\\") ||
				strings.Contains(text, "abab") || strings.Contains(text, "CLIENT_RANDOM") {
				t.Fatalf("%s (released %v) shows more than counts: %s", verb, release, text)
			}
		}
	}
}
