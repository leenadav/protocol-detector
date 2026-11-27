package parsertest

import (
	"strings"
	"testing"
)

func TestRenderedFollowsPointersAndPrintsNoAddress(t *testing.T) {
	value := "kerberos"
	text := Rendered(struct {
		P *string
		N *string
		E []struct{ V string }
	}{P: &value, E: []struct{ V string }{{V: "x"}}})
	if text != "{P:kerberos N:<nil> E:[{V:x}]}" || strings.Contains(text, "0x") {
		t.Fatalf("rendered %q", text)
	}
}
