package parsertest_test

import (
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/parsertest"
)

// Cases keeps the relative path when CasesEnv is unset, and takes the override when it is set: the nightly
// mutation run (migration/mutation/mutation.py) sets it because gremlins tests each mutant in a copy of go/ alone,
// where a path up to migration/ does not exist (PRO-521).
func TestCasesOverride(t *testing.T) {
	const rel = "../../../../migration/fixtures/cases.json"
	t.Setenv(parsertest.CasesEnv, "")
	if got := parsertest.Cases(rel); got != rel {
		t.Fatalf("unset: Cases(%q) = %q, want the relative path", rel, got)
	}
	t.Setenv(parsertest.CasesEnv, "/abs/migration/fixtures/cases.json")
	if got := parsertest.Cases(rel); got != "/abs/migration/fixtures/cases.json" {
		t.Fatalf("set: Cases(%q) = %q, want the override", rel, got)
	}
}
