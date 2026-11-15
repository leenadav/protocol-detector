package errs

import (
	"errors"
	"strings"
	"testing"
)

func TestBudgetErrorNamesLimitAndScope(t *testing.T) {
	err := Exceeded(ScopeDirection, 65536, "byte budget exhausted")
	if !errors.Is(err, Budget.Err()) || errors.Is(err, Malformed.Err()) {
		t.Fatalf("code comparison failed: %v", err)
	}
	if CodeOf(err) != Budget {
		t.Fatalf("CodeOf = %q", CodeOf(err))
	}
	if got := err.Error(); got != "budget: byte budget exhausted (limit 65536 per direction)" {
		t.Fatalf("message = %q", got)
	}
}

func TestScopedComparison(t *testing.T) {
	err := Exceeded(ScopeFlow, 4, "fragments")
	if !errors.Is(err, &Error{Code: Budget, Scope: ScopeFlow}) || errors.Is(err, &Error{Code: Budget, Scope: ScopeProcess}) {
		t.Fatal("scope comparison failed")
	}
}

func TestDetailIsNeverTheInput(t *testing.T) {
	// The convention is enforced by review and by this guard on the constructors' own messages.
	for _, err := range []error{New(Malformed, ScopeDirection, "length field exceeds the message"), New(Invalid, "", "content pack rejected")} {
		if strings.ContainsAny(err.Error(), "\x00\n") {
			t.Fatalf("control characters in %q", err.Error())
		}
	}
	if CodeOf(errors.New("plain")) != "" {
		t.Fatal("plain errors have no code")
	}
}
