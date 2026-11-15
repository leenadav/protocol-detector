// Package errs defines the structured, payload-free errors every Go component reports.
//
// An Error names a closed code, the scope the condition applies to (direction, flow, capture, worker,
// process), the limit involved when the code is Budget, and a short detail that never carries input
// bytes, hostnames or key material. Errors compare by code with errors.Is.
package errs

import (
	"errors"
	"fmt"
)

// Code is the closed vocabulary of failure classes (migration/CONTRACTS.md C16).
type Code string

const (
	// Malformed: the input violates the structure of the profile that was selected for it.
	Malformed Code = "malformed"
	// Budget: a configured byte, count, depth or work limit ended the operation; never a positive result.
	Budget Code = "budget"
	// Unsupported: a documented exclusion (PROTOCOLS.md) was met; the outcome stays unknown/unsupported.
	Unsupported Code = "unsupported"
	// Invalid: a caller or content error (bad configuration, content pack, schema); fails closed at load time.
	Invalid Code = "invalid"
	// Cancelled: the owning context ended before the work completed.
	Cancelled Code = "cancelled"
)

// Scopes a limit can apply to; a limit without a stated scope is a contract violation (plan §4).
const (
	ScopeDirection = "direction"
	ScopeFlow      = "flow"
	ScopeCapture   = "capture"
	ScopeWorker    = "worker"
	ScopeProcess   = "process"
)

// Error is the structured error. Detail must be a fixed sentence or a bounded identifier, never input.
type Error struct {
	Code   Code
	Scope  string
	Limit  int
	Detail string
}

func (e *Error) Error() string {
	switch {
	case e.Code == Budget && e.Scope != "":
		return fmt.Sprintf("%s: %s (limit %d per %s)", e.Code, e.Detail, e.Limit, e.Scope)
	case e.Scope != "":
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Detail, e.Scope)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Detail)
}

// Is makes errors.Is(err, errs.Budget.Err()) match on the code alone.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code && (t.Scope == "" || t.Scope == e.Scope)
}

// Err returns the sentinel for a code, for errors.Is comparisons.
func (c Code) Err() error { return &Error{Code: c} }

// New builds an error without a limit.
func New(code Code, scope, detail string) error {
	return &Error{Code: code, Scope: scope, Detail: detail}
}

// Exceeded builds a Budget error naming the limit and its scope.
func Exceeded(scope string, limit int, detail string) error {
	return &Error{Code: Budget, Scope: scope, Limit: limit, Detail: detail}
}

// CodeOf returns the code of a structured error, or "" for any other error.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
