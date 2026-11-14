// Package parsing is the vocabulary shared by the engine and every family parser: the parser failure
// classes of protocol_engine/parsers.py (reason sentences are compared verbatim with Python), the
// NotPorted marker for paths the Go backend does not have yet, and the Parser/Result duck type the
// Inspector drives.
package parsing

import "fmt"

// Error is a parser failure. Kind decides the terminal status; Message is the reason sentence.
type Error struct {
	Kind       string // malformed, budget, unsupported, ambiguous
	Message    string
	Candidates []string // ambiguous only
}

func (e *Error) Error() string { return e.Kind + ": " + e.Message }

// Malformed: the bytes violate the selected family's structure (status malformed).
func Malformed(msg string) error { return &Error{Kind: "malformed", Message: msg} }

// Budget: a configured limit ended inspection (status budget_exhausted).
func Budget(msg string) error { return &Error{Kind: "budget", Message: msg} }

// Unsupported: a documented exclusion was met (status unknown).
func Unsupported(msg string) error { return &Error{Kind: "unsupported", Message: msg} }

// Ambiguous: valid for several families; carries the candidates (status unknown with evidence).
func Ambiguous(msg string, candidates ...string) error {
	return &Error{Kind: "ambiguous", Message: msg, Candidates: candidates}
}

// NotPorted marks an outcome the Go backend cannot give yet. It is reported to the harness as
// "unsupported" and never becomes an observation.
type NotPorted struct{ What string }

func (n *NotPorted) Error() string { return fmt.Sprintf("not ported in the Go backend: %s", n.What) }

// Row is one evidence row before the inspector prefixes the provenance with the byte source.
type Row struct{ Field, Value, Provenance, Strength string }

// Shift is a structural boundary after which another protocol starts.
type Shift struct {
	Boundary string
	Expected string // family hint for the next phase, "" for none
}

// Parser is one family's incremental recognizer.
type Parser interface {
	Feed(data []byte) (int, error) // errors: *Error or *NotPorted
	Done() bool
	Result() *Result
}

// Result is what a done parser exposes to the inspector.
type Result struct {
	Family       string // the family a text route resolved to; "" keeps the dispatch candidate
	ProtocolName string
	Host         string
	HasHost      bool
	HostSource   string // "" means the inspector default (tls_sni / http_host)
	ALPN         []string
	Extra        []Row
	Reason       string
	Scope        string // "" means initial_message
	Shift        *Shift
	Continues    bool
}
