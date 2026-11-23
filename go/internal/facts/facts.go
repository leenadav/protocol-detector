// Package facts is a PLACEHOLDER for the facts-only phase (working plan 5.3, lab phase L2): typed facts the
// proxy has already parsed, passed in instead of bytes. Its field set is a strawman for the Culvert team to
// confirm or correct (docs/integration/CULVERT-TEAM-REQUEST.md, item 1); nothing here is agreed, which is why
// the package is internal and the public package does not use it.
//
// It fixes only what the working plan already requires of any facts input, whatever its final fields:
//   - provenance: a result built from facts is marked ProvenanceCulvertFacts and is never a raw-parser
//     classification (5.3, 8.4);
//   - legs: client-to-proxy and proxy-to-origin facts are kept apart (5.3, test matrix "TLS/HTTP facts");
//   - offered and negotiated values are separate fields, never merged (5.3);
//   - every value is bounded and validated before use, and nothing the caller passed is retained.
package facts

import (
	"errors"
	"fmt"

	"github.com/leenadav/protocol-detector/go/internal/names"
)

// ProvenanceCulvertFacts marks a result that came from the proxy's own parsing (working plan 5.3). Results with
// it are excluded from raw-parser accuracy (8.4).
const ProvenanceCulvertFacts = "culvert_facts"

// Leg is the connection a fact was observed on. A fact never moves between legs.
type Leg uint8

const (
	// LegClient is the client-to-proxy connection.
	LegClient Leg = 1
	// LegOrigin is the proxy-to-origin connection.
	LegOrigin Leg = 2
)

// Valid reports whether l is one of the two legs.
func (l Leg) Valid() bool { return l == LegClient || l == LegOrigin }

// Bounds, the same as the public package's export bounds where one exists.
const (
	MaxOfferedALPN = 16  // detector.MaxOfferedALPN
	MaxALPNLength  = 255 // an ALPN protocol name is 1..255 bytes (RFC 7301, section 3.1)
)

// TLS is what the proxy knows about one TLS handshake on one leg. Offered values come from the ClientHello the
// proxy read; negotiated values from the completed handshake, when there is one.
type TLS struct {
	Leg Leg
	// ServerName is the SNI the client sent, as sent. It is normalized and bounded by Validate.
	ServerName string
	// OfferedALPN lists the client's ALPN offer in order. OfferedALPNKnown distinguishes "offered nothing" from
	// "the proxy did not read the offer".
	OfferedALPN      []string
	OfferedALPNKnown bool
	// Negotiated is nil until the handshake completed on this leg.
	Negotiated *Negotiated
}

// Negotiated is the outcome of a completed handshake (the fields of Go's tls.ConnectionState it is built from).
type Negotiated struct {
	Version     uint16 // tls.VersionTLS12, tls.VersionTLS13, ...
	CipherSuite uint16
	ALPN        string // "" when none was negotiated
}

// Validated is a checked, owned copy of TLS facts: what a later stage may use. It shares no memory with the input.
type Validated struct {
	Provenance       string
	Leg              Leg
	ServerName       string
	OfferedALPN      []string
	OfferedALPNKnown bool
	Negotiated       *Negotiated
}

// ErrInvalid wraps every refusal of Validate.
var ErrInvalid = errors.New("facts: invalid")

func invalid(format string, args ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Validate checks the facts and returns an owned copy marked with ProvenanceCulvertFacts. A refusal names the
// field and never quotes its value, which may be a hostname.
func (t TLS) Validate() (Validated, error) {
	if !t.Leg.Valid() {
		return Validated{}, invalid("leg %d", t.Leg)
	}
	v := Validated{Provenance: ProvenanceCulvertFacts, Leg: t.Leg, OfferedALPNKnown: t.OfferedALPNKnown}
	if t.ServerName != "" {
		name, err := names.Normalize(t.ServerName)
		if err != nil || names.IsIPv4(name) || names.IsIPv6(name) {
			return Validated{}, invalid("server name is not a DNS host name")
		}
		v.ServerName = name
	}
	if !t.OfferedALPNKnown && len(t.OfferedALPN) > 0 {
		return Validated{}, invalid("an ALPN offer is given but marked unknown")
	}
	if len(t.OfferedALPN) > MaxOfferedALPN {
		return Validated{}, invalid("%d offered ALPN identifiers, at most %d", len(t.OfferedALPN), MaxOfferedALPN)
	}
	for i, p := range t.OfferedALPN {
		if len(p) == 0 || len(p) > MaxALPNLength {
			return Validated{}, invalid("offered ALPN identifier %d has length %d", i, len(p))
		}
	}
	v.OfferedALPN = append([]string(nil), t.OfferedALPN...)
	if n := t.Negotiated; n != nil {
		if len(n.ALPN) > MaxALPNLength {
			return Validated{}, invalid("negotiated ALPN has length %d", len(n.ALPN))
		}
		copied := *n
		v.Negotiated = &copied
	}
	return v, nil
}
