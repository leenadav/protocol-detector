package engine

import (
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
)

// The reference case-maps wire bytes with bytes.upper()/lower() (ASCII only). Go's Unicode-aware mappings made
// "ſtarttls" (U+017F LONG S) equal to STARTTLS: an SMTP client line opened a false TLS boundary and an IMAP-shaped
// line was rejected for the wrong reason. Expected outcomes are the Python reference's (found 2026-11-15).
func TestCaseMappingIsASCIIOnly(t *testing.T) {
	cases := []struct {
		line, status, protocol, reason string
	}{
		{"a1 ſtarttls\r\n", "malformed", "", "Unsupported HTTP/1.x start-line"},
		{"EHLO a.example\r\nſtarttls\r\n", "identified", "smtp", "SMTP client EHLO/HELO syntax validated; server exchange and message body not inspected"},
	}
	for _, c := range cases {
		in, _ := New(contracts.DefaultConfig(), "")
		in.Feed([]byte(c.line))
		in.End("fin")
		o := in.Observation
		protocol := ""
		if o.ApplicationProtocol != nil {
			protocol = *o.ApplicationProtocol
		}
		if string(o.Status) != c.status || protocol != c.protocol || o.Reason != c.reason {
			t.Fatalf("%q: %s %s %q", c.line, o.Status, protocol, o.Reason)
		}
		for _, e := range o.Evidence {
			if e.Field == "shift" {
				t.Fatalf("%q opened a %s boundary", c.line, e.Value)
			}
		}
	}
}
