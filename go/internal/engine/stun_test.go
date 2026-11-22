package engine

import (
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
)

// A STUN Binding request over TCP (RFC 8489 framing): the datagram profile validates the whole message, its rows
// carry the "message" provenance, and split delivery, a bad cookie and an oversized length behave as in Python.
func TestSTUNOverTCP(t *testing.T) {
	binding := []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	in, _ := New(contracts.DefaultConfig(), "")
	in.Feed(binding[:7])
	in.Feed(binding[7:])
	o := in.Observation
	if o.Status != contracts.Identified || o.ApplicationProtocol == nil || *o.ApplicationProtocol != "stun" {
		t.Fatalf("%+v", o)
	}
	var method string
	for _, e := range o.Evidence {
		if e.Field == "stun_method" {
			method = e.Source + "=" + e.Value
		}
	}
	if method != "wire:message=binding" {
		t.Fatalf("method row %q", method)
	}
	badCookie := append([]byte{}, binding...)
	badCookie[5] = 0
	in, _ = New(contracts.DefaultConfig(), "stun")
	if in.Feed(badCookie); in.Observation.Status != contracts.Malformed {
		t.Fatalf("bad cookie: %s", in.Observation.Status)
	}
	oversized := append([]byte{}, binding...)
	oversized[2], oversized[3] = 0xff, 0xfc
	cfg := contracts.DefaultConfig()
	cfg.MaxBytes = 4096
	in, _ = New(cfg, "stun")
	if in.Feed(oversized); in.Observation.Status != contracts.BudgetExhausted {
		t.Fatalf("oversized: %s", in.Observation.Status)
	}
}
