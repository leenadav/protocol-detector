package engine

import (
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
)

// SEC-HTTP-1 at the observation: an absolute-form request whose Host names another site is attributed to the
// target's authority (the name a proxy routes on), with the source saying so and the mismatch flagged.
func TestAbsoluteFormTargetIsTheObservedHostname(t *testing.T) {
	in, err := New(contracts.DefaultConfig(), "")
	if err != nil {
		t.Fatal(err)
	}
	in.Feed([]byte("GET http://www.netflix.test/watch HTTP/1.1\r\nHost: www.youtube.test\r\n\r\n"))
	o := in.Observation
	if o.Status != contracts.Identified || o.Hostname == nil || *o.Hostname != "www.netflix.test" {
		t.Fatalf("observation %+v", o)
	}
	var source, mismatch string
	for _, e := range o.Evidence {
		switch e.Field {
		case "hostname":
			source = e.Source
		case "http_host_mismatch":
			mismatch = e.Value
		}
		if e.Value == "www.youtube.test" {
			t.Fatalf("the Host header's name was emitted: %+v", e)
		}
	}
	if source != "wire:http_target" || mismatch != "present" {
		t.Fatalf("hostname source %q, mismatch %q: %+v", source, mismatch, o.Evidence)
	}
}
