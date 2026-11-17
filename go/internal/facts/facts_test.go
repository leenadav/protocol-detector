package facts

import (
	"errors"
	"strings"
	"testing"
)

func TestValidFactsAreCopiedAndMarked(t *testing.T) {
	offer := []string{"h2", "http/1.1"}
	n := &Negotiated{Version: 0x0304, CipherSuite: 0x1301, ALPN: "h2"}
	v, err := TLS{Leg: LegClient, ServerName: "Example.TEST.", OfferedALPN: offer, OfferedALPNKnown: true, Negotiated: n}.Validate()
	if err != nil {
		t.Fatal(err)
	}
	if v.Provenance != ProvenanceCulvertFacts || v.Leg != LegClient || v.ServerName != "example.test" {
		t.Fatalf("%+v", v)
	}
	offer[0], n.ALPN = "changed", "changed" // the caller's memory is not retained
	if v.OfferedALPN[0] != "h2" || v.Negotiated.ALPN != "h2" {
		t.Fatalf("the validated facts share memory with the input: %+v", v)
	}
}

func TestOfferedAndNegotiatedStaySeparate(t *testing.T) {
	v, err := TLS{Leg: LegOrigin, OfferedALPNKnown: true}.Validate()
	if err != nil || v.Negotiated != nil || len(v.OfferedALPN) != 0 || !v.OfferedALPNKnown {
		t.Fatalf("no negotiation yet must stay nil, an empty offer must stay known-empty: %+v %v", v, err)
	}
	if v, _ := (TLS{Leg: LegOrigin}).Validate(); v.OfferedALPNKnown {
		t.Fatal("an unread offer was reported as known")
	}
}

func TestInvalidFactsAreRefusedWithoutQuotingThem(t *testing.T) {
	long := strings.Repeat("a", MaxALPNLength+1)
	many := make([]string, MaxOfferedALPN+1)
	for i := range many {
		many[i] = "x"
	}
	for name, f := range map[string]TLS{
		"no leg":               {ServerName: "a.test"},
		"unknown leg":          {Leg: 3},
		"address as SNI":       {Leg: LegClient, ServerName: "192.0.2.1"},
		"malformed SNI":        {Leg: LegClient, ServerName: "secret..host"},
		"offer marked unknown": {Leg: LegClient, OfferedALPN: []string{"h2"}},
		"too many offers":      {Leg: LegClient, OfferedALPN: many, OfferedALPNKnown: true},
		"empty offer item":     {Leg: LegClient, OfferedALPN: []string{""}, OfferedALPNKnown: true},
		"long offer item":      {Leg: LegClient, OfferedALPN: []string{long}, OfferedALPNKnown: true},
		"long negotiated":      {Leg: LegClient, Negotiated: &Negotiated{ALPN: long}},
	} {
		_, err := f.Validate()
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "192.0.2.1") {
			t.Errorf("%s: the refusal quotes the value: %v", name, err)
		}
	}
}
