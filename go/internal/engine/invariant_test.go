package engine

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"os"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// A3 (PRO-119): Select never returns Wait on a full Lookahead-byte probe, so the Inspector's dispatch prefix stays
// shorter than Lookahead. Every prefix the Python decision table answers with Wait is extended to Lookahead bytes
// with several fillers, and seeded random full probes cover the rest.
func TestSelectNeverWaitsOnAFullProbe(t *testing.T) {
	data, err := os.ReadFile("../../../migration/fixtures/dispatch.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Decisions map[string]*string `json:"decisions"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewPCG(119, 24))
	fillers := [][]byte{{0}, {0xff}, {' '}, {'\r', '\n'}, {'A'}, {0x16, 3, 1}}
	waits, probes := 0, 0
	check := func(probe []byte) {
		probes++
		if Select(probe) == Wait {
			t.Fatalf("Select waits on a full %d-byte probe %s", len(probe), hex.EncodeToString(probe))
		}
	}
	for prefixHex, want := range doc.Decisions {
		if want != nil {
			continue
		}
		waits++
		prefix, _ := hex.DecodeString(prefixHex)
		for _, filler := range fillers {
			probe := append([]byte{}, prefix...)
			for len(probe) < Lookahead {
				probe = append(probe, filler...)
			}
			check(probe[:Lookahead])
		}
		for i := 0; i < 8; i++ {
			probe := append([]byte{}, prefix...)
			for len(probe) < Lookahead {
				probe = append(probe, byte(rng.UintN(256)))
			}
			check(probe)
		}
	}
	for i := 0; i < 200000; i++ {
		probe := make([]byte, Lookahead)
		for j := range probe {
			probe[j] = byte(rng.UintN(256))
		}
		check(probe)
	}
	if waits < 100 {
		t.Fatalf("decision table has only %d Wait prefixes", waits)
	}
	t.Logf("%d Wait prefixes extended, %d full probes, none waits", waits, probes)
}

// The Inspector side of the invariant: bytes fed one at a time grow the dispatch prefix only while Select waits,
// and it never reaches Lookahead.
func TestDispatchPrefixStaysBelowLookahead(t *testing.T) {
	for _, stream := range [][]byte{
		[]byte("GET /a-long-target-path-beyond-the-lookahead HTTP/1.1\r\n"),
		append([]byte{0x16, 3, 1, 0, 0x40, 1, 0, 0, 0x3c, 3, 3}, bytes.Repeat([]byte{7}, 40)...),
		bytes.Repeat([]byte{0}, 40),
	} {
		in, err := New(contracts.DefaultConfig(), "")
		if err != nil {
			t.Fatal(err)
		}
		for i := range stream {
			in.Feed(stream[i : i+1])
			if len(in.prefix) >= Lookahead {
				t.Fatalf("%q: dispatch prefix holds %d bytes after %d fed", stream[:8], len(in.prefix), i+1)
			}
		}
	}
}

// A3 (PRO-119): a validator error that is not a *parsing.Error becomes a malformed candidate failure, not a panic.
func TestParseFailureIsACheckedAssertion(t *testing.T) {
	if e := parseFailure(errors.New("future validator")); e.Kind != "malformed" || e.Message != "Datagram validator failed without a typed reason" {
		t.Fatalf("untyped error: %#v", e)
	}
	budget := parsing.Budget("limit")
	if e := parseFailure(budget); e != budget.(*parsing.Error) {
		t.Fatalf("typed error not passed through: %#v", e)
	}
	var typedNil *parsing.Error
	if e := parseFailure(error(typedNil)); e == nil || e.Kind != "malformed" {
		t.Fatalf("typed nil: %#v", e)
	}
}
