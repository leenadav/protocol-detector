package engine

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
)

// The plaintext of an identified TLS envelope (here a ServerHello direction) carries POP3 STLS and a second,
// inner ClientHello. Expectations from the Python reference (Inspector.feed_decrypted); every row the inner
// inspection derives keeps the "decrypted" provenance, including the shifted phase after STLS (the shifted phase
// once restarted as "wire", which the feed_decrypted differential caught).
func TestDecryptedPlaintextRefinesTheEnvelope(t *testing.T) {
	if _, err := mustNew(t).FeedDecrypted([]byte("x")); err == nil || !strings.Contains(err.Error(), "Decrypted data requires a previously identified TLS envelope") {
		t.Fatalf("before identification: %v", err)
	}
	in := mustNew(t)
	in.Feed(unhex("1603030038020000340303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00130200000c002b00020304002900020001"))
	var kinds []string
	for _, chunk := range []string{"53544c530d0a16", "030300", "4b010000470303000000000000000000000000000000000000000000000000000000000000000000000613011302c02f0100001800000014001200000f7777772e6578616d706c652e636f6d"} {
		events, err := in.FeedDecrypted(unhex(chunk))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range events {
			kinds = append(kinds, string(e.Kind))
		}
	}
	o := in.Observation
	if strings.Join(kinds, ",") != "refined,refined" || o.Status != contracts.Identified || o.Encryption == nil || *o.Encryption != "tls" ||
		o.Hostname == nil || *o.Hostname != "www.example.com" || o.Application != nil ||
		o.Reason != "TLS envelope retained; plaintext: After starttls boundary: ClientHello structure validated; SNI/ALPN are client assertions, not decrypted content" {
		t.Fatalf("%v %+v", kinds, o)
	}
	var rows []string
	for _, e := range o.Evidence[6:] {
		rows = append(rows, e.Field+"="+e.Source)
	}
	if got := strings.Join(rows, " "); got != "encryption=decrypted candidate_hint=shift:starttls hostname=decrypted:tls_sni tls_offered_max_version=decrypted:client_hello shift=decrypted shift_from=decrypted" {
		t.Fatalf("inner rows: %s", got)
	}
	if m := in.DecryptedMetrics(); m == nil || m.BytesReceived != 86 || m.ParserCalls != 4 || m.EventsEmitted != 2 {
		t.Fatalf("decrypted metrics %+v", m)
	}
}

func mustNew(t *testing.T) *Inspector {
	t.Helper()
	in, err := New(contracts.DefaultConfig(), "")
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
