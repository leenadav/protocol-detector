package quicx

import (
	"encoding/hex"
	"fmt"
	"github.com/leenadav/protocol-detector/go/internal/parsertest"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/testframes"
)

// SR-24: a client Initial carrying source and destination connection IDs and a retry token is identified, but
// no connection ID or token byte appears anywhere in the match (evidence, reason, hostname, ALPN); only the
// closed label initial_token=present records that a token was there. A ClientHello split across two datagrams
// assembles only through an Assembler: without one each half stays partial and names no server.
func TestSecurityQUICNeverEmitsConnectionIDsOrTokens(t *testing.T) {
	hello := load(t, "rfc9001_client_hello.hex")
	scid := []byte{0x5c, 0x1d, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	token := []byte{0x7a, 0x0c, 0xe4, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}
	frame := testframes.CryptoFrames(hello)[0]
	m, err := Validate(testframes.QUICInitial(V1, dcid, scid, frame, 2, token, 1200), defaults, nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !m.HasHost || m.Hostname != "example.com" || fieldsOf(m)["initial_token"] != "present" {
		t.Fatalf("match %+v", m)
	}
	rendered := parsertest.Rendered(*m)
	for _, r := range m.Evidence {
		rendered += fmt.Sprintf(" %x %x", r.Field, r.Value)
	}
	for _, secret := range [][]byte{dcid, scid, token} {
		for _, form := range []string{hex.EncodeToString(secret), hex.EncodeToString(secret[:4]), fmt.Sprint(secret), string(secret)} {
			if strings.Contains(rendered, form) {
				t.Fatalf("a connection ID or token (%s) is emitted: %s", form, rendered)
			}
		}
	}
	frames := testframes.CryptoFrames(hello, 100)
	for i, half := range frames {
		m, err := Validate(testframes.QUICInitial(V1, dcid, nil, half, uint32(2+i), nil, 1200), defaults, nil, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if m.HasHost || fieldsOf(m)["crypto_assembly"] == "complete" {
			t.Fatalf("half %d assembled without an assembler: %+v", i, m)
		}
	}
}
