package tlsx

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

func dtlsHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The three labelled DTLS fixtures (protocol_adapters fixtures 008, 035, 036).
const (
	dtlsClientHello = "16feff000000000000000000360100002a000000000000002afefd000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000002c02f0100"
	dtlsHelloVerify = "16fefd00000000000000000023030000170000000000000017feff14000102030405060708090a0b0c0d0e0f10111213"
	dtlsServerHello = "16fefd000000000000000000390200002d000000000000002dfefd000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00c02f000005ff01000100"
	dtlsMaxBytes    = 65536
	dtlsMaxHeaders  = 64
)

func handshakeOf(m *DTLSMatch) string {
	for _, r := range m.Rows {
		if r.Field == "handshake" {
			return r.Value
		}
	}
	return ""
}

func TestDTLSFixturesValidate(t *testing.T) {
	for payload, want := range map[string]string{dtlsClientHello: "client_hello", dtlsHelloVerify: "hello_verify_request", dtlsServerHello: "server_hello"} {
		m, err := DTLS(dtlsHex(t, payload), dtlsMaxBytes, dtlsMaxHeaders, false)
		if err != nil || handshakeOf(m) != want {
			t.Fatalf("%s: %v %+v", want, err, m)
		}
		for _, r := range m.Rows {
			if r.Field == "tls_handshake" || r.Field == "selected_tls_version" || r.Strength == "derived" {
				t.Fatalf("%s: a TLS label leaked into a DTLS flight: %+v", want, r)
			}
		}
	}
}

func kindOf(err error) string {
	if e, ok := err.(*parsing.Error); ok {
		return e.Kind
	}
	if _, ok := err.(*parsing.NotPorted); ok {
		return "notported"
	}
	return ""
}

func TestDTLSProfileBoundaries(t *testing.T) {
	base := dtlsHex(t, dtlsClientHello)
	patch := func(at int, b byte) []byte {
		out := append([]byte{}, base...)
		out[at] = b
		return out
	}
	cases := []struct {
		name string
		data []byte
		kind string
	}{
		{"short", base[:20], "malformed"},
		{"encrypted epoch", patch(4, 1), "unsupported"},
		{"two records", append(append([]byte{}, base...), 0x16), "unsupported"},
		{"fragment offset", patch(21, 1), "malformed"},
		{"TLS record version", patch(2, 0x03), "unsupported"},
		{"other handshake", patch(13, 11), "unsupported"},
		{"budget", base, "budget"},
	}
	for _, c := range cases {
		maxBytes := dtlsMaxBytes
		if c.name == "budget" {
			maxBytes = 64
		}
		if _, err := DTLS(c.data, maxBytes, dtlsMaxHeaders, false); kindOf(err) != c.kind {
			t.Fatalf("%s: %v", c.name, err)
		}
	}
	// With fingerprints the ClientHello carries its JA4 (protocol code d, DTLS 1.2 version code d2).
	if m, err := DTLS(base, dtlsMaxBytes, dtlsMaxHeaders, true); err != nil || m.Rows[len(m.Rows)-1].Field != "ja4" ||
		m.Rows[len(m.Rows)-1].Value[:4] != "dd2i" || m.Rows[len(m.Rows)-1].Strength != "derived" {
		t.Fatalf("fingerprints: %v %+v", err, m)
	}
	// The cookie is removed before the shared TLS decoder; it never becomes evidence.
	m, _ := DTLS(base, dtlsMaxBytes, dtlsMaxHeaders, false)
	for _, r := range m.Rows {
		if strings.Contains(r.Value, "0001020304") {
			t.Fatal("opaque bytes emitted")
		}
	}
}

func FuzzDTLSStaysBounded(f *testing.F) {
	for _, s := range []string{dtlsClientHello, dtlsHelloVerify, dtlsServerHello} {
		f.Add(dtlsHex(f, s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := DTLS(data, 4096, 16, false)
		if err == nil && (m == nil || handshakeOf(m) == "") {
			t.Fatal("a match without a handshake label")
		}
	})
}
