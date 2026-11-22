package analyzer

import (
	"strconv"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/session"
	"github.com/leenadav/protocol-detector/go/internal/transport"
)

// Post-merge detection items (migration/POST-MERGE-BACKLOG.md), prepared before the merge (2026-11-19); see
// go/internal/engine/postmerge_test.go for the convention. Synthetic messages only; no detection code changes.

func pendingItem(t *testing.T, item string, fixed bool, today string) {
	t.Helper()
	if fixed {
		t.Fatalf("%s now behaves as POST-MERGE-BACKLOG.md asks: remove pendingItem() and assert it plainly", item)
	}
	t.Skipf("%s (migration/POST-MERGE-BACKLOG.md): post-merge, Go-only fix; today %s", item, today)
}

func tlsRecord(handshake []byte) []byte {
	return append([]byte{0x16, 3, 3, byte(len(handshake) >> 8), byte(len(handshake))}, handshake...)
}

// helloOffering is a TLS 1.2 ClientHello offering the given suites, without extensions.
func helloOffering(suites ...uint16) []byte {
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, byte(len(suites)*2>>8), byte(len(suites)*2))
	for _, s := range suites {
		body = append(body, byte(s>>8), byte(s))
	}
	body = append(body, 1, 0)
	return tlsRecord(append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...))
}

// serverHelloSelecting is a TLS 1.2 ServerHello selecting suite, without extensions.
func serverHelloSelecting(suite uint16) []byte {
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body[2] = 0x5a // a nonzero server random
	body = append(body, 0, byte(suite>>8), byte(suite), 0)
	return tlsRecord(append([]byte{2, 0, byte(len(body) >> 8), byte(len(body))}, body...))
}

// tlsSession runs one TCP connection to port 443 (handshake, ClientHello, ServerHello, FIN both ways) and returns
// the TCP session record.
func tlsSession(t *testing.T, hello, reply []byte) map[string]interface{} {
	t.Helper()
	a := newAnalyzer(t, session.Options{MaxConnections: 4, ByteLimit: 65536, IdleTimeout: 60, MaxUDPFlows: -1})
	web := transport.Endpoint{Addr: "198.51.100.30", Port: 443}
	a.Process(0, seg(client, web, 999, 0, transport.SYN, nil))
	a.Process(0, seg(web, client, 8999, 1000, transport.SYN|transport.ACK, nil))
	a.Process(0, seg(client, web, 1000, 9000, transport.ACK, nil))
	a.Process(0.001, seg(client, web, 1000, 9000, transport.ACK|8, hello))
	a.Process(0.002, seg(web, client, 9000, 1000+uint32(len(hello)), transport.ACK|8, reply))
	a.Process(0.003, seg(client, web, 1000+uint32(len(hello)), 9000+uint32(len(reply)), transport.ACK|transport.FIN, nil))
	a.Process(0.004, seg(web, client, 9000+uint32(len(reply)), 1001+uint32(len(hello)), transport.ACK|transport.FIN, nil))
	if err := a.Finish("eof"); err != nil {
		t.Fatal(err)
	}
	if a.NotPorted != nil {
		t.Fatal(a.NotPorted)
	}
	for _, r := range a.Records {
		if r["transport"] == "tcp" {
			return r
		}
	}
	t.Fatalf("no TCP record in %v", a.Records)
	return nil
}

func serverProtocol(r map[string]interface{}) string {
	switch v := r["server_protocol"].(type) {
	case string:
		return v
	case *string:
		if v != nil {
			return *v
		}
	}
	return ""
}

// serverHelloVersion is a ServerHello with the given legacy version, suite and compression, without extensions.
func serverHelloVersion(version, suite uint16, compression byte) []byte {
	body := []byte{byte(version >> 8), byte(version)}
	body = append(body, make([]byte, 32)...)
	body[2] = 0x5a
	body = append(body, 0, byte(suite>>8), byte(suite), compression)
	return tlsRecord(append([]byte{2, 0, byte(len(body) >> 8), byte(len(body))}, body...))
}

func hasRisk(r map[string]interface{}, risk string) bool {
	switch list := r["risks"].(type) {
	case []string:
		for _, x := range list {
			if x == risk {
				return true
			}
		}
	case []interface{}:
		for _, x := range list {
			if x == risk {
				return true
			}
		}
	}
	return false
}

// PM-3 under the ServerHello widening Hermes decided (2026-11-19; research/protocol/tls-serverhello-legacy.md): any
// IANA-registered suite keeps the server-side identification, and TLS 1.0/1.1 or a weak suite becomes a risk mark
// (RFC 8996), not a lost identification; a malformed ServerHello still identifies nothing. Today only 0x002f and
// 0xc023..0xc032 at legacy version 0x0303 identify the server side. In every case the session itself stays
// identified from the ClientHello (asserted plainly); what is at stake is server_protocol and the risks. The guards
// (a selected SCSV or GREASE value, SSL 3.0, a nonzero compression method) must stay unidentified, today and after.
func TestPM3_ServerHelloWidening(t *testing.T) {
	offer := helloOffering(0x009c, 0xcca8, 0xc013, 0x0035, 0x002f, 0x00ff, 0x0a0a, 0xc02f)
	if control := tlsSession(t, offer, serverHelloVersion(0x0303, 0xc02f, 0)); serverProtocol(control) != "tls" {
		t.Fatalf("control: a listed suite does not identify the server side: %v", control)
	}
	for _, guard := range []struct {
		name           string
		version, suite uint16
		compression    byte
	}{{"V6 TLS_EMPTY_RENEGOTIATION_INFO_SCSV selected", 0x0303, 0x00ff, 0}, {"V7 GREASE 0x0a0a selected", 0x0303, 0x0a0a, 0},
		{"V8 SSL 3.0", 0x0300, 0x002f, 0}, {"compression method 1", 0x0303, 0xc02f, 1}} {
		r := tlsSession(t, offer, serverHelloVersion(guard.version, guard.suite, guard.compression))
		if r["engine_status"] != "identified" || serverProtocol(r) != "" {
			t.Errorf("%s: must stay unidentified on the server side with the session identified: %v", guard.name, r)
		}
	}
	cases := []struct {
		name           string
		version, suite uint16
		risk           string // a risk the item asks for; "" when none is specified
	}{
		{"V1 0x009c TLS_RSA_WITH_AES_128_GCM_SHA256", 0x0303, 0x009c, "tls-no-forward-secrecy"},
		{"V2 0xcca8 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0x0303, 0xcca8, ""},
		{"V3 0xc013 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 0x0303, 0xc013, ""},
		{"V4 TLS 1.0 with 0x0035", 0x0301, 0x0035, "tls-deprecated-version-selected"},
		{"V5 TLS 1.1 with 0x002f", 0x0302, 0x002f, "tls-deprecated-version-selected"},
	}
	met, today := 0, ""
	for _, c := range cases {
		r := tlsSession(t, offer, serverHelloVersion(c.version, c.suite, 0))
		if r["engine_status"] != "identified" {
			t.Fatalf("%s: the session itself is no longer identified: %v", c.name, r)
		}
		if serverProtocol(r) == "tls" && (c.risk == "" || hasRisk(r, c.risk)) {
			met++
		} else if today == "" {
			today = c.name + ": server_protocol " + strconv.Quote(serverProtocol(r))
		}
	}
	pendingItem(t, "PM-3", met == len(cases), strconv.Itoa(met)+" of "+strconv.Itoa(len(cases))+" vectors meet the decision ("+today+")")
}
