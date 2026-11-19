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

// PM-3: a server that selects a well-formed TLS 1.2 suite the posture table does not list (0x009c,
// TLS_RSA_WITH_AES_128_GCM_SHA256, offered by the client) loses its server-side identification today: the session
// still identifies from the ClientHello, but server_protocol stays empty and no posture is recorded, while a listed
// suite (0xc02f, the control, asserted plainly) gives server_protocol "tls". The item asks that the server side
// stay identified, with the suite reported as outside the posture profile. (On a clean flow the unlisted suite does
// not invalidate the session; the 211 invalidated D09 sessions in research/d09-iscx-vpn2016.md need the re-run to
// show what invalidated them; see POST-MERGE-BACKLOG.md.)
func TestPM3_UnlistedTLS12SuiteKeepsTheServerSideIdentification(t *testing.T) {
	control := tlsSession(t, helloOffering(0x009c, 0xc02f), serverHelloSelecting(0xc02f))
	if control["engine_status"] != "identified" || serverProtocol(control) != "tls" {
		t.Fatalf("control session with a listed suite: %v", control)
	}
	record := tlsSession(t, helloOffering(0x009c, 0xc02f), serverHelloSelecting(0x009c))
	if record["engine_status"] != "identified" {
		t.Fatalf("the session itself is no longer identified: %v", record)
	}
	got := serverProtocol(record)
	pendingItem(t, "PM-3", got == "tls", "server_protocol is "+strconv.Quote(got))
}
