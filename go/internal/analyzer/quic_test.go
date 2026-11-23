package analyzer

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/session"
	"github.com/leenadav/protocol-detector/go/internal/testframes"
	"github.com/leenadav/protocol-detector/go/internal/transport"
)

func quicHello(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../protocols/quicx/testdata/rfc9001_client_hello.hex")
	if err != nil {
		t.Fatal(err)
	}
	hello, _ := hex.DecodeString(strings.TrimSpace(string(raw)))
	return hello
}

func udp(src, dst transport.Endpoint, payload []byte) *transport.UDP {
	return &transport.UDP{Source: src, Destination: dst, Payload: payload}
}

// Codex finding R2: a retired UDP flow resets the QUIC CRYPTO state of both directions. A conflict marker made by
// server-to-client datagrams must not outlive the flow: at exactly the idle timeout the flow retires while the
// assembler entry (expiring only strictly beyond it) would still hold the marker, so a new flow on the tuple whose
// first datagram is a PING-only Initial from the same endpoint would be invalidated by the old flow's conflict.
func TestRetiredUDPFlowResetsBothQUICScopes(t *testing.T) {
	hello := quicHello(t)
	quicClient := transport.Endpoint{Addr: "192.0.2.10", Port: 51000}
	quicServer := transport.Endpoint{Addr: "198.51.100.20", Port: 443}
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	changed := append([]byte{}, hello...)
	changed[150] ^= 0xff
	a := newAnalyzer(t, session.Options{MaxConnections: 8, ByteLimit: 65536, IdleTimeout: 60, MaxUDPFlows: -1})
	a.Process(0, udp(quicClient, quicServer, testframes.QUICInitial(1, []byte{9, 9, 9, 9}, nil, testframes.CryptoFrames(hello)[0], 1, nil, 1200)))
	// Server-to-client datagrams (client-keyed for the test) build and then contradict an assembly in the "S>C" scope.
	a.Process(1, udp(quicServer, quicClient, testframes.QUICInitial(1, dcid, nil, testframes.CryptoFrames(hello, 100)[1], 1, nil, 1200)))
	a.Process(1, udp(quicServer, quicClient, testframes.QUICInitial(1, dcid, nil, testframes.CryptoFrames(changed, 140)[1], 2, nil, 1200)))
	if status := a.LastEvents[0].Observation.Status; status != contracts.Invalidated {
		t.Fatalf("server-direction contradiction: %s", status)
	}
	// At t = 61 the flow (last packet at t = 1) is retired by the idle timeout before the datagram is inspected.
	a.Process(61, udp(quicServer, quicClient, testframes.QUICInitial(1, dcid, nil, []byte{1}, 3, nil, 1200)))
	if len(a.Records) != 1 || a.Records[0]["engine_status"] != "invalidated" {
		t.Fatalf("the first flow's record: %v", a.Records)
	}
	if status := a.LastEvents[0].Observation.Status; status != contracts.Identified {
		t.Fatalf("the old flow's conflict marker outlived it: %s (%s)", status, a.LastEvents[0].Observation.Reason)
	}
	if a.udp.Assembler.Len() != 0 {
		t.Fatalf("%d assembler entries after the reset", a.udp.Assembler.Len())
	}
}

// withServerName returns the RFC 9001 ClientHello with its SNI "example.com" replaced by another 11-byte name.
func withServerName(t *testing.T, hello []byte, name string) []byte {
	t.Helper()
	at := strings.Index(string(hello), "example.com")
	if at < 0 || len(name) != len("example.com") {
		t.Fatal("the fixture's server name is not where the test expects it")
	}
	out := append([]byte{}, hello...)
	copy(out[at:], name)
	return out
}

// sessionHost runs datagrams from one client to one server through a fresh analyzer and returns the flow record.
func sessionHost(t *testing.T, datagrams ...[]byte) map[string]interface{} {
	t.Helper()
	client := transport.Endpoint{Addr: "192.0.2.10", Port: 51000}
	server := transport.Endpoint{Addr: "198.51.100.20", Port: 443}
	pack, err := content.Load(packPath)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(pack, Options{IncludeHostnames: true, Session: session.Options{MaxConnections: 8, ByteLimit: 65536, IdleTimeout: 60, MaxUDPFlows: -1}})
	if err != nil {
		t.Fatal(err)
	}
	for i, d := range datagrams {
		a.Process(float64(i), udp(client, server, d))
	}
	if err := a.Finish("end"); err != nil {
		t.Fatal(err)
	}
	if len(a.Records) != 1 {
		t.Fatalf("records: %v", a.Records)
	}
	return a.Records[0]
}

// SEC-QUIC-3 (PRO-47, PRO-123; a Go-only divergence Lee approved on PRO-124): a client Initial datagram below
// the RFC 9000 section 14.1 minimum of 1200 bytes is one a server discards. A decoy of 1000 bytes with SNI A on
// the real connection's DCID used to fix the flow's server name (or, as here, poison the CRYPTO assembly so the
// real 1200-byte Initial with SNI B invalidated the flow). Now the decoy is not evidence and B is identified.
func TestUndersizedDecoyInitialDoesNotFixTheServerName(t *testing.T) {
	hello := quicHello(t)
	decoy := withServerName(t, hello, "decoy.test0")
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	record := sessionHost(t,
		testframes.QUICInitial(1, dcid, nil, testframes.CryptoFrames(decoy)[0], 1, nil, 1000),
		testframes.QUICInitial(1, dcid, nil, testframes.CryptoFrames(hello)[0], 2, nil, 1200))
	if record["engine_status"] != "identified" || record["hostname"] != "example.com" {
		t.Fatalf("decoy then real Initial: status %v host %v", record["engine_status"], record["hostname"])
	}
	// The decoy on another DCID, alone first: it must not become the flow's first identification either.
	record = sessionHost(t,
		testframes.QUICInitial(1, []byte{9, 9, 9, 9}, nil, testframes.CryptoFrames(decoy)[0], 1, nil, 1000),
		testframes.QUICInitial(1, dcid, nil, testframes.CryptoFrames(hello)[0], 2, nil, 1200))
	if record["engine_status"] != "identified" || record["hostname"] != "example.com" {
		t.Fatalf("decoy on another DCID: status %v host %v", record["engine_status"], record["hostname"])
	}
}

// SEC-QUIC-3: two complete ClientHellos on one flow that name different servers (here on two DCIDs, which never
// meet in the CRYPTO assembler) invalidate the flow instead of keeping the first name; an identical ClientHello on
// a new DCID (the client's Initial after a Retry) keeps the identification.
func TestDisagreeingClientHellosOnOneFlowInvalidateIt(t *testing.T) {
	hello := quicHello(t)
	other := withServerName(t, hello, "example.org")
	first, second := []byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte{8, 7, 6, 5, 4, 3, 2, 1}
	record := sessionHost(t,
		testframes.QUICInitial(1, first, nil, testframes.CryptoFrames(hello)[0], 1, nil, 1200),
		testframes.QUICInitial(1, second, nil, testframes.CryptoFrames(other)[0], 1, nil, 1200))
	if record["engine_status"] != "invalidated" || record["hostname"] != nil {
		t.Fatalf("A then B on two DCIDs: status %v host %v", record["engine_status"], record["hostname"])
	}
	record = sessionHost(t,
		testframes.QUICInitial(1, first, nil, testframes.CryptoFrames(hello)[0], 1, nil, 1200),
		testframes.QUICInitial(1, second, nil, testframes.CryptoFrames(hello)[0], 1, nil, 1200))
	if record["engine_status"] != "identified" || record["hostname"] != "example.com" {
		t.Fatalf("the same ClientHello on a new DCID: status %v host %v", record["engine_status"], record["hostname"])
	}
}
