package analyzer

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"

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
