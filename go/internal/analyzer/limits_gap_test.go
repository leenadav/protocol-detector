package analyzer

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/session"
	"github.com/leenadav/protocol-detector/go/internal/testframes"
	"github.com/leenadav/protocol-detector/go/internal/transport"
)

// Limits audit (PRO-477): see go/internal/analyze/limits_gap_test.go for the convention.

func limitGap(t *testing.T, id string, fixed bool, today string) {
	t.Helper()
	if fixed {
		t.Fatalf("%s now reports its limit (docs/security/LIMITS-AUDIT-PRO-477.md): remove limitGap() and assert it plainly", id)
	}
	t.Skipf("%s (docs/security/LIMITS-AUDIT-PRO-477.md): limit hit silently, fix owned by the engine lane; today %s", id, today)
}

// quicSplitFlow sends the first 100 bytes of a QUIC ClientHello in one Initial, then (when flood > 0) partial
// Initials with flood other connection ids from other flows, then the rest of the ClientHello. It returns the
// target flow's last observation and session record.
func quicSplitFlow(t *testing.T, flood int) (contracts.Observation, map[string]interface{}, *Analyzer) {
	t.Helper()
	hello := quicHello(t)
	target := transport.Endpoint{Addr: "192.0.2.10", Port: 51000}
	server := transport.Endpoint{Addr: "198.51.100.20", Port: 443}
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	parts := testframes.CryptoFrames(hello, 100)
	a := newAnalyzer(t, session.Options{MaxConnections: 64, ByteLimit: 65536, IdleTimeout: 60, MaxUDPFlows: -1})
	a.Process(0, udp(target, server, testframes.QUICInitial(1, dcid, nil, parts[0], 1, nil, 1200)))
	for i := 0; i < flood; i++ {
		other := transport.Endpoint{Addr: "192.0.2.66", Port: uint16(30000 + i)}
		id := []byte{9, 9, 9, 9, byte(i >> 8), byte(i), 0, 1}
		a.Process(0, udp(other, server, testframes.QUICInitial(1, id, nil, parts[0], 1, nil, 1200)))
	}
	a.Process(0, udp(target, server, testframes.QUICInitial(1, dcid, nil, parts[1], 2, nil, 1200)))
	last := a.LastEvents[0].Observation
	if err := a.Finish("eof"); err != nil {
		t.Fatal(err)
	}
	for _, record := range a.Records {
		if client, _ := record["client"].([]interface{}); len(client) == 2 && client[1] == 51000 {
			return last, record, a
		}
	}
	t.Fatalf("no record for the target flow among %d", len(a.Records))
	return last, nil, a
}

// SEC-LIM-8: the QUIC CRYPTO assembler holds at most min(UDP flows, 1024) connections and evicts the least
// recently used one silently (quicx.Assembler.Counts["evictions"], never read by any output). An on-path sender
// that interleaves 64 partial Initials from other flows between the two halves of a ClientHello evicts the
// target's first half: the ClientHello never assembles, so its SNI and ALPN are lost (hostname-based application
// identity and policy are evaded), and neither the observation, the record nor any summary says that the
// reassembly state was evicted. Counts "expired", "exhausted" and "conflicts" are never surfaced either.
func TestLimitGapQUICAssemblerEvictionIsReported(t *testing.T) {
	clean, _, _ := quicSplitFlow(t, 0)
	if clean.Hostname == nil || *clean.Hostname != "example.com" {
		t.Fatalf("reproducer drifted: the split ClientHello alone gives hostname %v (%s)", clean.Hostname, clean.Reason)
	}
	evaded, record, a := quicSplitFlow(t, 64)
	if evaded.Hostname != nil || a.udp.Assembler.Counts["evictions"] < 1 {
		t.Fatalf("reproducer drifted: hostname %v after %d evictions", evaded.Hostname, a.udp.Assembler.Counts["evictions"])
	}
	text, _ := json.Marshal(record)
	fixed := strings.Contains(strings.ToLower(string(text)), "evict") || strings.Contains(strings.ToLower(evaded.Reason), "evict")
	limitGap(t, "SEC-LIM-8", fixed, "after "+jsonInt(a.udp.Assembler.Counts["evictions"])+" silent evictions the target's SNI is gone and "+
		"its reason reads \""+evaded.Reason+"\"")
}

// SEC-LIM-9: a UDP flow keeps its first identified observation (Tracker.ProcessUDP), so when the first Initial
// identifies QUIC with a partial ClientHello and the next one completes it, the session record keeps the partial
// one: reasons "ClientHello incomplete", and with IncludeHostnames the record's hostname is null although a later
// datagram of the same flow validated the ClientHello with SNI example.com. A ClientHello larger than one Initial
// (common with post-quantum key shares) therefore never reaches the record: the later, complete result is hidden.
func TestLimitGapUDPRecordHidesLaterCompleteObservation(t *testing.T) {
	pack := newAnalyzer(t, session.Options{MaxConnections: 8, ByteLimit: 65536, IdleTimeout: 60, MaxUDPFlows: -1}).pack
	a, err := New(pack, Options{IncludeHostnames: true, Session: session.Options{MaxConnections: 8, ByteLimit: 65536, IdleTimeout: 60, MaxUDPFlows: -1}})
	if err != nil {
		t.Fatal(err)
	}
	hello := quicHello(t)
	quicClient := transport.Endpoint{Addr: "192.0.2.10", Port: 51000}
	quicServer := transport.Endpoint{Addr: "198.51.100.20", Port: 443}
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	parts := testframes.CryptoFrames(hello, 100)
	a.Process(0, udp(quicClient, quicServer, testframes.QUICInitial(1, dcid, nil, parts[0], 1, nil, 1200)))
	a.Process(0, udp(quicClient, quicServer, testframes.QUICInitial(1, dcid, nil, parts[1], 2, nil, 1200)))
	last := a.LastEvents[0].Observation
	if err := a.Finish("eof"); err != nil {
		t.Fatal(err)
	}
	if last.Hostname == nil || *last.Hostname != "example.com" || len(a.Records) != 1 {
		t.Fatalf("reproducer drifted: the second Initial gives hostname %v (%s), %d records", last.Hostname, last.Reason, len(a.Records))
	}
	record := a.Records[0]
	fixed := record["hostname"] == "example.com"
	limitGap(t, "SEC-LIM-9", fixed, "the last datagram asserts SNI example.com but the record has hostname "+jsonText(record["hostname"])+
		" and reasons "+jsonText(record["reasons"]))
}

func jsonInt(n int) string { text, _ := json.Marshal(n); return string(text) }

func jsonText(v interface{}) string { text, _ := json.Marshal(v); return string(text) }
