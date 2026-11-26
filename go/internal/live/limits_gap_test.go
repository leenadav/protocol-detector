package live

import (
	"encoding/json"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/capture"
	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/testframes"
)

// Limits audit (PRO-477): see go/internal/analyze/limits_gap_test.go for the convention.

const auditDoc = "docs/security/LIMITS-AUDIT-PRO-477.md"

func limitGap(t *testing.T, id string, fixed bool, today string) {
	t.Helper()
	if fixed {
		t.Fatalf("%s now reports its limit (%s): remove limitGap() and assert it plainly", id, auditDoc)
	}
	t.Skipf("%s (%s): limit hit silently, fix owned by the engine lane; today %s", id, auditDoc, today)
}

// SEC-LIM-7: the live summary counts TCP connections refused at the table limit (connection_limit) but not UDP
// flows: with 32 connections, 800 DNS flows give 32 session events and a final summary whose counts have no
// entry for the 768 flows the tracker refused (Tracker.Counts["udp_flow_limit"] is never copied into m.counts).
func TestLimitGapLiveUDPFlowLimitInSummary(t *testing.T) {
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	var events []Event
	m, err := NewMonitor(pack, Options{MaxConnections: 32, ByteLimit: 16384, IdleTimeout: 60, CRC32CByteLimit: 4096, Observation: "handshake",
		Checksums: "ignore"}, "0123456789abcdef", func(e Event) { events = append(events, e) })
	if err != nil {
		t.Fatal(err)
	}
	query := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	for i := 0; i < 800; i++ {
		frame := testframes.UDP("192.0.2.10", uint16(20000+i), "198.51.100.53", 53, query)
		if err := m.Accept(capture.Record{Timestamp: 1, Data: frame, OriginalLength: len(frame), Linktype: 1}, 1); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.End("Capture stopped"); err != nil {
		t.Fatal(err)
	}
	sessions := 0
	for _, e := range events {
		if e.Kind == "session" {
			sessions++
		}
	}
	if sessions < 32 || sessions > 40 {
		t.Fatalf("reproducer drifted: %d session events, want about 32", sessions)
	}
	summary := m.Summary(1, true, nil, nil)
	counts, _ := summary.Fields["counts"].(map[string]interface{})
	fixed := false
	for key, value := range counts {
		if n, ok := value.(int); ok && n+sessions == 800 && (key == "udp_flow_limit" || key == "connection_limit") {
			fixed = true
		}
	}
	text, _ := json.Marshal(counts)
	limitGap(t, "SEC-LIM-7", fixed, "final counts "+string(text)+" have no entry for 768 refused UDP flows")
}
