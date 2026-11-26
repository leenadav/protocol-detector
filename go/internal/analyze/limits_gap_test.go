package analyze

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/testframes"
)

// Limits audit (PRO-477, docs/security/LIMITS-AUDIT-PRO-477.md): every limit, budget, cap or eviction that is hit
// must show in the output as a counter or a reason. Each test below reproduces one gap at scale, in the style of
// the external 800-flow proof of concept, and asserts the behaviour the audit asks for. While today's behaviour
// persists the test is skipped with the finding id; once a fix makes it pass, limitGap fails so the marker is
// removed and the test becomes a plain assertion (the convention of engine/postmerge_test.go). Synthetic frames
// only; nothing here changes product code.

const auditDoc = "docs/security/LIMITS-AUDIT-PRO-477.md"

func limitGap(t *testing.T, id string, fixed bool, today string) {
	t.Helper()
	if fixed {
		t.Fatalf("%s now reports its limit (%s): remove limitGap() and assert it plainly", id, auditDoc)
	}
	t.Skipf("%s (%s): limit hit silently, fix owned by the engine lane; today %s", id, auditDoc, today)
}

// sameInstant is a classic capture whose frames all carry one timestamp, so no flow reaches the idle timeout and
// the table limit, not expiry, decides what is tracked.
func sameInstant(frames ...[]byte) []byte {
	out := classicCapture(frames...)
	pos := 24
	for range frames {
		binary.LittleEndian.PutUint32(out[pos:], 1700000000)
		pos += 16 + int(binary.LittleEndian.Uint32(out[pos+8:]))
	}
	return out
}

// dnsQuery is a standard query for example.com A.
func dnsQuery(id uint16) []byte {
	q := []byte{byte(id >> 8), byte(id), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	q = append(q, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1)
	return q
}

// udpFlows is one DNS query from each of n client ports: n distinct UDP flows.
func udpFlows(n int) [][]byte {
	frames := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		frames = append(frames, testframes.UDP("192.0.2.10", uint16(20000+i), "198.51.100.53", 53, dnsQuery(uint16(i))))
	}
	return frames
}

// runAnalyze writes the frames as a classic capture and returns the JSON rows and the summary counters.
func runAnalyze(t *testing.T, frames [][]byte) (rows []map[string]interface{}, counts *Counts) {
	t.Helper()
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "capture.pcap")
	if err := os.WriteFile(path, sameInstant(frames...), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	counts, err = Run(path, pack, Options{JSON: true, Sessions: true}, &out)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var row map[string]interface{}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("row %q: %v", line, err)
		}
		rows = append(rows, row)
	}
	return rows, counts
}

func sessionRows(rows []map[string]interface{}) int {
	n := 0
	for _, row := range rows {
		if row["type"] == "session" {
			n++
		}
	}
	return n
}

// reported is the sum of the summary counters whose name contains any of the words.
func reported(counts *Counts, words ...string) int {
	total := 0
	for key, value := range counts.Values {
		for _, w := range words {
			if strings.Contains(key, w) {
				total += value
				break
			}
		}
	}
	return total
}

// SEC-LIM-1: the kidcarmi case. analyze tracks at most 32 UDP flows (MaxConnections 32, MaxUDPFlows -1); 800 flows
// give 32 session records and a summary with no counter for the 768 flows that were never recorded. The tracker
// counts them (Tracker.Counts["udp_flow_limit"]) but Run never copies Tracker.Counts into the summary.
func TestLimitGapAnalyzeUDPFlowLimitInSummary(t *testing.T) {
	rows, counts := runAnalyze(t, udpFlows(800))
	if got := sessionRows(rows); got != 32 {
		t.Fatalf("reproducer drifted: %d UDP session records, want 32 (the flow table limit)", got)
	}
	fixed := reported(counts, "udp_flow_limit", "flow_limit") == 800-32
	limitGap(t, "SEC-LIM-1", fixed, "summary "+summaryText(counts)+" has no counter for 768 unrecorded flows")
}

// SEC-LIM-2: the TCP side of the same table. Each SYN beyond 32 tracked connections gets the frame message
// "LIMIT: too many tracked connections" and nothing else: no session record, no summary counter (live counts it
// as connection_limit; analyze does not). With --events-only the frame rows are gone too.
func TestLimitGapAnalyzeTCPConnectionLimitInSummary(t *testing.T) {
	frames := make([][]byte, 0, 800)
	for i := 0; i < 800; i++ {
		frames = append(frames, testframes.TCP("192.0.2.10", uint16(20000+i), "198.51.100.80", 80, 1000, 0, 0x02, nil))
	}
	rows, counts := runAnalyze(t, frames)
	limited := 0
	for _, row := range rows {
		if m, _ := row["message"].(string); strings.HasPrefix(m, "LIMIT") {
			limited++
		}
	}
	if limited != 800-32 || sessionRows(rows) != 32 {
		t.Fatalf("reproducer drifted: %d LIMIT frames, %d sessions", limited, sessionRows(rows))
	}
	fixed := reported(counts, "connection_limit", "limit") == 800-32
	limitGap(t, "SEC-LIM-2", fixed, "summary "+summaryText(counts)+" has no counter for 768 refused connections")
}

// SEC-LIM-3: TCP whose start was not observed (handshake mode) is skipped per frame ("SKIP: connection beginning
// not observed") and never counted: 800 mid-stream HTTP requests give zero sessions and a summary that reads as a
// clean capture of 800 TCP frames. Live counts the same frames as tcp_without_start.
func TestLimitGapAnalyzeTCPWithoutStartInSummary(t *testing.T) {
	frames := make([][]byte, 0, 800)
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	for i := 0; i < 800; i++ {
		frames = append(frames, testframes.TCP("192.0.2.10", uint16(20000+i), "198.51.100.80", 80, 5000, 7000, 0x18, request))
	}
	rows, counts := runAnalyze(t, frames)
	if sessionRows(rows) != 0 || counts.Values["tcp"] != 800 {
		t.Fatalf("reproducer drifted: %d sessions, %d tcp", sessionRows(rows), counts.Values["tcp"])
	}
	fixed := reported(counts, "without_start", "not_observed") == 800
	limitGap(t, "SEC-LIM-3", fixed, "summary "+summaryText(counts)+" has no counter for 800 skipped segments")
}

// SEC-LIM-4: Present (the presentation service and its /api/analyze) tracks at most 256 UDP flows; 800 flows give
// 256 sessions and a meta block with no counter for the 544 flows that were dropped.
func TestLimitGapPresentFlowLimitInMeta(t *testing.T) {
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	text, err := Present(sameInstant(udpFlows(800)...), pack, DefaultLimits, func() float64 { return 0 })
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Sessions []map[string]interface{} `json:"sessions"`
		Meta     map[string]interface{}   `json:"meta"`
	}
	if err := json.Unmarshal([]byte(text), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Sessions) != 256 {
		t.Fatalf("reproducer drifted: %d sessions, want 256", len(doc.Sessions))
	}
	fixed := false
	for key, value := range doc.Meta {
		if n, ok := value.(float64); ok && strings.Contains(key, "limit") && int(n) == 800-256 {
			fixed = true
		}
	}
	limitGap(t, "SEC-LIM-4", fixed, "meta keys have no counter for 544 dropped flows")
}

// SEC-LIM-5: Present attaches at most 60 events to a session record and drops the rest without a marker: a flow of
// 100 datagrams has 100 events in meta.events but 60 on its record, and nothing on the record says 40 are missing
// (a later invalidation among them would be hidden from the session view).
func TestLimitGapPresentSessionEventCap(t *testing.T) {
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	frames := make([][]byte, 0, 100)
	for i := 0; i < 100; i++ {
		frames = append(frames, testframes.UDP("192.0.2.10", 20000, "198.51.100.53", 53, dnsQuery(uint16(i))))
	}
	text, err := Present(sameInstant(frames...), pack, DefaultLimits, func() float64 { return 0 })
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Sessions []map[string]interface{} `json:"sessions"`
		Meta     map[string]interface{}   `json:"meta"`
	}
	if err := json.Unmarshal([]byte(text), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Sessions) != 1 || doc.Meta["events"] != float64(100) {
		t.Fatalf("reproducer drifted: %d sessions, %v events", len(doc.Sessions), doc.Meta["events"])
	}
	record := doc.Sessions[0]
	own, _ := record["events"].([]interface{})
	fixed := len(own) == 100
	for key := range record {
		if key != "events" && strings.HasPrefix(key, "events") {
			fixed = true // e.g. events_total or events_truncated
		}
	}
	limitGap(t, "SEC-LIM-5", fixed, "the record carries 60 of 100 events and no truncation marker")
}

// SEC-LIM-6: one UDP flow whose first datagram identifies DNS and whose later datagrams identify another family.
// The flow keeps the first identification (Tracker.ProcessUDP), so the record says dns and nothing says a later
// datagram of the same flow was identified as something else: a mixed outcome hidden inside one session.
func TestLimitGapAnalyzeUDPMixedOutcomeHidden(t *testing.T) {
	// a STUN Binding request (RFC 8489): type 1, length 0, the magic cookie, a 12-byte transaction id
	stun := append([]byte{0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42}, []byte("transaction1")...)
	frames := [][]byte{testframes.UDP("192.0.2.10", 20000, "198.51.100.53", 53, dnsQuery(1))}
	for i := 0; i < 20; i++ {
		frames = append(frames, testframes.UDP("192.0.2.10", 20000, "198.51.100.53", 53, stun))
	}
	rows, _ := runAnalyze(t, frames)
	protocols := map[string]bool{}
	var record map[string]interface{}
	for _, row := range rows {
		if c, ok := row["classification"].(map[string]interface{}); ok && c["status"] == "identified" {
			if p, ok := c["application_protocol"].(string); ok {
				protocols[p] = true
			}
		}
		if row["type"] == "session" {
			record = row
		}
	}
	if len(protocols) < 2 || record == nil {
		t.Fatalf("reproducer drifted: it needs two identified families on one flow; got %v", protocols)
	}
	text, _ := json.Marshal(record)
	fixed := true
	for p := range protocols {
		if !strings.Contains(string(text), `"`+p+`"`) {
			fixed = false
		}
	}
	limitGap(t, "SEC-LIM-6", fixed, "frames identified "+keys(protocols)+"; the session record names only the first")
}

func keys(m map[string]bool) string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func summaryText(counts *Counts) string {
	text, _ := json.Marshal(counts.Values)
	return string(text)
}
