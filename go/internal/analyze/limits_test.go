package analyze

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/session"
)

// ipv4Frame is an Ethernet II frame carrying one IPv4 packet (valid header checksum, transport checksum 0).
func ipv4Frame(protocol byte, src, dst [4]byte, transportHeader, payload []byte) []byte {
	frame := make([]byte, 14, 14+20+len(transportHeader)+len(payload))
	binary.BigEndian.PutUint16(frame[12:], 0x0800)
	ip := make([]byte, 20)
	ip[0], ip[8], ip[9] = 0x45, 64, protocol
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(transportHeader)+len(payload)))
	copy(ip[12:], src[:])
	copy(ip[16:], dst[:])
	sum := 0
	for i := 0; i < 20; i += 2 {
		sum += int(binary.BigEndian.Uint16(ip[i:]))
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(ip[10:], ^uint16(sum))
	return append(append(append(frame, ip...), transportHeader...), payload...)
}

func udpFrame(src, dst [4]byte, sport, dport uint16, payload []byte) []byte {
	header := make([]byte, 8)
	binary.BigEndian.PutUint16(header[0:], sport)
	binary.BigEndian.PutUint16(header[2:], dport)
	binary.BigEndian.PutUint16(header[4:], uint16(8+len(payload)))
	return ipv4Frame(17, src, dst, header, payload)
}

// tcpSegment is a TCP segment with no payload and the given flags (0x02 SYN, 0x10 ACK, 0x12 SYN-ACK).
func tcpSegment(src, dst [4]byte, sport, dport uint16, sequence, ack uint32, flags byte) []byte {
	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header[0:], sport)
	binary.BigEndian.PutUint16(header[2:], dport)
	binary.BigEndian.PutUint32(header[4:], sequence)
	binary.BigEndian.PutUint32(header[8:], ack)
	header[12], header[13] = 5<<4, flags
	binary.BigEndian.PutUint16(header[14:], 65535)
	return ipv4Frame(6, src, dst, header, nil)
}

func tcpSYN(src, dst [4]byte, sport, dport uint16, sequence uint32) []byte {
	return tcpSegment(src, dst, sport, dport, sequence, 0, 0x02)
}

// dnsQuery is a standard query for example.com/A.
func dnsQuery(id uint16) []byte {
	q := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	q = append(q, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1)
	return q
}

// stunBinding is a STUN Binding request (RFC 5389 magic cookie, no attributes).
func stunBinding() []byte {
	return []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
}

// burstCapture is a classic PCAP whose records are 1 ms apart, so no flow reaches the idle timeout.
func burstCapture(frames ...[]byte) []byte {
	out := []byte{0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0}
	for i, frame := range frames {
		header := make([]byte, 16)
		binary.LittleEndian.PutUint32(header[0:], uint32(1700000000+i/1000))
		binary.LittleEndian.PutUint32(header[4:], uint32(i%1000*1000))
		binary.LittleEndian.PutUint32(header[8:], uint32(len(frame)))
		binary.LittleEndian.PutUint32(header[12:], uint32(len(frame)))
		out = append(append(out, header...), frame...)
	}
	return out
}

func runCapture(t *testing.T, opts Options, frames ...[]byte) []map[string]interface{} {
	t.Helper()
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "capture.pcap")
	if err := os.WriteFile(path, burstCapture(frames...), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := Run(path, pack, opts, &out); err != nil {
		t.Fatal(err)
	}
	var rows []map[string]interface{}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if !opts.JSON {
			rows = append(rows, map[string]interface{}{"text": line})
			continue
		}
		var row map[string]interface{}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("row %q: %v", line, err)
		}
		rows = append(rows, row)
	}
	return rows
}

func summaryOf(t *testing.T, rows []map[string]interface{}) (map[string]interface{}, map[string]interface{}) {
	t.Helper()
	last := rows[len(rows)-1]
	summary, ok := last["summary"].(map[string]interface{})
	if !ok {
		t.Fatalf("last row is not a summary: %v", last)
	}
	return summary, last["input_quality"].(map[string]interface{})
}

// PRO-448: 800 UDP flows against analyze's table of 32 (MaxUDPFlows follows MaxConnections). Every datagram
// is still inspected, but only the flows in the table get a session record; the datagrams turned away are
// reported in the summary and the input quality instead of disappearing.
//
// With SEC-SESS-1 (PRO-398) a flow with no decision yet is half-open and is evicted, not kept, when the table is
// full. Every query here is identified as DNS but query 9, whose competing candidate exhausts its budget, so that
// flow alone stays half-open: flow 33 evicts it (one "Half-open budget full" record) and takes its slot, and the
// 767 later flows find a table of decided flows and are turned away. Records plus refusals are the 800 flows.
func TestUDPFlowLimitIsReported(t *testing.T) {
	var frames [][]byte
	for i := 0; i < 800; i++ {
		client := [4]byte{198, 51, byte(100 + i/250), byte(1 + i%250)}
		frames = append(frames, udpFrame(client, [4]byte{192, 0, 2, 53}, uint16(40000+i), 53, dnsQuery(uint16(i))))
	}
	rows := runCapture(t, Options{JSON: true, Sessions: true, EventsOnly: true}, frames...)
	summary, quality := summaryOf(t, rows)
	if summary["udp_flow_limit"] != float64(767) || summary["tcp_connection_limit"] != float64(0) || summary["sessions"] != float64(33) {
		t.Fatalf("summary %v", summary)
	}
	if quality["udp_flow_limit"] != float64(767) || quality["tcp_connection_limit"] != float64(0) {
		t.Fatalf("input quality %v", quality)
	}
	sessions, evicted := 0, 0
	for _, row := range rows {
		if row["type"] == "session" {
			sessions++
			if row["end_reason"] == session.ReasonHalfOpenEvicted {
				evicted++
			}
		}
	}
	if sessions != 33 || evicted != 1 || sessions+767 != len(frames) {
		t.Fatalf("%d session records, %d evicted", sessions, evicted)
	}
	text := runCapture(t, Options{}, frames...)
	if last := text[len(text)-1]["text"]; !strings.HasSuffix(last.(string), "; sessions: 0; udp_flow_limit: 767") {
		t.Fatalf("text summary %q", last)
	}
}

// The counters are always present, 0 when nothing was turned away; the text summary is then unchanged.
func TestFlowLimitCountersAlwaysPresent(t *testing.T) {
	frame := udpFrame([4]byte{198, 51, 100, 1}, [4]byte{192, 0, 2, 53}, 40000, 53, dnsQuery(1))
	summary, quality := summaryOf(t, runCapture(t, Options{JSON: true}, frame))
	for _, counters := range []map[string]interface{}{summary, quality} {
		if counters["udp_flow_limit"] != float64(0) || counters["tcp_connection_limit"] != float64(0) {
			t.Fatalf("counters %v", counters)
		}
	}
	text := runCapture(t, Options{}, frame)
	if last := text[len(text)-1]["text"]; !strings.HasSuffix(last.(string), "; sessions: 0") {
		t.Fatalf("text summary %q", last)
	}
}

// The TCP equivalent: connection openings turned away by a full table (the "LIMIT" rows) are counted. Under
// SEC-SESS-1 only established connections fill the table for good (a half-open one is evicted for a new SYN),
// so 32 completed handshakes come first and the 8 SYNs after them are refused.
func TestTCPConnectionLimitIsReported(t *testing.T) {
	server := [4]byte{192, 0, 2, 80}
	var frames [][]byte
	for i := 0; i < 40; i++ {
		client, port, isn := [4]byte{198, 51, 100, byte(1 + i)}, uint16(40000+i), uint32(1000*i+1)
		frames = append(frames, tcpSYN(client, server, port, 80, isn))
		if i < 32 {
			frames = append(frames, tcpSegment(server, client, 80, port, 7000, isn+1, 0x12),
				tcpSegment(client, server, port, 80, isn+1, 7001, 0x10))
		}
	}
	summary, quality := summaryOf(t, runCapture(t, Options{JSON: true}, frames...))
	if summary["tcp_connection_limit"] != float64(8) || quality["tcp_connection_limit"] != float64(8) || summary["udp_flow_limit"] != float64(0) {
		t.Fatalf("summary %v, quality %v", summary, quality)
	}
}

// 40 bare SYNs are all half-open: from the 25th on (the half-open budget of 24) each evicts the oldest instead of
// being refused, so nothing counts as tcp_connection_limit and all 40 get a session record, 16 (40 - 24) of them evicted.
func TestHalfOpenSYNsAreEvictedNotCountedAsLimit(t *testing.T) {
	var frames [][]byte
	for i := 0; i < 40; i++ {
		frames = append(frames, tcpSYN([4]byte{198, 51, 100, byte(1 + i)}, [4]byte{192, 0, 2, 80}, uint16(40000+i), 80, uint32(1000*i+1)))
	}
	rows := runCapture(t, Options{JSON: true, Sessions: true, EventsOnly: true}, frames...)
	summary, quality := summaryOf(t, rows)
	if summary["tcp_connection_limit"] != float64(0) || quality["tcp_connection_limit"] != float64(0) {
		t.Fatalf("summary %v, quality %v", summary, quality)
	}
	sessions, evicted := 0, 0
	for _, row := range rows {
		if row["type"] == "session" {
			sessions++
			if row["end_reason"] == session.ReasonHalfOpenEvicted {
				evicted++
			}
		}
	}
	if sessions != 40 || evicted != 16 {
		t.Fatalf("%d session records, %d evicted", sessions, evicted)
	}
}

func udpSession(t *testing.T, rows []map[string]interface{}) map[string]interface{} {
	t.Helper()
	for _, row := range rows {
		if row["type"] == "session" && row["transport"] == "udp" {
			return row
		}
	}
	t.Fatal("no UDP session record")
	return nil
}

// PRO-448: a flow whose datagrams were identified as different protocols is marked; the first identification
// still names the session, and the distinct outcomes are listed with their datagram counts.
func TestMixedDatagramOutcomesAreMarked(t *testing.T) {
	client, server := [4]byte{198, 51, 100, 7}, [4]byte{192, 0, 2, 9}
	record := udpSession(t, runCapture(t, Options{JSON: true, Sessions: true, EventsOnly: true},
		udpFrame(client, server, 40000, 3478, dnsQuery(1)),
		udpFrame(client, server, 40000, 3478, stunBinding()),
		udpFrame(client, server, 40000, 3478, dnsQuery(2))))
	if record["mixed_outcomes"] != true {
		t.Fatalf("mixed_outcomes %v in %v", record["mixed_outcomes"], record)
	}
	outcomes := record["datagram_outcomes"].(map[string]interface{})
	distinct := outcomes["distinct"].([]interface{})
	if len(distinct) != 2 || outcomes["beyond_limit"] != float64(0) {
		t.Fatalf("datagram_outcomes %v", outcomes)
	}
	first, second := distinct[0].(map[string]interface{}), distinct[1].(map[string]interface{})
	if first["protocol"] != "dns" || first["datagrams"] != float64(2) || second["protocol"] != "stun" || second["datagrams"] != float64(1) {
		t.Fatalf("datagram_outcomes %v", outcomes)
	}

	plain := udpSession(t, runCapture(t, Options{JSON: true, Sessions: true, EventsOnly: true},
		udpFrame(client, server, 40000, 53, dnsQuery(1)), udpFrame(server, client, 53, 40000, dnsQuery(1))))
	if plain["mixed_outcomes"] != false {
		t.Fatalf("a single-protocol flow is marked: %v", plain)
	}
	if d := plain["datagram_outcomes"].(map[string]interface{})["distinct"].([]interface{}); len(d) != 1 {
		t.Fatalf("datagram_outcomes %v", plain["datagram_outcomes"])
	}
}
