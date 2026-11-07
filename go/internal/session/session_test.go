package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/parity"
	"github.com/leenadav/protocol-detector/go/internal/testframes"
	"github.com/leenadav/protocol-detector/go/internal/transport"
)

// recorder is the trivial inspector of M3: it records deliveries and lifecycle calls only.
type recorder struct {
	data        []byte
	ended       string
	invalidated string
	terminal    bool
}

func (r *recorder) Feed(delta []byte) bool { r.data = append(r.data, delta...); return true }
func (r *recorder) Invalidate(reason string) bool {
	if r.terminal {
		return false
	}
	r.invalidated, r.terminal = reason, true
	return true
}
func (r *recorder) End(reason string) bool {
	if r.terminal {
		return false
	}
	r.ended, r.terminal = reason, true
	return true
}

type harness struct {
	t        *testing.T
	tracker  *Tracker
	sinks    []*recorder
	closed   []Closed
	messages []string
}

func newHarness(t *testing.T, opts Options) *harness {
	h := &harness{t: t}
	if opts.MaxConnections == 0 {
		opts.MaxConnections = 32
	}
	if opts.ByteLimit == 0 {
		opts.ByteLimit = 65536
	}
	if opts.IdleTimeout == 0 {
		opts.IdleTimeout = 60
	}
	if opts.MaxUDPFlows == 0 {
		opts.MaxUDPFlows = -1
	}
	tr, err := NewTracker(opts, func() Sink { r := &recorder{}; h.sinks = append(h.sinks, r); return r },
		func(c Closed) { h.closed = append(h.closed, c) })
	if err != nil {
		t.Fatal(err)
	}
	h.tracker = tr
	return h
}

var (
	client  = transport.Endpoint{Addr: "192.0.2.10", Port: 52000}
	server  = transport.Endpoint{Addr: "198.51.100.20", Port: 8000}
	request = []byte("GET /a HTTP/1.1\r\nHost: a.example\r\n\r\n")
)

func seg(src, dst transport.Endpoint, seq, ack uint32, flags byte, payload []byte) *transport.TCP {
	frame := testframes.TCP(src.Addr, src.Port, dst.Addr, dst.Port, seq, ack, flags, payload)
	p, err := transport.Decode(frame, 1, transport.Verify)
	if err != nil {
		panic(err)
	}
	return p.(*transport.TCP)
}

func (h *harness) tcp(t float64, p *transport.TCP) string {
	m := h.tracker.Process(t, p)
	h.messages = append(h.messages, m)
	return m
}

func (h *harness) handshake(t float64, c, s transport.Endpoint, isn, sisn uint32) {
	h.tcp(t, seg(c, s, isn-1, 0, transport.SYN, nil))
	h.tcp(t, seg(s, c, sisn-1, isn, transport.SYN|transport.ACK, nil))
	h.tcp(t, seg(c, s, isn, sisn, transport.ACK, nil))
}

func (h *harness) delivered(index int) []byte { return h.sinks[index].data }

func TestHandshakeDataAndHalfCloseThenBothFIN(t *testing.T) {
	h := newHarness(t, Options{})
	h.handshake(0, client, server, 1000, 9000)
	if h.messages[0] != "SYN: waiting for SYN-ACK" || h.messages[1] != "Tracking both directions (SYN/SYN-ACK observed)" || h.messages[2] != "No new contiguous data" {
		t.Fatal(h.messages)
	}
	m := h.tcp(0.1, seg(client, server, 1000, 9000, transport.ACK|8, request))
	if !strings.HasPrefix(m, "192.0.2.10:52000 -> 198.51.100.20:8000 | contiguous=36 pending=0") {
		t.Fatal(m)
	}
	// Half close: the client's FIN ends its direction with the FIN reason; the server side stays open.
	h.tcp(0.2, seg(client, server, 1000+uint32(len(request)), 9000, transport.ACK|transport.FIN, nil))
	clientSink := h.sinks[1] // Open(destination=server, source=client): directions created server first
	if h.sinks[0].ended != "" && h.sinks[1].ended != "" {
		t.Fatal("both directions ended on one FIN")
	}
	var ended, open *recorder
	for _, s := range h.sinks {
		if s.ended != "" {
			ended = s
		} else {
			open = s
		}
	}
	_ = clientSink
	if ended == nil || ended.ended != ReasonFIN || !bytes.Equal(ended.data, request) || open == nil {
		t.Fatalf("half close: %+v", h.sinks)
	}
	if len(h.closed) != 0 {
		t.Fatal("connection closed on a half close")
	}
	m = h.tcp(0.3, seg(server, client, 9000, 1000+uint32(len(request))+1, transport.ACK|transport.FIN, nil))
	if !strings.HasSuffix(m, "CLOSED: both FIN boundaries reached") || len(h.closed) != 1 || h.closed[0].Reason != ReasonBothFIN {
		t.Fatalf("both FIN: %q %+v", m, h.closed)
	}
	if tracked, conns, _ := h.tracker.Tables(); tracked != 0 || conns != 0 {
		t.Fatal("state retained after close")
	}
}

func TestSYNRetransmitTupleReuseAndFINBeforeData(t *testing.T) {
	h := newHarness(t, Options{})
	h.tcp(0, seg(client, server, 999, 0, transport.SYN, nil))
	if m := h.tcp(0.5, seg(client, server, 999, 0, transport.SYN, nil)); m != "SYN retransmission" {
		t.Fatal(m)
	}
	if m := h.tcp(0.6, seg(client, server, 5000, 0, transport.SYN, nil)); m != "SYN: waiting for SYN-ACK" || len(h.closed) != 1 || h.closed[0].Reason != ReasonTrackingEnded {
		t.Fatalf("new SYN on the tuple: %q %+v", m, h.closed)
	}
	h.tcp(0.7, seg(server, client, 8999, 5001, transport.SYN|transport.ACK, nil))
	// FIN before any data: the direction ends at offset 0 with the FIN reason; data after it is rejected.
	h.tcp(0.8, seg(client, server, 5001, 9000, transport.ACK|transport.FIN, nil))
	if m := h.tcp(0.9, seg(client, server, 5001, 9000, transport.ACK, []byte("late"))); m != "INVALIDATED: data beyond observed FIN" {
		t.Fatal(m)
	}
	// Reuse of the tuple after the connection ended starts a fresh generation.
	h.handshake(1, client, server, 70000, 80000)
	h.tcp(1.1, seg(client, server, 70000, 80000, transport.ACK, request))
	if h.sinks[len(h.sinks)-1].data == nil && h.sinks[len(h.sinks)-2].data == nil {
		t.Fatal("reused tuple delivered nothing")
	}
}

func TestRSTIdleTimeoutAndEviction(t *testing.T) {
	h := newHarness(t, Options{MaxConnections: 2, IdleTimeout: 10})
	h.handshake(0, client, server, 1000, 9000)
	if m := h.tcp(0.1, seg(client, server, 1000, 9000, transport.RST, nil)); m != "RESET: tracking stopped (RST not endpoint-validated)" || h.closed[0].Reason != ReasonRST {
		t.Fatal(m)
	}
	other := transport.Endpoint{Addr: "192.0.2.11", Port: 40000}
	third := transport.Endpoint{Addr: "192.0.2.12", Port: 40001}
	h.handshake(1, client, server, 2000, 9000)
	h.handshake(1, other, server, 3000, 9000)
	if m := h.tcp(1, seg(third, server, 3999, 0, transport.SYN, nil)); m != "LIMIT: too many tracked connections" {
		t.Fatal(m)
	}
	h.tcp(12, seg(third, server, 3999, 0, transport.SYN, nil)) // 11 s later: both idle connections expire first
	reasons := map[string]int{}
	for _, c := range h.closed {
		reasons[c.Reason]++
	}
	if reasons[ReasonIdle] != 2 {
		t.Fatalf("idle expiry: %v", reasons)
	}
	if tracked, conns, _ := h.tracker.Tables(); tracked != 1 || conns != 0 {
		t.Fatalf("tables after expiry: %d %d", tracked, conns)
	}
}

func TestOutOfOrderConflictAndWraparoundThroughTheTracker(t *testing.T) {
	h := newHarness(t, Options{})
	isn := uint32(0xffffffff - 10)
	h.handshake(0, client, server, isn, 9000)
	cut := 20
	h.tcp(0.1, seg(client, server, isn+uint32(cut), 9000, transport.ACK, request[cut:])) // wraps past 2^32
	m := h.tcp(0.2, seg(client, server, isn, 9000, transport.ACK, request[:cut]))
	if !strings.Contains(m, "contiguous=36 pending=0") {
		t.Fatal(m)
	}
	var got []byte
	for _, s := range h.sinks {
		if len(s.data) > 0 {
			got = s.data
		}
	}
	if !bytes.Equal(got, request) {
		t.Fatalf("delivered %q", got)
	}
	changed := append([]byte{}, request[:10]...)
	changed[4] ^= 0xff
	if m := h.tcp(0.3, seg(client, server, isn, 9000, transport.ACK, changed)); m != "INVALIDATED: "+ReasonTrackingEnded && !strings.HasPrefix(m, "INVALIDATED: Conflicting") {
		t.Fatal(m)
	}
	if h.closed[len(h.closed)-1].Reason != ReasonTrackingEnded {
		t.Fatalf("conflict end reason %q", h.closed[len(h.closed)-1].Reason)
	}
	for _, s := range h.sinks {
		if s.invalidated != "" && s.invalidated != "Conflicting overlapping bytes; classification invalidated" {
			t.Fatal(s.invalidated)
		}
	}
}

func TestModesAndTruncatedCapture(t *testing.T) {
	h := newHarness(t, Options{Observation: ModeAsymmetric})
	h.tcp(0, seg(client, server, 999, 0, transport.SYN, nil))
	if m := h.tcp(0.1, seg(client, server, 1000, 5000, transport.ACK, request)); !strings.Contains(m, "contiguous=36") {
		t.Fatal(m)
	}
	if h.tracker.Tracked(client, server).Mode != ModeAsymmetric {
		t.Fatal("mode")
	}
	h2 := newHarness(t, Options{Observation: ModeMidstream})
	if m := h2.tcp(0, seg(client, server, 5000, 7000, transport.ACK, request)); !strings.Contains(m, "contiguous=36") {
		t.Fatal(m)
	}
	// A bare SYN on a midstream tuple takes the ordinary SYN path (as in Python): the old state ends with
	// the default reason; a SYN-ACK on it is the explicit restart.
	if m := h2.tcp(0.1, seg(client, server, 9999, 0, transport.SYN, nil)); m != "SYN: waiting for SYN-ACK" || h2.closed[0].Reason != ReasonTrackingEnded {
		t.Fatal(m, h2.closed)
	}
	h4 := newHarness(t, Options{Observation: ModeMidstream})
	h4.tcp(0, seg(client, server, 5000, 7000, transport.ACK, request))
	if m := h4.tcp(0.1, seg(server, client, 8999, 5000, transport.SYN|transport.ACK, nil)); h4.closed[0].Reason != ReasonRestart {
		t.Fatal(m, h4.closed)
	}
	h3 := newHarness(t, Options{})
	if m := h3.tcp(0, seg(client, server, 5000, 7000, transport.ACK, request)); m != "SKIP: connection beginning not observed" {
		t.Fatal(m)
	}
	h3.handshake(1, client, server, 1000, 9000)
	if !h3.tracker.NoteInput(transport.KindTruncated, &[2]transport.Endpoint{client, server}) || h3.closed[0].Reason != ReasonTruncated {
		t.Fatal("truncated record did not end the connection")
	}
	if h3.tracker.NoteInput(transport.KindFragment, &[2]transport.Endpoint{client, server}) {
		t.Fatal("untracked flow marked")
	}
}

func TestFinishAndUDPFlows(t *testing.T) {
	h := newHarness(t, Options{MaxConnections: 1, MaxUDPFlows: 1})
	h.handshake(0, client, server, 1000, 9000)
	u := testframes.UDP(client.Addr, 53001, server.Addr, 53, []byte("dns"))
	p, _ := transport.Decode(u, 1, transport.Ignore)
	if m := h.tracker.ProcessUDP(0.1, p.(*transport.UDP)); m != "UDP 192.0.2.10:53001 -> 198.51.100.20:53" {
		t.Fatal(m)
	}
	u2 := testframes.UDP(client.Addr, 53002, server.Addr, 53, []byte("dns"))
	p2, _ := transport.Decode(u2, 1, transport.Ignore)
	h.tracker.ProcessUDP(0.2, p2.(*transport.UDP))
	if h.tracker.Counts["udp_flow_limit"] != 1 {
		t.Fatal("UDP flow limit")
	}
	if err := h.tracker.Finish(""); err == nil {
		t.Fatal("empty reason accepted")
	}
	h.tracker.Finish(ReasonCaptureEnded)
	if len(h.closed) != 2 {
		t.Fatalf("closed %d", len(h.closed))
	}
	for _, c := range h.closed {
		if c.Reason != ReasonCaptureEnded {
			t.Fatal(c.Reason)
		}
	}
}

// Differential proof against the Python reference: per-packet messages (where the inspector does not
// decide them), the retained windows of both directions and the table sizes after every packet.
func TestSessionCasesMatchThePythonReassembly(t *testing.T) {
	doc, err := parity.Load(context.Background(), "../../../migration/fixtures/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	type streamState struct {
		Contiguous int    `json:"contiguous"`
		Stored     int    `json:"stored"`
		HighestEnd int    `json:"highest_end"`
		Digest     string `json:"digest"`
	}
	type packetExpectation struct {
		Message *string                `json:"message"`
		Streams map[string]streamState `json:"streams"`
		Tables  []int                  `json:"tables"`
	}
	compared, skipped, cases := 0, 0, 0
	for _, c := range doc.Cases {
		if c.Kind != "session" {
			continue
		}
		cases++
		var options struct {
			IdleTimeout *float64 `json:"idle_timeout"`
			Observation string   `json:"observation"`
		}
		json.Unmarshal(c.Options, &options)
		opts := Options{MaxConnections: 32, ByteLimit: 65536, IdleTimeout: 60, MaxUDPFlows: -1, Observation: options.Observation}
		if options.IdleTimeout != nil {
			opts.IdleTimeout = *options.IdleTimeout
		}
		tr, err := NewTracker(opts, func() Sink { return &recorder{} }, nil)
		if err != nil {
			t.Fatal(c.ID, err)
		}
		var expected struct {
			Packets []packetExpectation `json:"packets"`
		}
		json.Unmarshal(c.Expected, &expected)
		for i, pk := range c.Packets {
			frame, _ := hex.DecodeString(pk.Frame)
			decoded, err := transport.Decode(frame, pk.Linktype, transport.Ignore)
			if err != nil {
				t.Fatal(c.ID, err)
			}
			var message string
			var a, b transport.Endpoint
			inspectorDecides := false
			switch p := decoded.(type) {
			case *transport.TCP:
				message = tr.Process(pk.T, p)
				a, b = p.Source, p.Destination
				inspectorDecides = len(p.Payload) == 0 && p.Flags&transport.FIN != 0
			case *transport.UDP:
				message = tr.ProcessUDP(pk.T, p)
				a, b = p.Source, p.Destination
			}
			want := expected.Packets[i]
			if want.Message != nil {
				got := strings.SplitN(message, " | ", 2)[0]
				if inspectorDecides {
					skipped++
				} else if got != *want.Message {
					t.Fatalf("%s packet %d: message %q want %q", c.ID, i, got, *want.Message)
				}
			}
			tracked, conns, flows := tr.Tables()
			if len(want.Tables) == 3 && (tracked != want.Tables[0] || conns != want.Tables[1] || flows != want.Tables[2]) {
				t.Fatalf("%s packet %d: tables %d %d %d want %v", c.ID, i, tracked, conns, flows, want.Tables)
			}
			conn := tr.Manager().Connections[KeyOf(a, b)]
			if (conn == nil) != (want.Streams == nil) {
				t.Fatalf("%s packet %d: connection presence %v want %v", c.ID, i, conn != nil, want.Streams != nil)
			}
			if conn != nil {
				for endpoint, d := range conn.Directions {
					w, ok := want.Streams[endpoint.String()]
					if !ok {
						t.Fatalf("%s packet %d: unexpected direction %s", c.ID, i, endpoint)
					}
					sum := sha256.Sum256(d.Stream.Prefix())
					if d.Stream.Contiguous() != w.Contiguous || d.Stream.Stored() != w.Stored || d.Stream.HighestEnd() != w.HighestEnd || hex.EncodeToString(sum[:])[:16] != w.Digest {
						t.Fatalf("%s packet %d %s: stream %d/%d/%d want %+v", c.ID, i, endpoint, d.Stream.Contiguous(), d.Stream.Stored(), d.Stream.HighestEnd(), w)
					}
					if rec := d.Sink.(*recorder); !bytes.Equal(rec.data, d.Stream.Prefix()) {
						t.Fatalf("%s packet %d %s: delivered bytes differ from the contiguous prefix", c.ID, i, endpoint)
					}
				}
			}
			compared++
		}
	}
	if cases < 200 || compared < 1000 {
		t.Fatalf("compared %d packets of %d cases", compared, cases)
	}
	t.Logf("session cases %d, packets compared %d, messages left to the inspector (zero-payload FIN) %d", cases, compared, skipped)
}
