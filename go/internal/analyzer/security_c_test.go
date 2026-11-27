package analyzer

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/parity"
	"github.com/leenadav/protocol-detector/go/internal/session"
	"github.com/leenadav/protocol-detector/go/internal/transport"
)

// scConn builds the frames of one synthetic TCP connection with correct sequence numbers (tools/sequence_check.py
// Connection).
type scConn struct {
	client, server transport.Endpoint
	isn, serverISN uint32
}

func (c scConn) handshake() []interface{} {
	return []interface{}{seg(c.client, c.server, c.isn-1, 0, transport.SYN, nil), seg(c.server, c.client, c.serverISN-1, c.isn, transport.SYN|transport.ACK, nil),
		seg(c.client, c.server, c.isn, c.serverISN, transport.ACK, nil)}
}

func (c scConn) segments(data []byte, cuts []int) []interface{} {
	var out []interface{}
	bounds := append(append([]int{0}, cuts...), len(data))
	for i := 1; i < len(bounds); i++ {
		if bounds[i] > bounds[i-1] {
			out = append(out, seg(c.client, c.server, c.isn+uint32(bounds[i-1]), c.serverISN, transport.ACK|8, data[bounds[i-1]:bounds[i]]))
		}
	}
	return out
}

func (c scConn) fin(data []byte) interface{} {
	return seg(c.client, c.server, c.isn+uint32(len(data)), c.serverISN, transport.FIN|transport.ACK, nil)
}

func (c scConn) serverFin() interface{} {
	return seg(c.server, c.client, c.serverISN, c.isn, transport.FIN|transport.ACK, nil)
}

func scKey(client, server transport.Endpoint) string {
	return fmt.Sprint(endpoint(client), endpoint(server))
}

var scKeep = []string{"app", "base_app", "category", "subcategory", "client_protocol", "server_protocol", "encryption", "engine_status",
	"risks", "hostname", "shifted_from", "transport"}

func scNormalize(record map[string]interface{}) string {
	parts := make([]string, 0, len(scKeep))
	for _, k := range scKeep {
		v := record[k]
		if k == "risks" {
			var risks []string
			switch r := v.(type) {
			case []string:
				risks = append(risks, r...)
			case []interface{}:
				for _, x := range r {
					risks = append(risks, fmt.Sprint(x))
				}
			}
			sort.Strings(risks)
			v = risks
		}
		if p, ok := v.(*string); ok {
			if p == nil {
				v = nil
			} else {
				v = *p
			}
		}
		parts = append(parts, fmt.Sprintf("%s=%v", k, v))
	}
	return strings.Join(parts, " ")
}

type scTimed struct {
	at     float64
	packet interface{}
}

// scDrive runs one packet sequence through a fresh Analyzer and returns the normalized session records per
// connection key and the bytes.new telemetry counter.
func scDrive(t *testing.T, pack *content.Pack, frames []interface{}) (map[string][]string, int) {
	t.Helper()
	a, err := New(pack, Options{Session: session.Options{MaxConnections: 64, ByteLimit: 65536, IdleTimeout: 60, MaxUDPFlows: -1}})
	if err != nil {
		t.Fatal(err)
	}
	now := 0.0
	for _, f := range frames {
		if timed, ok := f.(scTimed); ok {
			now = timed.at
			f = timed.packet
		} else {
			now += 0.001
		}
		a.Process(now, f)
	}
	if err := a.Finish("eof"); err != nil {
		t.Fatal(err)
	}
	keyed := map[string][]string{}
	for _, r := range a.Records {
		k := fmt.Sprint(r["client"], r["server"])
		keyed[k] = append(keyed[k], scNormalize(r))
	}
	counters, _ := a.Telemetry.Render()
	n, _ := counters["counters"].(map[string]interface{})["bytes.new"].(int)
	return keyed, n
}

func scFamily(label string) string {
	if i := strings.IndexByte(label, '/'); i >= 0 {
		return label[:i]
	}
	return label
}

func scRecordFamily(normalized string) (identified bool, family string) {
	fields := map[string]string{}
	for _, part := range strings.Split(normalized, " ") {
		if i := strings.IndexByte(part, '='); i > 0 {
			fields[part[:i]] = part[i+1:]
		}
	}
	family = fields["client_protocol"]
	if family == "<nil>" || family == "" {
		family = fields["encryption"]
	}
	return fields["engine_status"] == "identified", scFamily(family)
}

func scCuts(r *rand.Rand, length, pieces int) []int {
	if length < 2 || pieces < 2 {
		return nil
	}
	if pieces-1 > length-1 {
		pieces = length
	}
	cuts := r.Perm(length - 1)[:pieces-1]
	for i := range cuts {
		cuts[i]++
	}
	sort.Ints(cuts)
	return cuts
}

func scSame(a, b []string) bool { return fmt.Sprint(a) == fmt.Sprint(b) }

// SR-68: the packet-sequence relations of tools/sequence_check.py on the public Analyzer path, for one unhinted
// stream fixture of every labelled family in migration/fixtures/cases.json: segmentation, reordering with identical
// retransmissions (each contiguous byte inspected once), a conflicting retransmission ending in the same record or
// an explicit invalidation (never another family), a FIN before the last segment, reuse of the 5-tuple, an idle
// half-message, and interleaved connections and a datagram flow sharing no state.
func TestPacketSequenceRelationsHoldOnTheAnalyzerPath(t *testing.T) {
	pack, err := content.Load(packPath)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := parity.Load(context.Background(), "../../../migration/fixtures/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	type fixture struct {
		label string
		data  []byte
	}
	var streams []fixture
	var datagrams [][]byte
	seen := map[string]bool{}
	for i := range doc.Cases {
		c := &doc.Cases[i]
		if c.Hint != nil || seen[c.Kind+c.Label] || (c.Config != contracts.DefaultConfig() && c.Config != (contracts.Config{})) {
			continue
		}
		switch c.Kind {
		case "stream":
			data, err := hex.DecodeString(strings.Join(c.Chunks, ""))
			if err != nil || len(data) == 0 || len(data) > 16384 {
				continue
			}
			seen[c.Kind+c.Label] = true
			streams = append(streams, fixture{c.Label, data})
		case "datagram":
			data, err := hex.DecodeString(c.Payload)
			if err != nil || len(data) == 0 || len(datagrams) >= 8 {
				continue
			}
			seen[c.Kind+c.Label] = true
			datagrams = append(datagrams, data)
		}
	}
	if len(streams) < 50 || len(datagrams) < 2 {
		t.Fatalf("only %d stream and %d datagram fixtures", len(streams), len(datagrams))
	}
	r := rand.New(rand.NewSource(7))
	counts := map[string]int{}
	conn := scConn{transport.Endpoint{Addr: "192.0.2.10", Port: 52000}, transport.Endpoint{Addr: "198.51.100.20", Port: 8000}, 1000, 9000}
	key := scKey(conn.client, conn.server)
	join := func(parts ...[]interface{}) []interface{} {
		var out []interface{}
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	for _, f := range streams {
		data := f.data
		plain := join(conn.handshake(), conn.segments(data, nil), []interface{}{conn.fin(data)})
		oracleAll, _ := scDrive(t, pack, plain)
		oracle := oracleAll[key]
		if len(oracle) == 0 {
			t.Fatalf("%s: no session record for the plain delivery", f.label)
		}
		record := oracle[len(oracle)-1]
		identified, found := scRecordFamily(record)
		if identified && found != scFamily(f.label) {
			t.Fatalf("%s: the plain delivery identified %s", f.label, found)
		}
		for iteration := 0; iteration < 2; iteration++ {
			segments := conn.segments(data, scCuts(r, len(data), 2+r.Intn(7)))
			got, _ := scDrive(t, pack, join(conn.handshake(), segments, []interface{}{conn.fin(data)}))
			counts["segmentation"]++
			if !scSame(oracle, got[key]) {
				t.Fatalf("%s [segmentation]: expected %v got %v", f.label, oracle, got[key])
			}
			shuffled := append([]interface{}{}, segments...)
			r.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
			for n := r.Intn(3); n > 0; n-- {
				at := r.Intn(len(shuffled) + 1)
				shuffled = append(shuffled[:at], append([]interface{}{segments[r.Intn(len(segments))]}, shuffled[at:]...)...)
			}
			got, unique := scDrive(t, pack, join(conn.handshake(), shuffled, []interface{}{conn.fin(data)}))
			counts["reordering"]++
			if !scSame(oracle, got[key]) {
				t.Fatalf("%s [reordering]: expected %v got %v", f.label, oracle, got[key])
			}
			if unique > len(data) {
				t.Fatalf("%s [reordering]: bytes.new %d exceeds the payload %d", f.label, unique, len(data))
			}
			if identified && len(data) > 1 {
				victim := r.Intn(len(segments))
				start := 0
				for _, s := range segments[:victim] {
					start += len(s.(*transport.TCP).Payload)
				}
				piece := append([]byte{}, segments[victim].(*transport.TCP).Payload...)
				piece[r.Intn(len(piece))] ^= 0xff
				conflicting := seg(conn.client, conn.server, conn.isn+uint32(start), conn.serverISN, transport.ACK|8, piece)
				sequence := join(conn.handshake(), segments)
				at := victim + 4 + r.Intn(len(sequence)-victim-3)
				sequence = append(sequence[:at], append([]interface{}{conflicting}, sequence[at:]...)...)
				got, _ := scDrive(t, pack, append(sequence, conn.fin(data)))
				counts["conflict"]++
				if outcome := got[key]; len(outcome) > 0 {
					last := outcome[len(outcome)-1]
					okIdentified, family := scRecordFamily(last)
					if strings.Contains(last, "engine_status=invalidated") {
						counts["conflict-invalidated"]++
					}
					if okIdentified && (last != record || family != scFamily(f.label)) {
						t.Fatalf("%s [conflict]: changed bytes produced %s, the oracle is %s", f.label, last, record)
					}
				}
			}
			if len(segments) > 1 {
				early := join(conn.handshake(), segments[:len(segments)-1], []interface{}{conn.fin(data), segments[len(segments)-1]})
				got, _ := scDrive(t, pack, early)
				counts["fin-first"]++
				if !scSame(oracle, got[key]) {
					t.Fatalf("%s [fin-first]: expected %v got %v", f.label, oracle, got[key])
				}
			}
		}
		http := []byte("GET /reuse HTTP/1.1\r\nHost: reuse.example\r\n\r\n")
		second := scConn{conn.client, conn.server, 70000, 80000}
		reused, _ := scDrive(t, pack, join(plain, []interface{}{conn.serverFin()}, second.handshake(), second.segments(http, nil), []interface{}{second.fin(http)}))
		alone, _ := scDrive(t, pack, join(second.handshake(), second.segments(http, nil), []interface{}{second.fin(http)}))
		counts["reuse"]++
		if got := reused[key]; len(got) < 2 || got[0] != oracle[0] || got[len(got)-1] != alone[key][len(alone[key])-1] {
			t.Fatalf("%s [reuse]: records %v, alone %v and %v", f.label, got, oracle, alone[key])
		}
		half := conn.segments(data[:max(1, len(data)/2)], nil)
		other := scConn{transport.Endpoint{Addr: "192.0.2.77", Port: 40000}, transport.Endpoint{Addr: "198.51.100.77", Port: 7000}, 1000, 9000}
		var idle []interface{}
		for _, p := range join(conn.handshake(), half) {
			idle = append(idle, scTimed{0, p})
		}
		for _, p := range other.handshake() {
			idle = append(idle, scTimed{61, p})
		}
		got, _ := scDrive(t, pack, idle)
		counts["expiry"]++
		if outcome := got[key]; len(outcome) == 0 {
			t.Fatalf("%s [expiry]: the idle connection produced no record", f.label)
		} else if ok, family := scRecordFamily(outcome[len(outcome)-1]); ok && family != scFamily(f.label) {
			t.Fatalf("%s [expiry]: half a message identified %s", f.label, family)
		}
	}
	for iteration := 0; iteration < 6; iteration++ {
		var flows [][]interface{}
		alone := map[string][]string{}
		for index, pick := range r.Perm(len(streams))[:3] {
			data := streams[pick].data
			c := scConn{transport.Endpoint{Addr: fmt.Sprintf("192.0.2.%d", 10+index), Port: uint16(52000 + index)},
				transport.Endpoint{Addr: fmt.Sprintf("198.51.100.%d", 20+index), Port: uint16(8000 + index)}, 1000, 9000}
			frames := join(c.handshake(), c.segments(data, scCuts(r, len(data), 1+r.Intn(4))), []interface{}{c.fin(data)})
			flows = append(flows, frames)
			got, _ := scDrive(t, pack, frames)
			alone[scKey(c.client, c.server)] = got[scKey(c.client, c.server)]
		}
		for index, pick := range r.Perm(len(datagrams))[:2] {
			client := transport.Endpoint{Addr: fmt.Sprintf("192.0.2.%d", 30+index), Port: uint16(53000 + index)}
			server := transport.Endpoint{Addr: fmt.Sprintf("198.51.100.%d", 40+index), Port: uint16(5300 + index)}
			frames := []interface{}{&transport.UDP{Source: client, Destination: server, Payload: datagrams[pick]}}
			flows = append(flows, frames)
			got, _ := scDrive(t, pack, frames)
			alone[scKey(client, server)] = got[scKey(client, server)]
		}
		var merged []interface{}
		cursors := make([]int, len(flows))
		for {
			var open []int
			for i, flow := range flows {
				if cursors[i] < len(flow) {
					open = append(open, i)
				}
			}
			if len(open) == 0 {
				break
			}
			i := open[r.Intn(len(open))]
			merged = append(merged, flows[i][cursors[i]])
			cursors[i]++
		}
		got, _ := scDrive(t, pack, merged)
		counts["interleaving"]++
		for k, want := range alone {
			if !scSame(want, got[k]) {
				t.Fatalf("[interleaving] %s: expected %v got %v", k, want, got[k])
			}
		}
	}
	for _, relation := range []string{"segmentation", "reordering", "conflict", "conflict-invalidated", "fin-first", "reuse", "expiry", "interleaving"} {
		if counts[relation] == 0 {
			t.Errorf("relation %s was never exercised", relation)
		}
	}
	t.Logf("%d stream fixtures, counts %v", len(streams), counts)
}

// SR-5: a TCP control segment the tracker rejects (data beyond or a changed FIN, FIN before buffered data, urgent
// data, a missing ACK, a changed or inconsistent SYN-ACK, a SYN-ACK from the client) must publish a retraction of
// the direction's identification to event consumers, release the connection, and leave nothing to report on a
// later packet of the same tuple. Ported from test_control_retractions.py
// test_analyzer_rejects_with_directional_event_and_releases_state.
func TestControlRejectionPublishesADirectionalRetraction(t *testing.T) {
	a := transport.Endpoint{Addr: "192.0.2.10", Port: 52000}
	b := transport.Endpoint{Addr: "192.0.2.20", Port: 8080}
	req := []byte("DELETE / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	n := uint32(len(req))
	const (
		fin = transport.FIN
		syn = transport.SYN
		ack = transport.ACK
		psh = byte(8)
		urg = transport.URG
	)
	handshake := []*transport.TCP{seg(a, b, 999, 0, syn, nil), seg(b, a, 8999, 1000, syn|ack, nil)}
	request := seg(a, b, 1000, 9000, psh|ack, req)
	finished := seg(a, b, 1000, 9000, fin|psh|ack, req)
	response := seg(b, a, 9000, 1000, psh|ack, []byte("SSH-2.0-demo\r\n"))
	cases := map[string]struct {
		packets []*transport.TCP
		source  transport.Endpoint
	}{
		"beyond_fin":         {[]*transport.TCP{finished, seg(a, b, 1000+n, 9000, psh|ack, []byte("X"))}, a},
		"changed_fin":        {[]*transport.TCP{finished, seg(a, b, 1001+n, 9000, fin|ack, nil)}, a},
		"fin_before_data":    {[]*transport.TCP{request, seg(a, b, 1001, 9000, fin|ack, nil)}, a},
		"urgent":             {[]*transport.TCP{request, seg(a, b, 1000, 9000, urg|psh|ack, nil)}, a},
		"missing_ack":        {[]*transport.TCP{request, seg(a, b, 1000, 9000, psh, nil)}, a},
		"changed_server_isn": {[]*transport.TCP{response, seg(b, a, 8998, 1000, syn|ack, nil)}, b},
		"bad_syn_ack":        {[]*transport.TCP{response, seg(b, a, 8999, 1001, syn|ack, nil)}, b},
		"client_syn_ack":     {[]*transport.TCP{request, seg(a, b, 999, 9000, syn|ack, nil)}, a},
	}
	for _, compact := range []bool{false, true} {
		for name, c := range cases {
			an := newAnalyzer(t, session.Options{MaxConnections: 64, ByteLimit: 65536, IdleTimeout: 60, MaxUDPFlows: -1, Compact: compact})
			packets := append(append([]*transport.TCP{}, handshake...), c.packets...)
			var message string
			for i, p := range packets {
				message = an.Process(float64(i), p)
			}
			if !strings.HasPrefix(message, "INVALIDATED") {
				t.Fatalf("compact=%v %s: message %q", compact, name, message)
			}
			if an.LastClassification == nil || an.LastClassification.Status != contracts.Invalidated ||
				an.LastClassification.ApplicationProtocol != nil {
				t.Fatalf("compact=%v %s: classification %+v", compact, name, an.LastClassification)
			}
			if len(an.LastEvents) != 1 || an.LastEvents[0].Revision != 2 || an.LastEvents[0].Kind != contracts.Retracted ||
				an.LastEvents[0].Observation.Status != contracts.Invalidated {
				t.Fatalf("compact=%v %s: events %+v", compact, name, an.LastEvents)
			}
			if an.Tracker.Tracked(a, b) != nil || len(an.Tracker.Manager().Connections) != 0 {
				t.Fatalf("compact=%v %s: the rejected connection is still tracked", compact, name)
			}
			an.Process(10, packets[len(packets)-1])
			if len(an.LastEvents) != 0 {
				t.Fatalf("compact=%v %s: a later packet reported %+v", compact, name, an.LastEvents)
			}
		}
	}
}
