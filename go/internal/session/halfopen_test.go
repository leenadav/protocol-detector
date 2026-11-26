package session

import (
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/testframes"
	"github.com/leenadav/protocol-detector/go/internal/transport"
)

// SEC-SESS-1 (PRO-398): connections whose handshake did not complete and UDP flows with no decision have their own
// budget and a short lifetime, so a flood of them cannot keep real connections out of the tracking tables.

func attacker(port uint16) transport.Endpoint {
	return transport.Endpoint{Addr: "203.0.113.66", Port: port}
}

func (h *harness) reasons() map[string]int {
	out := map[string]int{}
	for _, c := range h.closed {
		out[c.Reason]++
	}
	return out
}

func udpPacket(t *testing.T, src, dst transport.Endpoint) *transport.UDP {
	t.Helper()
	p, err := transport.Decode(testframes.UDP(src.Addr, src.Port, dst.Addr, dst.Port, []byte("datagram")), 1, transport.Ignore)
	if err != nil {
		t.Fatal(err)
	}
	return p.(*transport.UDP)
}

func identified(proto string) *contracts.Observation {
	return &contracts.Observation{Status: contracts.Identified, ApplicationProtocol: &proto, Reason: "validated"}
}

func TestHalfOpenDefaultsAndValidation(t *testing.T) {
	h := newHarness(t, Options{MaxConnections: 8, MaxUDPFlows: 8})
	if tcp, udp, timeout, _, _ := h.tracker.HalfOpen(); tcp != 6 || udp != 6 || timeout != DefaultHalfOpenTimeout {
		t.Fatalf("defaults: %d %d %v", tcp, udp, timeout)
	}
	short := newHarness(t, Options{MaxConnections: 1, MaxUDPFlows: 1, IdleTimeout: 0.5})
	if tcp, udp, timeout, _, _ := short.tracker.HalfOpen(); tcp != 1 || udp != 1 || timeout != 0.5 {
		t.Fatalf("small table: %d %d %v", tcp, udp, timeout)
	}
	for _, bad := range []Options{{MaxHalfOpen: 9}, {MaxHalfOpen: -1}, {MaxHalfOpenUDP: 9}, {HalfOpenTimeout: -1}} {
		bad.MaxConnections, bad.MaxUDPFlows, bad.ByteLimit, bad.IdleTimeout = 8, 8, 65536, 60
		if _, err := NewTracker(bad, func() Sink { return &recorder{} }, nil); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}

func TestSYNFloodEvictsOnlyHalfOpenAndARealConnectionStillPasses(t *testing.T) {
	h := newHarness(t, Options{MaxConnections: 8})
	established := []transport.Endpoint{{Addr: "192.0.2.10", Port: 40001}, {Addr: "192.0.2.10", Port: 40002}}
	for _, c := range established {
		h.handshake(0, c, server, 1000, 9000)
	}
	const flood = 100
	for i := 0; i < flood; i++ {
		m := h.tcp(0.01*float64(i), seg(attacker(uint16(10000+i)), server, 77, 0, transport.SYN, nil))
		if m != "SYN: waiting for SYN-ACK" {
			t.Fatalf("flood SYN %d: %s", i, m)
		}
		tracked, _, _ := h.tracker.Tables()
		if _, _, _, open, _ := h.tracker.HalfOpen(); open > 6 || tracked > 8 {
			t.Fatalf("flood SYN %d: %d half-open, %d tracked", i, open, tracked)
		}
	}
	if got := h.tracker.Counts["half_open_evicted"]; got != flood-6 {
		t.Fatalf("evicted %d, want %d", got, flood-6)
	}
	if r := h.reasons(); r[ReasonHalfOpenEvicted] != flood-6 || len(r) != 1 {
		t.Fatalf("reasons %v", r)
	}
	for _, c := range established {
		if s := h.tracker.Tracked(c, server); s == nil || !s.Ready {
			t.Fatalf("established connection %s was evicted", c)
		}
	}
	// The oldest flood entries went first: the six newest SYNs are what remains.
	if h.tracker.Tracked(attacker(10000+flood-7), server) != nil || h.tracker.Tracked(attacker(10000+flood-6), server) == nil {
		t.Fatal("eviction is not oldest first")
	}
	// A real handshake during the flood: its SYN evicts the oldest half-open entry and it completes.
	real := transport.Endpoint{Addr: "192.0.2.10", Port: 40003}
	h.handshake(1.5, real, server, 5000, 7000)
	if h.messages[len(h.messages)-2] != "Tracking both directions (SYN/SYN-ACK observed)" {
		t.Fatal(h.messages[len(h.messages)-3:])
	}
	if m := h.tcp(1.6, seg(real, server, 5000, 7000, transport.ACK|8, request)); m == "No new contiguous data" {
		t.Fatal("real connection received no data")
	}
	// More flood never evicts the now established connection.
	for i := 0; i < 20; i++ {
		h.tcp(1.7, seg(attacker(uint16(20000+i)), server, 77, 0, transport.SYN, nil))
	}
	if s := h.tracker.Tracked(real, server); s == nil || !s.Ready {
		t.Fatal("established connection evicted by a SYN")
	}
}

func TestSYNIntoATableOfEstablishedConnectionsIsRefusedWithoutAllocating(t *testing.T) {
	h := newHarness(t, Options{MaxConnections: 4})
	for i := 0; i < 4; i++ {
		h.handshake(0, transport.Endpoint{Addr: "192.0.2.10", Port: uint16(40000 + i)}, server, 1000, 9000)
	}
	syn := seg(attacker(10000), server, 77, 0, transport.SYN, nil)
	if m := h.tcp(0.1, syn); m != "LIMIT: too many tracked connections" || len(h.closed) != 0 {
		t.Fatalf("%s, %d closed", m, len(h.closed))
	}
	if allocs := testing.AllocsPerRun(200, func() { h.tracker.Process(0.1, syn) }); allocs != 0 {
		t.Fatalf("a refused SYN allocated %v times", allocs)
	}
	if h.tracker.Counts["half_open_evicted"] != 0 {
		t.Fatal("an established connection was evicted")
	}
}

func TestSYNRetransmissionDoesNotExtendTheConnection(t *testing.T) {
	h := newHarness(t, Options{})
	syn := seg(client, server, 4999, 0, transport.SYN, nil)
	h.tcp(0, syn)
	state := h.tracker.Tracked(client, server)
	for now := 0.5; now < DefaultHalfOpenTimeout; now += 0.5 {
		if !h.tracker.SYNRetransmission(now, syn) {
			t.Fatalf("not a retransmission at %v", now)
		}
		if m := h.tcp(now, syn); m != "SYN retransmission" {
			t.Fatalf("at %v: %s", now, m)
		}
		if state.Time != 0 || state.Start != 0 {
			t.Fatalf("retransmission at %v moved the state's time to %v", now, state.Time)
		}
	}
	// HalfOpenTimeout after the first SYN the half-open state ends, however many retransmissions came.
	if h.tracker.SYNRetransmission(DefaultHalfOpenTimeout, syn) {
		t.Fatal("an expired half-open state still counts as retransmitted")
	}
	if m := h.tcp(DefaultHalfOpenTimeout, syn); m != "SYN: waiting for SYN-ACK" {
		t.Fatal(m)
	}
	if len(h.closed) != 1 || h.closed[0].Reason != ReasonIdle || h.tracker.Counts["half_open_timeout"] != 1 {
		t.Fatalf("closed %+v counts %v", h.closed, h.tracker.Counts)
	}
	// An established connection: a retransmitted SYN neither refreshes its idle time nor its stream's LastSeen.
	e := newHarness(t, Options{})
	e.handshake(0, client, server, 5000, 9000)
	for now := 1.0; now < 60; now += 10 {
		if m := e.tcp(now, seg(client, server, 4999, 0, transport.SYN, nil)); m != "SYN retransmission" {
			t.Fatal(m)
		}
	}
	if s := e.tracker.Tracked(client, server); s.Time != 0 || e.tracker.Manager().Connections[KeyOf(client, server)].LastSeen != 0 {
		t.Fatal("retransmitted SYN refreshed an established connection")
	}
	e.tracker.Expire(60)
	if len(e.closed) != 1 || e.closed[0].Reason != ReasonIdle || e.tracker.Counts["half_open_timeout"] != 0 {
		t.Fatalf("established idle expiry: %+v", e.closed)
	}
}

func TestHalfOpenTimeoutCountsFromTheSYN(t *testing.T) {
	h := newHarness(t, Options{})
	h.tcp(0, seg(client, server, 4999, 0, transport.SYN, nil))
	// A bare ACK on a half-open connection (handshake mode) refreshes its idle time but not its half-open lifetime.
	for now := 1.0; now < DefaultHalfOpenTimeout; now++ {
		if m := h.tcp(now, seg(client, server, 5000, 1, transport.ACK, nil)); m != "SKIP: SYN-ACK not observed" {
			t.Fatal(m)
		}
	}
	h.tracker.Expire(DefaultHalfOpenTimeout)
	if len(h.closed) != 1 || h.closed[0].Reason != ReasonIdle {
		t.Fatalf("closed %+v", h.closed)
	}
	// A SYN-ACK within the timeout establishes it, and from then on only the idle timeout applies.
	h.tcp(10, seg(client, server, 4999, 0, transport.SYN, nil))
	h.tcp(14, seg(server, client, 8999, 5000, transport.SYN|transport.ACK, nil))
	h.tracker.Expire(60)
	if len(h.closed) != 1 || h.tracker.Tracked(client, server) == nil {
		t.Fatal("established connection expired on the half-open timeout")
	}
	if _, _, _, open, _ := h.tracker.HalfOpen(); open != 0 {
		t.Fatalf("%d half-open after the handshake", open)
	}
}

func TestUDPFloodEvictsOnlyUndecidedFlows(t *testing.T) {
	h := newHarness(t, Options{MaxConnections: 8, MaxUDPFlows: 8})
	dns := transport.Endpoint{Addr: "198.51.100.53", Port: 53}
	decided := transport.Endpoint{Addr: "192.0.2.10", Port: 50001}
	h.tracker.ProcessUDP(0, udpPacket(t, decided, dns), identified("dns"))
	const flood = 50
	for i := 0; i < flood; i++ {
		h.tracker.ProcessUDP(0.01*float64(i), udpPacket(t, attacker(uint16(30000+i)), dns), nil)
		_, _, flows := h.tracker.Tables()
		if _, _, _, _, open := h.tracker.HalfOpen(); open > 6 || flows > 8 {
			t.Fatalf("flood datagram %d: %d undecided, %d flows", i, open, flows)
		}
	}
	if got := h.tracker.Counts["udp_half_open_evicted"]; got != flood-6 || h.tracker.Counts["udp_flow_limit"] != 0 {
		t.Fatalf("evicted %d, limit %d", got, h.tracker.Counts["udp_flow_limit"])
	}
	if r := h.reasons(); r[ReasonHalfOpenEvicted] != flood-6 || len(r) != 1 {
		t.Fatalf("reasons %v", r)
	}
	if h.tracker.Tracked(decided, dns) == nil {
		t.Fatal("decided flow evicted")
	}
	// A real flow during the flood is admitted; once identified it is not evicted by more flood.
	real := transport.Endpoint{Addr: "192.0.2.10", Port: 50002}
	h.tracker.ProcessUDP(1, udpPacket(t, real, dns), nil)
	h.tracker.ProcessUDP(1.1, udpPacket(t, real, dns), identified("dns"))
	for i := 0; i < 20; i++ {
		h.tracker.ProcessUDP(1.2, udpPacket(t, attacker(uint16(31000+i)), dns), nil)
	}
	if h.tracker.Tracked(real, dns) == nil || h.tracker.Tracked(decided, dns) == nil {
		t.Fatal("identified flow evicted")
	}
	// Undecided flows end after HalfOpenTimeout of silence with the idle reason; decided ones stay.
	h.tracker.Expire(1.2 + DefaultHalfOpenTimeout)
	if _, _, flows := h.tracker.Tables(); flows != 2 || h.tracker.Counts["udp_half_open_timeout"] != 6 {
		t.Fatalf("%d flows, %d timed out", flows, h.tracker.Counts["udp_half_open_timeout"])
	}
	// A table full of decided flows still refuses a new flow, as before.
	full := newHarness(t, Options{MaxConnections: 2, MaxUDPFlows: 2})
	for i := 0; i < 2; i++ {
		full.tracker.ProcessUDP(0, udpPacket(t, transport.Endpoint{Addr: "192.0.2.10", Port: uint16(52000 + i)}, dns), identified("dns"))
	}
	full.tracker.ProcessUDP(0.1, udpPacket(t, attacker(1), dns), nil)
	if full.tracker.Counts["udp_flow_limit"] != 1 || full.tracker.Counts["udp_half_open_evicted"] != 0 || len(full.closed) != 0 {
		t.Fatalf("full table of decided flows: %v", full.tracker.Counts)
	}
}

func TestRealConnectionPassesASYNFloodInEveryObservationMode(t *testing.T) {
	for _, mode := range []string{ModeHandshake, ModeAsymmetric, ModeMidstream} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, Options{MaxConnections: 4, Observation: mode})
			flood := func(at float64, base int) {
				for i := 0; i < 40; i++ {
					h.tcp(at, seg(attacker(uint16(base+i)), server, 77, 0, transport.SYN, nil))
				}
			}
			flood(0, 10000)
			switch mode {
			case ModeHandshake:
				h.tcp(0.1, seg(client, server, 4999, 0, transport.SYN, nil))
				flood(0.15, 11000) // the real SYN is half-open now and can be evicted like any other
				h.tcp(0.2, seg(client, server, 4999, 0, transport.SYN, nil))
				if m := h.tcp(0.2, seg(server, client, 8999, 5000, transport.SYN|transport.ACK, nil)); m != "Tracking both directions (SYN/SYN-ACK observed)" {
					t.Fatal(m)
				}
			case ModeAsymmetric:
				h.tcp(0.1, seg(client, server, 4999, 0, transport.SYN, nil))
				h.tcp(0.2, seg(client, server, 5000, 9000, transport.ACK, request))
			case ModeMidstream:
				h.tcp(0.2, seg(client, server, 5000, 9000, transport.ACK, request))
			}
			s := h.tracker.Tracked(client, server)
			if s == nil || !s.Ready {
				t.Fatalf("%s: real connection not established: %v", mode, h.messages[len(h.messages)-1])
			}
			flood(0.3, 12000)
			if h.tracker.Tracked(client, server) != s {
				t.Fatalf("%s: established connection evicted", mode)
			}
			if tracked, _, _ := h.tracker.Tables(); tracked > 4 {
				t.Fatalf("%s: %d tracked", mode, tracked)
			}
			if mode != ModeMidstream && len(h.sinks) == 0 {
				t.Fatal("no stream opened")
			}
			delivered := 0
			for _, sink := range h.sinks {
				delivered += len(sink.data)
			}
			if mode != ModeHandshake && delivered != len(request) {
				t.Fatalf("%s: delivered %d bytes", mode, delivered)
			}
		})
	}
}
