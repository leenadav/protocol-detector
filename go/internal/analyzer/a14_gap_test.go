package analyzer

import (
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/session"
	"github.com/leenadav/protocol-detector/go/internal/transport"
)

// Security review A14 (PRO-497, docs/security/A14-MERGE-TRAIN-PRO-497.md): reproducers for the residual gaps of
// SEC-SESS-1 (#124). The half-open budget evicts only states nobody settled; these tests settle the flood states
// with the attacker's own packets. While a gap persists the test skips with its id; once a fix makes the target
// admitted, it fails and asks for the marker to be removed. Each checks its own reproducer first and fails
// (never skips) if the reproducer drifts. Synthetic frames only.

func secGap(t *testing.T, id string, fixed bool, today string) {
	t.Helper()
	if fixed {
		t.Fatalf("%s is fixed (docs/security/A14-MERGE-TRAIN-PRO-497.md): remove secGap() and assert it plainly", id)
	}
	t.Skipf("%s (docs/security/A14-MERGE-TRAIN-PRO-497.md): fix owned by the engine lane; today %s", id, today)
}

// a14DNSQuery is a plain DNS query for example.com A. The ID avoids the PRO-477 side observation (ID 9).
func a14DNSQuery() []byte {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	return append(q, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1)
}

// SEC-SESS-2: one valid DNS query per spoofed source port decides each flow at its first datagram, so the flood
// never enters the half-open queue; a table of decided flows refuses every new flow until the idle timeout.
func TestSecGapUDPDecidedFloodLocksOutNewFlows(t *testing.T) {
	a := newAnalyzer(t, session.Options{MaxConnections: 32, ByteLimit: 65536, IdleTimeout: 60, MaxUDPFlows: -1})
	resolver := transport.Endpoint{Addr: "198.51.100.53", Port: 53}
	for i := 0; i < 32; i++ {
		src := transport.Endpoint{Addr: "203.0.113.66", Port: uint16(30000 + i)}
		a.Process(0.001*float64(i), udp(src, resolver, a14DNSQuery()))
		if len(a.LastEvents) != 1 || a.LastEvents[0].Observation.Status != contracts.Identified {
			t.Fatalf("reproducer drifted: flood datagram %d is not an identified DNS query: %+v", i, a.LastEvents)
		}
	}
	if _, _, _, _, open := a.Tracker.HalfOpen(); open != 0 {
		t.Fatalf("reproducer drifted: %d flood flows still half-open", open)
	}
	victim := transport.Endpoint{Addr: "192.0.2.10", Port: 51000}
	a.Process(1, udp(victim, resolver, a14DNSQuery()))
	a.Process(59, udp(victim, resolver, a14DNSQuery()))
	admitted := a.Tracker.Tracked(victim, resolver) != nil
	if !admitted && a.Tracker.Counts["udp_flow_limit"] != 2 {
		t.Fatalf("reproducer drifted: refused without the counter: %v", a.Tracker.Counts)
	}
	secGap(t, "SEC-SESS-2", admitted,
		"32 one-datagram DNS flows fill the table; the victim's flow is refused at t=1 s and t=59 s (udp_flow_limit 2)")
}

// SEC-SESS-3: a passive sensor cannot tell a forged SYN-ACK from the server's, so a SYN plus a SYN-ACK per tuple
// (both sent by the attacker) completes each handshake; established connections are never evicted for a new SYN.
func TestSecGapTCPForgedHandshakeFloodLocksOutNewConnections(t *testing.T) {
	a := newAnalyzer(t, session.Options{MaxConnections: 32, ByteLimit: 65536, IdleTimeout: 60, MaxUDPFlows: -1})
	server := transport.Endpoint{Addr: "198.51.100.20", Port: 443}
	for i := 0; i < 32; i++ {
		src := transport.Endpoint{Addr: "203.0.113.66", Port: uint16(40000 + i)}
		a.Process(0.001*float64(i), seg(src, server, 999, 0, transport.SYN, nil))
		if m := a.Process(0.001*float64(i), seg(server, src, 8999, 1000, transport.SYN|transport.ACK, nil)); m != "Tracking both directions (SYN/SYN-ACK observed)" {
			t.Fatalf("reproducer drifted: forged handshake %d: %s", i, m)
		}
	}
	victim := transport.Endpoint{Addr: "192.0.2.10", Port: 52000}
	m := a.Process(1, seg(victim, server, 4999, 0, transport.SYN, nil))
	admitted := a.Tracker.Tracked(victim, server) != nil
	if !admitted && m != "LIMIT: too many tracked connections" {
		t.Fatalf("reproducer drifted: %s", m)
	}
	secGap(t, "SEC-SESS-3", admitted, "32 forged handshakes (64 packets) fill the table; the victim's SYN reads \""+m+"\"")
}
