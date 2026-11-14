package analyzer

import (
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/session"
	"github.com/leenadav/protocol-detector/go/internal/transport"
)

const packPath = "../../../migration/fixtures/content.json"

var (
	client  = transport.Endpoint{Addr: "192.0.2.10", Port: 52000}
	server  = transport.Endpoint{Addr: "198.51.100.20", Port: 80}
	request = []byte("GET / HTTP/1.1\r\nHost: a.example\r\n\r\n")
)

func seg(src, dst transport.Endpoint, seq, ack uint32, flags byte, payload []byte) *transport.TCP {
	return &transport.TCP{Source: src, Destination: dst, Sequence: seq, Ack: ack, Flags: flags, Payload: payload}
}

func newAnalyzer(t *testing.T, opts session.Options) *Analyzer {
	t.Helper()
	pack, err := content.Load(packPath)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(pack, Options{Session: opts})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// open runs SYN / SYN-ACK / ACK and the HTTP request; it returns the events of the request packet.
func open(a *Analyzer, now float64, c, s transport.Endpoint) []contracts.Event {
	a.Process(now, seg(c, s, 999, 0, transport.SYN, nil))
	a.Process(now, seg(s, c, 8999, 1000, transport.SYN|transport.ACK, nil))
	a.Process(now, seg(c, s, 1000, 9000, transport.ACK, nil))
	a.Process(now, seg(c, s, 1000, 9000, transport.ACK|8, request))
	return a.LastEvents
}

func identified(events []contracts.Event) bool {
	for _, e := range events {
		if e.Observation.Status == contracts.Identified {
			return true
		}
	}
	return false
}

// Review R1 (2026-11-14): the analyzer kept every direction sink ever created and scanned all of them on every
// packet. Retained sinks must be bounded by the packet in progress whatever the number of past connections, each
// closed connection must still produce its record, and the packet's events must still be reported.
func TestRetiredSinksAreReleased(t *testing.T) {
	endings := map[string]func(a *Analyzer, now float64){
		"rst": func(a *Analyzer, now float64) {
			a.Process(now, seg(client, server, 1000+uint32(len(request)), 9000, transport.RST, nil))
		},
		"fin": func(a *Analyzer, now float64) {
			end := 1000 + uint32(len(request))
			a.Process(now, seg(client, server, end, 9000, transport.FIN|transport.ACK, nil))
			a.Process(now, seg(server, client, 9000, end+1, transport.FIN|transport.ACK, nil))
			a.Process(now, seg(client, server, end+1, 9001, transport.ACK, nil))
		},
		"idle": func(a *Analyzer, now float64) {
			a.Process(now+120, &transport.UDP{Source: client, Destination: server, Payload: []byte("x")})
		},
	}
	for name, end := range endings {
		t.Run(name, func(t *testing.T) {
			a := newAnalyzer(t, session.Options{MaxConnections: 1, ByteLimit: 65536, IdleTimeout: 60, MaxUDPFlows: -1})
			records := 0
			for cycle := 0; cycle < 1000; cycle++ {
				now := float64(cycle) * 200
				if events := open(a, now, client, server); !identified(events) {
					t.Fatalf("cycle %d: request packet reported %+v", cycle, events)
				}
				end(a, now+1)
				if a.NotPorted != nil {
					t.Fatal(a.NotPorted)
				}
				for _, r := range a.Records {
					if r["transport"] == "tcp" {
						if r["app"] != "web-browsing" || r["engine_status"] != "identified" {
							t.Fatalf("cycle %d: record %v", cycle, r)
						}
						records++
					}
				}
				a.Records = nil // drain the intentionally accumulated output
				if _, connections, _ := a.Tracker.Tables(); connections != 0 {
					t.Fatalf("cycle %d: %d connections still tracked", cycle, connections)
				}
				if n := a.RetainedSinks(); n > 2 {
					t.Fatalf("cycle %d: analyzer retains %d sinks", cycle, n)
				}
			}
			if records != 1000 {
				t.Fatalf("%d TCP records for 1000 connections", records)
			}
			if err := a.Finish("eof"); err != nil || a.RetainedSinks() != 0 {
				t.Fatalf("after Finish: %v, %d sinks", err, a.RetainedSinks())
			}
		})
	}
}

// The sinks of connections that stay open are held by their connections only; Finish closes them all, produces
// every record and leaves nothing referenced.
func TestFinishReleasesOpenConnections(t *testing.T) {
	a := newAnalyzer(t, session.Options{MaxConnections: 64, ByteLimit: 65536, IdleTimeout: 60, MaxUDPFlows: -1})
	for i := 0; i < 50; i++ {
		c := transport.Endpoint{Addr: "192.0.2.10", Port: uint16(40000 + i)}
		if !identified(open(a, 0, c, server)) {
			t.Fatalf("connection %d not identified", i)
		}
		if n := a.RetainedSinks(); n > 2 {
			t.Fatalf("connection %d: analyzer retains %d sinks while 50 are open", i, n)
		}
	}
	if err := a.Finish("eof"); err != nil {
		t.Fatal(err)
	}
	if len(a.Records) != 50 || a.RetainedSinks() != 0 {
		t.Fatalf("%d records, %d retained sinks", len(a.Records), a.RetainedSinks())
	}
	if tracked, connections, _ := a.Tracker.Tables(); tracked != 0 || connections != 0 {
		t.Fatalf("tables after Finish: %d %d", tracked, connections)
	}
}

// An invalidation and the retirement that follows it in the same packet are still reported for that packet.
func TestInvalidationEventSurvivesRetirement(t *testing.T) {
	a := newAnalyzer(t, session.Options{MaxConnections: 4, ByteLimit: 65536, IdleTimeout: 60, MaxUDPFlows: -1})
	open(a, 0, client, server)
	conflicting := append([]byte{}, request...)
	conflicting[0] = 'P'
	a.Process(0.1, seg(client, server, 1000, 9000, transport.ACK|8, conflicting))
	found := false
	for _, e := range a.LastEvents {
		if e.Observation.Status == contracts.Invalidated {
			found = true
		}
	}
	if !found {
		t.Fatalf("no invalidation among %+v", a.LastEvents)
	}
	if n := a.RetainedSinks(); n > 2 {
		t.Fatalf("analyzer retains %d sinks", n)
	}
}

// ldapExtended builds an LDAP ExtendedRequest (0x77) or ExtendedResponse (0x78) with an optional name and result.
func ldapExtended(id byte, tag byte, oid string, result int) []byte {
	var body []byte
	if result >= 0 {
		body = append(body, 0x0a, 1, byte(result), 4, 0, 4, 0)
	}
	if oid != "" {
		nameTag := byte(0x80)
		if tag == 0x78 {
			nameTag = 0x8a
		}
		body = append(body, nameTag, byte(len(oid)))
		body = append(body, oid...)
	}
	message := append([]byte{2, 1, id, tag, byte(len(body))}, body...)
	return append([]byte{0x30, byte(len(message))}, message...)
}

const startTLS = "1.3.6.1.4.1.1466.20037"

// clientHello is a minimal TLS 1.2 ClientHello record the Go TLS parser identifies.
var clientHello = func() []byte {
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0, 0, 0)
	hs := append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}()

type step struct {
	server  bool
	payload []byte
}

// converse runs the handshake, the steps in capture order and FIN from both sides; it returns the analyzer, the
// events reported per step packet and the peer events per step packet.
func converse(t *testing.T, steps []step) (*Analyzer, [][]contracts.Event, [][]PeerEvent) {
	t.Helper()
	a := newAnalyzer(t, session.Options{MaxConnections: 4, ByteLimit: 65536, IdleTimeout: 60, MaxUDPFlows: -1})
	ldapServer := transport.Endpoint{Addr: "198.51.100.20", Port: 389}
	a.Process(0, seg(client, ldapServer, 999, 0, transport.SYN, nil))
	a.Process(0, seg(ldapServer, client, 8999, 1000, transport.SYN|transport.ACK, nil))
	a.Process(0, seg(client, ldapServer, 1000, 9000, transport.ACK, nil))
	sent := map[bool]uint32{}
	var events [][]contracts.Event
	var peers [][]PeerEvent
	for i, s := range steps {
		src, dst, base, peer := client, ldapServer, uint32(1000), uint32(9000)
		if s.server {
			src, dst, base, peer = ldapServer, client, 9000, 1000
		}
		a.Process(0.001*float64(i+1), seg(src, dst, base+sent[s.server], peer+sent[!s.server], transport.ACK|8, s.payload))
		sent[s.server] += uint32(len(s.payload))
		events = append(events, a.LastEvents)
		peers = append(peers, a.PeerEvents)
	}
	if a.NotPorted != nil {
		t.Fatal(a.NotPorted)
	}
	return a, events, peers
}

func connectionSinks(t *testing.T, a *Analyzer) (*Sink, *Sink) {
	t.Helper()
	ldapServer := transport.Endpoint{Addr: "198.51.100.20", Port: 389}
	c := a.Tracker.Manager().Connections[session.KeyOf(client, ldapServer)]
	if c == nil {
		t.Fatal("connection not tracked")
	}
	return c.Directions[client].Sink.(*Sink), c.Directions[ldapServer].Sink.(*Sink)
}

func encryption(o contracts.Observation) string {
	if o.Encryption == nil {
		return ""
	}
	return *o.Encryption
}

// A StartTLS success with the request's message id opens the client direction; a ClientHello recorded before the
// answer is replayed into it once and reported as a peer event of the server's packet.
func TestLDAPStartTLSOpensTheClientAndReplaysOnce(t *testing.T) {
	request, success := ldapExtended(1, 0x77, startTLS, -1), ldapExtended(1, 0x78, startTLS, 0)
	a, _, peers := converse(t, []step{{false, request}, {false, clientHello}, {true, success}})
	cl, _ := connectionSinks(t, a)
	if encryption(cl.In.Observation) != "tls" || a.Tracker.Counts["ldap_starttls_correlated"] != 1 {
		t.Fatalf("client %+v, count %d", cl.In.Observation, a.Tracker.Counts["ldap_starttls_correlated"])
	}
	if len(peers[2]) != 1 || peers[2][0].Source != client || peers[2][0].Event.Kind != contracts.Shifted {
		t.Fatalf("peer events of the answer: %+v", peers[2])
	}
	if cl.In.Metrics.BytesReceived != len(request)+len(clientHello) {
		t.Fatalf("replayed bytes counted twice: %d", cl.In.Metrics.BytesReceived)
	}
}

// Refusals, another message id, and a success to another operation open nothing.
func TestLDAPStartTLSOpensNothingWithoutAMatchingSuccess(t *testing.T) {
	request := ldapExtended(1, 0x77, startTLS, -1)
	for name, answer := range map[string][]byte{
		"refused":  ldapExtended(1, 0x78, startTLS, 52),
		"other id": ldapExtended(2, 0x78, "", 0),
	} {
		a, _, peers := converse(t, []step{{false, request}, {false, clientHello}, {true, answer}})
		cl, _ := connectionSinks(t, a)
		if encryption(cl.In.Observation) != "" || len(peers[2]) != 0 || a.Tracker.Counts["ldap_starttls_correlated"] != 0 {
			t.Errorf("%s: client %+v, peers %+v", name, cl.In.Observation, peers[2])
		}
	}
	whoami := ldapExtended(1, 0x77, "1.3.6.1.4.1.4203.1.11.3", -1)
	a, _, _ := converse(t, []step{{false, whoami}, {true, ldapExtended(1, 0x78, "", 0)}, {false, clientHello}})
	if cl, _ := connectionSinks(t, a); encryption(cl.In.Observation) != "" {
		t.Errorf("whoami success opened the client: %+v", cl.In.Observation)
	}
}

// The case found while porting (fixed in the Python reference too): a named success coalesced with the
// ServerHello shifts the server inside that packet, and the client must still be opened through the announcement.
func TestLDAPNamedSuccessCoalescedWithTheServerHello(t *testing.T) {
	request, success := ldapExtended(1, 0x77, startTLS, -1), ldapExtended(1, 0x78, startTLS, 0)
	serverHello := append([]byte{0x16, 3, 3, 0, 0}, []byte{}...) // placeholder record; the server phase result is not asserted
	a, _, peers := converse(t, []step{{false, append(append([]byte{}, request...), clientHello...)}, {true, append(append([]byte{}, success...), serverHello...)}})
	cl, sv := connectionSinks(t, a)
	if sv.In.Announcement == nil || *sv.In.Announcement.ApplicationProtocol != "ldap" {
		t.Fatalf("server announcement: %+v", sv.In.Announcement)
	}
	if encryption(cl.In.Observation) != "tls" || len(peers[1]) != 1 {
		t.Fatalf("client %+v, peers %+v", cl.In.Observation, peers[1])
	}
}

// OpenShift refuses a direction that is not a terminal, unshifted identification, and Replay refuses without a
// host-opened phase or beyond the skipped bytes.
func TestOpenShiftAndReplayPreconditions(t *testing.T) {
	a, _, _ := converse(t, []step{{false, ldapExtended(1, 0x77, startTLS, -1)}})
	cl, _ := connectionSinks(t, a)
	if _, ok := cl.In.Replay([]byte{1}); ok {
		t.Fatal("replay accepted without an opened phase")
	}
	if !cl.In.OpenShift("ldap-starttls", "tls") {
		t.Fatal("terminal identified direction refused")
	}
	if cl.In.OpenShift("ldap-starttls", "tls") {
		t.Fatal("second open accepted")
	}
	if _, ok := cl.In.Replay(make([]byte, 1)); ok {
		t.Fatal("replay beyond the skipped bytes accepted")
	}
}
