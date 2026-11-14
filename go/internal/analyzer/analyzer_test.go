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
