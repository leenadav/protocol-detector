package live

import (
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/capture"
	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/testframes"
)

const request = "GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n"

// closed is a complete HTTP exchange that ends with FIN from both sides (test_session_reuse.closed_connection).
func closed(base uint32) [][]byte {
	c, s := base, base+100000
	n := uint32(len(request))
	return [][]byte{
		testframes.TCP("192.0.2.10", 52000, "198.51.100.20", 80, c, 0, 0x02, nil),
		testframes.TCP("198.51.100.20", 80, "192.0.2.10", 52000, s, c+1, 0x12, nil),
		testframes.TCP("192.0.2.10", 52000, "198.51.100.20", 80, c+1, s+1, 0x18, []byte(request)),
		testframes.TCP("192.0.2.10", 52000, "198.51.100.20", 80, c+1+n, s+1, 0x11, nil),
		testframes.TCP("198.51.100.20", 80, "192.0.2.10", 52000, s+1, c+2+n, 0x11, nil),
		testframes.TCP("192.0.2.10", 52000, "198.51.100.20", 80, c+2+n, s+2, 0x10, nil),
	}
}

func monitor(t *testing.T) (*Monitor, *[]Event) {
	t.Helper()
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	var events []Event
	m, err := NewMonitor(pack, Options{MaxConnections: 8, ByteLimit: 16384, IdleTimeout: 5, CRC32CByteLimit: 4096, Observation: "handshake",
		Checksums: "ignore"}, "0123456789abcdef", func(e Event) { events = append(events, e) })
	if err != nil {
		t.Fatal(err)
	}
	return m, &events
}

func feed(t *testing.T, m *Monitor, frames [][]byte, start, step float64) {
	t.Helper()
	for i, f := range frames {
		now := start + float64(i)*step
		if err := m.Tick(now); err != nil {
			t.Fatal(err)
		}
		if err := m.Accept(capture.Record{Timestamp: now, Data: f, OriginalLength: len(f), Linktype: 1}, now); err != nil {
			t.Fatal(err)
		}
	}
}

func generations(events []Event, transportName string) (gens []int, ids map[interface{}]bool) {
	ids = map[interface{}]bool{}
	for _, e := range events {
		if e.Kind == "session" && e.Fields["transport"] == transportName {
			gens = append(gens, e.Fields["generation"].(int))
			ids[e.Fields["session_id"]] = true
		}
	}
	return gens, ids
}

// Milestone B: a connection after the tuple closed is the next generation, never a suppressed duplicate.
func TestAConnectionAfterTheTupleClosedIsTheNextGeneration(t *testing.T) {
	m, events := monitor(t)
	frames := append(append(closed(1000), closed(500000)...), closed(900000)...)
	feed(t, m, frames, 10, 1)
	if err := m.End("stop"); err != nil {
		t.Fatal(err)
	}
	gens, ids := generations(*events, "tcp")
	if len(gens) != 3 || gens[0] != 0 || gens[1] != 1 || gens[2] != 2 || len(ids) != 1 {
		t.Fatalf("generations %v over %d ids", gens, len(ids))
	}
	if m.generations.Held() != 0 {
		t.Fatalf("%d tuples still hold a generation after every flow was published", m.generations.Held())
	}
}

// Generations come from one counter per capture: unique across tuples, and only flows in flight hold one.
func TestGenerationsAreUniquePerCaptureAndTheTableStaysBounded(t *testing.T) {
	m, events := monitor(t)
	held := 0
	n := uint32(len(request))
	for i := 0; i < 3000; i++ {
		client := "192.0.2." + itoaTest(1+i%200)
		port := uint16(40000 + i/200)
		frames := [][]byte{
			testframes.TCP(client, port, "198.51.100.20", 80, 1000, 0, 0x02, nil),
			testframes.TCP("198.51.100.20", 80, client, port, 9000, 1001, 0x12, nil),
			testframes.TCP(client, port, "198.51.100.20", 80, 1001, 9001, 0x18, []byte(request)),
			testframes.TCP(client, port, "198.51.100.20", 80, 1001+n, 9001, 0x11, nil),
			testframes.TCP("198.51.100.20", 80, client, port, 9001, 1002+n, 0x11, nil),
		}
		feed(t, m, frames, 10+float64(i), 0)
		if h := m.generations.Held(); h > held {
			held = h
		}
	}
	if err := m.End("stop"); err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	for _, e := range *events {
		if e.Kind == "session" {
			seen[e.Fields["generation"].(int)] = true
		}
	}
	if len(seen) != 3000 || !seen[0] || !seen[2999] || held > 8 || m.generations.Held() != 0 {
		t.Fatalf("%d distinct generations, at most %d held, %d left", len(seen), held, m.generations.Held())
	}
}

func itoaTest(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return itoaTest(n/10) + string(rune('0'+n%10))
}

func TestAUDPFlowAfterTheEarlierOneExpiredIsTheNextGeneration(t *testing.T) {
	m, events := monitor(t)
	dns := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	datagram := testframes.UDP("192.0.2.10", 53000, "198.51.100.53", 53, dns)
	feed(t, m, [][]byte{datagram, datagram}, 10, 60)
	if err := m.End("stop"); err != nil {
		t.Fatal(err)
	}
	if gens, ids := generations(*events, "udp"); len(gens) != 2 || gens[0] != 0 || gens[1] != 1 || len(ids) != 1 {
		t.Fatalf("generations %v over %d ids", gens, len(ids))
	}
}

func TestAConnectionAfterAGapRetractedTheTupleIsTheNextGeneration(t *testing.T) {
	m, events := monitor(t)
	feed(t, m, closed(1000)[:3], 10, 1)
	if err := m.InvalidateAll("Capture reported packet loss", "active_connections"); err != nil {
		t.Fatal(err)
	}
	feed(t, m, closed(500000), 20, 1)
	if err := m.End("stop"); err != nil {
		t.Fatal(err)
	}
	if gens, _ := generations(*events, "tcp"); len(gens) != 1 || gens[0] != 1 {
		t.Fatalf("generations %v (generation 0 was retracted)", gens)
	}
}
