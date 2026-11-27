package session

import (
	"bytes"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/reassembly"
	"github.com/leenadav/protocol-detector/go/internal/transport"
)

// SR-17: reassembly memory is bounded by the configured window and released on expiry. A handshake-only
// connection allocates nothing, the table holds at most MaxConnections, a segment larger than the window grows
// the direction to at most 2 * ByteLimit (bytes plus presence map), and idle expiry drops and zeroes every window.
func TestSecurityReassemblyMemoryIsWindowBoundedAndReleased(t *testing.T) {
	h := newHarness(t, Options{MaxConnections: 8, ByteLimit: 1024, IdleTimeout: 60, HalfOpenTimeout: 60, Compact: true})
	for i := 0; i < 12; i++ {
		source := transport.Endpoint{Addr: "192.0.2.1", Port: uint16(50000 + i)}
		h.tcp(float64(i), seg(source, server, 999, 0, transport.SYN, nil))
		h.tcp(float64(i), seg(server, source, 8999, 1000, transport.SYN|transport.ACK, nil))
	}
	connections := h.tracker.Manager().Connections
	if len(connections) != 8 {
		t.Fatalf("%d connections tracked with a limit of 8", len(connections))
	}
	allocated := func() int {
		total := 0
		for _, c := range connections {
			for _, d := range c.Directions {
				total += d.Stream.Allocated()
			}
		}
		return total
	}
	if got := allocated(); got != 0 {
		t.Fatalf("handshake-only connections allocated %d bytes", got)
	}
	// Half-open eviction may have replaced the oldest handshakes; any tracked connection will do.
	var source transport.Endpoint
	for port := 50000; port < 50012; port++ {
		candidate := transport.Endpoint{Addr: "192.0.2.1", Port: uint16(port)}
		if connections[KeyOf(candidate, server)] != nil {
			source = candidate
			break
		}
	}
	h.tcp(20, seg(source, server, 1000, 9000, transport.ACK|8, bytes.Repeat([]byte("x"), 3000)))
	c := connections[KeyOf(source, server)]
	if c == nil {
		t.Fatal("no connection is tracked")
	}
	stream := c.Directions[source].Stream
	if stream.Allocated() != 2*1024 || stream.Buffered() > 1024 {
		t.Fatalf("a 3000-byte segment allocated %d (%d buffered) in a 1024-byte window", stream.Allocated(), stream.Buffered())
	}
	var streams []*reassembly.Stream
	for _, c := range connections {
		for _, d := range c.Directions {
			streams = append(streams, d.Stream)
		}
	}
	h.tracker.Manager().Expire(100)
	if len(connections) != 0 {
		t.Fatalf("%d connections left after idle expiry", len(connections))
	}
	for _, s := range streams {
		if s.Allocated() != 0 {
			t.Fatalf("an expired window still holds %d bytes", s.Allocated())
		}
	}
}
