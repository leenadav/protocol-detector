// Package session owns TCP connection lifecycle and the per-direction reassembly windows, mirroring
// protocol_adapters/sessions.py (SessionManager) and the connection-tracking part of
// protocol_adapters/analyze_pcap.py (Analyzer.process). It feeds ordered, deduplicated deltas to a
// Sink per direction; the Sink is the engine's inspector in M4 and a recorder in the M3 tests.
//
// Time is the capture timestamp handed to each call (seconds, float64 as in the Python reference),
// never the host clock. All tables are bounded: connections and tracked states by maxConnections, UDP
// flows by maxUDPFlows, each direction by the byte window, and retained bytes in aggregate by an
// Account the caller sizes (ADR 0001).
package session

import (
	"github.com/leenadav/protocol-detector/go/internal/errs"
	"github.com/leenadav/protocol-detector/go/internal/reassembly"
	"github.com/leenadav/protocol-detector/go/internal/transport"
)

// Sink consumes one direction. Feed receives each contiguous byte exactly once, in order. Each method
// reports whether the consumer's observation changed (the Python snapshot comparison).
type Sink interface {
	Feed(delta []byte) (changed bool)
	Invalidate(reason string) (changed bool)
	// End: the direction ended at a trusted boundary (contiguous FIN); its events belong to the packet.
	End(reason string) (changed bool)
	// Retire: tracking of the connection ends (RST, idle, limits, capture end); the direction is ended
	// with the reason, but its events are retirement events, not the packet's (Python on_retire).
	Retire(reason string) (changed bool)
}

// Key identifies a connection or flow irrespective of direction (Python: sorted endpoint tuple).
type Key [2]transport.Endpoint

// KeyOf orders the endpoints like Python's tuple sort.
func KeyOf(a, b transport.Endpoint) Key {
	if b.Less(a) {
		return Key{b, a}
	}
	return Key{a, b}
}

// Direction is one side of a connection.
type Direction struct {
	Stream *reassembly.Stream
	Sink   Sink
}

// Connection is the reassembly state of one tracked TCP connection.
type Connection struct {
	LastSeen   float64
	Directions map[transport.Endpoint]*Direction
}

// Manager holds the bounded connection table (Python SessionManager).
type Manager struct {
	byteLimit      int
	maxConnections int
	idleTimeout    float64
	expiryInterval float64
	nextExpiry     float64
	prefixOnly     bool
	factory        func() Sink
	Connections    map[Key]*Connection
}

// NewManager validates the limits exactly like the Python constructor.
func NewManager(byteLimit, maxConnections int, idleTimeout float64, factory func() Sink, prefixOnly bool, expiryInterval float64) (*Manager, error) {
	if byteLimit < 1 || byteLimit > 65536 || maxConnections < 1 || idleTimeout <= 0 {
		return nil, errs.New(errs.Invalid, errs.ScopeCapture, "Invalid reassembly limits")
	}
	if factory == nil {
		return nil, errs.New(errs.Invalid, errs.ScopeCapture, "a sink factory is required")
	}
	return &Manager{byteLimit: byteLimit, maxConnections: maxConnections, idleTimeout: idleTimeout, factory: factory,
		prefixOnly: prefixOnly, expiryInterval: expiryInterval, nextExpiry: -1e308, Connections: map[Key]*Connection{}}, nil
}

// Expire drops connections idle for idleTimeout or longer; returns how many.
func (m *Manager) Expire(now float64) int {
	if now < m.nextExpiry {
		return 0
	}
	m.nextExpiry = now + m.expiryInterval
	count := 0
	for key, c := range m.Connections {
		if now-c.LastSeen >= m.idleTimeout {
			m.release(key)
			count++
		}
	}
	return count
}

func (m *Manager) release(key Key) {
	if c, ok := m.Connections[key]; ok {
		for _, d := range c.Directions {
			d.Stream.Release()
		}
		delete(m.Connections, key)
	}
}

// Open starts tracking with the first data sequence number of each direction.
func (m *Manager) Open(source, destination transport.Endpoint, sourceSeq, destinationSeq uint32, now float64) error {
	m.Expire(now)
	if source == destination {
		return errs.New(errs.Invalid, errs.ScopeFlow, "Endpoints must differ")
	}
	key := KeyOf(source, destination)
	if _, exists := m.Connections[key]; exists {
		return errs.New(errs.Invalid, errs.ScopeFlow, "Connection already exists; close it before reusing endpoints")
	}
	if len(m.Connections) >= m.maxConnections {
		return errs.Exceeded(errs.ScopeCapture, m.maxConnections, "Connection limit reached")
	}
	a, _ := reassembly.New(sourceSeq, m.byteLimit, m.prefixOnly)
	b, _ := reassembly.New(destinationSeq, m.byteLimit, m.prefixOnly)
	m.Connections[key] = &Connection{LastSeen: now, Directions: map[transport.Endpoint]*Direction{
		source: {Stream: a, Sink: m.factory()}, destination: {Stream: b, Sink: m.factory()}}}
	return nil
}

// Feed admits one segment of a direction and delivers the new contiguous bytes to its sink.
// It returns whether the sink's observation changed, and the stream's error if any.
func (m *Manager) Feed(source, destination transport.Endpoint, sequence uint32, payload []byte, now float64) (bool, error) {
	m.Expire(now)
	c, ok := m.Connections[KeyOf(source, destination)]
	if !ok {
		return false, errs.New(errs.Invalid, errs.ScopeFlow, "Unknown connection: first data sequences must be established")
	}
	d := c.Directions[source]
	delta, err := d.Stream.Feed(sequence, payload)
	c.LastSeen = now
	if err != nil {
		// A conflicting overlap or an out-of-window segment withdraws this direction's observation before
		// the owner releases the connection (Python Stream.feed: inspector.invalidate(self.error)).
		if e, ok := err.(*errs.Error); ok {
			d.Sink.Invalidate(e.Detail)
		}
		return false, err
	}
	if delta == nil {
		return false, nil
	}
	return d.Sink.Feed(delta), nil
}

// Close releases a connection's windows.
func (m *Manager) Close(source, destination transport.Endpoint) {
	m.release(KeyOf(source, destination))
}

// FinishDirection tells the sink the direction ended at a trusted boundary; bytes stay retained for
// overlap checks until Close.
func (m *Manager) FinishDirection(source, destination transport.Endpoint, reason string) bool {
	c, ok := m.Connections[KeyOf(source, destination)]
	if !ok {
		return false
	}
	return c.Directions[source].Sink.End(reason)
}
