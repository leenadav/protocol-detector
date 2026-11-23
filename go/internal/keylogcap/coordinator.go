// Package keylogcap is the offline key-log decryption adapter (presentation/poc_decryption/capture.py and
// decryptor.py over protocol_adapters/coordinator.py): one owner reassembles each TCP direction once under a
// retention budget, the decryptor feeds those bytes to one TLS decoder per connection, classifies the
// authenticated plaintext, and reports one row per connection. It keeps no flow table of its own and
// emits no payload, key material, hostname or credential.
package keylogcap

import (
	"github.com/leenadav/protocol-detector/go/internal/analyzer"
	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/errs"
	"github.com/leenadav/protocol-detector/go/internal/reassembly"
	"github.com/leenadav/protocol-detector/go/internal/session"
	"github.com/leenadav/protocol-detector/go/internal/sessionid"
	"github.com/leenadav/protocol-detector/go/internal/telemetry"
	"github.com/leenadav/protocol-detector/go/internal/transport"
)

// Budget is RetentionBudget: explicit limits of the retained tier.
type Budget struct{ PerDirection, Aggregate, Connections, Pending int }

// StreamError is sessions.StreamError raised by the owner itself (the consumer queue overflowed).
type StreamError struct{ Message string }

func (e *StreamError) Error() string { return e.Message }

const restartReason = "Connection restarted (new SYN on a tracked tuple)"

type progress struct {
	endpoint           transport.Endpoint
	contiguous, stored int
	fin                int
	hasFin             bool
}

// event is one consumer event: open, data, error, fin or close.
type event struct {
	kind           string
	key            session.Key
	client, server transport.Endpoint // open
	sid            string
	generation     int
	endpoint       transport.Endpoint // data
	data           []byte
	reason         string // error, close
	progress       []progress
}

type retained struct {
	client, server transport.Endpoint
	order          []transport.Endpoint // insertion order of streams
	streams        map[transport.Endpoint]*reassembly.Stream
	fin            map[transport.Endpoint]uint32
	err            string
	failed         bool
	sid            string
	generation     int
	time           float64 // last activity on the owner's clock
}

// Tier is the coordinator's retained reassembly tier: the bounded full stream of each TCP connection for a
// second consumer (the TLS decoder), under an explicit budget. Its owner decides tuple reuse and time.
type Tier struct {
	budget      Budget
	generations *Generations           // the owner's session identity
	tracks      func(session.Key) bool // whether the owner's analyzer still tracks a connection
	retained    map[session.Key]*retained
	order       []session.Key // insertion order of retained
	allocated   int
	pending     []queued
	now         float64
	idle        float64 // seconds a retained connection may stay silent (Tick)
	// Telemetry receives the tier's counters and histograms (nil: none).
	Telemetry *telemetry.Telemetry

	RejectedConnections, RejectedBytes int
}

type queued struct {
	event
	at float64 // enqueue time on the owner's clock (D11)
}

// NewTier builds a retained tier over the owner's generations; tracks reports whether the owner's analyzer still
// tracks a connection (a closed retained flow no tracked flow holds releases its generation).
func NewTier(budget Budget, idleTimeout float64, generations *Generations, tracks func(session.Key) bool) *Tier {
	return &Tier{budget: budget, generations: generations, tracks: tracks, retained: map[session.Key]*retained{}, idle: idleTimeout}
}

// Holds reports whether a connection with this key is retained.
func (c *Tier) Holds(key session.Key) bool { _, ok := c.retained[key]; return ok }

// SYNRetransmission reports whether this bare SYN repeats the SYN that opened the retained connection (same
// client, same ISN, no FIN or data): the same connection, not tuple reuse (Go-only, Codex PRO-18 P2).
func (c *Tier) SYNRetransmission(packet *transport.TCP) bool {
	state := c.retained[session.KeyOf(packet.Source, packet.Destination)]
	if state == nil || packet.Source != state.client || packet.Flags&(transport.SYN|transport.ACK|transport.FIN) != transport.SYN || len(packet.Payload) > 0 {
		return false
	}
	stream, ok := state.streams[packet.Source]
	return ok && stream.First() == packet.Sequence+1
}

// Retransmission is the owner's check before a restart: the tracker decides for a tracked connection, the
// retained tier for one only it still holds.
func (c *Tier) Retransmission(tracker *session.Tracker, now float64, packet *transport.TCP) bool {
	if tracker.TracksTCP(session.KeyOf(packet.Source, packet.Destination)) {
		return tracker.SYNRetransmission(now, packet)
	}
	return c.SYNRetransmission(packet)
}

// Allocated is the bytes all retained streams hold; Limit the aggregate budget; Pending the queued events.
func (c *Tier) Allocated() int { return c.allocated }
func (c *Tier) Limit() int     { return c.budget.Aggregate }
func (c *Tier) Pending() int   { return len(c.pending) }

// SetNow advances the tier's clock (the owner's now).
func (c *Tier) SetNow(now float64) {
	if now > c.now {
		c.now = now
	}
}

// coordinator is SessionCoordinator for an offline capture: the analyzer's connection table decides tuple
// reuse, the retained tier reassembles the bounded full stream for the decryptor.
type coordinator struct {
	*Tier
	an          *analyzer.Analyzer
	generations *Generations
	records     int // analyzer records already published (their generations released)
}

func newCoordinator(pack *content.Pack, budget Budget, connections int) (*coordinator, error) {
	an, err := analyzer.New(pack, analyzer.Options{Session: session.Options{MaxConnections: connections, ByteLimit: 16384, IdleTimeout: 60,
		MaxUDPFlows: -1, Compact: true, Observation: "handshake"}})
	if err != nil {
		return nil, err
	}
	c := &coordinator{an: an, generations: NewGenerations()}
	c.Tier = NewTier(budget, 60, c.generations, an.Tracker.TracksTCP)
	c.Tier.Telemetry = an.Telemetry
	return c, nil
}

func (c *Tier) queue(e event) error {
	if len(c.pending) >= c.budget.Pending {
		if c.Telemetry != nil {
			c.Telemetry.Add("events.dropped", 1)
		}
		return &StreamError{"Retained consumer queue exhausted; the consumer must drain between packets"}
	}
	c.pending = append(c.pending, queued{e, c.now})
	return nil
}

func (c *Tier) retainedError(key session.Key, state *retained, reason string) error {
	if state.failed {
		return nil
	}
	state.failed, state.err = true, reason
	return c.queue(event{kind: "error", key: key, reason: reason})
}

func (c *Tier) progress(state *retained) []progress {
	out := make([]progress, 0, len(state.order))
	for _, endpoint := range state.order {
		stream := state.streams[endpoint]
		p := progress{endpoint: endpoint, contiguous: stream.Contiguous(), stored: stream.Stored()}
		if fin, ok := state.fin[endpoint]; ok {
			p.fin, p.hasFin = int((uint64(fin)+reassembly.Modulus-uint64(stream.First()))%reassembly.Modulus), true
		}
		out = append(out, p)
	}
	return out
}

func (c *Tier) retainedClose(key session.Key, reason string) error {
	state, ok := c.retained[key]
	if !ok {
		return nil
	}
	delete(c.retained, key)
	if c.tracks != nil && !c.tracks(key) {
		c.generations.Release(state.sid) // no tracked flow holds the tuple now
	}
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
	for _, stream := range state.streams {
		c.allocated -= stream.Allocated()
	}
	return c.queue(event{kind: "close", key: key, reason: reason, progress: c.progress(state)})
}

// noteSessions is the reference coordinator's session sink for what the analyzer finalized since the last call:
// each session takes (and so releases) its flow's generation, in emission order.
func (c *coordinator) noteSessions() {
	for ; c.records < len(c.an.Records); c.records++ {
		record := c.an.Records[c.records]
		name, _ := record["transport"].(string)
		c.generations.Publish(sessionid.Identity(name, endpointOf(record["client"]), endpointOf(record["server"])))
	}
}

func endpointOf(v interface{}) transport.Endpoint {
	pair, _ := v.([]interface{})
	if len(pair) != 2 {
		return transport.Endpoint{}
	}
	addr, _ := pair[0].(string)
	port, _ := pair[1].(int)
	return transport.Endpoint{Addr: addr, Port: uint16(port)}
}

// accept hands one decoded TCP packet to the owner; tuple reuse on a SYN renews the generation.
func (c *coordinator) accept(packet *transport.TCP, now float64) error {
	c.SetNow(now)
	key := session.KeyOf(packet.Source, packet.Destination)
	// A retransmitted SYN is the same connection: only a new SYN on the tuple restarts it.
	if packet.Flags&transport.SYN != 0 && packet.Flags&transport.ACK == 0 && !c.Retransmission(c.an.Tracker, now, packet) {
		held := c.Holds(key)
		if tracked := c.an.Tracker.TracksTCP(key); tracked || held {
			if tracked {
				c.an.Tracker.Drop(key, restartReason)
				c.noteSessions()
			}
			if held {
				if err := c.Close(key, restartReason); err != nil {
					return err
				}
			}
			c.generations.Release(sessionid.Identity("tcp", packet.Source, packet.Destination))
		}
	}
	c.an.Process(now, packet)
	c.noteSessions()
	if c.an.NotPorted != nil {
		return c.an.NotPorted
	}
	return c.Retain(packet)
}

// Close releases a retained connection with the reason (the consumer gets its close event).
func (c *Tier) Close(key session.Key, reason string) error { return c.retainedClose(key, reason) }

// Retain is the tier's part of accepting one TCP packet.
func (c *Tier) Retain(packet *transport.TCP) error {
	return c.retain(session.KeyOf(packet.Source, packet.Destination), packet)
}

// Tick closes retained connections that stayed silent for the idle timeout and reports the tier's gauges.
func (c *Tier) Tick(now float64) error {
	c.SetNow(now)
	if c.Telemetry != nil {
		c.Telemetry.Set("bytes.retained", c.allocated)
		c.Telemetry.Set("queue.depth", len(c.pending))
	}
	for _, key := range append([]session.Key{}, c.order...) {
		if state := c.retained[key]; c.now-state.time >= c.idle {
			if err := c.retainedClose(key, "Idle timeout; retained stream ended"); err != nil {
				return err
			}
		}
	}
	return nil
}

// SessionIDs are the session ids of the retained connections (a capture gap names them).
func (c *Tier) SessionIDs() []string {
	out := make([]string, 0, len(c.order))
	for _, key := range c.order {
		out = append(out, c.retained[key].sid)
	}
	return out
}

// Gap is a capture gap: every retained connection fails with the reason and is released.
func (c *Tier) Gap(reason string) error {
	for _, key := range append([]session.Key{}, c.order...) {
		if err := c.retainedError(key, c.retained[key], reason); err != nil {
			return err
		}
		if err := c.retainedClose(key, reason); err != nil {
			return err
		}
	}
	return nil
}

// End releases every retained connection with the reason.
func (c *Tier) End(reason string) error {
	for _, key := range append([]session.Key{}, c.order...) {
		if err := c.retainedClose(key, reason); err != nil {
			return err
		}
	}
	return nil
}

// retain reassembles the bounded full stream for the consumer, under the retention budget.
func (c *Tier) retain(key session.Key, packet *transport.TCP) error {
	state := c.retained[key]
	flags := packet.Flags
	if flags&transport.RST != 0 {
		if state != nil {
			return c.retainedClose(key, "Observed RST; retained stream ended")
		}
		return nil
	}
	if flags&transport.SYN != 0 {
		first := packet.Sequence + 1
		if state == nil {
			if flags&transport.ACK != 0 {
				return nil // SYN-ACK without its SYN: origin unknown
			}
			if len(c.retained) >= c.budget.Connections {
				c.RejectedConnections++
				return nil
			}
			sid := sessionid.Identity("tcp", packet.Source, packet.Destination)
			state = &retained{client: packet.Source, server: packet.Destination, streams: map[transport.Endpoint]*reassembly.Stream{},
				fin: map[transport.Endpoint]uint32{}, sid: sid, generation: c.generations.Of(sid), time: c.now}
			c.retained[key] = state
			c.order = append(c.order, key)
			if err := c.queue(event{kind: "open", key: key, client: packet.Source, server: packet.Destination, sid: sid, generation: state.generation}); err != nil {
				return err
			}
		}
		state.time = c.now
		if previous, ok := state.streams[packet.Source]; ok {
			if previous.First() != first {
				return c.retainedError(key, state, "Connection tuple reuse is outside the POC profile.")
			}
			return nil
		}
		if flags&transport.ACK != 0 && packet.Source != state.server {
			return c.retainedError(key, state, "Inconsistent SYN-ACK direction.")
		}
		stream, err := reassembly.NewRetained(first, c.budget.PerDirection)
		if err != nil {
			return err
		}
		state.streams[packet.Source] = stream
		state.order = append(state.order, packet.Source)
		if len(packet.Payload) > 0 {
			return c.retainedError(key, state, "SYN with data (Fast Open) is outside the POC profile.")
		}
		return nil
	}
	if state == nil {
		return nil
	}
	state.time = c.now
	stream := state.streams[packet.Source]
	if len(packet.Payload) > 0 {
		switch {
		case stream == nil:
			if err := c.retainedError(key, state, "TCP SYN is missing; stream origin cannot be established."); err != nil {
				return err
			}
		case !state.failed:
			before := stream.Allocated()
			offset := int((uint64(packet.Sequence) + reassembly.Modulus - uint64(stream.First())) % reassembly.Modulus)
			grow := offset + len(packet.Payload) - stream.Buffered()
			if grow < 0 {
				grow = 0
			}
			if c.allocated+2*grow > c.budget.Aggregate {
				c.RejectedBytes += len(packet.Payload)
				if err := c.retainedError(key, state, "Aggregate reassembly budget exhausted; this connection is not decoded."); err != nil {
					return err
				}
			} else {
				delta, ferr := stream.Feed(packet.Sequence, packet.Payload)
				c.allocated += stream.Allocated() - before
				if ferr != nil {
					reason := ferr.Error()
					if typed, ok := ferr.(*errs.Error); ok {
						reason = typed.Detail // str(StreamError): the reason sentence alone
					}
					if err := c.retainedError(key, state, reason); err != nil {
						return err
					}
				} else if delta != nil {
					if err := c.queue(event{kind: "data", key: key, endpoint: packet.Source, data: delta}); err != nil {
						return err
					}
				}
			}
		}
	}
	if _, seen := state.fin[packet.Source]; flags&transport.FIN != 0 && !seen {
		state.fin[packet.Source] = packet.Sequence + uint32(len(packet.Payload))
		if len(state.fin) == 2 && len(state.streams) == 2 {
			// Both directions ended. The streams stay retained until end(), so a late conflicting
			// retransmission still invalidates; the consumer may settle its view now.
			return c.queue(event{kind: "fin", key: key, progress: c.progress(state)})
		}
	}
	return nil
}

// drain hands out the consumer events queued since the last call, in order; each delta exactly once.
func (c *Tier) drain() []event {
	items := make([]event, 0, len(c.pending))
	for _, item := range c.pending {
		if c.Telemetry != nil {
			wait := c.now - item.at
			if wait < 0 {
				wait = 0
			}
			c.Telemetry.Observe("queue.wait_seconds", wait) // D11: capture-clock wait per event
		}
		items = append(items, item.event)
	}
	c.pending = nil
	if len(items) > 0 && c.Telemetry != nil {
		c.Telemetry.Add("queue.drained", len(items))
	}
	return items
}

// end finalizes everything still tracked, once.
func (c *coordinator) end(reason string) error {
	if err := c.an.Finish(reason); err != nil {
		return err
	}
	return c.Tier.End(reason)
}
