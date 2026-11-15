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
}

// coordinator is SessionCoordinator for an offline capture: the analyzer's connection table decides tuple
// reuse, the retained tier reassembles the bounded full stream for the decryptor.
type coordinator struct {
	an          *analyzer.Analyzer
	budget      Budget
	generations map[string]int
	retained    map[session.Key]*retained
	order       []session.Key // insertion order of retained
	allocated   int
	pending     []event
	now         float64

	rejectedConnections, rejectedBytes int
}

func newCoordinator(pack *content.Pack, budget Budget, connections int) (*coordinator, error) {
	an, err := analyzer.New(pack, analyzer.Options{Session: session.Options{MaxConnections: connections, ByteLimit: 16384, IdleTimeout: 60,
		MaxUDPFlows: -1, Compact: true, Observation: "handshake"}})
	if err != nil {
		return nil, err
	}
	return &coordinator{an: an, budget: budget, generations: map[string]int{}, retained: map[session.Key]*retained{}}, nil
}

func (c *coordinator) queue(e event) error {
	if len(c.pending) >= c.budget.Pending {
		return &StreamError{"Retained consumer queue exhausted; the consumer must drain between packets"}
	}
	c.pending = append(c.pending, e)
	return nil
}

func (c *coordinator) retainedError(key session.Key, state *retained, reason string) error {
	if state.failed {
		return nil
	}
	state.failed, state.err = true, reason
	return c.queue(event{kind: "error", key: key, reason: reason})
}

func (c *coordinator) progress(state *retained) []progress {
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

func (c *coordinator) retainedClose(key session.Key, reason string) error {
	state, ok := c.retained[key]
	if !ok {
		return nil
	}
	delete(c.retained, key)
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

// accept hands one decoded TCP packet to the owner; tuple reuse on a SYN renews the generation.
func (c *coordinator) accept(packet *transport.TCP, now float64) error {
	if now > c.now {
		c.now = now
	}
	key := session.KeyOf(packet.Source, packet.Destination)
	if packet.Flags&transport.SYN != 0 && packet.Flags&transport.ACK == 0 {
		_, held := c.retained[key]
		if tracked := c.an.Tracker.TracksTCP(key); tracked || held {
			if tracked {
				c.an.Tracker.Drop(key, restartReason)
			}
			if held {
				if err := c.retainedClose(key, restartReason); err != nil {
					return err
				}
			}
			c.generations[sessionid.Identity("tcp", packet.Source, packet.Destination)]++
		}
	}
	c.an.Process(now, packet)
	if c.an.NotPorted != nil {
		return c.an.NotPorted
	}
	return c.retain(key, packet)
}

// retain reassembles the bounded full stream for the consumer, under the retention budget.
func (c *coordinator) retain(key session.Key, packet *transport.TCP) error {
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
				c.rejectedConnections++
				return nil
			}
			sid := sessionid.Identity("tcp", packet.Source, packet.Destination)
			state = &retained{client: packet.Source, server: packet.Destination, streams: map[transport.Endpoint]*reassembly.Stream{},
				fin: map[transport.Endpoint]uint32{}, sid: sid, generation: c.generations[sid]}
			c.retained[key] = state
			c.order = append(c.order, key)
			if err := c.queue(event{kind: "open", key: key, client: packet.Source, server: packet.Destination, sid: sid, generation: state.generation}); err != nil {
				return err
			}
		}
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
				c.rejectedBytes += len(packet.Payload)
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

func (c *coordinator) drain() []event {
	items := c.pending
	c.pending = nil
	return items
}

// end finalizes everything still tracked, once.
func (c *coordinator) end(reason string) error {
	if err := c.an.Finish(reason); err != nil {
		return err
	}
	for _, key := range append([]session.Key{}, c.order...) {
		if err := c.retainedClose(key, reason); err != nil {
			return err
		}
	}
	return nil
}
