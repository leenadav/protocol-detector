// Package replay runs the language-neutral cases (migration/fixtures/cases.json) through the Go backend
// and produces the results file migration/parity/compare.py reads. A case the Go backend cannot answer
// yields {"unsupported": "<reason>"} instead of a result; it is never reported as a detection.
package replay

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/engine"
	"github.com/leenadav/protocol-detector/go/internal/errs"
	"github.com/leenadav/protocol-detector/go/internal/parity"
	"github.com/leenadav/protocol-detector/go/internal/parsing"
	"github.com/leenadav/protocol-detector/go/internal/session"
	"github.com/leenadav/protocol-detector/go/internal/transport"
)

// Backend is the name written into the results file.
const Backend = "go"

// Unsupported is the marker result.
type Unsupported struct {
	Unsupported string `json:"unsupported"`
}

// StreamResult mirrors cases.py run_stream.
type StreamResult struct {
	Events  []contracts.Event     `json:"events"`
	Final   contracts.Observation `json:"final"`
	Metrics contracts.Metrics     `json:"metrics"`
}

// DatagramResult mirrors run_datagram.
type DatagramResult struct {
	Observation contracts.Observation `json:"observation"`
	Metrics     contracts.Metrics     `json:"metrics"`
}

// PacketResult mirrors one entry of run_session's packets (records are not produced yet: M6).
type PacketResult struct {
	Index      int                `json:"index"`
	Message    *string            `json:"message"`
	Events     []contracts.Event  `json:"events"`
	PeerEvents []json.RawMessage  `json:"peer_events"`
	Streams    map[string]Streams `json:"streams"`
	Tables     []int              `json:"tables"`
}

// Streams mirrors stream_state.
type Streams struct {
	Contiguous int    `json:"contiguous"`
	Stored     int    `json:"stored"`
	HighestEnd int    `json:"highest_end"`
	Digest     string `json:"digest"`
}

// SessionResult mirrors run_session minus records.
type SessionResult struct {
	Packets []PacketResult `json:"packets"`
}

func events(list []contracts.Event) []contracts.Event {
	if list == nil {
		return []contracts.Event{}
	}
	return list
}

// Stream runs one stream case.
func Stream(c *parity.Case) interface{} {
	hint := ""
	if c.Hint != nil {
		hint = *c.Hint
	}
	in, err := engine.New(c.Config, hint)
	if err != nil {
		return Unsupported{err.Error()}
	}
	var all []contracts.Event
	for _, chunk := range c.Chunks {
		data, derr := hex.DecodeString(chunk)
		if derr != nil {
			return Unsupported{"bad chunk hex"}
		}
		all = append(all, in.Feed(data)...)
		if in.NotPorted != nil {
			return Unsupported{in.NotPorted.Error()}
		}
	}
	if c.End != nil {
		all = append(all, in.End(*c.End)...)
		if in.NotPorted != nil {
			return Unsupported{in.NotPorted.Error()}
		}
	}
	return StreamResult{Events: events(all), Final: in.Observation, Metrics: in.Metrics}
}

// Datagram runs one datagram case.
func Datagram(c *parity.Case) interface{} {
	d, err := engine.NewDatagram(c.Config)
	if err != nil {
		return Unsupported{err.Error()}
	}
	data, derr := hex.DecodeString(c.Payload)
	if derr != nil {
		return Unsupported{"bad payload hex"}
	}
	hint := ""
	if c.Hint != nil {
		hint = *c.Hint
	}
	obs, err := d.Inspect(data, hint)
	if err != nil {
		return Unsupported{err.Error()}
	}
	return DatagramResult{Observation: obs, Metrics: d.Metrics}
}

// inspectorSink adapts an engine.Inspector to the session.Sink interface and collects its events.
type inspectorSink struct {
	in      *engine.Inspector
	pending []contracts.Event
}

func (s *inspectorSink) Feed(delta []byte) bool {
	ev := s.in.Feed(delta)
	s.pending = append(s.pending, ev...)
	return len(ev) > 0
}

func (s *inspectorSink) Invalidate(reason string) bool {
	ev := s.in.Invalidate(reason)
	s.pending = append(s.pending, ev...)
	return len(ev) > 0
}

func (s *inspectorSink) End(reason string) bool {
	ev := s.in.End(reason)
	s.pending = append(s.pending, ev...)
	return len(ev) > 0
}

// Retire ends the direction without reporting its events on the packet (Python routes them to on_retire).
func (s *inspectorSink) Retire(reason string) bool {
	return len(s.in.End(reason)) > 0
}

// Session runs one session case through the tracker with the engine attached as the sink.
func Session(c *parity.Case) interface{} {
	var options struct {
		IdleTimeout  *float64 `json:"idle_timeout"`
		Observation  string   `json:"observation"`
		Continuation int      `json:"continuation"`
	}
	if len(c.Options) > 0 {
		if err := json.Unmarshal(c.Options, &options); err != nil {
			return Unsupported{"bad options"}
		}
	}
	cfg := contracts.DefaultConfig()
	cfg.Continuation = options.Continuation
	opts := session.Options{MaxConnections: 32, ByteLimit: 65536, IdleTimeout: 60, MaxUDPFlows: -1, Observation: options.Observation}
	if options.IdleTimeout != nil {
		opts.IdleTimeout = *options.IdleTimeout
	}
	var sinks []*inspectorSink
	var notPorted *parsing.NotPorted
	tr, err := session.NewTracker(opts, func() session.Sink {
		in, err := engine.New(cfg, "")
		if err != nil {
			if np, ok := err.(*parsing.NotPorted); ok {
				notPorted = np
			}
			in, _ = engine.New(contracts.DefaultConfig(), "")
		}
		s := &inspectorSink{in: in}
		sinks = append(sinks, s)
		return s
	}, nil)
	if err != nil {
		return Unsupported{err.Error()}
	}
	udp, err := engine.NewDatagram(cfg)
	if err != nil {
		return Unsupported{err.Error()}
	}
	result := SessionResult{Packets: []PacketResult{}}
	for index, pk := range c.Packets {
		frame, _ := hex.DecodeString(pk.Frame)
		decoded, derr := transport.Decode(frame, pk.Linktype, transport.Ignore)
		if derr != nil {
			return Unsupported{"frame rejected: " + derr.Error()}
		}
		for _, s := range sinks {
			s.pending = nil
		}
		var message string
		var a, b transport.Endpoint
		var packetEvents []contracts.Event
		switch p := decoded.(type) {
		case *transport.TCP:
			message = tr.Process(pk.T, p)
			a, b = p.Source, p.Destination
			for _, s := range sinks {
				if s.in.NotPorted != nil {
					return Unsupported{s.in.NotPorted.Error()}
				}
				packetEvents = append(packetEvents, s.pending...)
			}
		case *transport.UDP:
			message = tr.ProcessUDP(pk.T, p)
			a, b = p.Source, p.Destination
			obs, ierr := udp.Inspect(p.Payload, "")
			if ierr != nil {
				return Unsupported{ierr.Error()}
			}
			return Unsupported{"UDP flows in sessions need the datagram flow state (M6): " + obs.Reason}
		}
		if notPorted != nil {
			return Unsupported{notPorted.Error()}
		}
		message, _, _ = strings.Cut(message, " | ") // the harness compares the first segment (cases.py)
		pr := PacketResult{Index: index, Message: &message, Events: events(packetEvents), PeerEvents: []json.RawMessage{}}
		tracked, conns, flows := tr.Tables()
		pr.Tables = []int{tracked, conns, flows}
		if conn := tr.Manager().Connections[session.KeyOf(a, b)]; conn != nil {
			pr.Streams = map[string]Streams{}
			for endpoint, d := range conn.Directions {
				pr.Streams[endpoint.String()] = Streams{d.Stream.Contiguous(), d.Stream.Stored(), d.Stream.HighestEnd(), digest(d.Stream.Prefix())}
			}
		}
		result.Packets = append(result.Packets, pr)
	}
	return result
}

// Run executes every case and returns the results document; ctx cancels between cases.
func Run(ctx context.Context, doc *parity.Document) (*parity.Results, error) {
	out := &parity.Results{Backend: Backend, Results: map[string]json.RawMessage{}}
	for i := range doc.Cases {
		if err := ctx.Err(); err != nil {
			return nil, errs.New(errs.Cancelled, errs.ScopeProcess, "replay")
		}
		c := &doc.Cases[i]
		var value interface{}
		switch c.Kind {
		case "stream":
			value = Stream(c)
		case "datagram":
			value = Datagram(c)
		case "session":
			value = Session(c)
		default:
			value = Unsupported{"case kind " + c.Kind}
		}
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		out.Results[c.ID] = raw
	}
	return out, nil
}
