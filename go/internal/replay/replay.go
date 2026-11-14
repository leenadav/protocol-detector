// Package replay runs the language-neutral cases (migration/fixtures/cases.json) through the Go backend
// and produces the results file migration/parity/compare.py reads. A case the Go backend cannot answer
// yields {"unsupported": "<reason>"} instead of a result; it is never reported as a detection.
package replay

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/analyzer"
	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/engine"
	"github.com/leenadav/protocol-detector/go/internal/errs"
	"github.com/leenadav/protocol-detector/go/internal/parity"
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

// SessionResult mirrors run_session.
type SessionResultFull struct {
	Packets []PacketResult           `json:"packets"`
	Records []map[string]interface{} `json:"records"`
}

// packPath overrides the content pack location; empty means content.json beside the cases file.
var packPath = ""

// SetPackPath points the session replay at another content pack file.
func SetPackPath(path string) { packPath = path }

// Session runs one session case through the analyzer (tracker + engine + record layer).
func Session(pack *content.Pack, c *parity.Case) interface{} {
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
	opts := analyzer.Options{Continuation: options.Continuation,
		Session: session.Options{MaxConnections: 32, ByteLimit: 65536, IdleTimeout: 60, MaxUDPFlows: -1, Observation: options.Observation}}
	if options.IdleTimeout != nil {
		opts.Session.IdleTimeout = *options.IdleTimeout
	}
	an, err := analyzer.New(pack, opts)
	if err != nil {
		return Unsupported{err.Error()}
	}
	result := SessionResultFull{Packets: []PacketResult{}}
	for index, pk := range c.Packets {
		frame, _ := hex.DecodeString(pk.Frame)
		decoded, derr := transport.Decode(frame, pk.Linktype, transport.Ignore)
		if derr != nil {
			return Unsupported{"frame rejected: " + derr.Error()}
		}
		message := an.Process(pk.T, decoded)
		if an.NotPorted != nil {
			return Unsupported{an.NotPorted.Error()}
		}
		var a, b transport.Endpoint
		switch p := decoded.(type) {
		case *transport.TCP:
			a, b = p.Source, p.Destination
		case *transport.UDP:
			a, b = p.Source, p.Destination
		}
		message, _, _ = strings.Cut(message, " | ") // the harness compares the first segment (cases.py)
		pr := PacketResult{Index: index, Message: &message, Events: events(an.LastEvents), PeerEvents: []json.RawMessage{}}
		for _, pe := range an.PeerEvents {
			raw, err := json.Marshal([]interface{}{[]interface{}{pe.Source.Addr, int(pe.Source.Port)},
				[]interface{}{pe.Destination.Addr, int(pe.Destination.Port)}, pe.Event})
			if err != nil {
				return Unsupported{"peer event: " + err.Error()}
			}
			pr.PeerEvents = append(pr.PeerEvents, raw)
		}
		tracked, conns, flows := an.Tracker.Tables()
		pr.Tables = []int{tracked, conns, flows}
		if conn := an.Tracker.Manager().Connections[session.KeyOf(a, b)]; conn != nil {
			pr.Streams = map[string]Streams{}
			for endpoint, d := range conn.Directions {
				pr.Streams[endpoint.String()] = Streams{d.Stream.Contiguous(), d.Stream.Stored(), d.Stream.HighestEnd(), digest(d.Stream.Prefix())}
			}
		}
		result.Packets = append(result.Packets, pr)
	}
	finish := c.Finish
	if finish == "" {
		finish = "eof"
	}
	if err := an.Finish(finish); err != nil {
		return Unsupported{err.Error()}
	}
	if an.NotPorted != nil {
		return Unsupported{an.NotPorted.Error()}
	}
	result.Records = an.Records
	if result.Records == nil {
		result.Records = []map[string]interface{}{}
	}
	return result
}

// Run executes every case and returns the results document; ctx cancels between cases.
func Run(ctx context.Context, doc *parity.Document) (*parity.Results, error) {
	path := packPath
	if path == "" {
		path = filepath.Join(doc.Dir, "content.json")
	}
	pack, perr := content.Load(path)
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
			if perr != nil {
				value = Unsupported{"content pack: " + perr.Error()}
			} else {
				value = Session(pack, c)
			}
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
