// Package analyzer ports the record-producing part of protocol_adapters/analyze_pcap.Analyzer: the
// tracker drives TCP connections with the engine attached as each direction's sink, the datagram
// inspector classifies UDP payloads per flow, and when tracking of a connection or flow ends one
// JSON-friendly session record is produced (verdict, flow risks, layered view, structured unknown
// reasons, decision timing, content pin). Signatures, policy, hostnames-in-records, certificates,
// continuation and the live telemetry are not ported; a direction the engine cannot answer makes the
// whole run report NotPorted instead of a record.
package analyzer

import (
	"math"
	"sort"

	"github.com/leenadav/protocol-detector/go/internal/appid"
	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/engine"
	"github.com/leenadav/protocol-detector/go/internal/parsing"
	"github.com/leenadav/protocol-detector/go/internal/session"
	"github.com/leenadav/protocol-detector/go/internal/transport"
)

var midstreamFamilies = map[string]bool{"http": true, "dns": true, "syslog": true, "modbus": true, "dnp3": true, "iec-104": true,
	"resp": true, "memcached": true, "sip": true, "rtsp": true}

// Sink is the engine inspector as a session.Sink; it keeps the events of the current packet. The connection
// owns it: the analyzer holds a sink only while it is in the touched list of the packet being processed, so
// retained state and per-packet work are bounded by the active connections, not by the connections ever seen.
type Sink struct {
	In         *engine.Inspector
	Pending    []contracts.Event
	identified []session.Label
	owner      *Analyzer
	seq        uint64 // creation order; the packet's events are reported in this order
	touched    bool
}

// touch registers the sink for the current packet and propagates an engine gap to the analyzer.
func (s *Sink) touch() {
	if s.In.NotPorted != nil && s.owner.NotPorted == nil {
		s.owner.NotPorted = s.In.NotPorted
	}
	if !s.touched {
		s.touched = true
		s.owner.touched = append(s.owner.touched, s)
	}
}

func (s *Sink) collect(events []contracts.Event) bool {
	s.touch()
	s.Pending = append(s.Pending, events...)
	for _, e := range events {
		if e.Observation.Status == contracts.Identified {
			label := session.Label{}
			if e.Observation.ApplicationProtocol != nil {
				label.Protocol = *e.Observation.ApplicationProtocol
			} else if e.Observation.Encryption != nil {
				label.Protocol = *e.Observation.Encryption
			}
			if e.Observation.Application != nil {
				label.Application, label.HasApp = *e.Observation.Application, true
			}
			s.identified = append(s.identified, label)
		}
	}
	return len(events) > 0
}

func (s *Sink) Feed(delta []byte) bool        { return s.collect(s.In.Feed(delta)) }
func (s *Sink) Invalidate(reason string) bool { return s.collect(s.In.Invalidate(reason)) }
func (s *Sink) End(reason string) bool        { return s.collect(s.In.End(reason)) }

// Retire ends the direction when tracking ends; its events are retirement events, not the packet's.
func (s *Sink) Retire(reason string) bool {
	changed := len(s.In.End(reason)) > 0
	s.touch()
	return changed
}
func (s *Sink) TakeIdentified() []session.Label { out := s.identified; s.identified = nil; return out }

// Analyzer is the record producer.
type Analyzer struct {
	pack      *content.Pack
	cfg       contracts.Config
	Tracker   *session.Tracker
	udp       *engine.Datagram
	udpRev    int
	touched   []*Sink // sinks the current packet (or Finish) reached; reset at the next packet
	sinkSeq   uint64
	Records   []map[string]interface{}
	NotPorted *parsing.NotPorted
	// Per packet (Python last_events / peer_events).
	LastEvents []contracts.Event
}

// Options mirrors the Analyzer constructor arguments the Go backend honours.
type Options struct {
	Session      session.Options
	Continuation int
}

// New builds an analyzer; options the engine lacks are reported through NotPorted on first use.
func New(pack *content.Pack, opts Options) (*Analyzer, error) {
	cfg := contracts.DefaultConfig()
	cfg.Continuation = opts.Continuation
	a := &Analyzer{pack: pack, cfg: cfg}
	tr, err := session.NewTracker(opts.Session, func() session.Sink {
		in, err := engine.New(cfg, "")
		if err != nil {
			if np, ok := err.(*parsing.NotPorted); ok && a.NotPorted == nil {
				a.NotPorted = np
			}
			in, _ = engine.New(contracts.DefaultConfig(), "")
		}
		a.sinkSeq++
		return &Sink{In: in, owner: a, seq: a.sinkSeq}
	}, a.closed)
	if err != nil {
		return nil, err
	}
	a.Tracker = tr
	udp, err := engine.NewDatagram(cfg)
	if err != nil {
		if np, ok := err.(*parsing.NotPorted); ok {
			a.NotPorted = np
		}
		udp, _ = engine.NewDatagram(contracts.DefaultConfig())
	}
	a.udp = udp
	return a, nil
}

// Process handles one decoded packet and returns the adapter message (first segment compared by the harness).
func (a *Analyzer) Process(timestamp float64, decoded interface{}) string {
	a.LastEvents = nil
	a.resetTouched()
	switch p := decoded.(type) {
	case *transport.UDP:
		obs, err := a.udp.Inspect(p.Payload, "")
		if err != nil {
			if np, ok := err.(*parsing.NotPorted); ok && a.NotPorted == nil {
				a.NotPorted = np
			}
			return "UDP"
		}
		a.udpRev++
		a.LastEvents = []contracts.Event{{Kind: contracts.DatagramObs, Revision: a.udpRev, Observation: obs}}
		return a.Tracker.ProcessUDP(timestamp, p, &obs)
	case *transport.TCP:
		message := a.Tracker.Process(timestamp, p)
		sort.Slice(a.touched, func(i, j int) bool { return a.touched[i].seq < a.touched[j].seq })
		for _, s := range a.touched {
			a.LastEvents = append(a.LastEvents, s.Pending...)
		}
		return message
	}
	return ""
}

// resetTouched forgets the previous packet's sinks and their events.
func (a *Analyzer) resetTouched() {
	for i, s := range a.touched {
		s.Pending, s.touched = nil, false
		a.touched[i] = nil
	}
	a.touched = a.touched[:0]
}

// Finish ends every connection and flow with the reason and releases the sinks it reached.
func (a *Analyzer) Finish(reason string) error {
	err := a.Tracker.Finish(reason)
	a.resetTouched()
	a.touched = nil
	return err
}

// RetainedSinks reports how many direction sinks the analyzer itself still references (tests).
func (a *Analyzer) RetainedSinks() int { return len(a.touched) }

func (a *Analyzer) closed(c session.Closed) {
	state := c.State
	if state.Transport == "udp" {
		a.udpSession(state, c.Reason, c.End)
		return
	}
	var clientObs, serverObs *contracts.Observation
	clientFacts, serverFacts := appid.DirectionFacts{}, appid.DirectionFacts{}
	if c.Sinks != nil {
		if s, ok := c.Sinks[state.Client].(*Sink); ok {
			o := s.In.Observation
			clientObs = &o
			clientFacts = appid.DirectionFacts{ResolvedFamily: s.In.ResolvedFamily(), BytesReceived: s.In.Metrics.BytesReceived, Known: true}
		}
		if s, ok := c.Sinks[state.Server].(*Sink); ok {
			o := s.In.Observation
			serverObs = &o
			serverFacts = appid.DirectionFacts{ResolvedFamily: s.In.ResolvedFamily(), BytesReceived: s.In.Metrics.BytesReceived, Known: true}
		}
	}
	verdict := appid.SessionVerdict(a.pack, clientObs, serverObs, "tcp", int(state.Server.Port), true,
		appid.Bytes{N: state.Bytes[state.Client], Known: true}, appid.Bytes{N: state.Bytes[state.Server], Known: true}, state.Ready)
	if state.Mode == session.ModeMidstream {
		if verdict.Identified(a.pack) {
			proto := ""
			if verdict.ClientProtocol != nil {
				proto = *verdict.ClientProtocol
			} else if verdict.ServerProtocol != nil {
				proto = *verdict.ServerProtocol
			}
			family := proto
			for i, ch := range proto {
				if ch == '/' {
					family = proto[:i]
					break
				}
			}
			if !midstreamFamilies[family] {
				if family == "" {
					family = verdict.App
				}
				verdict = appid.MidstreamOutcome(a.pack, "tcp", family)
			}
		} else if verdict.App == "unknown-tcp" || verdict.App == "incomplete" || verdict.App == "insufficient-data" {
			reason := "no reason"
			if len(verdict.Reasons) > 0 {
				reason = verdict.Reasons[0]
			}
			verdict = appid.UnobservedStartOutcome(a.pack, "tcp", reason)
		}
	}
	a.record("tcp", state, verdict, c.Reason, c.End, clientObs, serverObs, clientFacts, serverFacts)
}

func (a *Analyzer) udpSession(flow *session.State, reason string, end float64) {
	clientObs := flow.Observation
	serverObs := flow.Observations[flow.Server]
	var verdict *appid.Verdict
	if serverObs == nil {
		verdict = appid.SessionVerdict(a.pack, clientObs, nil, "udp", int(flow.Server.Port), true,
			appid.Bytes{N: flow.Bytes[flow.Client], Known: true}, appid.Bytes{}, true)
	} else {
		verdict = appid.SessionVerdict(a.pack, clientObs, serverObs, "udp", int(flow.Server.Port), true,
			appid.Bytes{N: flow.Bytes[flow.Client], Known: true}, appid.Bytes{N: flow.Bytes[flow.Server], Known: true}, true)
	}
	a.record("udp", flow, verdict, reason, end, clientObs, serverObs, appid.DirectionFacts{}, appid.DirectionFacts{})
}

func endpoint(e transport.Endpoint) []interface{} { return []interface{}{e.Addr, int(e.Port)} }

func round6(v float64) float64 { return math.Round(v*1e6) / 1e6 }

func (a *Analyzer) record(transportName string, state *session.State, verdict *appid.Verdict, reason string, end float64,
	clientObs, serverObs *contracts.Observation, clientFacts, serverFacts appid.DirectionFacts) {
	record := map[string]interface{}{"type": "session", "transport": transportName, "client": endpoint(state.Client), "server": endpoint(state.Server),
		"start": state.Start, "end": end, "packets": state.Packets, "client_bytes": state.Bytes[state.Client], "server_bytes": state.Bytes[state.Server],
		"end_reason": reason}
	for k, v := range verdict.Fields() {
		record[k] = v
	}
	record["content"] = map[string]interface{}{"version": a.pack.Release.Version, "digest": a.pack.Release.Digest}
	mode := state.Mode
	if mode == "" {
		mode = session.ModeHandshake
	}
	handshake := transportName != "tcp" || state.Ready
	if unknown := appid.SessionUnknown(verdict, clientObs, serverObs, clientFacts, serverFacts, mode, handshake); unknown != nil {
		record["unknown"] = unknown
	}
	observationMode := state.Mode
	if observationMode == "" {
		if transportName == "tcp" {
			observationMode = session.ModeHandshake
		} else {
			observationMode = "datagram"
		}
	}
	var seen []string
	for ep, n := range state.Bytes {
		if n > 0 {
			if ep == state.Client {
				seen = append(seen, "client")
			} else {
				seen = append(seen, "server")
			}
		}
	}
	sort.Strings(seen)
	if seen == nil {
		seen = []string{}
	}
	roles := "observed"
	if state.Mode == session.ModeMidstream {
		roles = "assumed-from-first-segment"
	}
	record["observation"] = map[string]interface{}{"mode": observationMode,
		"handshake_observed": transportName == "tcp" && (state.Mode == "" || state.Mode == session.ModeHandshake) && state.Ready,
		"directions_seen":    seen, "roles": roles}
	quality := "intact"
	if len(state.Input) > 0 {
		record["input_quality"] = state.Input
		quality = "degraded"
	}
	record["layers"] = appid.LayeredView(a.pack, transportName, clientObs, serverObs, verdict, quality)
	if state.HasFirst {
		record["decision"] = map[string]interface{}{"first_seconds": round6(state.FirstDecision - state.Start), "stable_seconds": round6(state.StableAt - state.Start)}
	}
	a.Records = append(a.Records, record)
}
