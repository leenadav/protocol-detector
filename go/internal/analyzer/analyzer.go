// Package analyzer ports the record-producing part of protocol_adapters/analyze_pcap.Analyzer: the
// tracker drives TCP connections with the engine attached as each direction's sink, the datagram
// inspector classifies UDP payloads per flow, and when tracking of a connection or flow ends one
// JSON-friendly session record is produced (verdict, flow risks, layered view, structured unknown
// reasons, decision timing, content pin, the HTTP/1 continuation summary, fingerprints, certificate
// structure, custom signatures with their set digest). Policy, hostnames-in-records and the live telemetry are not
// ported; a direction the engine cannot answer makes the whole run report NotPorted instead of a record.
package analyzer

import (
	"sort"
	"strconv"
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/appid"
	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/engine"
	"github.com/leenadav/protocol-detector/go/internal/errs"
	"github.com/leenadav/protocol-detector/go/internal/parsing"
	"github.com/leenadav/protocol-detector/go/internal/policy"
	"github.com/leenadav/protocol-detector/go/internal/protocols/quicx"
	"github.com/leenadav/protocol-detector/go/internal/protocols/x509x"
	"github.com/leenadav/protocol-detector/go/internal/pyjson"
	"github.com/leenadav/protocol-detector/go/internal/session"
	"github.com/leenadav/protocol-detector/go/internal/signatures"
	"github.com/leenadav/protocol-detector/go/internal/telemetry"
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
	retired    []contracts.Event // the events of Retire, until the tracker's Retired hook takes them
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
	s.retired = s.In.End(reason)
	s.touch()
	return len(s.retired) > 0
}
func (s *Sink) TakeIdentified() []session.Label { out := s.identified; s.identified = nil; return out }

// Analyzer is the record producer.
type Analyzer struct {
	pack      *content.Pack
	cfg       contracts.Config
	sigs      *signatures.Set
	Tracker   *session.Tracker
	udp       *engine.Datagram
	udpRev    int
	touched   []*Sink // sinks the current packet (or Finish) reached; reset at the next packet
	sinkSeq   uint64
	Records   []map[string]interface{}
	NotPorted *parsing.NotPorted
	opts      Options
	// Telemetry is the capture path's registry (Analyzer.telemetry): latency histograms and byte counters.
	Telemetry *telemetry.Telemetry
	// Rows is the adapter output since the caller last drained it (Options.Rows).
	Rows []Row
	// LastClassification is the observation of the packet in progress (Analyzer.last_classification), nil when the
	// packet classified nothing; LastServer is the server endpoint when tracking knows it.
	LastClassification *contracts.Observation
	LastServer         *transport.Endpoint
	// Sessions counts the session records produced (Analyzer.counts["sessions"]).
	Sessions int
	// Per packet (Python last_events / peer_events).
	LastEvents []contracts.Event
	PeerEvents []PeerEvent
	// Replayed events of the packet's own direction and where they go among that direction's events.
	replaySink   *Sink
	replayAt     int
	replayEvents []contracts.Event
}

// PeerEvent is an event a correlation published on the other direction of the packet's connection
// (Python Analyzer.peer_events: replayed bytes publish there, not on the packet's direction).
type PeerEvent struct {
	Source, Destination transport.Endpoint
	Event               contracts.Event
}

// Options mirrors the Analyzer constructor arguments the Go backend honours.
type Options struct {
	Session      session.Options
	Continuation int
	Fingerprints bool
	Certificates bool
	Heuristics   bool
	// Signatures are custom application signatures (nil or empty: none); a non-empty set retains parser contexts.
	Signatures *signatures.Set
	// TCPHint restricts both TCP directions to one validated candidate; UDPHint restricts UDP validation.
	TCPHint, UDPHint string
	// CRC32CByteLimit is Config.max_crc32c_bytes (nil: the default).
	CRC32CByteLimit *int
	// IncludeHostnames adds the asserted SNI/Host name to session records.
	IncludeHostnames bool
	// Policy, when set, is evaluated on every session record (POLICY.md).
	Policy *policy.Policy
	// Rows collects the adapter output in emission order (stream-end events and session records).
	Rows bool
}

// Row is one adapter output besides the per-packet row: a directional terminal event when tracking of its
// connection ended (Python on_retire) or a session record (on_session), in the order the reference emits them.
type Row struct {
	Source, Destination transport.Endpoint // stream end only
	Event               *contracts.Event   // stream end only
	// Bytes is the payload the retiring connection saw from Source (stream end only); BytesKnown is false when
	// no tracked state was being retired (Analyzer.retiring is None).
	Bytes      int
	BytesKnown bool
	Session    map[string]interface{}
	// Order names, for the maps of a session record the reference fills in evidence order, their keys in
	// that order: "fingerprints", "certificate", "input_quality", "continuation.client", "continuation.server".
	Order map[string][]string
}

// New builds an analyzer; options the engine lacks are reported through NotPorted on first use.
func New(pack *content.Pack, opts Options) (*Analyzer, error) {
	cfg := contracts.DefaultConfig()
	cfg.Continuation = opts.Continuation
	cfg.Fingerprints = opts.Fingerprints
	cfg.Certificates = opts.Certificates
	cfg.Heuristics = opts.Heuristics
	if opts.CRC32CByteLimit != nil {
		cfg.MaxCRC32CBytes = *opts.CRC32CByteLimit
	}
	if opts.Session.ByteLimit > 0 {
		cfg.MaxBytes = opts.Session.ByteLimit
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if opts.UDPHint != "" && !engine.DatagramHints[opts.UDPHint] {
		return nil, errs.New(errs.Invalid, errs.ScopeProcess, "Unsupported UDP candidate hint")
	}
	if opts.TCPHint != "" {
		if _, err := engine.New(contracts.DefaultConfig(), opts.TCPHint); err != nil {
			return nil, errs.New(errs.Invalid, errs.ScopeProcess, "Unsupported TCP candidate hint")
		}
	}
	a := &Analyzer{pack: pack, cfg: cfg, opts: opts, Telemetry: telemetry.New()}
	if opts.Signatures.Len() > 0 {
		a.sigs = opts.Signatures
		cfg.RetainContexts = true
		a.cfg = cfg
	}
	tr, err := session.NewTracker(opts.Session, func() session.Sink {
		in, err := engine.New(cfg, opts.TCPHint)
		if err != nil {
			if np, ok := err.(*parsing.NotPorted); ok && a.NotPorted == nil {
				a.NotPorted = np
			}
			in, _ = engine.New(contracts.DefaultConfig(), "")
		} else if a.sigs != nil {
			_ = in.SetSignatures(a.sigs) // retain_contexts is set with them
		}
		a.sinkSeq++
		return &Sink{In: in, owner: a, seq: a.sinkSeq}
	}, a.closed)
	if err != nil {
		return nil, err
	}
	a.Tracker = tr
	tr.Correlate = a.correlate
	tr.Classified = func(sink session.Sink) {
		if s, ok := sink.(*Sink); ok {
			o := s.In.Observation
			a.LastClassification = &o
		}
	}
	tr.Evidence = func(sink session.Sink) string {
		if s, ok := sink.(*Sink); ok {
			return compatEvidence(s.In.Observation, s.In.Candidate())
		}
		return ""
	}
	tr.Retired = func(source, destination transport.Endpoint, sink session.Sink) {
		s, ok := sink.(*Sink)
		if !ok {
			return
		}
		if opts.Rows {
			seen, known := 0, false
			if state := tr.Retiring; state != nil {
				seen, known = state.Bytes[source], true
			}
			for i := range s.retired {
				a.Rows = append(a.Rows, Row{Source: source, Destination: destination, Event: &s.retired[i], Bytes: seen, BytesKnown: known})
			}
		}
		s.retired = nil
	}
	udp, err := engine.NewDatagram(cfg)
	if err != nil {
		if np, ok := err.(*parsing.NotPorted); ok {
			a.NotPorted = np
		}
		udp, _ = engine.NewDatagram(contracts.DefaultConfig())
	} else if a.sigs != nil {
		_ = udp.SetSignatures(a.sigs)
	}
	// D01: the QUIC CRYPTO store is scoped per flow direction and expires with the flow table.
	maxQUIC := tr.MaxUDPFlows()
	if maxQUIC > 1024 {
		maxQUIC = 1024
	}
	if maxQUIC < 1 {
		maxQUIC = 1
	}
	udp.Assembler = quicx.NewAssembler(maxQUIC, tr.IdleTimeout())
	a.udp = udp
	return a, nil
}

// quicScope is the flow identity a datagram's QUIC CRYPTO state is kept under (Python passes (source, destination)).
func quicScope(source, destination transport.Endpoint) string {
	return source.String() + ">" + destination.String()
}

// Process handles one decoded packet and returns the adapter message (first segment compared by the harness).
func (a *Analyzer) Process(timestamp float64, decoded interface{}) string {
	a.LastEvents, a.PeerEvents = nil, nil
	a.LastClassification, a.LastServer = nil, nil
	a.replaySink, a.replayAt, a.replayEvents = nil, 0, nil
	a.resetTouched()
	defer func() { a.LastServer = a.Tracker.LastServer }()
	switch p := decoded.(type) {
	case *transport.UDP:
		// Python Analyzer.process expires idle state (retiring flows resets their QUIC scopes) before inspecting.
		a.Tracker.Expire(timestamp)
		now := a.Tracker.Now()
		obs, err := a.udp.InspectFlow(p.Payload, a.opts.UDPHint, quicScope(p.Source, p.Destination), &now)
		if err != nil {
			if np, ok := err.(*parsing.NotPorted); ok && a.NotPorted == nil {
				a.NotPorted = np
			}
			return "UDP"
		}
		a.udpRev++
		a.LastEvents = []contracts.Event{{Kind: contracts.DatagramObs, Revision: a.udpRev, Observation: obs}}
		classified := obs
		a.LastClassification = &classified
		return a.Tracker.ProcessUDP(timestamp, p, &obs)
	case *transport.TCP:
		message := a.Tracker.Process(timestamp, p)
		sort.Slice(a.touched, func(i, j int) bool { return a.touched[i].seq < a.touched[j].seq })
		for _, s := range a.touched {
			if s == a.replaySink {
				a.LastEvents = append(a.LastEvents, s.Pending[:a.replayAt]...)
				a.LastEvents = append(a.LastEvents, a.replayEvents...)
				a.LastEvents = append(a.LastEvents, s.Pending[a.replayAt:]...)
				continue
			}
			a.LastEvents = append(a.LastEvents, s.Pending...)
		}
		if a.replaySink != nil && !a.replaySink.touched {
			a.LastEvents = append(a.LastEvents, a.replayEvents...)
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

// Reset forgets every connection, flow and QUIC assembly without producing records (a capture gap: active
// observations are retracted, not ended).
func (a *Analyzer) Reset() {
	a.Tracker.Reset()
	a.udp.Assembler.Clear()
	a.resetTouched()
	a.LastEvents, a.PeerEvents, a.LastClassification = nil, nil, nil
	a.Rows = a.Rows[:0]
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
		seen, unique, candidates := 0, 0, 0
		for _, n := range state.Bytes {
			seen += n
		}
		for endpoint, n := range c.Stored {
			unique += n
			if s, ok := c.Sinks[endpoint].(*Sink); ok {
				candidates += s.In.Metrics.SignatureCandidates
			}
		}
		replayed := seen - unique
		if replayed < 0 {
			replayed = 0
		}
		if seen < unique {
			unique = seen
		}
		a.Telemetry.Add("bytes.new", unique)
		a.Telemetry.Add("bytes.replayed", replayed)
		a.Telemetry.Add("signatures.candidates", candidates)
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
	start := state.Start // Python passes at=state["start"] for TCP verdicts only (certificate validity)
	verdict := appid.SessionVerdictWith(a.pack, a.sigs, clientObs, serverObs, "tcp", int(state.Server.Port), true,
		appid.Bytes{N: state.Bytes[state.Client], Known: true}, appid.Bytes{N: state.Bytes[state.Server], Known: true}, state.Ready, &start)
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
	// D01: the flow's CRYPTO state ends with it, in both directions (Codex finding R2: resetting only the
	// client-to-server scope let a server-direction conflict marker or partial assembly outlive the flow).
	a.udp.Assembler.Reset(quicScope(flow.Client, flow.Server))
	a.udp.Assembler.Reset(quicScope(flow.Server, flow.Client))
	clientObs := flow.Observation
	serverObs := flow.Observations[flow.Server]
	var verdict *appid.Verdict
	if serverObs == nil {
		verdict = appid.SessionVerdictWith(a.pack, a.sigs, clientObs, nil, "udp", int(flow.Server.Port), true,
			appid.Bytes{N: flow.Bytes[flow.Client], Known: true}, appid.Bytes{}, true, nil)
	} else {
		verdict = appid.SessionVerdictWith(a.pack, a.sigs, clientObs, serverObs, "udp", int(flow.Server.Port), true,
			appid.Bytes{N: flow.Bytes[flow.Client], Known: true}, appid.Bytes{N: flow.Bytes[flow.Server], Known: true}, true, nil)
	}
	a.record("udp", flow, verdict, reason, end, clientObs, serverObs, appid.DirectionFacts{}, appid.DirectionFacts{})
}

func endpoint(e transport.Endpoint) []interface{} { return []interface{}{e.Addr, int(e.Port)} }

// seconds renders a capture time as the reference holds it: the integer 0 before any timestamp above zero,
// a float afterwards.
func seconds(v float64) interface{} {
	if v == 0 {
		return 0
	}
	return v
}

func (a *Analyzer) record(transportName string, state *session.State, verdict *appid.Verdict, reason string, end float64,
	clientObs, serverObs *contracts.Observation, clientFacts, serverFacts appid.DirectionFacts) {
	order := map[string][]string{}
	record := map[string]interface{}{"type": "session", "transport": transportName, "client": endpoint(state.Client), "server": endpoint(state.Server),
		"start": seconds(state.Start), "end": seconds(end), "packets": state.Packets, "client_bytes": state.Bytes[state.Client], "server_bytes": state.Bytes[state.Server],
		"end_reason": reason}
	for k, v := range verdict.Fields() {
		record[k] = v
	}
	record["content"] = map[string]interface{}{"version": a.pack.Release.Version, "digest": a.pack.Digests.Release}
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
	if summary := continuationSummary(clientObs, serverObs, order); len(summary) > 0 {
		record["continuation"] = summary // D07: what followed the identification, per direction
	}
	quality := "intact"
	if len(state.Input) > 0 {
		record["input_quality"] = state.Input
		order["input_quality"] = state.InputOrder
		quality = "degraded"
	}
	record["layers"] = appid.LayeredView(a.pack, transportName, clientObs, serverObs, verdict, quality)
	if a.sigs != nil {
		record["signature_set"] = a.sigs.Digest // stage 7 (A11): the rule set this verdict used
	}
	// Latency telemetry (P2): the session's lifetime is not its decision time.
	positive := func(v float64) float64 {
		if v < 0 {
			return 0
		}
		return v
	}
	a.Telemetry.Observe("session_lifetime_seconds", positive(end-state.Start))
	if state.HasFirst {
		a.Telemetry.Observe("time_to_first_decision_seconds", positive(state.FirstDecision-state.Start))
		a.Telemetry.Observe("time_to_stable_verdict_seconds", positive(state.StableAt-state.Start))
	}
	a.Telemetry.Add("sessions."+verdict.Status, 1)
	if state.HasFirst {
		// The reference's clock is the integer 0 until a capture timestamp above zero arrives; a decision at
		// that instant is the integer 0 there (round(0 - 0, 6)), any other is a float.
		decision := map[string]interface{}{"first_seconds": interface{}(0), "stable_seconds": interface{}(0)}
		if state.FirstDecision != 0 {
			decision["first_seconds"] = pyjson.Round(state.FirstDecision-state.Start, 6)
		}
		if state.StableAt != 0 {
			decision["stable_seconds"] = pyjson.Round(state.StableAt-state.Start, 6)
		}
		record["decision"] = decision
	}
	// Derived evidence (Config.fingerprints) of both directions, by field; a later direction's value wins.
	fingerprints := map[string]interface{}{}
	for _, obs := range []*contracts.Observation{clientObs, serverObs} {
		if obs == nil {
			continue
		}
		for _, e := range obs.Evidence {
			if e.Strength == "derived" {
				if _, seen := fingerprints[e.Field]; !seen {
					order["fingerprints"] = append(order["fingerprints"], e.Field)
				}
				fingerprints[e.Field] = e.Value
			}
		}
	}
	if len(fingerprints) > 0 {
		record["fingerprints"] = fingerprints
	}
	if certificate := certificateFields(clientObs, serverObs, state.Start, order); len(certificate) > 0 {
		record["certificate"] = certificate // structure labels only: no names, serials or keys
	}
	if a.opts.Policy != nil {
		// D04: the decision sees the typed evidence contract, never a confidence number.
		layers, _ := record["layers"].(map[string]interface{})
		record["policy"] = a.opts.Policy.Evaluate(verdict, transportName, int(state.Server.Port), true, layers, observationMode).Fields()
	}
	if a.opts.IncludeHostnames {
		var hostname interface{}
		for _, obs := range []*contracts.Observation{clientObs, serverObs} {
			if obs != nil && obs.Hostname != nil && *obs.Hostname != "" {
				hostname = *obs.Hostname
				break
			}
		}
		record["hostname"] = hostname
	}
	a.Sessions++
	if a.opts.Rows {
		a.Rows = append(a.Rows, Row{Session: record, Order: order})
		return
	}
	a.Records = append(a.Records, record)
}

// compatFamilies is sessions.TCP_FAMILIES: the legacy display order followed by the remaining TCP families in
// inventory order. test_migration_parity compares it with the Python tuple.
var compatFamilies = []string{"http", "ssh", "tls", "http2", "socks5", "smtp", "mqtt", "resp", "amqp", "dns", "stun", "postgresql", "rfb",
	"bittorrent", "memcached", "ldap", "sip", "rtsp", "bgp", "smb2", "stomp", "nats", "imap", "rdp", "mysql", "mongodb", "websocket", "ftp",
	"pop3", "telnet", "smb1", "netbios-ss", "kerberos", "tacacs-plus", "openvpn", "pptp", "modbus", "dnp3", "iso-tsap", "s7comm", "ethernet-ip",
	"iec-104", "kafka", "cql", "dcerpc", "giop", "git", "fastcgi", "rsync", "tds", "tns", "onc-rpc", "diameter", "zmtp", "bolt", "opcua", "syslog",
	"x11", "spice", "afp", "irc", "fins", "xmpp"}

var textCandidates = map[string]bool{"http": true, "ssh": true, "smtp": true, "sip": true, "rtsp": true, "nats": true, "imap": true, "git": true}

// compatEvidence ports sessions._compat_rows as the analyzer prints it: "FAMILY=STATUS (evidence)" per TCP family.
func compatEvidence(o contracts.Observation, candidate string) string {
	if candidate == "git_text" {
		candidate = "text" // shared routing scope before a structural discriminator
	}
	if candidate == "tpkt" {
		candidate = "rdp"
	}
	matched := ""
	if o.Encryption != nil && *o.Encryption == "tls" {
		matched = "tls"
	} else if o.ApplicationProtocol != nil {
		matched = *o.ApplicationProtocol
	}
	if matched == "http/2" {
		matched = "http2"
	} else if strings.HasPrefix(matched, "http/") {
		matched = "http"
	}
	if i := strings.IndexByte(matched, '/'); i >= 0 {
		matched = matched[:i] // mqtt/, amqp/ and every other versioned label
	}
	var b strings.Builder
	for i, name := range compatFamilies {
		routed := candidate == "" || name == candidate || (candidate == "text" && textCandidates[name])
		status := "NO_MATCH"
		switch {
		case o.Status == contracts.Identified && matched == name && matched != "":
			status = "MATCH"
		case o.Status == contracts.Detecting && routed:
			status = "NEED_MORE"
		case o.Status == contracts.Unknown && routed:
			status = "UNKNOWN"
		case (o.Status == contracts.BudgetExhausted || o.Status == contracts.Incomplete || o.Status == contracts.Invalidated) && routed:
			status = strings.ToUpper(string(o.Status))
		}
		evidence := "Excluded by prefix dispatch"
		if routed || status == "MATCH" {
			evidence = o.Reason
		}
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(strings.ToUpper(name) + "=" + status + " (" + evidence + ")")
	}
	return b.String()
}

// correlate ports the Analyzer._correlate_connect and _correlate_ldap calls that follow a data segment whose
// direction published an identification. It returns the endpoints whose observation a replay changed.
func (a *Analyzer) correlate(state *session.State, source transport.Endpoint) []transport.Endpoint {
	connection := a.Tracker.Manager().Connections[session.KeyOf(state.Client, state.Server)]
	if connection == nil {
		return nil
	}
	sink, ok := connection.Directions[source].Sink.(*Sink)
	if !ok || !hasIdentified(sink.Pending) {
		return nil
	}
	client, okc := connection.Directions[state.Client].Sink.(*Sink)
	server, oks := connection.Directions[state.Server].Sink.(*Sink)
	if !okc || !oks {
		return nil
	}
	var changed []transport.Endpoint
	open := func(endpoint transport.Endpoint, boundary, expected string) bool {
		opened, events := a.openShift(connection.Directions[endpoint], boundary, expected)
		if !opened {
			return false
		}
		other := state.Server
		if endpoint == state.Server {
			other = state.Client
		}
		if len(events) > 0 {
			changed = append(changed, endpoint)
		}
		if endpoint == source {
			a.replaySink, a.replayAt = connection.Directions[endpoint].Sink.(*Sink), len(sink.Pending)
			a.replayEvents = append(a.replayEvents, events...)
		} else {
			for _, e := range events {
				a.PeerEvents = append(a.PeerEvents, PeerEvent{Source: endpoint, Destination: other, Event: e})
			}
		}
		return true
	}
	a.correlateConnect(state, client, server, open)
	a.correlateLDAP(state, client, server, open)
	a.correlateHTTP2(client, server)
	return changed
}

// correlateHTTP2 ports Analyzer._correlate_http2: with prior knowledge (RFC 9113 3.3, including after ALPN) the
// server's first frame is a bare SETTINGS frame no prefix routes anywhere, so once the client preface identified
// the connection the server direction expects HTTP/2; its bytes still have to validate as SETTINGS and HEADERS.
// Only a direction that has not sent anything yet adopts the expectation.
func (a *Analyzer) correlateHTTP2(client, server *Sink) {
	request := client.In.Observation
	if request.Status != contracts.Identified || request.ApplicationProtocol == nil || *request.ApplicationProtocol != "http/2" {
		return
	}
	if _, shifted := evidenceValue(request, "shift"); shifted {
		return
	}
	if server.In.Expect("http2-server", "http2-preface") {
		a.Tracker.Counts["http2_servers_expected"]++
	}
}

func hasIdentified(events []contracts.Event) bool {
	for _, e := range events {
		if e.Observation.Status == contracts.Identified {
			return true
		}
	}
	return false
}

// openShift ports Analyzer._open_shift with Stream.open_shift: open the peer-decided phase, then replay the bytes
// the direction carried past its message (a ClientHello recorded before the answer, a ServerHello coalesced with
// it) exactly once from the bounded reassembly window.
func (a *Analyzer) openShift(d *session.Direction, boundary, expected string) (bool, []contracts.Event) {
	sink := d.Sink.(*Sink)
	in := sink.In
	start, has := in.Boundary, in.HasBoundary()
	if !in.OpenShift(boundary, expected) {
		if in.NotPorted != nil && a.NotPorted == nil {
			a.NotPorted = in.NotPorted
		}
		return false, nil
	}
	if has && d.Stream.Contiguous() > start {
		retained := append([]byte(nil), d.Stream.Prefix()[start:d.Stream.Contiguous()]...)
		events, _ := in.Replay(retained)
		if in.NotPorted != nil && a.NotPorted == nil {
			a.NotPorted = in.NotPorted
		}
		return true, events
	}
	return true, nil
}

func evidenceValue(o contracts.Observation, field string) (string, bool) {
	for _, e := range o.Evidence {
		if e.Field == field {
			return e.Value, true
		}
	}
	return "", false
}

// correlateConnect ports Analyzer._correlate_connect: the server direction of a CONNECT opens its tunnel phase
// once its 2xx answer is seen; nothing is retracted.
func (a *Analyzer) correlateConnect(state *session.State, client, server *Sink, open func(transport.Endpoint, string, string) bool) {
	request, response := client.In.Observation, server.In.Observation
	if response.Status != contracts.Identified || response.ApplicationProtocol == nil || len(*response.ApplicationProtocol) < 5 ||
		(*response.ApplicationProtocol)[:5] != "http/" {
		return
	}
	if request.Status != contracts.Identified {
		return
	}
	connect := false
	for _, e := range request.Evidence {
		if (e.Field == "http_method" && e.Value == "CONNECT") || (e.Field == "shift" && e.Value == "http-connect") {
			connect = true
		}
	}
	if !connect {
		return
	}
	if status, _ := evidenceValue(response, "http_status"); len(status) > 0 && status[0] == '2' && open(state.Server, "http-connect", "") {
		a.Tracker.Counts["connect_tunnels_correlated"]++
	}
}

// correlateLDAP ports Analyzer._correlate_ldap: the client's StartTLS request decides nothing by itself; its
// direction is opened only when the server's ExtendedResponse is a success for the same message id, and the
// server's too when the response is unnamed. A server that shifted inside the segment of its named success is
// compared through its announcement.
func (a *Analyzer) correlateLDAP(state *session.State, client, server *Sink, open func(transport.Endpoint, string, string) bool) {
	request, response := client.In.Observation, server.In.Observation
	if (response.ApplicationProtocol == nil || *response.ApplicationProtocol != "ldap") && server.In.Announcement != nil {
		response = *server.In.Announcement
	}
	if request.Status != contracts.Identified || response.Status != contracts.Identified || response.ApplicationProtocol == nil ||
		*response.ApplicationProtocol != "ldap" {
		return
	}
	asked := map[string]string{}
	for _, e := range request.Evidence {
		if e.Field == "ldap_message" || e.Field == "ldap_extended" {
			asked[e.Field] = e.Value
		}
	}
	if len(asked) != 2 || asked["ldap_message"] != "extended_request" || asked["ldap_extended"] != "starttls" {
		return
	}
	answered := map[string]string{}
	for _, e := range response.Evidence {
		if e.Field == "ldap_message" || e.Field == "ldap_extended" || e.Field == "ldap_result" {
			answered[e.Field] = e.Value
		}
	}
	if answered["ldap_message"] != "extended_response" || answered["ldap_result"] != "success" ||
		(answered["ldap_extended"] != "starttls" && answered["ldap_extended"] != "unnamed") {
		return
	}
	requestID, okRequest := client.In.LDAPMessageID()
	responseID, okResponse := server.In.LDAPMessageID()
	if !okRequest || !okResponse || requestID != responseID {
		return
	}
	opened := open(state.Client, "ldap-starttls", "tls")
	if answered["ldap_extended"] == "unnamed" {
		opened = open(state.Server, "ldap-starttls", "tls") || opened
	}
	if opened {
		a.Tracker.Counts["ldap_starttls_correlated"]++
	}
}

// continuationFields is continuation.SUMMARY_FIELDS.
var continuationFields = map[string]bool{"http_messages": true, "http_methods": true, "http_status_classes": true, "http_host_variation": true,
	"tls_records": true, "tls_application_data": true, "tls_alert": true, "continuation": true}

// continuationSummary ports continuation.continuation_summary: per-direction continuation evidence ({} when none ran).
func continuationSummary(client, server *contracts.Observation, order map[string][]string) map[string]interface{} {
	summary := map[string]interface{}{}
	for _, side := range []struct {
		name string
		obs  *contracts.Observation
	}{{"client", client}, {"server", server}} {
		if side.obs == nil {
			continue
		}
		fields := map[string]interface{}{}
		for _, item := range side.obs.Evidence {
			source := item.Source
			if i := strings.LastIndexByte(source, ':'); i >= 0 {
				source = source[i+1:]
			}
			if source != "continuation" || !continuationFields[item.Field] {
				continue
			}
			key := item.Field
			if key == "continuation" {
				key = "ended"
			}
			if _, seen := fields[key]; !seen && order != nil {
				order["continuation."+side.name] = append(order["continuation."+side.name], key)
			}
			if item.Field == "http_messages" {
				n, err := strconv.Atoi(item.Value)
				if err != nil {
					continue
				}
				fields[key] = n
			} else {
				fields[key] = item.Value
			}
		}
		if len(fields) > 0 {
			summary[side.name] = fields
		}
	}
	return summary
}

// certificateFields ports analyze_pcap.certificate_fields: the tls_certificate_* evidence of both directions without
// its prefix, plus the validity label at the capture time when both dates and the clock allow it.
// CertificateFields is certificate_fields((observation,), at) with the fields in evidence order.
func CertificateFields(o *contracts.Observation, at float64) (map[string]interface{}, []string) {
	order := map[string][]string{}
	fields := certificateFields(o, nil, at, order)
	return fields, order["certificate"]
}

// Content is the content release every record of this run names (Analyzer.content).
func (a *Analyzer) Content() map[string]interface{} {
	return map[string]interface{}{"version": a.pack.Release.Version, "digest": a.pack.Digests.Release}
}

// Signatures is the custom signature set in force (nil: none).
func (a *Analyzer) Signatures() *signatures.Set { return a.sigs }

func certificateFields(client, server *contracts.Observation, at float64, order map[string][]string) map[string]interface{} {
	certificate := map[string]interface{}{}
	for _, obs := range []*contracts.Observation{client, server} {
		if obs == nil {
			continue
		}
		for _, e := range obs.Evidence {
			if strings.HasPrefix(e.Field, "tls_certificate_") {
				key := e.Field[len("tls_certificate_"):]
				if _, seen := certificate[key]; !seen && order != nil {
					order["certificate"] = append(order["certificate"], key)
				}
				certificate[key] = e.Value
			}
		}
	}
	notBefore, _ := certificate["not_before"].(string)
	notAfter, _ := certificate["not_after"].(string)
	if label := x509x.Validity(notBefore, notAfter, &at); label != "" {
		if _, seen := certificate["validity"]; !seen && order != nil {
			order["certificate"] = append(order["certificate"], "validity")
		}
		certificate["validity"] = label
	}
	return certificate
}
