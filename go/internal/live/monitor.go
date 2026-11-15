// Package live is the host capture adapter (protocol_adapters/live_capture.py): tcpdump owns capture, this
// process stays unprivileged and inspects only the initial message of each stream scope. It emits metadata
// events (classifications, session records, capture gaps, summaries) and never payload, credentials or names.
package live

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/analyze"
	"github.com/leenadav/protocol-detector/go/internal/analyzer"
	"github.com/leenadav/protocol-detector/go/internal/appid"
	"github.com/leenadav/protocol-detector/go/internal/capture"
	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/keylogcap"
	"github.com/leenadav/protocol-detector/go/internal/policy"
	"github.com/leenadav/protocol-detector/go/internal/pyjson"
	"github.com/leenadav/protocol-detector/go/internal/session"
	"github.com/leenadav/protocol-detector/go/internal/sessionid"
	"github.com/leenadav/protocol-detector/go/internal/signatures"
	"github.com/leenadav/protocol-detector/go/internal/transport"
)

// Options are the CaptureMonitor arguments.
type Options struct {
	MaxConnections   int
	ByteLimit        int
	IdleTimeout      float64
	AllEvents        bool
	UDPHint, TCPHint string
	CRC32CByteLimit  int
	IncludeHostnames bool
	Signatures       *signatures.Set
	Fingerprints     bool
	Heuristics       bool
	Policy           *policy.Policy
	Certificates     bool
	Observation      string
	Checksums        string
	Continuation     int
}

// Event is one emitted event: a JSON object, its layout name and the key orders of the maps the reference
// fills in first-use order.
type Event struct {
	// Raw, when set, is the event already rendered as JSON text (Kind "raw").
	Raw    string
	Kind   string // classification, retired, invalidated, session, capture_gap, summary, started, error
	Fields map[string]interface{}
	Order  map[string][]string
}

// counter is collections.Counter: counts in first-touched order.
type counter struct {
	order  []string
	values map[string]int
}

func newCounter() *counter { return &counter{values: map[string]int{}} }

func (c *counter) add(key string, n int) {
	if _, seen := c.values[key]; !seen {
		c.order = append(c.order, key)
	}
	c.values[key] += n
}

func (c *counter) render() map[string]interface{} {
	out := make(map[string]interface{}, len(c.values))
	for key, value := range c.values {
		out[key] = value
	}
	return out
}

// Monitor is CaptureMonitor with its SessionCoordinator: the one lifecycle owner of a live capture.
type Monitor struct {
	emit   func(Event)
	pack   *content.Pack
	opts   Options
	an     *analyzer.Analyzer
	counts *counter

	protocols, apps, risks, policyCounts *counter
	rejected                             map[string]int
	flowsMarked                          int

	// tier is the retained reassembly tier a second consumer (the TLS decoder) reads; nil on the plain live path.
	tier *keylogcap.Tier

	captureID   string
	generations map[string]int
	finalized   map[string]bool // session id and generation already published or retracted: never twice
	now         float64
	ended       bool
}

// NewMonitor builds the monitor; captureID "" draws a random capture id.
func NewMonitor(pack *content.Pack, opts Options, captureID string, emit func(Event)) (*Monitor, error) {
	if opts.Checksums != transport.Ignore && opts.Checksums != transport.Audit && opts.Checksums != transport.Verify {
		return nil, &Error{"checksums must be one of ignore, audit, verify"}
	}
	limit := opts.CRC32CByteLimit
	an, err := analyzer.New(pack, analyzer.Options{Continuation: opts.Continuation, Fingerprints: opts.Fingerprints, Certificates: opts.Certificates,
		Heuristics: opts.Heuristics, Signatures: opts.Signatures, TCPHint: opts.TCPHint, UDPHint: opts.UDPHint, CRC32CByteLimit: &limit,
		IncludeHostnames: opts.IncludeHostnames, Policy: opts.Policy, Rows: true,
		Session: session.Options{MaxConnections: opts.MaxConnections, ByteLimit: opts.ByteLimit, IdleTimeout: opts.IdleTimeout, MaxUDPFlows: -1,
			Compact: true, Observation: opts.Observation}})
	if err != nil {
		return nil, err
	}
	if captureID == "" {
		raw := make([]byte, 8)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		captureID = hex.EncodeToString(raw)
	}
	return &Monitor{emit: emit, pack: pack, opts: opts, an: an, counts: newCounter(), protocols: newCounter(), apps: newCounter(),
		risks: newCounter(), policyCounts: newCounter(), rejected: map[string]int{}, captureID: captureID,
		generations: map[string]int{}, finalized: map[string]bool{}}, nil
}

// Error is a ValueError of the adapter.
type Error struct{ Message string }

func (e *Error) Error() string { return e.Message }

func endpoint(e transport.Endpoint) []interface{} { return []interface{}{e.Addr, int(e.Port)} }

func protocolOf(o *contracts.Observation) interface{} {
	if o.ApplicationProtocol != nil && *o.ApplicationProtocol != "" {
		return *o.ApplicationProtocol
	}
	if o.Encryption != nil {
		return *o.Encryption
	}
	return nil
}

func hint(value string) interface{} {
	if value == "" {
		return nil
	}
	return value
}

// drain publishes what tracking emitted since the last call: retired directions and session records, in order.
func (m *Monitor) drain() {
	for _, row := range m.an.Rows {
		if row.Event != nil {
			m.retired(row)
			continue
		}
		m.session(row)
	}
	m.an.Rows = m.an.Rows[:0]
}

// session is the coordinator's one session sink (identity, exactly-once) followed by CaptureMonitor._session.
func (m *Monitor) session(row analyzer.Row) {
	record := row.Session
	transportName, _ := record["transport"].(string)
	client, server := endpointOf(record["client"]), endpointOf(record["server"])
	sid := sessionid.Identity(transportName, client, server)
	generation := m.generations[sid]
	key := sid + "/" + itoa(generation)
	if m.finalized[key] {
		return // a path that both expires and finishes must never publish one (session, generation) twice
	}
	m.finalized[key] = true
	record["capture_id"], record["session_id"], record["generation"] = m.captureID, sid, generation
	m.counts.add("sessions", 1)
	app, _ := record["app"].(string)
	m.apps.add(app, 1)
	if risks, ok := record["risks"].([]string); ok {
		for _, risk := range risks {
			m.risks.add(risk, 1)
		}
	}
	if decision, ok := record["policy"].(map[string]interface{}); ok && len(decision) > 0 {
		action, _ := decision["action"].(string)
		m.policyCounts.add(action, 1)
	}
	m.emit(Event{Kind: "session", Fields: record, Order: row.Order})
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

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// retired is CaptureMonitor._retired: a direction's terminal observation when tracking of its connection ends.
func (m *Monitor) retired(row analyzer.Row) {
	o := row.Event.Observation
	m.counts.add(string(o.Status), 1)
	if !m.opts.AllEvents {
		return
	}
	verdict := appid.SessionVerdictWith(m.pack, m.an.Signatures(), &o, nil, "tcp", 0, false, appid.Bytes{N: row.Bytes, Known: row.BytesKnown},
		appid.Bytes{}, true, nil)
	m.emit(Event{Kind: "retired", Fields: map[string]interface{}{"type": "classification", "timestamp": nil, "source": endpoint(row.Source),
		"destination": endpoint(row.Destination), "transport": "tcp", "status": string(o.Status), "protocol": protocolOf(&o), "app": verdict.App,
		"scope": o.Scope, "candidate_hint": hint(m.opts.TCPHint), "reason": o.Reason, "boundary": "observation_retired"}})
}

// Retain adds the retained reassembly tier under the budget (CaptureMonitor's `retain`) and returns it.
func (m *Monitor) Retain(budget keylogcap.Budget) *keylogcap.Tier {
	m.tier = keylogcap.NewTier(budget, m.opts.IdleTimeout, func(sid string) int { return m.generations[sid] })
	m.tier.Telemetry = m.an.Telemetry
	return m.tier
}

// Accept is CaptureMonitor.accept: one captured record at the clock value now. The error is the retained
// tier's (its consumer queue overflowed); without a tier it is always nil.
func (m *Monitor) Accept(record capture.Record, now float64) error {
	m.counts.add("packets", 1)
	m.counts.add("captured_bytes", len(record.Data))
	if record.Truncated() {
		m.counts.add("truncated", 1)
		m.rejected["truncated"]++
		// A truncated packet cannot be associated with one flow: discard all partial state, require new
		// handshakes, retract prior active labels.
		return m.InvalidateAll("Capture truncation; active stream observations invalidated", "active_connections")
	}
	packet, err := transport.Decode(record.Data, record.Linktype, m.opts.Checksums)
	if err != nil {
		reject, ok := err.(*transport.Reject)
		if !ok {
			return nil
		}
		m.counts.add("unsupported_or_malformed_packets", 1)
		m.rejected[reject.Kind]++
		if reject.Endpoints != nil && m.an.Tracker.NoteInput(reject.Kind, reject.Endpoints) {
			m.flowsMarked++ // D06: the flow never reads as fully inspected
		}
		m.drain()
		return nil
	}
	var source, destination transport.Endpoint
	var failures []string
	var tcp *transport.TCP
	transportName, payload := "udp", 0
	switch p := packet.(type) {
	case *transport.TCP:
		source, destination, failures, tcp, transportName, payload = p.Source, p.Destination, p.ChecksumFailures, p, "tcp", len(p.Payload)
	case *transport.UDP:
		source, destination, failures, payload = p.Source, p.Destination, p.ChecksumFailures, len(p.Payload)
	}
	if len(failures) > 0 {
		m.rejected["checksum"]++
		if m.an.Tracker.NoteInput("checksum", &[2]transport.Endpoint{source, destination}) {
			m.flowsMarked++
		}
		m.drain()
	}
	m.counts.add(transportName, 1)
	done := m.an.Telemetry.Stage("packet")
	// The coordinator's accept: tuple reuse on a SYN finalizes the old generation, then starts the next.
	if now > m.now {
		m.now = now
	}
	if m.tier != nil {
		m.tier.SetNow(now)
	}
	if tcp != nil && tcp.Flags&transport.SYN != 0 && tcp.Flags&transport.ACK == 0 {
		key := session.KeyOf(source, destination)
		tracked, held := m.an.Tracker.TracksTCP(key), m.tier != nil && m.tier.Holds(key)
		if tracked || held {
			const restart = "Connection restarted (new SYN on a tracked tuple)"
			if tracked {
				m.an.Tracker.Drop(key, restart)
				m.drain()
			}
			if held {
				if err := m.tier.Close(key, restart); err != nil {
					done()
					return err
				}
			}
			m.generations[sessionid.Identity("tcp", source, destination)]++
		}
	}
	message := m.an.Process(now, packet)
	var retainErr error
	if tcp != nil && m.tier != nil {
		retainErr = m.tier.Retain(tcp)
	}
	done()
	m.drain()
	if retainErr != nil {
		return retainErr
	}
	switch {
	case strings.HasPrefix(message, "SKIP"):
		if payload > 0 {
			m.counts.add("tcp_without_start", 1)
		} else {
			m.counts.add("tcp_control_without_state", 1)
		}
	case strings.HasPrefix(message, "LIMIT"):
		m.counts.add("connection_limit", 1)
	case strings.HasPrefix(message, "INVALIDATED"):
		m.counts.add("stream_invalidations", 1)
	}
	if strings.HasPrefix(message, "INVALIDATED") && len(m.an.LastEvents) == 0 {
		m.emit(Event{Kind: "invalidated", Fields: map[string]interface{}{"type": "classification", "timestamp": record.Timestamp,
			"source": endpoint(source), "destination": endpoint(destination), "transport": transportName, "status": "invalidated",
			"protocol": nil, "scope": "initial_message", "reason": message}})
	}
	server := m.an.LastServer
	for i := range m.an.LastEvents {
		m.classification(&m.an.LastEvents[i], source, destination, transportName, record.Timestamp, server)
	}
	// A correlation may have replayed retained bytes on the other direction of the same connection; those
	// events carry their own direction.
	for i := range m.an.PeerEvents {
		p := &m.an.PeerEvents[i]
		m.classification(&p.Event, p.Source, p.Destination, transportName, record.Timestamp, server)
	}
	return nil
}

func (m *Monitor) classification(event *contracts.Event, source, destination transport.Endpoint, transportName string, timestamp float64,
	server *transport.Endpoint) {
	o := event.Observation
	m.counts.add(string(o.Status), 1)
	protocol := protocolOf(&o)
	if o.Status == contracts.Identified {
		name, _ := protocol.(string)
		if protocol == nil {
			name = "null" // the reference counts under the None key, which json.dumps writes as "null"
		}
		m.protocols.add(name, 1)
	}
	if !m.opts.AllEvents && o.Status != contracts.Identified && o.Status != contracts.Invalidated {
		return
	}
	// No payload, community, credentials, HTTP path, or hostname output.
	order := map[string][]string{}
	derived := map[string]interface{}{}
	for _, e := range o.Evidence {
		if e.Strength == "derived" {
			if _, seen := derived[e.Field]; !seen {
				order["classification.fingerprints"] = append(order["classification.fingerprints"], e.Field)
			}
			derived[e.Field] = e.Value
		}
	}
	certificate, certificateOrder := analyzer.CertificateFields(&o, timestamp)
	order["classification.certificate"] = certificateOrder
	port, hasPort := 0, false
	if server != nil {
		port, hasPort = int(server.Port), true
	}
	at := timestamp
	verdict := appid.SessionVerdictWith(m.pack, m.an.Signatures(), &o, nil, transportName, port, hasPort, appid.Bytes{}, appid.Bytes{}, true, &at)
	risks := verdict.Risks
	if risks == nil {
		risks = []string{}
	}
	var action interface{}
	if m.opts.Policy != nil {
		action = m.opts.Policy.Evaluate(verdict, transportName, port, hasPort, nil, "").Action
	}
	fields := map[string]interface{}{"type": "classification", "timestamp": timestamp, "source": endpoint(source), "destination": endpoint(destination),
		"transport": transportName, "status": string(o.Status), "protocol": protocol, "app": verdict.App, "risks": risks, "policy": action,
		"fingerprints": nil, "certificate": nil, "event": string(event.Kind), "scope": o.Scope, "candidate_hint": hint(m.opts.TCPHint),
		"reason": o.Reason}
	if transportName == "udp" {
		fields["candidate_hint"] = hint(m.opts.UDPHint)
	}
	if len(derived) > 0 {
		fields["fingerprints"] = derived
	}
	if len(certificate) > 0 {
		fields["certificate"] = certificate
	}
	m.emit(Event{Kind: "classification", Fields: fields, Order: order})
}

// InvalidateAll is CaptureMonitor.invalidate_all with the coordinator's gap: name and retract every active
// session, then drop their state.
func (m *Monitor) InvalidateAll(reason, scope string) error {
	tracked := m.an.Tracker.TrackedTCP()
	active := len(tracked)
	ids := map[string]bool{}
	for _, state := range tracked {
		ids[sessionid.Identity("tcp", state.Client, state.Server)] = true
	}
	if active > 0 || scope == "all_observations_this_capture" {
		retracted := make([]string, 0, len(ids))
		for id := range ids {
			retracted = append(retracted, id)
		}
		sort.Strings(retracted)
		m.emit(Event{Kind: "capture_gap", Fields: map[string]interface{}{"type": "capture_gap", "active_connections": active, "scope": scope,
			"reason": reason, "session_ids": retracted, "capture_id": m.captureID}})
	}
	m.counts.add("connections_discarded_after_gap", active)
	m.an.Telemetry.Add("capture.gaps", 1)
	for id := range ids {
		m.finalized[id+"/"+itoa(m.generations[id])] = true // retracted, never finalized
	}
	m.an.Reset()
	if m.tier != nil {
		return m.tier.Gap(reason)
	}
	return nil
}

// Tick advances the injected time; idle expiration happens here, never on packet arrival alone.
func (m *Monitor) Tick(now float64) error {
	if m.ended {
		return nil
	}
	if now > m.now {
		m.now = now
	}
	done := m.an.Telemetry.Stage("tick")
	m.an.Tracker.Expire(m.now)
	done()
	m.drain()
	if m.tier != nil {
		return m.tier.Tick(m.now)
	}
	m.an.Telemetry.Set("bytes.retained", 0)
	m.an.Telemetry.Set("queue.depth", 0)
	return nil
}

// End finalizes everything still tracked, exactly once.
func (m *Monitor) End(reason string) error {
	if m.ended {
		return nil
	}
	m.ended = true
	_ = m.an.Finish(reason)
	m.drain()
	if m.tier != nil {
		return m.tier.End(reason)
	}
	return nil
}

// Packets is counts["packets"]; Truncated counts["truncated"].
func (m *Monitor) Packets() int   { return m.counts.values["packets"] }
func (m *Monitor) Truncated() int { return m.counts.values["truncated"] }

// AddCount adds to a named counter (the run loop's own counters).
func (m *Monitor) AddCount(name string, n int) { m.counts.add(name, n) }

// Summary is CaptureMonitor.summary: a progress or final summary event. stats is tcpdump's own statistics in
// the order it printed them (nil: none).
func (m *Monitor) Summary(elapsed float64, final bool, stats map[string]int, statsOrder []string) Event {
	return m.summary(elapsed, final, stats, statsOrder, false)
}

// SummaryWithStats is Summary with the statistics always rendered as an object, empty when tcpdump printed
// none (the live decryption worker passes its statistics dictionary as it is).
func (m *Monitor) SummaryWithStats(elapsed float64, final bool, stats map[string]int, statsOrder []string) Event {
	return m.summary(elapsed, final, stats, statsOrder, true)
}

func (m *Monitor) summary(elapsed float64, final bool, stats map[string]int, statsOrder []string, always bool) Event {
	kind := "progress"
	if final {
		kind = "summary"
	}
	tracked, _, flows := m.an.Tracker.Tables()
	telemetry, telemetryOrder := m.an.Telemetry.Render()
	var captureStats interface{}
	if len(stats) > 0 || always {
		rendered := make(map[string]interface{}, len(stats))
		for key, value := range stats {
			rendered[key] = value
		}
		captureStats = rendered
	}
	fields := map[string]interface{}{"type": kind, "elapsed_seconds": pyjson.Round(elapsed, 3), "counts": m.counts.render(), "protocols": m.protocols.render(),
		"apps": m.apps.render(), "risks": m.risks.render(), "policy": m.policyCounts.render(), "active_connections": tracked,
		"active_udp_flows": flows, "capture_stats": captureStats, "telemetry": telemetry,
		"input_quality": analyze.RenderQuality("host", m.opts.Checksums, m.rejected, m.flowsMarked), "content": m.an.Content(),
		"scope": "Initial messages only; capture loss may be reported at shutdown"}
	order := map[string][]string{"summary.counts": m.counts.order, "summary.protocols": m.protocols.order, "summary.apps": m.apps.order,
		"summary.risks": m.risks.order, "summary.policy": m.policyCounts.order, "summary.capture_stats": statsOrder,
		"summary.telemetry.counters": telemetryOrder["counters"], "summary.telemetry.histograms": telemetryOrder["histograms"]}
	return Event{Kind: "summary", Fields: fields, Order: order}
}
