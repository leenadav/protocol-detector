package session

import (
	"container/list"
	"fmt"
	"sort"
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/errs"
	"github.com/leenadav/protocol-detector/go/internal/reassembly"
	"github.com/leenadav/protocol-detector/go/internal/transport"
)

// Observation modes (D05).
const (
	ModeHandshake  = "handshake"
	ModeAsymmetric = "asymmetric"
	ModeMidstream  = "midstream"
)

// Reason sentences and messages shared verbatim with the Python reference.
const (
	ReasonTrackingEnded = "Tracking ended before initial message completed"
	ReasonCaptureEnded  = "Capture ended before initial message completed"
	ReasonRST           = "Observed RST before initial message completed; reset not endpoint-validated"
	ReasonIdle          = "Idle timeout before initial message completed"
	ReasonIdleUDP       = "Idle timeout"
	ReasonBothFIN       = "Both TCP directions closed with FIN"
	ReasonFIN           = "Observed contiguous TCP FIN before initial message completed"
	ReasonRestart       = "Connection restarted with an observed SYN after a midstream observation"
	ReasonTruncated     = "Capture record truncated; stream bytes missing"
	// SEC-SESS-1 (PRO-398, Go only): a connection whose handshake did not complete, or a UDP flow with no decision
	// yet, is evicted when its separate budget is full; one that reaches the short half-open timeout ends with the
	// idle reasons above.
	ReasonHalfOpenEvicted = "Half-open budget full; oldest unestablished state evicted"
)

// Half-open defaults (SEC-SESS-1): when Options leave them zero, at most three quarters of a table may be half-open,
// and a half-open state lives DefaultHalfOpenTimeout seconds (never longer than the idle timeout).
const DefaultHalfOpenTimeout = 5.0

func defaultHalfOpen(limit int) int {
	n := limit - limit/4
	if n < 1 {
		n = 1
	}
	return n
}

// State is the tracker's view of one TCP connection or UDP flow (Python Analyzer.tracked / udp_flows).
type State struct {
	Transport    string
	Client       transport.Endpoint
	Server       transport.Endpoint
	ISN          uint32
	HasISN       bool
	ServerISN    uint32
	Time, Start  float64
	Packets      int
	Bytes        map[transport.Endpoint]int
	Ready        bool
	FIN          map[transport.Endpoint]int
	Mode         string
	Input        map[string]int
	InputOrder   []string // the kinds of Input in first-seen order (the reference's dict order)
	reportedSeen map[transport.Endpoint]snapshot
	// Decision timing (P2): when the flow was first identified and when its label last changed.
	FirstDecision float64
	HasFirst      bool
	StableAt      float64
	Label         Label
	HasLabel      bool
	// UDP flows: the flow's observation and the first identified (or latest) observation per direction.
	Observation  *contracts.Observation
	Observations map[transport.Endpoint]*contracts.Observation
	// order is the table insertion order: the reference walks its tables in insertion order when several
	// states expire or finish together, so records come out in that order.
	order uint64
	// halfOpen is the state's element in its table's half-open queue (oldest first), nil once the TCP handshake
	// completed (Ready) or the UDP flow was decided (identified or invalidated), and for midstream connections.
	halfOpen *list.Element
}

// inOrder returns the keys of a state table in insertion order.
func inOrder(table map[Key]*State) []Key {
	keys := make([]Key, 0, len(table))
	for key := range table {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return table[keys[i]].order < table[keys[j]].order })
	return keys
}

// Decided records an identification at the tracker's current time (Python Analyzer._decided).
func (t *Tracker) Decided(state *State, label Label) {
	if !state.HasFirst {
		state.FirstDecision, state.HasFirst = t.now, true
	}
	if !state.HasLabel || state.Label != label {
		state.Label, state.HasLabel, state.StableAt = label, true, t.now
	}
}

// Now is the tracker's current capture time.
func (t *Tracker) Now() float64 { return t.now }

// IdleTimeout and MaxUDPFlows are the resolved limits (MaxUDPFlows -1 already replaced by MaxConnections).
func (t *Tracker) IdleTimeout() float64 { return t.opts.IdleTimeout }
func (t *Tracker) MaxUDPFlows() int     { return t.opts.MaxUDPFlows }

type snapshot struct {
	contiguous, pending int
	next                uint32
	valid               bool
	generation          int
}

// Closed is what the tracker reports when tracking of a connection or flow ends.
type Closed struct {
	State     *State
	Reason    string
	End       float64
	Delivered map[transport.Endpoint]int  // contiguous bytes handed to each direction's sink
	Stored    map[transport.Endpoint]int  // bytes each direction's window retained (Stream.stored)
	Sinks     map[transport.Endpoint]Sink // the directions' sinks (nil when no connection was opened)
}

// Options configure a Tracker like the Python Analyzer's constructor arguments that concern tracking.
type Options struct {
	MaxConnections int
	ByteLimit      int
	IdleTimeout    float64
	MaxUDPFlows    int // -1: same as MaxConnections
	Observation    string
	Compact        bool
	// SEC-SESS-1: MaxHalfOpen bounds the TCP connections whose handshake is not complete (a part of MaxConnections),
	// MaxHalfOpenUDP the UDP flows with no decision yet (a part of MaxUDPFlows), and HalfOpenTimeout how long either
	// may stay unestablished: TCP from its SYN, UDP since its last datagram. Zero selects the defaults.
	MaxHalfOpen     int
	MaxHalfOpenUDP  int
	HalfOpenTimeout float64
}

// Tracker ports Analyzer.process for TCP and the flow table for UDP; verdicts are not its concern.
type Tracker struct {
	opts     Options
	manager  *Manager
	tracked  map[Key]*State
	udpFlows map[Key]*State
	now      float64
	nextExp  float64
	Counts   map[string]int
	onClosed func(Closed)
	// Correlate, when set, runs after a data segment was fed and its identifications recorded, before the
	// direction's FIN is applied (Python Analyzer._correlate_* between feed and finish_direction). It returns the
	// endpoints whose observation it changed, so their next segment reports a change as Python's snapshot does.
	Correlate func(state *State, source transport.Endpoint) []transport.Endpoint
	factory   func() Sink
	gen       int
	created   uint64
	// Adapter hooks (all optional). Retired runs for each direction when tracking of its connection ends, client
	// first, after the sink was retired (Python on_retire). Classified names the sink whose observation is the
	// packet's classification (Analyzer.last_classification) at the moment Python reads it. Evidence renders the
	// legacy per-family table appended to a data segment's message.
	Retired func(source, destination transport.Endpoint, sink Sink)
	// Retiring is the state of the connection Drop is retiring, nil outside Drop and for an untracked key.
	Retiring   *State
	Classified func(sink Sink)
	Evidence   func(sink Sink) string
	// LastServer is the server endpoint of the packet in progress when tracking knows it (Analyzer.last_server).
	LastServer *transport.Endpoint
	// Half-open queues (SEC-SESS-1), oldest first; each element's value is the state's Key.
	halfOpenTCP, halfOpenUDP *list.List
}

// NewTracker validates the options like the Python constructor.
func NewTracker(opts Options, factory func() Sink, onClosed func(Closed)) (*Tracker, error) {
	if opts.Observation == "" {
		opts.Observation = ModeHandshake
	}
	if opts.Observation != ModeHandshake && opts.Observation != ModeAsymmetric && opts.Observation != ModeMidstream {
		return nil, errs.New(errs.Invalid, errs.ScopeCapture, "observation must be one of handshake, asymmetric, midstream")
	}
	if opts.MaxUDPFlows < 0 {
		opts.MaxUDPFlows = opts.MaxConnections
	}
	if opts.MaxUDPFlows > 65536 {
		return nil, errs.New(errs.Invalid, errs.ScopeCapture, "Invalid UDP flow table limit")
	}
	if opts.MaxHalfOpen < 0 || opts.MaxHalfOpen > opts.MaxConnections || opts.MaxHalfOpenUDP < 0 ||
		opts.MaxHalfOpenUDP > opts.MaxUDPFlows || opts.HalfOpenTimeout < 0 || opts.HalfOpenTimeout != opts.HalfOpenTimeout {
		return nil, errs.New(errs.Invalid, errs.ScopeCapture, "Invalid half-open limit")
	}
	if opts.MaxHalfOpen == 0 {
		opts.MaxHalfOpen = defaultHalfOpen(opts.MaxConnections)
	}
	if opts.MaxHalfOpenUDP == 0 {
		opts.MaxHalfOpenUDP = defaultHalfOpen(opts.MaxUDPFlows)
	}
	if opts.HalfOpenTimeout == 0 {
		opts.HalfOpenTimeout = DefaultHalfOpenTimeout
	}
	if opts.HalfOpenTimeout > opts.IdleTimeout {
		opts.HalfOpenTimeout = opts.IdleTimeout
	}
	interval := 0.0
	if opts.Compact {
		interval = 1
	}
	manager, err := NewManager(opts.ByteLimit, opts.MaxConnections, opts.IdleTimeout, factory, opts.Compact, interval)
	if err != nil {
		return nil, err
	}
	return &Tracker{opts: opts, manager: manager, tracked: map[Key]*State{}, udpFlows: map[Key]*State{}, nextExp: -1e308,
		Counts: map[string]int{}, onClosed: onClosed, factory: factory, halfOpenTCP: list.New(), halfOpenUDP: list.New()}, nil
}

// Manager exposes the connection table (tests and the M4 replay read stream counters through it).
func (t *Tracker) Manager() *Manager { return t.manager }

// Tables reports the sizes of the tracked, connection and UDP flow tables.
func (t *Tracker) Tables() (tracked, connections, flows int) {
	return len(t.tracked), len(t.manager.Connections), len(t.udpFlows)
}

// Tracked returns the state of the connection or flow the endpoints belong to, if any.
func (t *Tracker) Tracked(a, b transport.Endpoint) *State {
	if s, ok := t.tracked[KeyOf(a, b)]; ok {
		return s
	}
	return t.udpFlows[KeyOf(a, b)]
}

// TracksTCP reports whether a TCP connection with this key is tracked (key in Analyzer.tracked).
func (t *Tracker) TracksTCP(key Key) bool { _, ok := t.tracked[key]; return ok }

// SYNRetransmission reports whether Process at now would take this bare SYN as a retransmission of the tracked
// connection's SYN (same client, same ISN, no FIN or data, not expired: idle, or half-open past HalfOpenTimeout):
// the same connection, so an owner must not restart the tuple's generation for it. A Go-only refinement of the reference coordinator, which
// restarts on every bare SYN of a tracked tuple (Codex PRO-18 P2).
func (t *Tracker) SYNRetransmission(now float64, p *transport.TCP) bool {
	state := t.tracked[KeyOf(p.Source, p.Destination)]
	if state == nil || p.Flags&(transport.SYN|transport.ACK|transport.FIN) != transport.SYN || len(p.Payload) > 0 {
		return false
	}
	if now < t.now {
		now = t.now
	}
	return state.Client == p.Source && state.HasISN && state.ISN == p.Sequence && !t.expired(state, now)
}

// HalfOpen reports the resolved half-open limits and timeout, and how many TCP and UDP states are half-open now.
func (t *Tracker) HalfOpen() (maxTCP, maxUDP int, timeout float64, tcp, udp int) {
	return t.opts.MaxHalfOpen, t.opts.MaxHalfOpenUDP, t.opts.HalfOpenTimeout, t.halfOpenTCP.Len(), t.halfOpenUDP.Len()
}

// expired reports whether a state reached its timeout at now: a half-open TCP connection HalfOpenTimeout after
// its SYN (nothing it receives while half-open extends that), a half-open UDP flow HalfOpenTimeout after its last
// datagram, and any other state IdleTimeout after its last packet.
func (t *Tracker) expired(state *State, now float64) bool {
	if state.halfOpen != nil {
		if state.Transport == "tcp" {
			return now-state.Start >= t.opts.HalfOpenTimeout
		}
		return now-state.Time >= t.opts.HalfOpenTimeout
	}
	return now-state.Time >= t.opts.IdleTimeout
}

// queue returns the half-open queue of a state's table.
func (t *Tracker) queue(state *State) *list.List {
	if state.Transport == "tcp" {
		return t.halfOpenTCP
	}
	return t.halfOpenUDP
}

// settle takes a state out of its half-open queue: its handshake completed, it was decided, or it left the table.
func (t *Tracker) settle(state *State) {
	if state != nil && state.halfOpen != nil {
		t.queue(state).Remove(state.halfOpen)
		state.halfOpen = nil
	}
}

// evictHalfOpen retires the oldest half-open state of a table when the half-open budget is full or the table
// itself is full; established connections and decided flows are never evicted for a new state. It runs before
// the new state is allocated.
func (t *Tracker) evictHalfOpen(queue *list.List, size, limit, halfLimit int, udp bool) {
	if queue.Len() == 0 || (queue.Len() < halfLimit && size < limit) {
		return
	}
	key := queue.Front().Value.(Key)
	if udp {
		flow := t.udpFlows[key]
		t.settle(flow)
		delete(t.udpFlows, key)
		t.Counts["udp_half_open_evicted"]++
		t.closed(flow, ReasonHalfOpenEvicted, nil, nil)
		return
	}
	t.Counts["half_open_evicted"]++
	t.Drop(key, ReasonHalfOpenEvicted)
}

func (t *Tracker) closed(state *State, reason string, delivered map[transport.Endpoint]int, sinks map[transport.Endpoint]Sink) {
	t.closedWith(state, reason, delivered, nil, sinks)
}

func (t *Tracker) closedWith(state *State, reason string, delivered, stored map[transport.Endpoint]int, sinks map[transport.Endpoint]Sink) {
	if t.onClosed != nil {
		t.onClosed(Closed{State: state, Reason: reason, End: t.now, Delivered: delivered, Stored: stored, Sinks: sinks})
	}
}

// TrackedTCP are the tracked TCP connections in table order (Analyzer.tracked.values()).
func (t *Tracker) TrackedTCP() []*State {
	out := make([]*State, 0, len(t.tracked))
	for _, key := range inOrder(t.tracked) {
		out = append(out, t.tracked[key])
	}
	return out
}

// Drop ends tracking of a connection: each direction's sink is ended with the reason.
func (t *Tracker) Drop(key Key, reason string) {
	connection := t.manager.Connections[key]
	state := t.tracked[key]
	t.settle(state)
	delete(t.tracked, key)
	// Lets Retired consumers read the per-direction byte counts of the state being retired (Analyzer.retiring).
	t.Retiring = state
	defer func() { t.Retiring = nil }()
	var delivered, stored map[transport.Endpoint]int
	var sinks map[transport.Endpoint]Sink
	if connection != nil {
		delivered, stored = map[transport.Endpoint]int{}, map[transport.Endpoint]int{}
		sinks = map[transport.Endpoint]Sink{}
		// Client first, as the reference's direction table is ordered.
		order := []transport.Endpoint{key[0], key[1]}
		if state != nil {
			order = []transport.Endpoint{state.Client, state.Server}
		}
		for i, endpoint := range order {
			d := connection.Directions[endpoint]
			if d == nil {
				continue
			}
			d.Sink.Retire(reason)
			if t.Retired != nil {
				t.Retired(endpoint, order[len(order)-1-i], d.Sink)
			}
			delivered[endpoint] = d.Stream.Delivered()
			stored[endpoint] = d.Stream.Stored()
			sinks[endpoint] = d.Sink
		}
		t.manager.release(key)
	}
	if state != nil {
		t.closedWith(state, reason, delivered, stored, sinks)
	}
}

func (t *Tracker) reject(key Key, source transport.Endpoint, reason string) string {
	if c := t.manager.Connections[key]; c != nil {
		c.Directions[source].Sink.Invalidate(reason)
		if t.Classified != nil {
			t.Classified(c.Directions[source].Sink)
		}
	}
	t.Drop(key, reason)
	return "INVALIDATED: " + reason
}

// Reset forgets every connection and flow without ending them: a capture gap retracts active observations and
// requires a newly observed start; it is not a clean end, so no session record is produced (analyze.capture_gap).
func (t *Tracker) Reset() {
	t.tracked, t.udpFlows = map[Key]*State{}, map[Key]*State{}
	t.halfOpenTCP.Init()
	t.halfOpenUDP.Init()
	for key := range t.manager.Connections {
		t.manager.release(key)
	}
}

// Finish releases all tracking with the reason (1..256 characters).
func (t *Tracker) Finish(reason string) error {
	if reason == "" || len(reason) > 256 {
		return errs.New(errs.Invalid, errs.ScopeCapture, "End reason must contain 1..256 characters")
	}
	for _, key := range inOrder(t.tracked) {
		t.Drop(key, reason)
	}
	for _, key := range inOrder(t.udpFlows) {
		flow := t.udpFlows[key]
		t.settle(flow)
		delete(t.udpFlows, key)
		t.closed(flow, reason, nil, nil)
	}
	return nil
}

// idle returns the keys of the states that reached the idle timeout, in table (insertion) order.
func (t *Tracker) idle(table map[Key]*State) []Key {
	var keys []Key
	for key, state := range table {
		if t.expired(state, t.now) {
			keys = append(keys, key)
		}
	}
	if len(keys) > 1 {
		sort.Slice(keys, func(i, j int) bool { return table[keys[i]].order < table[keys[j]].order })
	}
	return keys
}

// Expire advances time and retires idle states, then idle connections.
func (t *Tracker) Expire(timestamp float64) {
	if timestamp > t.now {
		t.now = timestamp
	}
	if t.now < t.nextExp {
		return
	}
	t.nextExp = t.now
	if t.opts.Compact {
		t.nextExp = t.now + 1
	}
	// This runs for every packet, so the tables are only put in order when something expired: the states that
	// expire, and the table order in which they are retired, are the reference's.
	for _, key := range t.idle(t.tracked) {
		if state := t.tracked[key]; state != nil && t.expired(state, t.now) {
			if state.halfOpen != nil {
				t.Counts["half_open_timeout"]++ // the session record keeps the reference's idle reason
			}
			t.Drop(key, ReasonIdle)
		}
	}
	for _, key := range t.idle(t.udpFlows) {
		if flow := t.udpFlows[key]; flow != nil && t.expired(flow, t.now) {
			if flow.halfOpen != nil {
				t.Counts["udp_half_open_timeout"]++
			}
			t.settle(flow)
			delete(t.udpFlows, key)
			t.closed(flow, ReasonIdleUDP, nil, nil)
		}
	}
	t.manager.Expire(t.now)
}

// NoteInput marks a flow whose packet was rejected or suspect (D06); a truncated TCP record ends it.
func (t *Tracker) NoteInput(kind string, endpoints *[2]transport.Endpoint) bool {
	if endpoints == nil {
		return false
	}
	key := KeyOf(endpoints[0], endpoints[1])
	state := t.tracked[key]
	if state == nil {
		state = t.udpFlows[key]
	}
	if state == nil {
		return false
	}
	if state.Input == nil {
		state.Input = map[string]int{}
	}
	if _, seen := state.Input[kind]; !seen {
		state.InputOrder = append(state.InputOrder, kind)
	}
	state.Input[kind]++
	if kind == transport.KindTruncated {
		if _, tcp := t.tracked[key]; tcp {
			t.Drop(key, ReasonTruncated)
		}
	}
	return true
}

// ProcessUDP ports Analyzer._udp: the caller inspected the datagram (obs may be nil when no engine runs);
// the flow keeps the first identification, never revives after an invalidation, and records decisions.
func (t *Tracker) ProcessUDP(timestamp float64, p *transport.UDP, obs *contracts.Observation) string {
	t.Expire(timestamp)
	key := KeyOf(p.Source, p.Destination)
	flow := t.udpFlows[key]
	if flow == nil {
		t.evictHalfOpen(t.halfOpenUDP, len(t.udpFlows), t.opts.MaxUDPFlows, t.opts.MaxHalfOpenUDP, true)
		if len(t.udpFlows) >= t.opts.MaxUDPFlows {
			t.Counts["udp_flow_limit"]++
		} else {
			flow = &State{Transport: "udp", Client: p.Source, Server: p.Destination, Start: t.now, Time: t.now, Ready: true,
				Bytes: map[transport.Endpoint]int{}, Mode: "", Observation: obs, Observations: map[transport.Endpoint]*contracts.Observation{}}
			t.created++
			flow.order = t.created
			t.udpFlows[key] = flow
			flow.halfOpen = t.halfOpenUDP.PushBack(key)
		}
	}
	if flow != nil {
		flow.Time = t.now
		flow.Packets++
		flow.Bytes[p.Source] += len(p.Payload)
		if obs != nil {
			latest := obs
			previous := flow.Observations[p.Source]
			switch {
			case latest.Status == contracts.Invalidated:
				// The flow is withdrawn, including a peer identification retained before the conflict; otherwise
				// the session verdict could select that peer and revive the invalidated session (Python
				// Analyzer._udp, the R1 repair of Codex PR #25).
				flow.Observation = latest
				for endpoint := range flow.Observations {
					delete(flow.Observations, endpoint)
				}
				flow.Observations[p.Source] = latest
			case flow.Observation != nil && flow.Observation.Status == contracts.Invalidated,
				previous != nil && previous.Status == contracts.Invalidated:
				// nothing after an invalidation revives the flow
			default:
				if flow.Observation == nil || flow.Observation.Status != contracts.Identified {
					flow.Observation = latest
				}
				if previous == nil || previous.Status != contracts.Identified {
					flow.Observations[p.Source] = latest
				}
			}
			if latest.Status == contracts.Identified && flow.Observation.Status != contracts.Invalidated {
				proto := ""
				if latest.ApplicationProtocol != nil {
					proto = *latest.ApplicationProtocol
				} else if latest.Encryption != nil {
					proto = *latest.Encryption
				}
				label := Label{Protocol: proto}
				if latest.Application != nil {
					label.Application, label.HasApp = *latest.Application, true
				}
				t.Decided(flow, label)
			}
			if flow.Observation.Status == contracts.Identified || flow.Observation.Status == contracts.Invalidated || flow.HasFirst {
				t.settle(flow) // decided: no longer half-open
			}
		}
	}
	status, proto, reason := "", "unidentified", ""
	if obs != nil {
		status, reason = string(obs.Status), obs.Reason
		if obs.ApplicationProtocol != nil {
			proto = *obs.ApplicationProtocol
		} else if obs.Encryption != nil {
			proto = *obs.Encryption
		}
	}
	server := p.Destination
	if flow != nil {
		server = flow.Server
	}
	t.LastServer = &server
	return fmt.Sprintf("UDP %s -> %s | %s | %s | %s", p.Source, p.Destination, strings.ToUpper(status), proto, reason)
}

func newState(client, server transport.Endpoint, now float64) *State {
	return &State{Transport: "tcp", Client: client, Server: server, Time: now, Start: now, Bytes: map[transport.Endpoint]int{},
		FIN: map[transport.Endpoint]int{}, Mode: ModeHandshake, reportedSeen: map[transport.Endpoint]snapshot{}}
}

// Process handles one TCP segment and returns the Python adapter's message for it (the part before
// the first " | " is compared by the differential harness).
func (t *Tracker) Process(timestamp float64, p *transport.TCP) string {
	t.LastServer = nil
	t.Expire(timestamp)
	source, destination := p.Source, p.Destination
	key := KeyOf(source, destination)
	state := t.tracked[key]
	if state != nil {
		server := state.Server
		t.LastServer = &server
		state.Packets++
		if len(p.Payload) > 0 {
			state.Bytes[source] += len(p.Payload)
		}
	}
	flags := p.Flags
	if flags&transport.RST != 0 {
		t.Drop(key, ReasonRST)
		return "RESET: tracking stopped (RST not endpoint-validated)"
	}
	if flags&transport.SYN != 0 && flags&transport.ACK == 0 {
		if flags&transport.FIN != 0 || len(p.Payload) > 0 {
			t.Drop(key, ReasonTrackingEnded)
			return "UNSUPPORTED: SYN with FIN or data (Fast Open)"
		}
		if state != nil && state.Client == source && state.HasISN && state.ISN == p.Sequence {
			// SEC-SESS-1: a retransmitted SYN is the same connection but extends neither its idle time nor its
			// half-open lifetime, so a repeated SYN cannot keep a table slot alive.
			return "SYN retransmission"
		}
		t.Drop(key, ReasonTrackingEnded)
		t.evictHalfOpen(t.halfOpenTCP, len(t.tracked), t.opts.MaxConnections, t.opts.MaxHalfOpen, false)
		if len(t.tracked) >= t.opts.MaxConnections {
			return "LIMIT: too many tracked connections"
		}
		state = newState(source, destination, t.now)
		state.ISN, state.HasISN, state.Packets = p.Sequence, true, 1
		t.created++
		state.order = t.created
		t.tracked[key] = state
		state.halfOpen = t.halfOpenTCP.PushBack(key)
		server := destination // copied here, so a refused SYN does not move destination to the heap
		t.LastServer = &server
		return "SYN: waiting for SYN-ACK"
	}
	if state == nil {
		if t.opts.Observation != ModeMidstream || len(p.Payload) == 0 || flags&transport.SYN != 0 || flags&transport.ACK == 0 || flags&transport.URG != 0 {
			return "SKIP: connection beginning not observed"
		}
		if len(t.tracked) >= t.opts.MaxConnections {
			return "LIMIT: too many tracked connections"
		}
		if err := t.manager.Open(source, destination, p.Sequence, p.Ack, t.now); err != nil {
			return "INVALIDATED: " + detail(err)
		}
		state = newState(source, destination, t.now)
		state.Ready, state.Mode, state.Packets = true, ModeMidstream, 1
		state.Bytes[source] = len(p.Payload)
		t.created++
		state.order = t.created
		t.tracked[key] = state
		server := destination // copied here, so a refused SYN does not move destination to the heap
		t.LastServer = &server
		t.Counts["midstream_connections"]++
	}
	state.Time = t.now
	if c := t.manager.Connections[key]; c != nil {
		c.LastSeen = t.now
	}
	if flags&transport.SYN != 0 && state.Mode == ModeMidstream {
		t.Drop(key, ReasonRestart)
		return t.Process(t.now, p)
	}
	if flags&transport.SYN != 0 {
		if source == state.Client || flags&transport.ACK == 0 || flags&transport.FIN != 0 || p.Ack != state.ISN+1 || len(p.Payload) > 0 {
			return t.reject(key, source, "inconsistent or unsupported SYN-ACK")
		}
		if state.Ready {
			if p.Sequence != state.ServerISN {
				return t.reject(key, source, "changed server sequence")
			}
			return "SYN-ACK retransmission"
		}
		if err := t.manager.Open(destination, source, state.ISN+1, p.Sequence+1, t.now); err != nil {
			t.Drop(key, ReasonTrackingEnded)
			return "INVALIDATED: " + detail(err)
		}
		state.Ready, state.ServerISN = true, p.Sequence
		t.settle(state)
		return "Tracking both directions (SYN/SYN-ACK observed)"
	}
	if !state.Ready {
		if t.opts.Observation != ModeAsymmetric || source != state.Client || len(p.Payload) == 0 || flags&transport.ACK == 0 {
			return "SKIP: SYN-ACK not observed"
		}
		if err := t.manager.Open(source, destination, state.ISN+1, p.Ack, t.now); err != nil {
			t.Drop(key, ReasonTrackingEnded)
			return "INVALIDATED: " + detail(err)
		}
		state.Ready, state.Mode, state.ServerISN = true, ModeAsymmetric, p.Ack-1
		t.settle(state)
		t.Counts["asymmetric_connections"]++
	}
	if flags&transport.URG != 0 || flags&transport.ACK == 0 {
		return t.reject(key, source, "urgent data or missing ACK unsupported")
	}
	connection := t.manager.Connections[key]
	if connection == nil {
		t.Drop(key, ReasonTrackingEnded)
		return "INVALIDATED: Unknown connection: first data sequences must be established"
	}
	stream := connection.Directions[source].Stream
	offset := int((uint64(p.Sequence) + reassembly.Modulus - uint64(stream.First())) % reassembly.Modulus)
	end := offset + len(p.Payload)
	if t.opts.Compact && offset >= reassembly.Modulus/2 {
		end -= reassembly.Modulus
		if end < 0 && flags&transport.FIN != 0 {
			return t.reject(key, source, "FIN outside unambiguous retained-origin range")
		}
	}
	previousFIN, hadFIN := state.FIN[source]
	if len(p.Payload) > 0 && hadFIN && end > previousFIN {
		return t.reject(key, source, "data beyond observed FIN")
	}
	if flags&transport.FIN != 0 {
		if (end > stream.Limit() && !t.opts.Compact) || (hadFIN && previousFIN != end) {
			return t.reject(key, source, "inconsistent FIN or stream limit")
		}
		if stream.HighestEnd() > end {
			return t.reject(key, source, "stored data beyond FIN")
		}
		state.FIN[source] = end
	}
	changed, err := t.manager.Feed(source, destination, p.Sequence, p.Payload, t.now)
	if err != nil {
		if t.Classified != nil {
			t.Classified(connection.Directions[source].Sink)
		}
		t.Drop(key, ReasonTrackingEnded)
		return "INVALIDATED: " + detail(err)
	}
	// The reference's snapshot holds the direction's classification and legacy table as they were when the
	// segment was fed, before any cross-direction correlation; a FIN that ends the direction re-reads both.
	evidence := ""
	capture := func() {
		if t.Classified != nil {
			t.Classified(connection.Directions[source].Sink)
		}
		if t.Evidence != nil && !t.opts.Compact {
			// Only a non-compact message prints the per-family table; building it for every packet of a compact
			// tracker (live capture, the presentation analysis) was most of the per-packet cost under load.
			evidence = t.Evidence(connection.Directions[source].Sink)
		}
	}
	capture()
	if decider, ok := connection.Directions[source].Sink.(Decider); ok {
		for _, label := range decider.TakeIdentified() {
			t.Decided(state, label)
		}
	}
	var correlated []transport.Endpoint
	if t.Correlate != nil {
		correlated = t.Correlate(state, source)
	}
	if final, ok := state.FIN[source]; ok && final <= stream.Limit() && stream.Contiguous() == final {
		if t.manager.FinishDirection(source, destination, ReasonFIN) {
			changed = true
		}
		capture()
	}
	t.gen++
	current := snapshot{contiguous: stream.Contiguous(), pending: stream.Pending(), next: stream.NextSequence(), valid: true}
	previous := state.reportedSeen[source]
	if !previous.valid || previous.contiguous != current.contiguous || previous.pending != current.pending || previous.next != current.next {
		changed = true
	}
	state.reportedSeen[source] = current
	for _, endpoint := range correlated {
		previous := state.reportedSeen[endpoint]
		previous.valid = false // the observation changed outside this endpoint's own segments
		state.reportedSeen[endpoint] = previous
	}
	message := "No new contiguous data"
	if !t.opts.Compact && changed && (current.contiguous > 0 || current.pending > 0) {
		message = fmt.Sprintf("%s -> %s | contiguous=%d pending=%d", source, destination, current.contiguous, current.pending)
		if t.Evidence != nil {
			message += " | " + evidence
		}
	}
	if len(state.FIN) == 2 {
		all := true
		for endpoint, final := range state.FIN {
			want := final
			if t.opts.Compact && final > stream.Limit() {
				want = stream.Limit()
			}
			if connection.Directions[endpoint].Stream.Contiguous() != want {
				all = false
			}
		}
		if all {
			t.Drop(key, ReasonBothFIN)
			message += " | CLOSED: both FIN boundaries reached"
		}
	}
	return message
}

func detail(err error) string {
	if e, ok := err.(*errs.Error); ok {
		return e.Detail
	}
	return err.Error()
}
