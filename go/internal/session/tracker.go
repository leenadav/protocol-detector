package session

import (
	"fmt"

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
)

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
	reportedSeen map[transport.Endpoint]snapshot
}

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
	Delivered map[transport.Endpoint]int // contiguous bytes handed to each direction's sink
}

// Options configure a Tracker like the Python Analyzer's constructor arguments that concern tracking.
type Options struct {
	MaxConnections int
	ByteLimit      int
	IdleTimeout    float64
	MaxUDPFlows    int // -1: same as MaxConnections
	Observation    string
	Compact        bool
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
	factory  func() Sink
	gen      int
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
	interval := 0.0
	if opts.Compact {
		interval = 1
	}
	manager, err := NewManager(opts.ByteLimit, opts.MaxConnections, opts.IdleTimeout, factory, opts.Compact, interval)
	if err != nil {
		return nil, err
	}
	return &Tracker{opts: opts, manager: manager, tracked: map[Key]*State{}, udpFlows: map[Key]*State{}, nextExp: -1e308,
		Counts: map[string]int{}, onClosed: onClosed, factory: factory}, nil
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

func (t *Tracker) closed(state *State, reason string, delivered map[transport.Endpoint]int) {
	if t.onClosed != nil {
		t.onClosed(Closed{State: state, Reason: reason, End: t.now, Delivered: delivered})
	}
}

// Drop ends tracking of a connection: each direction's sink is ended with the reason.
func (t *Tracker) Drop(key Key, reason string) {
	connection := t.manager.Connections[key]
	state := t.tracked[key]
	delete(t.tracked, key)
	var delivered map[transport.Endpoint]int
	if connection != nil {
		delivered = map[transport.Endpoint]int{}
		for endpoint, d := range connection.Directions {
			d.Sink.Retire(reason)
			delivered[endpoint] = d.Stream.Delivered()
		}
		t.manager.release(key)
	}
	if state != nil {
		t.closed(state, reason, delivered)
	}
}

func (t *Tracker) reject(key Key, source transport.Endpoint, reason string) string {
	if c := t.manager.Connections[key]; c != nil {
		c.Directions[source].Sink.Invalidate(reason)
	}
	t.Drop(key, reason)
	return "INVALIDATED: " + reason
}

// Finish releases all tracking with the reason (1..256 characters).
func (t *Tracker) Finish(reason string) error {
	if reason == "" || len(reason) > 256 {
		return errs.New(errs.Invalid, errs.ScopeCapture, "End reason must contain 1..256 characters")
	}
	for key := range t.tracked {
		t.Drop(key, reason)
	}
	for key, flow := range t.udpFlows {
		delete(t.udpFlows, key)
		t.closed(flow, reason, nil)
	}
	return nil
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
	for key, state := range t.tracked {
		if t.now-state.Time >= t.opts.IdleTimeout {
			t.Drop(key, ReasonIdle)
		}
	}
	for key, flow := range t.udpFlows {
		if t.now-flow.Time >= t.opts.IdleTimeout {
			delete(t.udpFlows, key)
			t.closed(flow, ReasonIdleUDP, nil)
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
	state.Input[kind]++
	if kind == transport.KindTruncated {
		if _, tcp := t.tracked[key]; tcp {
			t.Drop(key, ReasonTruncated)
		}
	}
	return true
}

// ProcessUDP counts a datagram on its flow; inspection belongs to the datagram engine (M4).
func (t *Tracker) ProcessUDP(timestamp float64, p *transport.UDP) string {
	t.Expire(timestamp)
	key := KeyOf(p.Source, p.Destination)
	flow := t.udpFlows[key]
	if flow == nil {
		if len(t.udpFlows) >= t.opts.MaxUDPFlows {
			t.Counts["udp_flow_limit"]++
		} else {
			flow = &State{Transport: "udp", Client: p.Source, Server: p.Destination, Start: t.now, Time: t.now, Ready: true,
				Bytes: map[transport.Endpoint]int{}, Mode: "datagram"}
			t.udpFlows[key] = flow
		}
	}
	if flow != nil {
		flow.Time = t.now
		flow.Packets++
		flow.Bytes[p.Source] += len(p.Payload)
	}
	return fmt.Sprintf("UDP %s -> %s", p.Source, p.Destination)
}

func newState(client, server transport.Endpoint, now float64) *State {
	return &State{Transport: "tcp", Client: client, Server: server, Time: now, Start: now, Bytes: map[transport.Endpoint]int{},
		FIN: map[transport.Endpoint]int{}, Mode: ModeHandshake, reportedSeen: map[transport.Endpoint]snapshot{}}
}

// Process handles one TCP segment and returns the Python adapter's message for it (the part before
// the first " | " is compared by the differential harness).
func (t *Tracker) Process(timestamp float64, p *transport.TCP) string {
	t.Expire(timestamp)
	source, destination := p.Source, p.Destination
	key := KeyOf(source, destination)
	state := t.tracked[key]
	if state != nil {
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
			state.Time = t.now
			if c := t.manager.Connections[key]; c != nil {
				c.LastSeen = t.now
			}
			return "SYN retransmission"
		}
		t.Drop(key, ReasonTrackingEnded)
		if len(t.tracked) >= t.opts.MaxConnections {
			return "LIMIT: too many tracked connections"
		}
		state = newState(source, destination, t.now)
		state.ISN, state.HasISN, state.Packets = p.Sequence, true, 1
		t.tracked[key] = state
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
		t.tracked[key] = state
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
		t.Drop(key, ReasonTrackingEnded)
		return "INVALIDATED: " + detail(err)
	}
	if final, ok := state.FIN[source]; ok && final <= stream.Limit() && stream.Contiguous() == final {
		if t.manager.FinishDirection(source, destination, ReasonFIN) {
			changed = true
		}
	}
	t.gen++
	current := snapshot{contiguous: stream.Contiguous(), pending: stream.Pending(), next: stream.NextSequence(), valid: true}
	previous := state.reportedSeen[source]
	if !previous.valid || previous.contiguous != current.contiguous || previous.pending != current.pending || previous.next != current.next {
		changed = true
	}
	state.reportedSeen[source] = current
	message := "No new contiguous data"
	if !t.opts.Compact && changed && (current.contiguous > 0 || current.pending > 0) {
		message = fmt.Sprintf("%s -> %s | contiguous=%d pending=%d", source, destination, current.contiguous, current.pending)
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
