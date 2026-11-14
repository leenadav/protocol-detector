package detector

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/engine"
)

// Errors returned by this package. Compare with errors.Is.
var (
	ErrInvalidConfig = errors.New("detector: invalid configuration")
	ErrAdmission     = errors.New("detector: observation admission refused (flow limit reached)")
	ErrDisabled      = errors.New("detector: observation disabled after repeated engine failures")
	ErrClosed        = errors.New("detector: flow closed")
	ErrQuarantined   = errors.New("detector: flow quarantined after an engine failure")
	ErrDirection     = errors.New("detector: invalid direction")
)

// profileFamilies are the families this slice can admit to a profile: their evidence fields are classified
// (evidence.go) and their identification is covered by this package's tests.
var profileFamilies = []string{"http", "tls", "ssh", "smtp"}

// ProfileFamilies lists the family names Config.Families may contain.
func ProfileFamilies() []string { return append([]string(nil), profileFamilies...) }

// Config is the immutable configuration of an Engine. The budgets are starting hypotheses for the lab
// (working plan section 9), not production limits.
type Config struct {
	// Families is the profile: the families whose identification this engine reports. A stream of any
	// other family ends as OutcomeOutsideProfile. Required; each name must be in ProfileFamilies.
	Families []string
	// MaxBytesPerDirection bounds the bytes inspected per direction (64..1048576).
	MaxBytesPerDirection int
	// MaxFeedsPerDirection bounds the Feed calls inspected per direction (1..1000000). It is a CPU bound,
	// not a protocol rule: a valid message split into more reads ends as OutcomeBudgetExhausted.
	MaxFeedsPerDirection int
	// MaxFlows bounds the flows admitted and not yet closed (1..1048576).
	MaxFlows int
	// PanicLimit disables admission after this many recovered engine panics (0 disables the breaker).
	PanicLimit int
}

// DefaultConfig is the lab starting profile: HTTP/1, TLS and SSH, 16 KiB and 16 reads per direction.
func DefaultConfig() Config {
	return Config{Families: []string{"http", "tls", "ssh"}, MaxBytesPerDirection: 16384, MaxFeedsPerDirection: 16,
		MaxFlows: 1024, PanicLimit: 8}
}

// Engine admits flows under one immutable configuration. It is safe for concurrent use.
type Engine struct {
	cfg        contracts.Config
	families   []string
	profile    map[string]bool // never written after New
	maxFlows   int64
	panicLimit int64

	active   atomic.Int64
	admitted atomic.Int64
	refused  atomic.Int64
	panics   atomic.Int64

	// testHook runs inside the panic boundary of every engine call (tests only; nil in production).
	testHook func(op string, d Direction)
}

// New validates c and builds an Engine.
func New(c Config) (*Engine, error) {
	if len(c.Families) == 0 {
		return nil, fmt.Errorf("%w: the profile needs at least one family", ErrInvalidConfig)
	}
	profile := map[string]bool{}
	for _, name := range c.Families {
		if !contains(profileFamilies, name) {
			return nil, fmt.Errorf("%w: family %q is not available for a profile (available: %v)", ErrInvalidConfig, name, profileFamilies)
		}
		if profile[name] {
			return nil, fmt.Errorf("%w: family %q listed twice", ErrInvalidConfig, name)
		}
		profile[name] = true
	}
	if c.MaxFlows < 1 || c.MaxFlows > 1<<20 {
		return nil, fmt.Errorf("%w: max flows must be 1..%d", ErrInvalidConfig, 1<<20)
	}
	if c.PanicLimit < 0 {
		return nil, fmt.Errorf("%w: panic limit cannot be negative", ErrInvalidConfig)
	}
	cfg := contracts.DefaultConfig()
	cfg.MaxBytes, cfg.MaxUpdates = c.MaxBytesPerDirection, c.MaxFeedsPerDirection
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	if _, err := engine.New(cfg, ""); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	return &Engine{cfg: cfg, families: append([]string(nil), c.Families...), profile: profile,
		maxFlows: int64(c.MaxFlows), panicLimit: int64(c.PanicLimit)}, nil
}

// Families returns a copy of the engine's profile.
func (e *Engine) Families() []string { return append([]string(nil), e.families...) }

// Stats is a point-in-time view of an engine's counters.
type Stats struct {
	Active, Admitted, Refused, Panics int64
	Disabled                          bool
}

// Stats reads the counters.
func (e *Engine) Stats() Stats {
	return Stats{Active: e.active.Load(), Admitted: e.admitted.Load(), Refused: e.refused.Load(),
		Panics: e.panics.Load(), Disabled: e.disabled()}
}

func (e *Engine) disabled() bool { return e.panicLimit > 0 && e.panics.Load() >= e.panicLimit }

// MaxFlowID bounds the host's flow identifier, in bytes.
const MaxFlowID = 128

// NewFlow admits one flow. id is the host's own opaque identifier, copied and bounded; the engine never
// interprets it. The flow holds an admission slot until Close.
func (e *Engine) NewFlow(id string) (*Flow, error) {
	if e.disabled() {
		e.refused.Add(1)
		return nil, ErrDisabled
	}
	for {
		n := e.active.Load()
		if n >= e.maxFlows {
			e.refused.Add(1)
			return nil, ErrAdmission
		}
		if e.active.CompareAndSwap(n, n+1) {
			break
		}
	}
	e.admitted.Add(1)
	f := &Flow{e: e, id: bounded(trimID(id))}
	for _, d := range allDirections {
		f.dirs[d].snap = initialSnapshot(d)
	}
	return f, nil
}

func trimID(id string) string {
	if len(id) > MaxFlowID {
		return id[:MaxFlowID]
	}
	return id
}

// Flow is one observed connection. Its methods may be called from several goroutines.
type Flow struct {
	e  *Engine
	id string

	mu          sync.Mutex
	dirs        [2]direction
	closed      bool
	quarantined bool
}

type direction struct {
	in   *engine.Inspector // nil before the first byte and after the direction is done
	snap DirectionSnapshot
}

// Update reports what one call changed for one direction.
type Update struct {
	Direction Direction
	// Changed is true when the direction's observation changed in this call.
	Changed bool
	Outcome Outcome
	// Done is true when the direction needs no further bytes: it decided, failed, expired or was closed.
	// An identified direction may stay not-done while the parser derives optional evidence.
	Done bool
}

// DirectionSnapshot is a detached copy of one direction's observation.
type DirectionSnapshot struct {
	Direction Direction
	Outcome   Outcome
	Reason    Reason
	// Detail is the engine's reason sentence or the name of what is not ported, bounded. Record only.
	Detail string
	// Revision increases with every published change of the engine's observation.
	Revision int
	// Family is the registry family the stream was attributed to ("" when none).
	Family              string
	ApplicationProtocol string
	Encryption          string
	Hostname            Hostname
	OfferedALPN         []string
	// OfferedALPNTruncated is true when the client offered more than MaxOfferedALPN identifiers.
	OfferedALPNTruncated bool
	Evidence             []Evidence
	// EvidenceTruncated is true when any evidence item was left out: more than MaxEvidence items, or
	// offered_alpn items beyond MaxOfferedALPN.
	EvidenceTruncated bool
	Scope             string
	// BytesFed counts every byte passed to Feed; BytesInspected the bytes the engine examined.
	BytesFed, BytesInspected int
	Done                     bool
}

// Hostname is a peer-asserted host name (SNI, HTTP Host). It is not authenticated identity, and it must be
// pseudonymized wherever the host's privacy posture requires.
type Hostname string

// Snapshot is a detached copy of a flow.
type Snapshot struct {
	ID          string
	Directions  [2]DirectionSnapshot
	Closed      bool
	Quarantined bool
}

// Direction returns the snapshot of d.
func (s Snapshot) Direction(d Direction) DirectionSnapshot {
	if !d.Valid() {
		return DirectionSnapshot{}
	}
	return s.Directions[d]
}

func initialSnapshot(d Direction) DirectionSnapshot {
	return DirectionSnapshot{Direction: d, Outcome: OutcomeDetecting, Reason: ReasonNone}
}

// Feed observes bytes the host has already read on direction d. data is borrowed for the call only.
func (f *Flow) Feed(d Direction, data []byte) (Update, error) {
	if !d.Valid() {
		return Update{}, ErrDirection
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.usable(); err != nil {
		return f.update(d, false), err
	}
	ds := &f.dirs[d]
	ds.snap.BytesFed += len(data)
	if ds.snap.Done || len(data) == 0 {
		return f.update(d, false), nil
	}
	changed := false
	if f.guard("feed", d, func() {
		if ds.in == nil {
			in, err := engine.New(f.e.cfg, "")
			if err != nil { // validated in New; kept as a typed outcome rather than a panic
				f.finish(ds, OutcomeUnsupported, ReasonNotPorted, err.Error())
				changed = true
				return
			}
			ds.in = in
		}
		changed = f.absorb(ds, ds.in.Feed(data), ReasonEngine)
	}) {
		return f.update(d, true), ErrQuarantined
	}
	return f.update(d, changed), nil
}

// EndDirection tells the engine that direction d will carry no more bytes.
func (f *Flow) EndDirection(d Direction, cause EndCause) (Update, error) {
	if !d.Valid() {
		return Update{}, ErrDirection
	}
	if !cause.Valid() {
		cause = EndAborted
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.usable(); err != nil {
		return f.update(d, false), err
	}
	ds := &f.dirs[d]
	if ds.snap.Done {
		return f.update(d, false), nil
	}
	changed := false
	if f.guard("end", d, func() { changed = f.endDirection(ds, cause.sentence(), ReasonEnded) }) {
		return f.update(d, true), ErrQuarantined
	}
	return f.update(d, changed), nil
}

// Expire ends the observation window: every direction not yet done gets its final outcome now and its
// engine state is released. The connection itself is the host's; Expire touches no socket and is safe to
// call from a timer while another goroutine is blocked writing. Later Feed calls are no-ops.
func (f *Flow) Expire() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.usable(); err != nil {
		return err
	}
	for _, d := range allDirections {
		ds := &f.dirs[d]
		if ds.snap.Done {
			continue
		}
		if f.guard("expire", d, func() { f.endDirection(ds, "Observation window expired", ReasonExpired) }) {
			return ErrQuarantined
		}
	}
	return nil
}

// Snapshot returns a detached copy of the flow.
func (f *Flow) Snapshot() Snapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snapshot()
}

// Close releases all engine state and the flow's admission slot, and returns the final snapshot. A
// direction that had not decided ends as OutcomeIncomplete with ReasonClosed. Close is idempotent.
func (f *Flow) Close() Snapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		for _, d := range allDirections {
			ds := &f.dirs[d]
			switch {
			case ds.snap.Done:
			case ds.snap.Outcome == OutcomeIdentified: // identified, still deriving optional evidence: keep it
				ds.snap.Done = true
			default:
				f.finish(ds, OutcomeIncomplete, ReasonClosed, "")
			}
			ds.in = nil
		}
		f.e.active.Add(-1)
	}
	return f.snapshot()
}

func (f *Flow) usable() error {
	if f.quarantined {
		return ErrQuarantined
	}
	if f.closed {
		return ErrClosed
	}
	return nil
}

func (f *Flow) update(d Direction, changed bool) Update {
	s := f.dirs[d].snap
	return Update{Direction: d, Changed: changed, Outcome: s.Outcome, Done: s.Done}
}

// guard runs fn inside the panic boundary. On a panic the flow is quarantined and guard returns true.
func (f *Flow) guard(op string, d Direction, fn func()) (panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			// The panic value is dropped on purpose: it may quote input bytes.
			panicked = true
			f.quarantine()
		}
	}()
	if f.e.testHook != nil {
		f.e.testHook(op, d)
	}
	fn()
	return false
}

func (f *Flow) quarantine() {
	f.quarantined = true
	f.e.panics.Add(1)
	for _, d := range allDirections {
		ds := &f.dirs[d]
		ds.in = nil
		ds.snap = DirectionSnapshot{Direction: d, Outcome: OutcomeFailed, Reason: ReasonPanic, Done: true,
			BytesFed: ds.snap.BytesFed, BytesInspected: ds.snap.BytesInspected, Revision: ds.snap.Revision}
	}
}

func (f *Flow) endDirection(ds *direction, sentence string, reason Reason) bool {
	if ds.in == nil { // no byte arrived: nothing to inspect
		f.finish(ds, OutcomeIncomplete, reason, sentence)
		return true
	}
	changed := f.absorb(ds, ds.in.End(sentence), reason)
	if !ds.snap.Done { // End published nothing that made the direction final
		if ds.snap.Outcome == OutcomeDetecting {
			f.finish(ds, OutcomeIncomplete, reason, sentence)
			return true
		}
		ds.in, ds.snap.Done = nil, true
	}
	return changed
}

// absorb copies the inspector's state into the snapshot after a call, applies the profile and releases
// the inspector once it is terminal. reason is what a terminal non-identified outcome is attributed to.
func (f *Flow) absorb(ds *direction, events []contracts.Event, reason Reason) bool {
	in := ds.in
	if in.NotPorted != nil {
		f.finish(ds, OutcomeUnsupported, ReasonNotPorted, in.NotPorted.What)
		return true
	}
	family := in.ResolvedFamily()
	if family != "" && !f.e.profile[family] {
		f.finish(ds, OutcomeOutsideProfile, ReasonOutsideProfile, family)
		ds.snap.Family = bounded(family)
		return true
	}
	changed := len(events) > 0
	if changed {
		f.copyObservation(ds, in.Observation, events[len(events)-1].Revision, family, reason)
	}
	ds.snap.BytesInspected = in.Metrics.BytesInspected
	if in.Terminal() {
		ds.in, ds.snap.Done = nil, true
	}
	return changed
}

func (f *Flow) finish(ds *direction, outcome Outcome, reason Reason, detail string) {
	if ds.in != nil {
		ds.snap.BytesInspected = ds.in.Metrics.BytesInspected
	}
	ds.in = nil
	s := &ds.snap
	s.Outcome, s.Reason, s.Detail, s.Done = outcome, reason, bounded(detail), true
	s.Family, s.ApplicationProtocol, s.Encryption, s.Hostname, s.Scope = "", "", "", "", ""
	s.OfferedALPN, s.OfferedALPNTruncated, s.Evidence, s.EvidenceTruncated = nil, false, nil, false
}

// MaxOfferedALPN bounds the ALPN identifiers a client offered that leave the engine, in OfferedALPN and
// as offered_alpn evidence alike (review round 1, R1: the evidence rows used to carry every offer while
// the list was capped). The TLS parser itself accepts up to 64 offers; this is an export bound only.
const MaxOfferedALPN = 16

func (f *Flow) copyObservation(ds *direction, o contracts.Observation, revision int, family string, reason Reason) {
	s := &ds.snap
	s.Outcome = Outcome(o.Status)
	if !s.Outcome.Valid() {
		s.Outcome = OutcomeUnknown
	}
	switch s.Outcome {
	case OutcomeDetecting:
		s.Reason = ReasonNone
	case OutcomeIncomplete: // only End produces it: attribute it to the host's end, expiry or close
		s.Reason = reason
	default:
		s.Reason = ReasonEngine
	}
	s.Detail = bounded(o.Reason)
	s.Revision = revision
	s.Family = ""
	if s.Outcome == OutcomeIdentified {
		s.Family = bounded(family)
	}
	s.ApplicationProtocol, s.Encryption, s.Hostname = deref(o.ApplicationProtocol), deref(o.Encryption), Hostname(deref(o.Hostname))
	s.Scope = bounded(o.Scope)
	s.OfferedALPN, s.OfferedALPNTruncated = nil, len(o.OfferedALPN) > MaxOfferedALPN
	for i, a := range o.OfferedALPN {
		if i == MaxOfferedALPN {
			break
		}
		s.OfferedALPN = append(s.OfferedALPN, bounded(a))
	}
	s.Evidence, s.EvidenceTruncated = nil, false
	offers := 0
	for _, ev := range o.Evidence {
		if ev.Field == "offered_alpn" { // the same export bound as OfferedALPN, signalled the same way
			if offers == MaxOfferedALPN {
				s.OfferedALPNTruncated, s.EvidenceTruncated = true, true
				continue
			}
			offers++
		}
		if len(s.Evidence) == MaxEvidence {
			s.EvidenceTruncated = true
			break
		}
		class := classify(ev.Field)
		value := ""
		if class != ClassWithheld {
			value = bounded(ev.Value)
		}
		s.Evidence = append(s.Evidence, Evidence{Field: bounded(ev.Field), Value: value, Source: bounded(ev.Source),
			Strength: bounded(ev.Strength), Class: class})
	}
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return bounded(*p)
}

func (f *Flow) snapshot() Snapshot {
	s := Snapshot{ID: f.id, Closed: f.closed, Quarantined: f.quarantined}
	for _, d := range allDirections {
		src := f.dirs[d].snap
		src.OfferedALPN = append([]string(nil), src.OfferedALPN...)
		src.Evidence = append([]Evidence(nil), src.Evidence...)
		s.Directions[d] = src
	}
	return s
}
