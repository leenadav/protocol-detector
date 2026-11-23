package detector

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/leenadav/protocol-detector/go/internal/buffer"
	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/engine"
	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// Errors returned by this package. Compare with errors.Is.
var (
	ErrInvalidConfig = errors.New("detector: invalid configuration")
	ErrAdmission     = errors.New("detector: observation admission refused (flow limit reached)")
	ErrMemory        = errors.New("detector: observation admission refused (retained-memory budget reached)")
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
	// MaxRetainedPerFlow is the flow allowance: the capacity, in bytes, of the byte buffers the parsers of
	// both directions of one flow may keep between calls. 0 selects 2 x MaxBytesPerDirection (32 KiB at the
	// default). It must be at least MaxBytesPerDirection and at most MaxRetainedCeiling. It is a different
	// unit from MaxBytesPerDirection: that one counts bytes inspected, this one buffer capacity retained.
	// A direction whose flow would exceed the allowance ends as OutcomeBudgetExhausted with ReasonMemory.
	MaxRetainedPerFlow int
	// MaxRetainedTotal is the engine allowance. Admitting a flow reserves one flow allowance from it, and
	// NewFlow returns ErrMemory when it cannot. 0 selects MaxFlows x MaxRetainedPerFlow (32 MiB at the
	// default). It must be at least one flow allowance and at most MaxRetainedCeiling; a derived value
	// above the ceiling is rejected, not clamped.
	MaxRetainedTotal int
}

// MaxRetainedCeiling bounds MaxRetainedPerFlow and MaxRetainedTotal: 1 GiB.
const MaxRetainedCeiling = 1 << 30

// DefaultConfig is the first visibility profile (working plan decision 4, approved 2026-11-18): HTTP/1, TLS,
// SSH and SMTP identified with evidence, every other family reported as OutcomeOutsideProfile, with 16 KiB and
// 16 reads per direction. The budgets are the plan's starting hypotheses (section 9), not agreed limits.
func DefaultConfig() Config {
	return Config{Families: []string{"http", "tls", "ssh", "smtp"}, MaxBytesPerDirection: 16384, MaxFeedsPerDirection: 16,
		MaxFlows: 1024, PanicLimit: 8}
}

// Engine admits flows under one immutable configuration. It is safe for concurrent use.
type Engine struct {
	cfg        contracts.Config
	families   []string
	profile    map[string]bool // never written after New
	maxFlows   int64
	panicLimit int64
	// Memory budget (integration work item #14). Two separately named quantities:
	//   reservation: one flowAllowance per admitted flow, charged to account at NewFlow before anything
	//                is allocated and returned exactly once at Close;
	//   retained:    the buffer capacity the flows' parsers hold right now, tracked inside each flow's
	//                reservation and never charged to account a second time.
	flowAllowance int
	account       *buffer.Account

	active        atomic.Int64
	admitted      atomic.Int64
	refused       atomic.Int64
	refusedMemory atomic.Int64
	panics        atomic.Int64
	retained      atomic.Int64

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
	// The memory allowances. All arithmetic is done in int64 on values already bounded above, so it cannot
	// overflow; a result outside the bounds is an error, never a clamp.
	if c.MaxRetainedPerFlow < 0 || c.MaxRetainedTotal < 0 {
		return nil, fmt.Errorf("%w: retained-memory limits cannot be negative", ErrInvalidConfig)
	}
	perFlow := int64(c.MaxRetainedPerFlow)
	if perFlow == 0 {
		perFlow = 2 * int64(c.MaxBytesPerDirection)
	}
	if perFlow < int64(c.MaxBytesPerDirection) || perFlow > MaxRetainedCeiling {
		return nil, fmt.Errorf("%w: max retained per flow must be %d (max bytes per direction)..%d, got %d",
			ErrInvalidConfig, c.MaxBytesPerDirection, MaxRetainedCeiling, perFlow)
	}
	total := int64(c.MaxRetainedTotal)
	if total == 0 {
		total = int64(c.MaxFlows) * perFlow
		if total > MaxRetainedCeiling {
			return nil, fmt.Errorf("%w: max flows x max retained per flow is %d bytes, over the %d ceiling; lower one or set max retained total",
				ErrInvalidConfig, total, MaxRetainedCeiling)
		}
	}
	if total < perFlow || total > MaxRetainedCeiling {
		return nil, fmt.Errorf("%w: max retained total must be %d (one flow allowance)..%d, got %d",
			ErrInvalidConfig, perFlow, MaxRetainedCeiling, total)
	}
	account, err := buffer.NewAccount("detector engine", int(total))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	return &Engine{cfg: cfg, families: append([]string(nil), c.Families...), profile: profile,
		maxFlows: int64(c.MaxFlows), panicLimit: int64(c.PanicLimit), flowAllowance: int(perFlow), account: account}, nil
}

// Families returns a copy of the engine's profile.
func (e *Engine) Families() []string { return append([]string(nil), e.families...) }

// Stats is a point-in-time view of an engine's counters.
type Stats struct {
	Active, Admitted, Refused, Panics int64
	Disabled                          bool
	// RefusedMemory counts the refusals (included in Refused) caused by the engine allowance.
	RefusedMemory int64
	// FlowAllowance and EngineAllowance are the configured limits, in bytes.
	FlowAllowance, EngineAllowance int64
	// ReservedBytes is the sum of the flow allowances of the admitted flows: Active x FlowAllowance once
	// every admission in flight has completed.
	ReservedBytes int64
	// RetainedBytes is the byte-buffer capacity the parsers of all flows hold right now. It is at most
	// ReservedBytes. It is not heap or RSS: snapshots, evidence strings and transient allocations are
	// bounded separately (MaxEvidence, MaxEvidenceValue, MaxOfferedALPN, MaxFlowID).
	RetainedBytes int64
}

// Stats reads the counters.
func (e *Engine) Stats() Stats {
	return Stats{Active: e.active.Load(), Admitted: e.admitted.Load(), Refused: e.refused.Load(),
		Panics: e.panics.Load(), Disabled: e.disabled(), RefusedMemory: e.refusedMemory.Load(),
		FlowAllowance: int64(e.flowAllowance), EngineAllowance: int64(e.account.Limit()),
		ReservedBytes: int64(e.account.Used()), RetainedBytes: e.retained.Load()}
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
	// Reserve the flow allowance before anything is allocated for the flow. A refusal gives the slot back,
	// so it leaves neither a count nor a reservation behind, and it never takes memory from a flow already
	// admitted. The slot is taken first so that the flow limit, when it is the tighter one, is the error
	// the host sees.
	if e.account.Reserve(e.flowAllowance) != nil {
		e.active.Add(-1)
		e.refused.Add(1)
		e.refusedMemory.Add(1)
		return nil, ErrMemory
	}
	e.admitted.Add(1)
	f := &Flow{e: e, id: bounded(trimID(id)), reserved: e.flowAllowance}
	f.credit.Reset(f.reserved)
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
	reserved    int // the flow allowance held from the engine account; returned once, at Close
	retained    int // buffer capacity the two inspectors hold now; at most reserved between calls
	// credit is the flow allowance as the inspectors draw from it: every covered buffer is charged before it
	// grows, so the covered buffers never hold more than reserved, not even inside a call (work item #14).
	credit parsing.Credit
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
	// RetainedBytes is the byte-buffer capacity the flow's parsers hold at the time of the snapshot.
	RetainedBytes int
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
			in.SetCredit(&f.credit)
			ds.in = in
		}
		changed = f.absorb(ds, ds.in.Feed(data), ReasonEngine)
		if f.credit.Denied() { // a covered buffer could not grow inside the allowance: nothing was allocated for it
			f.finish(ds, OutcomeBudgetExhausted, ReasonMemory, memoryDetail)
			changed = true
		}
		changed = f.settle(ds) || changed
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
	if f.guard("end", d, func() {
		changed = f.endDirection(ds, cause.sentence(), ReasonEnded)
		f.settle(nil)
	}) {
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
	f.settle(nil)
	return nil
}

// Snapshot returns a detached copy of the flow. It runs inside the panic boundary like every other call: a
// panic while it is copied quarantines the flow and returns the quarantined flow's snapshot, which holds no
// evidence or ALPN lists to copy (working plan item #10).
func (f *Flow) Snapshot() (s Snapshot) {
	f.mu.Lock()
	defer f.mu.Unlock()
	defer func() {
		if recover() != nil { // the panic value is dropped: it may quote input bytes
			f.quarantine()
			s = f.quarantinedSnapshot()
		}
	}()
	if f.e.testHook != nil {
		f.e.testHook("snapshot", ClientToServer)
	}
	return f.snapshot()
}

// quarantinedSnapshot is the snapshot of a quarantined flow, built from fields quarantine itself set: it calls
// nothing that could fail again.
func (f *Flow) quarantinedSnapshot() Snapshot {
	return Snapshot{ID: f.id, Closed: f.closed, Quarantined: true, Directions: [2]DirectionSnapshot{f.dirs[0].snap, f.dirs[1].snap}}
}

// Close releases all engine state and the flow's admission slot, and returns the final snapshot. A
// direction that had not decided ends as OutcomeIncomplete with ReasonClosed. Close is idempotent.
//
// Close has two parts (working plan item #10, "what happens when cleanup itself fails"). Settling the
// directions and dropping the inspectors runs inside the panic boundary; a panic there quarantines the flow,
// and Close returns its quarantined snapshot. Returning the flow's reservation and admission slot runs after
// that part on every path, deferred, so a panic cannot keep them: it is counter arithmetic only (the account
// release clamps at zero), so it has no failure of its own to define. Each is returned exactly once,
// because the flow is marked closed before either part runs.
func (f *Flow) Close() (s Snapshot) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed { // idempotent: nothing engine-side remains, so this is the plain copy
		return f.snapshot()
	}
	f.closed = true
	defer f.releaseAdmission()
	if f.guard("close", ClientToServer, func() {
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
		f.settle(nil)
	}) {
		return f.quarantinedSnapshot()
	}
	return f.snapshot()
}

// releaseAdmission returns what the flow holds from the engine: its retained figure, its reservation and its
// admission slot. It runs once, from Close.
func (f *Flow) releaseAdmission() {
	f.e.retained.Add(int64(-f.retained))
	f.retained = 0
	f.e.account.Release(f.reserved) // the one and only release of this flow's reservation
	f.reserved = 0
	f.e.active.Add(-1)
}

// memoryDetail is the detail of a direction that ended for the memory allowance.
const memoryDetail = "Retained parser memory exceeds the flow allowance"

// settle brings the flow's retained figure, and the engine's, in line with what the inspectors hold after
// a call, and settles the flow's Credit to it. The allowance itself is enforced before any covered buffer
// grows (f.credit; a refused growth ends the direction as OutcomeBudgetExhausted with ReasonMemory and
// allocates nothing), so the covered buffers never hold more than the allowance, inside a call or between
// calls. The check here is the second line: when fed is the direction that just received bytes and the
// measured figure is above the allowance (a buffer that grew outside the Credit), that direction ends the
// same way and its inspector is dropped; settle reports whether it did so.
//
// Covered are the buffers parsing.Retainer reports, of the parsers that take a Credit (TLS, the text route
// with HTTP, SSH, SMTP and the control protocols, IRC) and the dispatch prefix. A parser of another family
// reports nothing and takes no Credit; no such family is in the profile, so it ends as OutcomeOutsideProfile
// after the call that selected it, its growth bounded by that call's bytes.
func (f *Flow) settle(fed *direction) (ended bool) {
	measure := func() int {
		n := 0
		for i := range f.dirs {
			if in := f.dirs[i].in; in != nil {
				m, _ := in.RetainedBytes()
				n += m
			}
		}
		return n
	}
	now := measure()
	if fed != nil && fed.in != nil && now > f.reserved {
		f.finish(fed, OutcomeBudgetExhausted, ReasonMemory, memoryDetail)
		now, ended = measure(), true
	}
	f.e.retained.Add(int64(now - f.retained))
	f.retained = now
	f.credit.Settle(now)
	return ended
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
	f.e.retained.Add(int64(-f.retained)) // the inspectors are gone; the reservation stays until Close
	f.retained = 0
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
	// Every string kept here is either this package's own static copy of a closed-vocabulary value
	// (canonical) or a copy this package made, reused while the engine reports the same text (keep). Go strings
	// are immutable and the engine builds none with unsafe, so a snapshot can never change when the flow's
	// input buffers are reused; the copies only keep a snapshot from holding a larger engine allocation alive.
	// Copying unchanged values again on every revision bought nothing (work item #14 follow-up, PRO-148).
	s.Detail = keep(s.Detail, o.Reason)
	s.Revision = revision
	if s.Outcome == OutcomeIdentified {
		s.Family = canonical(familyNames, s.Family, family)
	} else {
		s.Family = ""
	}
	s.ApplicationProtocol = keepPtr(s.ApplicationProtocol, o.ApplicationProtocol)
	s.Encryption = labelPtr(o.Encryption)
	s.Hostname = Hostname(keepPtr(string(s.Hostname), o.Hostname))
	s.Scope = label(o.Scope)
	s.OfferedALPNTruncated = len(o.OfferedALPN) > MaxOfferedALPN
	offered := s.OfferedALPN[:0] // the snapshot's own slice: Snapshot copies it out, so it is reused in place
	for i, a := range o.OfferedALPN {
		if i == MaxOfferedALPN {
			break
		}
		previous := ""
		if i < len(s.OfferedALPN) {
			previous = s.OfferedALPN[i]
		}
		offered = append(offered, keep(previous, a))
	}
	s.OfferedALPN = offered
	if len(s.OfferedALPN) == 0 {
		s.OfferedALPN = nil
	}
	previousEvidence := s.Evidence
	s.Evidence, s.EvidenceTruncated = s.Evidence[:0], false
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
		var previous Evidence
		if i := len(s.Evidence); i < len(previousEvidence) {
			previous = previousEvidence[i] // read before the in-place append below overwrites index i
		}
		value := ""
		switch class {
		case ClassCategorical: // drawn from a protocol or engine vocabulary, never a slice of flow input
			value = label(ev.Value)
		case ClassAsserted, ClassHostname: // bytes a peer chose: a copy this package owns
			value = keep(previous.Value, ev.Value)
		}
		s.Evidence = append(s.Evidence, Evidence{Field: canonical(fieldNames, previous.Field, ev.Field), Value: value,
			Source: label(ev.Source), Strength: canonical(strengthNames, previous.Strength, ev.Strength), Class: class})
	}
	if len(s.Evidence) == 0 {
		s.Evidence = nil
	}
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return bounded(*p)
}

// keep returns previous when the engine still reports the same text (previous is already a bounded copy this
// package made), else a bounded copy of next.
func keep(previous, next string) string {
	if next == "" {
		return ""
	}
	if len(next) <= MaxEvidenceValue && previous == next {
		return previous
	}
	return bounded(next)
}

// label returns an engine-composed label as it is: a source label (the byte source and a parser provenance,
// both constants, joined), an encryption name or a scope. The engine builds none of them from flow input, so
// holding one holds no input-derived memory; an over-long one is still cut to MaxEvidenceValue.
func label(s string) string {
	if len(s) > MaxEvidenceValue {
		return bounded(s)
	}
	return s
}

func labelPtr(p *string) string {
	if p == nil {
		return ""
	}
	return label(*p)
}

// keepPtr is keep for the engine's optional fields.
func keepPtr(previous string, next *string) string {
	if next == nil {
		return ""
	}
	return keep(previous, *next)
}

// canonical returns this package's own static copy of next when next is a value of the closed vocabulary set
// (no allocation, and nothing of the engine's is held), else keep(previous, next).
func canonical(set map[string]string, previous, next string) string {
	if c, ok := set[next]; ok {
		return c
	}
	return keep(previous, next)
}

func (f *Flow) snapshot() Snapshot {
	s := Snapshot{ID: f.id, Closed: f.closed, Quarantined: f.quarantined, RetainedBytes: f.retained}
	for _, d := range allDirections {
		src := f.dirs[d].snap
		src.OfferedALPN = append([]string(nil), src.OfferedALPN...)
		src.Evidence = append([]Evidence(nil), src.Evidence...)
		s.Directions[d] = src
	}
	return s
}
