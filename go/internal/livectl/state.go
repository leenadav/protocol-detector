// Package livectl ports presentation/live_manager.py: the bounded live metadata bridge behind the dashboard's
// /api/live/* endpoints (contracts C14 and C15). This file is the run's retained state: what a worker line
// does to it (ingest) and the three read views (snapshot, state_view, events_since), plus the run-scoped reset.
// Every view is an ojson object in the reference's key order. Process control is in process.go.
package livectl

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync"
	"time"

	"github.com/leenadav/protocol-detector/go/internal/events"
	"github.com/leenadav/protocol-detector/go/internal/ojson"
)

const (
	maxEvents   = 200 // deque(maxlen=200)
	maxSessions = 500 // deque(maxlen=500)
	leaseWindow = 30  // seconds a run lives without a heartbeat
)

var logKinds = map[string]bool{"session": true, "classification": true, "capture_gap": true, "error": true,
	"summary": true, "decryption": true}

// State is the run state the reference keeps on LiveManager. All methods take the lock.
type State struct {
	mu           sync.Mutex
	phase        string // idle | running | stopping | stopped | failed
	events       []ojson.Value
	sessions     []ojson.Value
	summary      ojson.Value
	errorText    ojson.Value // None or the reason (any JSON value, as the reference keeps event.get('reason'))
	sequence     int64
	sessionCount int64
	captureID    ojson.Value // None or the hex run id
	log          *events.Log
	lease        time.Time
	iface        ojson.Value
	decryption   ojson.Value
	now          func() time.Time
}

// NewState is LiveManager.__init__'s state.
func NewState(now func() time.Time) *State {
	if now == nil {
		now = time.Now
	}
	return &State{phase: "idle", summary: ojson.NewObject(), now: now}
}

// begin is the part of start() that clears the previous run and opens a fresh log (the lock is held).
func (s *State) begin(captureID, iface string) {
	s.events, s.sessions = nil, nil
	s.summary = ojson.NewObject()
	s.decryption, s.errorText = nil, nil
	s.sequence, s.sessionCount = 0, 0
	s.captureID = captureID
	s.log, _ = events.NewLog(captureID, events.DefaultRetention)
	s.iface = iface
	s.lease = s.now()
	s.phase = "running"
}

// Begin opens a run without a process (the replay harness; start() does this and then spawns the worker).
func (s *State) Begin(captureID, iface, phase string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.begin(captureID, iface)
	s.phase = phase
}

// Ingest is ingest(event) for one decoded worker line.
func (s *State) Ingest(event *ojson.Object) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ingest(event)
}

func (s *State) ingest(event *ojson.Object) {
	kindValue, _ := event.Get("type")
	kind, _ := kindValue.(string)
	if s.log != nil && logKinds[kind] {
		_, _ = s.log.WrapAndAppend(event) // a malformed worker line never breaks the legacy path below
	}
	switch kind {
	case "decryption":
		s.decryption = event
	case "progress", "summary":
		s.summary = event
	case "session":
		s.sessionCount++
		copy := event.Copy()
		copy.Set("id", fmt.Sprintf("L-%06d", s.sessionCount))
		copy.Set("events", []ojson.Value{})
		s.sessions = appendBounded(s.sessions, copy, maxSessions)
	case "classification", "capture_gap", "error":
		s.sequence++
		copy := event.Copy()
		copy.Set("sequence", ojson.FromInt(s.sequence))
		s.events = appendBounded(s.events, copy, maxEvents)
		if kind == "error" {
			reason, present := event.Get("reason")
			if !present {
				reason = "Capture failed"
			}
			s.errorText = reason
		}
		if kind == "capture_gap" {
			s.sessions = nil // never retain apparently valid session verdicts across reported capture loss
		}
	}
}

func appendBounded(list []ojson.Value, v ojson.Value, max int) []ojson.Value {
	list = append(list, v)
	if len(list) > max {
		list = append([]ojson.Value(nil), list[len(list)-max:]...)
	}
	return list
}

func list(values []ojson.Value) []ojson.Value { return append([]ojson.Value{}, values...) }

func (s *State) leaseLeft() ojson.Value {
	if s.phase != "running" {
		return nil
	}
	left := leaseWindow - s.now().Sub(s.lease).Seconds()
	if left < 0 {
		return ojson.FromInt(0)
	}
	return ojson.FromInt(int64(math.Trunc(left))) // int() truncates toward zero
}

func (s *State) cursor() ojson.Int {
	if s.log == nil {
		return ojson.FromInt(0)
	}
	return ojson.FromInt(s.log.Cursor())
}

// Snapshot is snapshot(): side-effect free.
func (s *State) Snapshot() *ojson.Object {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot()
}

func (s *State) snapshot() *ojson.Object {
	return ojson.NewObject("state", s.phase, "interface", s.iface, "error", s.errorText, "run_id", s.captureID,
		"lease_seconds_left", s.leaseLeft(), "decryption", s.decryption,
		"events", list(s.events), "sessions", list(s.sessions),
		"summary", s.summary, "events_total", ojson.FromInt(s.sequence),
		"sessions_total", ojson.FromInt(s.sessionCount), "retained_sessions", ojson.FromInt(int64(len(s.sessions))),
		"capture_id", s.captureID, "cursor", s.cursor())
}

// StateView is state_view(): the control state alone.
func (s *State) StateView() *ojson.Object {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stateView()
}

func (s *State) stateView() *ojson.Object {
	var summary ojson.Value
	if d, ok := s.decryption.(*ojson.Object); ok {
		provisional, _ := d.Get("provisional")
		quality, _ := d.Get("capture_quality")
		var decrypted ojson.Value
		if report, ok := d.Get("report"); ok && ojson.Truthy(report) {
			if r, ok := report.(*ojson.Object); ok {
				decrypted, _ = r.Get("decrypted")
			}
		}
		summary = ojson.NewObject("provisional", provisional, "capture_quality", quality, "decrypted", decrypted)
	}
	return ojson.NewObject("state", s.phase, "interface", s.iface, "error", s.errorText, "run_id", s.captureID,
		"capture_id", s.captureID, "lease_seconds_left", s.leaseLeft(),
		"summary", s.summary, "events_total", ojson.FromInt(s.sequence), "sessions_total", ojson.FromInt(s.sessionCount),
		"cursor", s.cursor(), "decryption_summary", summary)
}

// EventsSince is events_since(cursor, limit); the error is the reference's ValueError text.
func (s *State) EventsSince(cursor, limit int64) (*ojson.Object, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.log == nil {
		return ojson.NewObject("capture_id", nil, "events", []ojson.Value{}, "cursor", ojson.FromInt(0),
			"reset_required", false, "view", nil), nil
	}
	page, err := s.log.Read(cursor, limit)
	if err != nil {
		return nil, err
	}
	view, err := s.log.View()
	if err != nil {
		return nil, err
	}
	page.Set("capture_id", s.captureID)
	page.Set("view", view)
	return page, nil
}

// runMatches is `run_id is not None and run_id == self.capture_id` for a decoded request value.
func (s *State) runMatches(runID ojson.Value) bool {
	id, ok := runID.(string)
	current, ok2 := s.captureID.(string)
	return ok && ok2 && id == current
}

// clear is the part of reset() that drops every retained result (the lock is held).
func (s *State) clear() *ojson.Object {
	s.events, s.sessions = nil, nil
	s.summary = ojson.NewObject()
	s.decryption, s.errorText = nil, nil
	s.sequence, s.sessionCount = 0, 0
	s.log = nil
	s.captureID, s.iface = nil, nil
	if s.phase == "running" || s.phase == "stopping" {
		s.phase = "stopped"
	}
	return ojson.NewObject("reset", true, "reason", "cleared", "run_id", nil)
}

// staleReset is reset()'s answer for a request naming another run, or none.
func (s *State) staleReset(runID ojson.Value) *ojson.Object {
	reason := "no_run"
	if ojson.Truthy(runID) {
		reason = "stale"
	}
	return ojson.NewObject("reset", false, "reason", reason, "run_id", s.captureID)
}

// Merge is dict(base, **extra).
func Merge(base, extra *ojson.Object) *ojson.Object {
	out := base.Copy()
	for _, k := range extra.Keys() {
		v, _ := extra.Get(k)
		out.Set(k, v)
	}
	return out
}

// ResetIdle is reset(run_id) for a run without a live process (the process path is Manager.Reset).
func (s *State) ResetIdle(runID ojson.Value) *ojson.Object {
	s.mu.Lock()
	defer s.mu.Unlock()
	if runID == nil || !s.runMatches(runID) {
		return s.staleReset(runID)
	}
	return s.clear()
}

// ExpireLease puts the lease at the zero time (the replay harness: no run is ever renewed there).
func (s *State) ExpireLease() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lease = time.Time{}
}

// EventsSinceBig is events_since for the integers int() admits from a query: any size. A cursor beyond int64
// can only be ahead of the log: no events, and the cursor is returned as given (max(cursor, last)).
func (s *State) EventsSinceBig(cursor, limit *big.Int) (*ojson.Object, error) {
	if cursor.IsInt64() && limit.IsInt64() {
		return s.EventsSince(cursor.Int64(), limit.Int64())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.log == nil {
		return ojson.NewObject("capture_id", nil, "events", []ojson.Value{}, "cursor", ojson.FromInt(0),
			"reset_required", false, "view", nil), nil
	}
	if cursor.Sign() < 0 {
		return nil, errors.New("cursor must be a non-negative integer")
	}
	if !limit.IsInt64() || limit.Int64() < 1 || limit.Int64() > 10_000 {
		return nil, errors.New("limit outside 1..10000")
	}
	page, err := s.log.Read(0, 1) // validates nothing further; only "start" is taken from it
	if err != nil {
		return nil, err
	}
	view, err := s.log.View()
	if err != nil {
		return nil, err
	}
	start, _ := page.Get("start")
	out := ojson.NewObject("events", []ojson.Value{}, "cursor", ojson.Int(cursor.String()), "reset_required", false, "start", start)
	out.Set("capture_id", s.captureID)
	out.Set("view", view)
	return out, nil
}
