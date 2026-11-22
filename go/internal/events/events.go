// Package events ports protocol_adapters/events.py: the versioned envelope of a live event, the bounded
// sequenced log read by cursor, and the deterministic reducer that folds the log into the session view.
// Envelopes and views are ojson objects in the reference's key order, so a page or view written with
// ojson.Dumps is the reference's json.dumps text.
//
// Domain: events are live worker lines (schemas/live-event.json). Where a malformed line would make the
// reference raise something other than ValueError (an endpoint that is not an [address, port] pair, a
// decryption row that is not an object), this port refuses the line as the reference refuses a ValueError:
// it is not appended. The reference's reader thread would instead die on such a line; see STATUS.md.
package events

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/ojson"
	"github.com/leenadav/protocol-detector/go/internal/sessionid"
)

const (
	SchemaVersion    = "1"
	DefaultRetention = 4096
	MaxRetracts      = 1024
)

var kinds = map[string]bool{"session": true, "classification": true, "capture_gap": true, "error": true,
	"summary": true, "started": true, "decryption": true, "progress": true}

var layerOf = map[string]string{"session": "application", "classification": "outer", "decryption": "inner",
	"capture_gap": "capture", "error": "capture", "summary": "capture", "started": "capture", "progress": "capture"}

// ErrRefused is the reference's ValueError for an event it does not wrap.
var ErrRefused = errors.New("event refused")

// endpoint is one side of a session as the reference sorts it: tuple(value) of [address, port].
type endpoint struct {
	addr string
	port int64
	text string // str(port)
}

func endpointOf(v ojson.Value) (endpoint, bool) {
	list, ok := v.([]ojson.Value)
	if !ok || len(list) != 2 {
		return endpoint{}, false
	}
	addr, ok := list[0].(string)
	if !ok {
		return endpoint{}, false
	}
	port, ok := ojson.IntValue(list[1])
	if !ok {
		return endpoint{}, false
	}
	return endpoint{addr, port, strconv.FormatInt(port, 10)}, true
}

func less(a, b endpoint) bool {
	if a.addr != b.addr {
		return a.addr < b.addr // UTF-8 byte order is code point order, as Python compares str
	}
	return a.port < b.port
}

// SessionIdentity is session_identity(transport, client, server).
func SessionIdentity(transport string, client, server endpoint) string {
	a, b := client, server
	if less(b, a) {
		a, b = b, a
	}
	text := fmt.Sprintf("%s|%s:%s|%s:%s", transport, a.addr, a.text, b.addr, b.text)
	ascii := make([]byte, 0, len(text))
	for _, r := range text {
		if r > 0x7f {
			ascii = append(ascii, '?') // .encode("ascii", "replace")
		} else {
			ascii = append(ascii, byte(r))
		}
	}
	return sessionid.Blake2s8(ascii)
}

// PyStr is str() of a decoded JSON value, as the reference formats it into reason codes and identities.
func PyStr(v ojson.Value) string {
	switch x := v.(type) {
	case string:
		return x
	default:
		return pyRepr(v)
	}
}

func pyRepr(v ojson.Value) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case ojson.Int:
		return string(x)
	case float64:
		switch {
		case math.IsNaN(x):
			return "nan"
		case math.IsInf(x, 1):
			return "inf"
		case math.IsInf(x, -1):
			return "-inf"
		}
		s, _ := ojson.Dumps(x)
		return s
	case string:
		return pyStrRepr(x)
	case []ojson.Value:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = pyRepr(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case *ojson.Object:
		parts := make([]string, 0, x.Len())
		for _, k := range x.Keys() {
			e, _ := x.Get(k)
			parts = append(parts, pyStrRepr(k)+": "+pyRepr(e))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return ""
}

// pyStrRepr is repr(str) for printable text; it only feeds substring tests for "loss", so non-printable
// characters (escaped by the reference) are written as escapes that cannot form that word either.
func pyStrRepr(s string) string {
	quote := "'"
	if strings.Contains(s, "'") && !strings.Contains(s, `"`) {
		quote = `"`
	}
	var b strings.Builder
	b.WriteString(quote)
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case string(r) == quote:
			b.WriteString(`\` + quote)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteString(quote)
	return b.String()
}

func get(o *ojson.Object, key string) ojson.Value {
	v, _ := o.Get(key)
	return v
}

// or is Python's `a or b`.
func or(a, b ojson.Value) ojson.Value {
	if ojson.Truthy(a) {
		return a
	}
	return b
}

// Wrap is wrap(event, capture_id, generations, revision=0, quality="intact").
func Wrap(event *ojson.Object, captureID string, generations map[string]int64) (*ojson.Object, error) {
	kindValue, present := event.Get("type")
	if !present {
		kindValue = "session"
	}
	kind, ok := kindValue.(string)
	if !ok || !kinds[kind] {
		return nil, ErrRefused
	}
	client := or(get(event, "client"), get(event, "source"))
	server := or(get(event, "server"), get(event, "destination"))
	var sessionID ojson.Value
	generation := int64(0)
	if ojson.Truthy(client) && ojson.Truthy(server) {
		transportValue, present := event.Get("transport")
		if !present {
			transportValue = "tcp"
		}
		a, okA := endpointOf(client)
		b, okB := endpointOf(server)
		if !okA || !okB {
			return nil, ErrRefused
		}
		sid := SessionIdentity(PyStr(transportValue), a, b)
		sessionID = sid
		generation = generations[sid]
	}
	layer := layerOf[kind]
	source := "wire"
	if kind == "decryption" {
		source = "decrypted"
	} else if layer == "capture" {
		source = "capture"
	}
	var budget ojson.Value
	status := or(get(event, "status"), get(event, "engine_status"))
	if s, ok := status.(string); ok && s == "budget_exhausted" {
		budget = ojson.NewObject("exhausted", true, "scope", or(get(event, "scope"), "inspection"))
	}
	quality := "intact"
	retracts := []ojson.Value{}
	if kind == "capture_gap" {
		quality = "degraded"
		if s, ok := get(event, "scope").(string); ok && s == "all_observations_this_capture" {
			retracts = []ojson.Value{"*"}
		} else {
			ids := or(get(event, "session_ids"), []ojson.Value{})
			list, ok := ids.([]ojson.Value)
			if !ok {
				return nil, ErrRefused
			}
			retracts = append(retracts, list...)
		}
	}
	if len(retracts) > MaxRetracts {
		return nil, ErrRefused
	}
	var reasonCode ojson.Value
	switch {
	case kind == "capture_gap":
		reason, present := event.Get("reason")
		if !present {
			reason = ""
		}
		if strings.Contains(strings.ToLower(PyStr(reason)), "loss") {
			reasonCode = "capture.loss"
		} else {
			reasonCode = "capture.gap"
		}
	case kind == "error":
		reasonCode = "capture.error"
	case ojson.Truthy(status):
		reasonCode = "engine." + PyStr(status)
	}
	if err := reducible(kind, sessionID, event, retracts); err != nil {
		return nil, err
	}
	// Envelope.__init__: the defaults first, then the fields in wrap's keyword order (existing keys keep place).
	return ojson.NewObject(
		"schema_version", SchemaVersion, "sequence", nil, "generation", ojson.FromInt(generation),
		"revision", ojson.FromInt(0), "reason_code", reasonCode, "budget", budget,
		"capture_id", captureID, "session_id", sessionID, "layer", layer, "kind", kind, "source", source,
		"quality", quality, "retracts", retracts, "payload", event), nil
}

// Log is EventLog: the bounded, sequenced log of one capture.
type Log struct {
	CaptureID   string
	Retention   int
	events      []*ojson.Object // a ring would avoid the copy on drop; retention is at most a few thousand
	next        int64
	start       int64
	generations map[string]int64
	revision    map[string]int64 // session_id + "\x00" + generation
}

// NewLog is EventLog(capture_id, retention).
func NewLog(captureID string, retention int) (*Log, error) {
	if retention < 1 || retention > 1_000_000 {
		return nil, errors.New("retention outside 1..1000000")
	}
	return &Log{CaptureID: captureID, Retention: retention, next: 1, start: 1,
		generations: map[string]int64{}, revision: map[string]int64{}}, nil
}

func (l *Log) append(e *ojson.Object) int64 {
	if sid, ok := get(e, "session_id").(string); ok {
		g, _ := ojson.IntValue(get(e, "generation"))
		key := sid + "\x00" + strconv.FormatInt(g, 10)
		l.revision[key]++
		e.Set("revision", ojson.FromInt(l.revision[key]))
	}
	e.Set("sequence", ojson.FromInt(l.next))
	l.next++
	l.events = append(l.events, e)
	if len(l.events) > l.Retention {
		l.events[0] = nil
		l.events = l.events[1:]
		l.start++
	}
	return l.next - 1
}

// WrapAndAppend is wrap_and_append(event).
func (l *Log) WrapAndAppend(event *ojson.Object) (int64, error) {
	e, err := Wrap(event, l.CaptureID, l.generations)
	if err != nil {
		return 0, err
	}
	return l.append(e), nil
}

// Read is read(cursor, limit); the error texts are the reference's ValueError messages.
func (l *Log) Read(cursor, limit int64) (*ojson.Object, error) {
	if cursor < 0 {
		return nil, errors.New("cursor must be a non-negative integer")
	}
	if limit < 1 || limit > 10_000 {
		return nil, errors.New("limit outside 1..10000")
	}
	if cursor != 0 && cursor < l.start-1 {
		return ojson.NewObject("events", []ojson.Value{}, "cursor", ojson.FromInt(l.next-1),
			"reset_required", true, "start", ojson.FromInt(l.start)), nil
	}
	out := []ojson.Value{}
	for _, e := range l.events {
		if int64(len(out)) >= limit {
			break
		}
		if s, _ := ojson.IntValue(get(e, "sequence")); s > cursor {
			out = append(out, e)
		}
	}
	newCursor := cursor
	if len(out) > 0 {
		newCursor, _ = ojson.IntValue(get(out[len(out)-1].(*ojson.Object), "sequence"))
	} else if l.next-1 > newCursor {
		newCursor = l.next - 1
	}
	return ojson.NewObject("events", out, "cursor", ojson.FromInt(newCursor), "reset_required", false,
		"start", ojson.FromInt(l.start)), nil
}

// Cursor is snapshot()["cursor"].
func (l *Log) Cursor() int64 { return l.next - 1 }

// Events is snapshot()["events"]: every retained envelope, oldest first.
func (l *Log) Events() []*ojson.Object { return l.events }

// --- reducer -------------------------------------------------------------------------------------------

// State is reduce()'s state.
type State struct {
	order          []string
	sessions       map[string]*ojson.Object
	Quality        string
	Errors         []ojson.Value
	Summary        ojson.Value
	LastSequence   int64
	RetractedTotal int64
	seen           map[int64]bool
}

func newView(generation ojson.Value) *ojson.Object {
	return ojson.NewObject("generation", generation, "revision", ojson.FromInt(0), "status", "open",
		"session", nil, "classifications", []ojson.Value{}, "decryption", nil, "retracted_by", nil, "effective", nil)
}

func (s *State) put(sid string, view *ojson.Object) {
	if _, ok := s.sessions[sid]; !ok {
		s.order = append(s.order, sid)
	}
	s.sessions[sid] = view
}

// compare orders two decoded numbers as Python compares int and float; false when either is not a number.
func compare(a, b ojson.Value) (int, bool) {
	fa, okA := number(a)
	fb, okB := number(b)
	if !okA || !okB {
		return 0, false
	}
	switch {
	case fa < fb:
		return -1, true
	case fa > fb:
		return 1, true
	}
	return 0, true
}

func number(v ojson.Value) (float64, bool) {
	switch x := v.(type) {
	case ojson.Int:
		if n, ok := ojson.IntValue(x); ok {
			return float64(n), true
		}
		f, err := strconv.ParseFloat(string(x), 64)
		return f, err == nil
	case float64:
		return x, !math.IsNaN(x)
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

// Reduce is public_state(reduce(envelopes)): a fresh fold of the whole sequence.
func Reduce(envelopes []*ojson.Object) (*State, error) {
	s := &State{sessions: map[string]*ojson.Object{}, Quality: "intact", Errors: []ojson.Value{}, seen: map[int64]bool{}}
	for _, e := range envelopes {
		if seq, ok := ojson.IntValue(get(e, "sequence")); ok {
			if s.seen[seq] {
				continue
			}
			s.seen[seq] = true
			if seq > s.LastSequence {
				s.LastSequence = seq
			}
		}
		kind, _ := get(e, "kind").(string)
		sidValue := get(e, "session_id")
		payload, _ := get(e, "payload").(*ojson.Object)
		if kind == "decryption" && sidValue == nil {
			if report, ok := get(payload, "report").(*ojson.Object); ok {
				if err := s.decryptionReport(report); err != nil {
					return nil, err
				}
				continue
			}
		}
		switch {
		case kind == "summary" || kind == "progress":
			s.Summary = payload
		case kind == "error":
			s.Errors = append(s.Errors, ojson.NewObject("sequence", get(e, "sequence"),
				"reason_code", get(e, "reason_code"), "reason", get(payload, "reason")))
		case kind == "capture_gap":
			s.Quality = "degraded"
			retracts, _ := get(e, "retracts").([]ojson.Value)
			var targets []string
			all := false
			for _, r := range retracts {
				if r == "*" {
					all = true
				}
			}
			if all {
				targets = append(targets, s.order...)
			} else {
				for _, r := range retracts {
					if id, ok := r.(string); ok && s.sessions[id] != nil {
						targets = append(targets, id)
					} else if !ok {
						return nil, ErrRefused // an unhashable retraction target is a TypeError in the reference
					}
				}
			}
			for _, target := range targets {
				view := s.sessions[target]
				if get(view, "status") != "retracted" {
					s.RetractedTotal++
				}
				view.Set("status", "retracted")
				view.Set("retracted_by", ojson.NewObject("sequence", get(e, "sequence"), "reason_code", get(e, "reason_code")))
				view.Set("decryption", nil)
				if err := effective(view); err != nil {
					return nil, err
				}
			}
		case sidValue != nil:
			sid := sidValue.(string)
			view := s.sessions[sid]
			generation := get(e, "generation")
			newer := false
			if view != nil {
				c, _ := compare(generation, get(view, "generation"))
				if c > 0 {
					newer = true
				} else if c < 0 {
					continue
				} else if r, _ := compare(get(e, "revision"), get(view, "revision")); r <= 0 {
					continue
				}
			}
			if view == nil || newer {
				view = newView(generation)
				s.put(sid, view)
			}
			view.Set("revision", get(e, "revision"))
			if get(view, "status") == "retracted" {
				continue
			}
			switch kind {
			case "session":
				view.Set("session", payload)
				view.Set("status", "final")
			case "classification":
				list, _ := get(view, "classifications").([]ojson.Value)
				view.Set("classifications", append(list, payload))
			case "decryption":
				view.Set("decryption", payload)
			}
			if err := effective(view); err != nil {
				return nil, err
			}
		}
	}
	return s, nil
}

func (s *State) decryptionReport(report *ojson.Object) error {
	rows, present := report.Get("connections")
	if !ojson.Truthy(rows) {
		return nil
	}
	list, ok := rows.([]ojson.Value)
	if !ok || !present {
		return ErrRefused
	}
	for _, r := range list {
		row, ok := r.(*ojson.Object)
		if !ok {
			return ErrRefused
		}
		sidValue := get(row, "session_id")
		if !ojson.Truthy(sidValue) {
			continue
		}
		sid, ok := sidValue.(string)
		if !ok {
			return ErrRefused
		}
		view := s.sessions[sid]
		generation, present := row.Get("generation")
		if !present {
			generation = ojson.FromInt(0)
		}
		if view == nil {
			view = newView(generation)
			s.put(sid, view)
		} else {
			c, ok := compare(generation, get(view, "generation"))
			if !ok {
				return ErrRefused
			}
			if c > 0 {
				view = newView(generation)
				s.put(sid, view)
			} else if c < 0 || get(view, "status") == "retracted" {
				continue
			}
		}
		view.Set("decryption", row)
		if err := effective(view); err != nil {
			return err
		}
	}
	return nil
}

// reducible refuses, at wrap time, the shapes on which the reference's reducer would raise (a TypeError,
// KeyError or AttributeError when the view is next read), so the Go log never holds an event it cannot fold.
func reducible(kind string, sessionID ojson.Value, event *ojson.Object, retracts []ojson.Value) error {
	for _, r := range retracts {
		if _, ok := r.(string); !ok {
			return ErrRefused
		}
	}
	if kind == "decryption" && sessionID == nil {
		if report, ok := get(event, "report").(*ojson.Object); ok {
			rows := get(report, "connections")
			if !ojson.Truthy(rows) {
				return nil
			}
			list, ok := rows.([]ojson.Value)
			if !ok {
				return ErrRefused
			}
			for _, r := range list {
				row, ok := r.(*ojson.Object)
				if !ok {
					return ErrRefused
				}
				sid := get(row, "session_id")
				if !ojson.Truthy(sid) {
					continue
				}
				if _, ok := sid.(string); !ok {
					return ErrRefused
				}
				if g, present := row.Get("generation"); present {
					if _, ok := number(g); !ok {
						return ErrRefused
					}
				}
				if err := effective(ojson.NewObject("decryption", row, "session", nil)); err != nil {
					return err
				}
			}
			return nil
		}
	}
	if sessionID != nil && (kind == "session" || kind == "decryption") {
		probe := ojson.NewObject("decryption", nil, "session", nil)
		probe.Set(map[bool]string{true: "session", false: "decryption"}[kind == "session"], event)
		return effective(probe)
	}
	return nil
}

// effective is _effective(view).
func effective(view *ojson.Object) error {
	var layers *ojson.Object
	for _, key := range []string{"decryption", "session"} {
		if c, ok := get(view, key).(*ojson.Object); ok {
			if l, ok := get(c, "layers").(*ojson.Object); ok {
				layers = l
				break
			}
		}
	}
	if layers != nil {
		app, ok := get(layers, "application").(*ojson.Object)
		if !ok {
			return ErrRefused
		}
		name, okName := app.Get("name")
		basis, okBasis := app.Get("basis")
		status, okStatus := app.Get("status")
		chain, okChain := get(layers, "chain").([]ojson.Value)
		if !okName || !okBasis || !okStatus || !okChain {
			return ErrRefused
		}
		view.Set("effective", ojson.NewObject("app", name, "basis", basis, "chain", append([]ojson.Value{}, chain...),
			"status", status, "from", "layers"))
		return nil
	}
	if session, ok := get(view, "session").(*ojson.Object); ok {
		chain := []ojson.Value{}
		seen := map[string]bool{}
		for _, v := range []ojson.Value{get(session, "encryption"), or(get(session, "client_protocol"), get(session, "server_protocol")), get(session, "app")} {
			if !ojson.Truthy(v) {
				continue
			}
			key, err := hashKey(v)
			if err != nil {
				return err
			}
			if !seen[key] {
				seen[key] = true
				chain = append(chain, v)
			}
		}
		view.Set("effective", ojson.NewObject("app", get(session, "app"), "basis", nil, "chain", chain,
			"status", get(session, "engine_status"), "from", "session"))
		return nil
	}
	view.Set("effective", nil)
	return nil
}

// hashKey is dict.fromkeys identity for hashable scalars (a list or object is a TypeError in the reference).
func hashKey(v ojson.Value) (string, error) {
	switch x := v.(type) {
	case string:
		return "s" + x, nil
	case bool, ojson.Int, float64:
		f, _ := number(x)
		return "n" + strconv.FormatFloat(f, 'g', -1, 64), nil // 1 == 1.0 == True, as in Python
	}
	return "", ErrRefused
}

// View is LiveManager.view(): the session view reduced from the whole retained log.
func (l *Log) View() (*ojson.Object, error) {
	s, err := Reduce(l.events)
	if err != nil {
		return nil, err
	}
	sessions := make([]ojson.Value, 0, len(s.order))
	for _, sid := range s.order {
		view := s.sessions[sid]
		out := ojson.NewObject("id", sid)
		classifications := 0
		for _, k := range view.Keys() {
			v, _ := view.Get(k)
			if k == "classifications" {
				list, _ := v.([]ojson.Value)
				classifications = len(list)
				continue
			}
			out.Set(k, v)
		}
		out.Set("classifications", ojson.FromInt(int64(classifications)))
		sessions = append(sessions, out)
	}
	return ojson.NewObject("quality", s.Quality, "retracted_total", ojson.FromInt(s.RetractedTotal),
		"sessions", sessions, "errors", s.Errors, "last_sequence", ojson.FromInt(s.LastSequence),
		"summary", s.Summary), nil
}

// SortedKeys is a helper for tests.
func SortedKeys(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
