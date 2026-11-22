package analyze

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/analyzer"
	"github.com/leenadav/protocol-detector/go/internal/capture"
	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/pyjson"
	"github.com/leenadav/protocol-detector/go/internal/session"
	"github.com/leenadav/protocol-detector/go/internal/transport"
)

// Limits are the presentation service's per-capture bounds (presentation/server.py MAX_FRAMES, MAX_SESSIONS,
// MAX_EVENTS).
type Limits struct{ Frames, Sessions, Events int }

// DefaultLimits are the service's shipped bounds.
var DefaultLimits = Limits{Frames: 20000, Sessions: 500, Events: 4000}

// PresentError is an exception the reference's analyze_bytes raises: Type is its class (ValueError or
// CaptureError), Message its str().
type PresentError struct{ Type, Message string }

func (e *PresentError) Error() string { return e.Message }

type presentEvent struct {
	source, destination transport.Endpoint
	timestamp           float64
	frame               int
	event               contracts.Event
}

func presentOrders(row map[string][]string) pyjson.Orders {
	base := orders(row)
	sessionKeys := append(append([]string{}, keyOrders["session"]...), "id", "events")
	eventKeys := []string{"revision", "kind", "observation", "source", "destination", "timestamp", "frame"}
	return func(path string) []string {
		switch path {
		case "session":
			return sessionKeys
		case "session.events[]":
			return eventKeys
		}
		return base(path)
	}
}

func number(v interface{}) float64 {
	switch n := v.(type) {
	case int:
		return float64(n)
	case float64:
		return n
	}
	return math.NaN()
}

func sameEndpoint(v interface{}, e transport.Endpoint) bool {
	pair, ok := v.([]interface{})
	return ok && len(pair) == 2 && pair[0] == e.Addr && pair[1] == int(e.Port)
}

// Present is presentation/server.py analyze_bytes: the session records of one uploaded capture with their
// events, and the capture's meta data, as the JSON text json.dumps writes for that result. processingMS is the
// caller's measured time (the one field that is not a function of the capture).
func Present(data []byte, pack *content.Pack, limits Limits, processingMS func() float64) (string, error) {
	an, err := analyzer.New(pack, analyzer.Options{Fingerprints: true, Heuristics: true, Certificates: true, Rows: true,
		Session: session.Options{MaxConnections: 256, MaxUDPFlows: 256, ByteLimit: 65536, IdleTimeout: 120, Compact: true, Observation: "handshake"}})
	if err != nil {
		return "", err
	}
	var events []presentEvent
	type sessionRow struct {
		record map[string]interface{}
		order  map[string][]string
	}
	var sessions []sessionRow
	histogram := map[int]int{}
	now, frames, skipped, wire := 0.0, 0, 0, 0

	addEvent := func(source, destination transport.Endpoint, e contracts.Event) error {
		if len(events) >= limits.Events {
			return &PresentError{"ValueError", "Event limit reached. Use a smaller capture (maximum 4,000 events)."}
		}
		events = append(events, presentEvent{source, destination, now, frames, e})
		return nil
	}
	drain := func() error {
		defer func() { an.Rows = an.Rows[:0] }()
		for _, row := range an.Rows {
			if row.Event != nil {
				if err := addEvent(row.Source, row.Destination, *row.Event); err != nil {
					return err
				}
				continue
			}
			if len(sessions) >= limits.Sessions {
				return &PresentError{"ValueError", "Session limit reached. Use a capture with fewer than 500 sessions."}
			}
			sessions = append(sessions, sessionRow{row.Session, row.Order})
		}
		return nil
	}
	readErr := capture.Read(bytes.NewReader(data), func(record capture.Record) error {
		frames++
		if frames > limits.Frames {
			return &PresentError{"ValueError", "Frame limit reached. Use a capture with at most 20,000 frames."}
		}
		if record.Truncated() {
			return &PresentError{"CaptureError", "Truncated capture record. No results published; use a complete capture."}
		}
		now = record.Timestamp
		wire += len(record.Data)
		histogram[int(now)]++
		packet, derr := transport.Decode(record.Data, record.Linktype, transport.Ignore)
		if derr != nil {
			if _, ok := derr.(*transport.Reject); !ok {
				return derr
			}
			skipped++
			return nil
		}
		var source, destination transport.Endpoint
		switch pk := packet.(type) {
		case *transport.TCP:
			source, destination = pk.Source, pk.Destination
		case *transport.UDP:
			source, destination = pk.Source, pk.Destination
		}
		an.Process(now, packet)
		if an.NotPorted != nil {
			return an.NotPorted
		}
		if err := drain(); err != nil {
			return err
		}
		for _, e := range an.LastEvents {
			if err := addEvent(source, destination, e); err != nil {
				return err
			}
		}
		for _, p := range an.PeerEvents {
			if err := addEvent(p.Source, p.Destination, p.Event); err != nil {
				return err
			}
		}
		return nil
	})
	if readErr != nil {
		if c, ok := readErr.(*capture.Error); ok {
			return "", &PresentError{"CaptureError", c.Message}
		}
		return "", readErr
	}
	if err := an.Finish("Capture EOF"); err != nil {
		return "", err
	}
	if err := drain(); err != nil {
		return "", err
	}
	if frames == 0 {
		return "", &PresentError{"ValueError", "The capture contains no frames."}
	}
	var b strings.Builder
	b.WriteString(`{"sessions": [`)
	identified := 0
	for i, s := range sessions {
		record := s.record
		record["id"] = fmt.Sprintf("S-%04d", i+1)
		start, end := number(record["start"]), number(record["end"])
		own := []interface{}{}
		for _, e := range events {
			if len(own) == 60 {
				break
			}
			// {source, destination} == {client, server}, as sets
			sc, sv := sameEndpoint(record["client"], e.source), sameEndpoint(record["server"], e.source)
			dc, dv := sameEndpoint(record["client"], e.destination), sameEndpoint(record["server"], e.destination)
			if !((sc || sv) && (dc || dv) && (sc || dc) && (sv || dv)) || !(start <= e.timestamp && e.timestamp <= end) {
				continue
			}
			d := eventDict(e.event)
			d["source"], d["destination"], d["timestamp"], d["frame"] = endpoint(e.source), endpoint(e.destination), e.timestamp, e.frame
			own = append(own, d)
		}
		record["events"] = own
		if app, _ := record["app"].(string); !pack.Outcomes[app] {
			identified++
		}
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(pyjson.Dumps(record, "session", presentOrders(s.order)))
	}
	seconds := make([]int, 0, len(histogram))
	for second := range histogram {
		seconds = append(seconds, second)
	}
	sort.Ints(seconds)
	timeline := make([]interface{}, 0, len(seconds))
	for _, second := range seconds {
		timeline = append(timeline, []interface{}{second, histogram[second]})
	}
	digest := sha256.Sum256(data)
	meta := map[string]interface{}{"frames": frames, "skipped": skipped, "wire_bytes": wire, "processing_ms": pyjson.Round(processingMS(), 2),
		"events": len(events), "identified": identified, "timeline": timeline, "sha256": hex.EncodeToString(digest[:])}
	b.WriteString(`], "meta": `)
	b.WriteString(pyjson.Dumps(meta, "meta", func(string) []string {
		return []string{"frames", "skipped", "wire_bytes", "processing_ms", "events", "identified", "timeline", "sha256"}
	}))
	b.WriteString("}")
	return b.String(), nil
}
