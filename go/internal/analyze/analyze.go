// Package analyze ports protocol_adapters/analyze_pcap.analyze: offline inspection of a classic PCAP or pcapng
// capture. It needs no capture privileges and no network access. Rows are the reference's rows: one per
// frame (or only classification changes with EventsOnly), a stream-end row per directional terminal event,
// one session record per TCP connection or UDP flow, capture gaps, and a final summary with the input-quality
// contract (D06) and the content release that classified the run (D08).
package analyze

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/analyzer"
	"github.com/leenadav/protocol-detector/go/internal/appid"
	"github.com/leenadav/protocol-detector/go/internal/capture"
	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/policy"
	"github.com/leenadav/protocol-detector/go/internal/pyjson"
	"github.com/leenadav/protocol-detector/go/internal/session"
	"github.com/leenadav/protocol-detector/go/internal/signatures"
	"github.com/leenadav/protocol-detector/go/internal/transport"
)

// Options are the analyze() arguments.
type Options struct {
	JSON             bool
	EventsOnly       bool
	Sessions         bool
	IncludeHostnames bool
	Signatures       *signatures.Set
	Fingerprints     bool
	Heuristics       bool
	Policy           *policy.Policy
	Certificates     bool
	Observation      string // handshake (default), asymmetric or midstream
	Checksums        string // ignore (default), audit or verify
	Continuation     int
	TCPHint, UDPHint string
	CRC32CByteLimit  int // Config.max_crc32c_bytes (the reference default is 4096)
}

// Counts is the summary counter of one run; Order holds its keys in first-touched order, as the reference's
// Counter (a dict) reports them.
type Counts struct {
	Values map[string]int
	Order  []string
}

func (c *Counts) add(key string, n int) {
	if _, seen := c.Values[key]; !seen {
		c.Order = append(c.Order, key)
	}
	c.Values[key] += n
}

func (c *Counts) set(key string, n int) {
	if _, seen := c.Values[key]; !seen {
		c.Order = append(c.Order, key)
	}
	c.Values[key] = n
}

var observationKeys = []string{"status", "transport", "encryption", "application_protocol", "application", "hostname", "offered_alpn", "evidence", "reason", "scope"}
var evidenceKeys = []string{"field", "value", "source", "strength"}
var eventKeys = []string{"revision", "kind", "observation"}

// keyOrders is the key order of every object the reference writes with a fixed layout (dict literals and
// dataclasses.asdict); objects it fills in evidence order are ordered per row (analyzer.Row.Order).
var keyOrders = map[string][]string{
	"frame":                          {"frame", "source", "destination", "message", "classification", "events", "app"},
	"skip":                           {"frame", "status", "reason", "kind"},
	"capture_gap":                    {"type", "scope", "active_connections", "reason", "frame"},
	"stream_end":                     {"type", "source", "destination", "classification", "events"},
	"summary":                        {"summary", "input_quality", "content"},
	"summary.input_quality":          {"adapter", "checksums", "rejected", "flows_marked", "unsupported", "checksums_note"},
	"summary.input_quality.rejected": rejectKinds,
	"summary.content":                {"version", "digest"},
	"session": {"type", "transport", "client", "server", "start", "end", "packets", "client_bytes", "server_bytes", "end_reason",
		"app", "category", "subcategory", "technology", "risk", "characteristics", "base_app", "implicitly_uses", "port_usage", "engine_status",
		"client_protocol", "server_protocol", "encryption", "reasons", "shifted_from", "risks", "attribution", "content", "unknown", "observation",
		"continuation", "input_quality", "layers", "signature_set", "decision", "policy", "fingerprints", "certificate", "hostname"},
	"session.attribution":        {"provider", "kind", "family", "activity", "asserted_by"},
	"session.content":            {"version", "digest"},
	"session.unknown":            {"session", "client", "server"},
	"session.unknown.session":    {"code", "stage", "family", "detail"},
	"session.unknown.client":     {"code", "stage", "family", "detail"},
	"session.unknown.server":     {"code", "stage", "family", "detail"},
	"session.observation":        {"mode", "handshake_observed", "directions_seen", "roles"},
	"session.continuation":       {"client", "server"},
	"session.layers":             {"version", "transport", "outer", "encryption", "inner", "application", "decryption", "capture_quality", "chain", "claims", "note"},
	"session.layers.outer":       {"protocol", "app", "status"},
	"session.layers.encryption":  {"protocol", "offered_alpn", "server_name_asserted", "version"},
	"session.layers.inner":       {"protocol", "app", "status", "source", "authenticated"},
	"session.layers.application": {"name", "category", "status", "basis", "provider", "affiliation", "activity"},
	"session.layers.decryption":  {"state", "reason_code", "authenticated_records"},
	"session.layers.claims[]":    {"field", "source", "strength"},
	"session.decision":           {"first_seconds", "stable_seconds"},
	"session.policy":             {"action", "rule", "reasons", "predicates"},
	"session.policy.predicates": {"identity_basis", "activity", "affiliation", "decryption", "capture_quality", "engine_status", "directions",
		"observation"},
}

// orders resolves a path: the fixed table, the observation and event layouts wherever they occur, then the
// per-row orders of the evidence-ordered maps.
func orders(row map[string][]string) pyjson.Orders {
	return func(path string) []string {
		if keys, ok := keyOrders[path]; ok {
			return keys
		}
		switch {
		case strings.HasSuffix(path, ".classification"), strings.HasSuffix(path, ".observation") && path != "session.observation":
			return observationKeys
		case strings.HasSuffix(path, ".evidence[]"):
			return evidenceKeys
		case strings.HasSuffix(path, ".events[]"):
			return eventKeys
		}
		if keys, ok := row[path]; ok {
			return keys
		}
		return row[strings.TrimPrefix(path, "session.")]
	}
}

var rejectKinds = []string{"link", "network", "fragment", "length", "transport", "truncated", "checksum", "malformed"}

// quality is InputQuality("recorded", checksums).
type quality struct {
	checksums   string
	counts      map[string]int
	flowsMarked int
}

func (q *quality) render() map[string]interface{} {
	rejected := map[string]interface{}{}
	for _, kind := range rejectKinds {
		if q.counts[kind] > 0 {
			rejected[kind] = q.counts[kind]
		}
	}
	note := "verified; failing packets skipped and their flows marked"
	switch q.checksums {
	case transport.Ignore:
		note = "not verified: capture may precede checksum offload"
	case transport.Audit:
		note = "computed; failures counted, packets inspected"
	}
	return map[string]interface{}{"adapter": "recorded", "checksums": q.checksums, "rejected": rejected, "flows_marked": q.flowsMarked,
		"unsupported": []string{"ipv4-fragments", "ipv6", "non-ipv4-link-types"}, "checksums_note": note}
}

func endpoint(e transport.Endpoint) []interface{} { return []interface{}{e.Addr, int(e.Port)} }

func optional(s *string) interface{} {
	if s == nil {
		return nil
	}
	return *s
}

// observationDict is dataclasses.asdict(Observation): evidence rows are objects here, not the parity arrays.
func observationDict(o contracts.Observation) map[string]interface{} {
	evidence := make([]map[string]string, 0, len(o.Evidence))
	for _, e := range o.Evidence {
		evidence = append(evidence, map[string]string{"field": e.Field, "value": e.Value, "source": e.Source, "strength": e.Strength})
	}
	alpn := o.OfferedALPN
	if alpn == nil {
		alpn = []string{}
	}
	return map[string]interface{}{"status": string(o.Status), "transport": o.Transport, "encryption": optional(o.Encryption),
		"application_protocol": optional(o.ApplicationProtocol), "application": optional(o.Application), "hostname": optional(o.Hostname),
		"offered_alpn": alpn, "evidence": evidence, "reason": o.Reason, "scope": o.Scope}
}

func eventDict(e contracts.Event) map[string]interface{} {
	return map[string]interface{}{"revision": e.Revision, "kind": string(e.Kind), "observation": observationDict(e.Observation)}
}

type printer struct {
	w    *bufio.Writer
	json bool
	err  error
}

// row writes one JSON line as json.dumps would: kind names the row layout, order the row's own map orders.
func (p *printer) row(kind string, v map[string]interface{}, order map[string][]string) {
	if p.err == nil {
		_, p.err = p.w.WriteString(pyjson.Dumps(v, kind, orders(order)) + "\n")
	}
}

func (p *printer) line(text string) {
	if p.err == nil {
		_, p.err = p.w.WriteString(text + "\n")
	}
}

// pyStr renders a record value as Python's str() does for the types records hold.
func pyStr(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case string:
		return x
	case *string:
		if x == nil {
			return "None"
		}
		return *x
	}
	return fmt.Sprint(v)
}

func orDash(v interface{}) string {
	if s := pyStr(v); v != nil && s != "" && s != "None" {
		return s
	}
	return "-"
}

func endpointText(v interface{}) string {
	if parts, ok := v.([]interface{}); ok && len(parts) == 2 {
		return fmt.Sprintf("%v:%v", parts[0], parts[1])
	}
	return fmt.Sprint(v)
}

// readableSession is readable_session(record).
func readableSession(r map[string]interface{}) string {
	text := fmt.Sprintf("SESSION %-16s %s -> %s | %s/%s risk=%v port=%v | client=%s server=%s | %v pkts %v+%v B | %v",
		pyStr(r["app"]), endpointText(r["client"]), endpointText(r["server"]), pyStr(r["category"]), pyStr(r["subcategory"]), r["risk"],
		r["port_usage"], orDash(r["client_protocol"]), orDash(r["server_protocol"]), r["packets"], r["client_bytes"], r["server_bytes"],
		r["end_reason"])
	switch risks := r["risks"].(type) {
	case []string:
		if len(risks) > 0 {
			text += " | risks=" + strings.Join(risks, ",")
		}
	case []interface{}:
		if len(risks) > 0 {
			parts := make([]string, 0, len(risks))
			for _, risk := range risks {
				parts = append(parts, pyStr(risk))
			}
			text += " | risks=" + strings.Join(parts, ",")
		}
	}
	if decision, ok := r["policy"].(map[string]interface{}); ok && len(decision) > 0 {
		text += " | policy=" + pyStr(decision["action"])
		if rule := decision["rule"]; rule != nil && pyStr(rule) != "" {
			text += "(" + pyStr(rule) + ")"
		}
	}
	if certificate, ok := r["certificate"].(map[string]interface{}); ok && len(certificate) > 0 {
		keys := make([]string, 0, len(certificate))
		for k := range certificate {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+"="+pyStr(certificate[k]))
		}
		text += " | certificate=" + strings.Join(parts, ",")
	}
	return text
}

func isOSError(err error) bool {
	var pathErr *os.PathError
	return errors.As(err, &pathErr)
}

// Run analyzes the capture at path and writes the rows to out. The returned error is a capture, I/O or option
// error the caller reports as "Capture error: ..."; the rows written before it stand, with a capture-gap row.
func Run(path string, pack *content.Pack, opts Options, out io.Writer) (*Counts, error) {
	if opts.Checksums == "" {
		opts.Checksums = transport.Ignore
	}
	if opts.Checksums != transport.Ignore && opts.Checksums != transport.Audit && opts.Checksums != transport.Verify {
		return nil, fmt.Errorf("unknown checksum policy")
	}
	limit := opts.CRC32CByteLimit
	an, err := analyzer.New(pack, analyzer.Options{Continuation: opts.Continuation, Fingerprints: opts.Fingerprints, Certificates: opts.Certificates,
		Heuristics: opts.Heuristics, Signatures: opts.Signatures, TCPHint: opts.TCPHint, UDPHint: opts.UDPHint, CRC32CByteLimit: &limit,
		IncludeHostnames: opts.IncludeHostnames, Policy: opts.Policy, Rows: true,
		Session: session.Options{MaxConnections: 32, ByteLimit: 65536, IdleTimeout: 60, MaxUDPFlows: -1, Observation: opts.Observation}})
	if err != nil {
		return nil, err
	}
	p := &printer{w: bufio.NewWriterSize(out, 1<<16), json: opts.JSON}
	defer p.w.Flush()
	q := &quality{checksums: opts.Checksums, counts: map[string]int{}}
	counts := &Counts{Values: map[string]int{}}
	sessions := opts.Sessions || opts.Policy != nil

	// drain prints what tracking emitted since the last call: stream ends and session records, in order.
	drain := func() {
		for _, row := range an.Rows {
			if row.Event != nil {
				if opts.JSON {
					p.row("stream_end", map[string]interface{}{"type": "stream_end", "source": endpoint(row.Source), "destination": endpoint(row.Destination),
						"classification": observationDict(row.Event.Observation), "events": []interface{}{eventDict(*row.Event)}}, nil)
				} else {
					p.line(fmt.Sprintf("END %s -> %s | %s | %s", row.Source, row.Destination,
						strings.ToUpper(string(row.Event.Observation.Status)), row.Event.Observation.Reason))
				}
				continue
			}
			if !sessions {
				continue
			}
			if opts.JSON {
				p.row("session", row.Session, row.Order)
			} else {
				p.line(readableSession(row.Session))
			}
		}
		an.Rows = an.Rows[:0]
	}
	gap := func(reason, scope string, number int) {
		tracked, _, _ := an.Tracker.Tables()
		counts.add("connections_discarded_after_gap", tracked)
		// A partial link/IP header cannot safely identify the affected flow. Active labels are retracted
		// explicitly, both directions are discarded and a newly observed handshake is required: capture loss
		// is never turned into a clean end.
		if opts.JSON {
			event := map[string]interface{}{"type": "capture_gap", "scope": scope, "active_connections": tracked, "reason": reason}
			if number > 0 {
				event["frame"] = number
			}
			p.row("capture_gap", event, nil)
		} else {
			p.line("CAPTURE_GAP: " + reason)
		}
		an.Reset()
	}

	number := 0
	readErr := capture.ReadFile(path, func(record capture.Record) error {
		number++
		counts.add("frames", 1)
		if record.Truncated() {
			counts.add("truncated", 1)
			counts.add("skipped", 1)
			q.counts["truncated"]++
			gap("Capture truncation; active stream observations invalidated", "active_connections", number)
			return p.err
		}
		packet, derr := transport.Decode(record.Data, record.Linktype, opts.Checksums)
		if derr != nil {
			reject, ok := derr.(*transport.Reject)
			if !ok {
				return derr
			}
			counts.add("skipped", 1)
			q.counts[reject.Kind]++
			if reject.Endpoints != nil && an.Tracker.NoteInput(reject.Kind, reject.Endpoints) {
				q.flowsMarked++
			}
			drain()
			if !opts.EventsOnly {
				if opts.JSON {
					p.row("skip", map[string]interface{}{"frame": number, "status": "skipped", "reason": reject.Message, "kind": reject.Kind}, nil)
				} else {
					p.line(fmt.Sprintf("#%d SKIP (%s): %s", number, reject.Kind, reject.Message))
				}
			}
			return p.err
		}
		var source, destination transport.Endpoint
		var failures []string
		transportName := "tcp"
		switch pk := packet.(type) {
		case *transport.TCP:
			source, destination, failures = pk.Source, pk.Destination, pk.ChecksumFailures
		case *transport.UDP:
			source, destination, failures = pk.Source, pk.Destination, pk.ChecksumFailures
			transportName = "udp"
		}
		if len(failures) > 0 {
			q.counts["checksum"]++
			if an.Tracker.NoteInput("checksum", &[2]transport.Endpoint{source, destination}) {
				q.flowsMarked++
			}
		}
		counts.add(transportName, 1)
		message := an.Process(record.Timestamp, packet)
		if an.NotPorted != nil {
			return an.NotPorted
		}
		drain()
		if !opts.EventsOnly || len(an.LastEvents) > 0 {
			if opts.JSON {
				events := make([]interface{}, 0, len(an.LastEvents))
				for _, e := range an.LastEvents {
					events = append(events, eventDict(e))
				}
				row := map[string]interface{}{"frame": number, "source": endpoint(source), "destination": endpoint(destination),
					"message": message, "classification": nil, "events": events}
				if an.LastClassification != nil {
					row["classification"] = observationDict(*an.LastClassification)
					port, hasPort := 0, false
					if an.LastServer != nil {
						port, hasPort = int(an.LastServer.Port), true
					}
					row["app"] = appid.SessionVerdictWith(pack, opts.Signatures, an.LastClassification, nil, transportName, port, hasPort,
						appid.Bytes{}, appid.Bytes{}, true, nil).App
				}
				p.row("frame", row, nil)
			} else {
				p.line(fmt.Sprintf("#%d %s", number, message))
			}
		}
		return p.err
	})
	if readErr != nil {
		if p.err != nil {
			return counts, p.err
		}
		if _, isCapture := readErr.(*capture.Error); isCapture || isOSError(readErr) {
			gap("Capture failed; observations may be incomplete", "all_observations_this_capture", 0)
		}
		return counts, readErr
	}
	if err := an.Finish("Capture input EOF before initial message completed"); err != nil {
		return counts, err
	}
	drain()
	if sessions { // the reference counts session records only when it emits them
		counts.set("sessions", an.Sessions)
	} else {
		counts.set("sessions", 0)
	}
	if opts.JSON {
		p.row("summary", map[string]interface{}{"summary": counts.Values, "input_quality": q.render(),
			"content": map[string]interface{}{"version": pack.Release.Version, "digest": pack.Release.Digest}},
			map[string][]string{"summary.summary": counts.Order})
	} else {
		v := counts.Values
		p.line(fmt.Sprintf("\nFrames: %d; TCP: %d; UDP: %d; skipped: %d; sessions: %d", v["frames"], v["tcp"], v["udp"], v["skipped"], v["sessions"]))
	}
	if p.err != nil {
		return counts, p.err
	}
	return counts, p.w.Flush()
}
