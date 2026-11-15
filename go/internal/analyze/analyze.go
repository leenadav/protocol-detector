// Package analyze ports protocol_adapters/analyze_pcap.analyze: offline inspection of a classic PCAP or pcapng
// capture. It needs no capture privileges and no network access. Rows are the reference's rows: one per
// frame (or only classification changes with EventsOnly), a stream-end row per directional terminal event,
// one session record per TCP connection or UDP flow, capture gaps, and a final summary with the input-quality
// contract (D06) and the content release that classified the run (D08).
package analyze

import (
	"bufio"
	"encoding/json"
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

// Counts is the summary counter of one run.
type Counts map[string]int

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

func (p *printer) row(v map[string]interface{}) {
	if p.err != nil {
		return
	}
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		p.err = err
		return
	}
	_, p.err = p.w.WriteString(b.String())
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
func Run(path string, pack *content.Pack, opts Options, out io.Writer) (Counts, error) {
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
	counts := Counts{}
	sessions := opts.Sessions || opts.Policy != nil

	// drain prints what tracking emitted since the last call: stream ends and session records, in order.
	drain := func() {
		for _, row := range an.Rows {
			if row.Event != nil {
				if opts.JSON {
					p.row(map[string]interface{}{"type": "stream_end", "source": endpoint(row.Source), "destination": endpoint(row.Destination),
						"classification": observationDict(row.Event.Observation), "events": []interface{}{eventDict(*row.Event)}})
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
				p.row(row.Session)
			} else {
				p.line(readableSession(row.Session))
			}
		}
		an.Rows = an.Rows[:0]
	}
	gap := func(reason, scope string, number int) {
		tracked, _, _ := an.Tracker.Tables()
		counts["connections_discarded_after_gap"] += tracked
		// A partial link/IP header cannot safely identify the affected flow. Active labels are retracted
		// explicitly, both directions are discarded and a newly observed handshake is required: capture loss
		// is never turned into a clean end.
		if opts.JSON {
			event := map[string]interface{}{"type": "capture_gap", "scope": scope, "active_connections": tracked, "reason": reason}
			if number > 0 {
				event["frame"] = number
			}
			p.row(event)
		} else {
			p.line("CAPTURE_GAP: " + reason)
		}
		an.Reset()
	}

	number := 0
	readErr := capture.ReadFile(path, func(record capture.Record) error {
		number++
		counts["frames"]++
		if record.Truncated() {
			counts["truncated"]++
			counts["skipped"]++
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
			counts["skipped"]++
			q.counts[reject.Kind]++
			if reject.Endpoints != nil && an.Tracker.NoteInput(reject.Kind, reject.Endpoints) {
				q.flowsMarked++
			}
			drain()
			if !opts.EventsOnly {
				if opts.JSON {
					p.row(map[string]interface{}{"frame": number, "status": "skipped", "reason": reject.Message, "kind": reject.Kind})
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
		counts[transportName]++
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
				p.row(row)
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
	counts["sessions"] = 0 // the reference counts session records only when it emits them
	if sessions {
		counts["sessions"] = an.Sessions
	}
	if opts.JSON {
		summary := map[string]interface{}{}
		for k, v := range counts {
			summary[k] = v
		}
		p.row(map[string]interface{}{"summary": summary, "input_quality": q.render(),
			"content": map[string]interface{}{"version": pack.Release.Version, "digest": pack.Release.Digest}})
	} else {
		p.line(fmt.Sprintf("\nFrames: %d; TCP: %d; UDP: %d; skipped: %d; sessions: %d", counts["frames"], counts["tcp"], counts["udp"],
			counts["skipped"], counts["sessions"]))
	}
	if p.err != nil {
		return counts, p.err
	}
	return counts, p.w.Flush()
}
