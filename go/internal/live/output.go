package live

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/analyze"
	"github.com/leenadav/protocol-detector/go/internal/pyjson"
	"github.com/leenadav/protocol-detector/go/internal/telemetry"
)

// eventOrders is the key order of every event layout the reference writes from dict literals.
var eventOrders = map[string][]string{
	"classification": {"type", "timestamp", "source", "destination", "transport", "status", "protocol", "app", "risks", "policy", "fingerprints",
		"certificate", "event", "scope", "candidate_hint", "reason"},
	"retired":     {"type", "timestamp", "source", "destination", "transport", "status", "protocol", "app", "scope", "candidate_hint", "reason", "boundary"},
	"invalidated": {"type", "timestamp", "source", "destination", "transport", "status", "protocol", "scope", "reason"},
	"capture_gap": {"type", "active_connections", "scope", "reason", "session_ids", "capture_id"},
	"summary": {"type", "elapsed_seconds", "counts", "protocols", "apps", "risks", "policy", "active_connections", "active_udp_flows", "capture_stats",
		"telemetry", "input_quality", "content", "scope", "capture_quality", "stop_reason"},
	"summary.telemetry":     {"counters", "histograms"},
	"summary.input_quality": {"adapter", "checksums", "rejected", "flows_marked", "unsupported", "checksums_note"},
	"summary.content":       {"version", "digest"},
	"started": {"type", "reason", "interface", "filter", "tcp_hint", "udp_hint", "signatures", "crc32c_byte_limit", "max_reassembly_buffer_bytes",
		"content"},
	"started.content": {"version", "digest"},
	"error":           {"type", "reason"},
}

// JSON is one event as json.dumps writes it.
func JSON(e Event) string {
	if e.Raw != "" {
		return e.Raw
	}
	if e.Kind == "session" {
		base := analyze.Orders(e.Order)
		keys := append(analyze.SessionKeys(), "capture_id", "session_id", "generation")
		return pyjson.Dumps(e.Fields, "session", func(path string) []string {
			if path == "session" {
				return keys
			}
			return base(path)
		})
	}
	return pyjson.Dumps(e.Fields, e.Kind, func(path string) []string {
		if keys, ok := e.Order[path]; ok {
			return keys
		}
		if keys, ok := eventOrders[path]; ok {
			return keys
		}
		switch {
		case path == "summary.input_quality.rejected":
			return analyze.RejectKinds()
		case strings.HasPrefix(path, "summary.telemetry.histograms."):
			return telemetry.HistogramKeys
		}
		return nil
	})
}

func text(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case string:
		return x
	case bool:
		if x {
			return "True"
		}
		return "False"
	case float64:
		return pyjson.Float(x)
	}
	return fmt.Sprint(v)
}

func endpointText(v interface{}) string {
	pair, _ := v.([]interface{})
	if len(pair) != 2 {
		return ""
	}
	return text(pair[0]) + ":" + text(pair[1])
}

// sortedItems is ' '.join('{}={}'.format(k, v) for k, v in sorted(m.items())) with the given separator.
func sortedItems(m map[string]interface{}, separator string) string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+text(m[key]))
	}
	return strings.Join(parts, separator)
}

func count(m map[string]interface{}, key string) int {
	n, _ := m[key].(int)
	return n
}

// Readable writes one event as the text form (live_capture.readable).
func Readable(w io.Writer, e Event) {
	f := e.Fields
	kind, _ := f["type"].(string)
	switch kind {
	case "classification":
		suffix := ""
		if candidate, ok := f["candidate_hint"].(string); ok && candidate != "" {
			suffix = " [candidate: " + candidate + "]"
		}
		if f["status"] == "incomplete" {
			suffix += " | " + text(f["reason"])
		}
		if fingerprints, ok := f["fingerprints"].(map[string]interface{}); ok && len(fingerprints) > 0 {
			suffix += " | " + sortedItems(fingerprints, " ")
		}
		if certificate, ok := f["certificate"].(map[string]interface{}); ok && len(certificate) > 0 {
			suffix += " | certificate=" + sortedItems(certificate, ",")
		}
		if risks, ok := f["risks"].([]string); ok && len(risks) > 0 {
			suffix += " | risks=" + strings.Join(risks, ",")
		}
		if policy, ok := f["policy"].(string); ok && policy != "" {
			suffix += " | policy=" + policy
		}
		protocol, app := "unknown", "-"
		if p, ok := f["protocol"].(string); ok && p != "" {
			protocol = p
		}
		if a, ok := f["app"].(string); ok && a != "" {
			app = a
		}
		fmt.Fprintf(w, "%-12s %-13s %-17s %s -> %s%s\n", strings.ToUpper(text(f["status"])), protocol, app, endpointText(f["source"]),
			endpointText(f["destination"]), suffix)
	case "session":
		fmt.Fprintln(w, analyze.ReadableSession(f))
	case "summary", "progress":
		counts, _ := f["counts"].(map[string]interface{})
		identifications := "no identifications"
		if protocols, ok := f["protocols"].(map[string]interface{}); ok && len(protocols) > 0 {
			parts := make([]string, 0, len(protocols))
			for _, key := range e.Order["summary.protocols"] {
				name := key
				if name == "null" {
					name = "None"
				}
				parts = append(parts, name+"="+text(protocols[key]))
			}
			identifications = strings.Join(parts, ", ")
		}
		elapsed, _ := f["elapsed_seconds"].(float64)
		fmt.Fprintf(w, "%s %.1fs | packets=%d identified=%d skipped=%d truncated=%d limits=%d invalidated=%d incomplete=%d | %s\n",
			strings.ToUpper(kind), elapsed, count(counts, "packets"), count(counts, "identified"),
			count(counts, "unsupported_or_malformed_packets")+count(counts, "tcp_without_start"), count(counts, "truncated"),
			count(counts, "connection_limit")+count(counts, "budget_exhausted"), count(counts, "stream_invalidations"), count(counts, "incomplete"),
			identifications)
		for _, section := range []struct{ key, title string }{{"apps", "Applications: "}, {"risks", "Flow risks: "}, {"policy", "Policy decisions: "}} {
			if values, ok := f[section.key].(map[string]interface{}); ok && len(values) > 0 {
				fmt.Fprintln(w, section.title+sortedItems(values, ", "))
			}
		}
		if kind == "summary" {
			if stats, ok := f["capture_stats"].(map[string]interface{}); ok && len(stats) > 0 {
				fmt.Fprintln(w, "Capture statistics: "+pyjson.Dumps(stats, "stats", func(string) []string { return e.Order["summary.capture_stats"] }))
			} else {
				fmt.Fprintln(w, "Capture statistics: unavailable; absence of capture loss is not established")
			}
		}
	default:
		reason, _ := f["reason"].(string)
		fmt.Fprintln(w, strings.ToUpper(kind)+": "+reason)
	}
}
