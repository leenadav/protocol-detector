package live

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/analyze"
	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/policy"
	"github.com/leenadav/protocol-detector/go/internal/testframes"
)

// SR-9: live output and session records omit the hostname unless it is explicitly enabled; enabling it adds the
// asserted name to session records only, never to classification events.
func TestSecurityHostnamesAreOptInForLiveOutputAndSessionRecords(t *testing.T) {
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, include := range []bool{false, true} {
		var events []Event
		m, err := NewMonitor(pack, Options{MaxConnections: 8, ByteLimit: 16384, IdleTimeout: 5, CRC32CByteLimit: 4096, Observation: "handshake",
			Checksums: "ignore", IncludeHostnames: include}, "0123456789abcdef", func(e Event) { events = append(events, e) })
		if err != nil {
			t.Fatal(err)
		}
		feed(t, m, closed(1000), 10, 1)
		if err := m.End("stop"); err != nil {
			t.Fatal(err)
		}
		sessions, classifications := 0, 0
		for _, e := range events {
			text := e.Raw
			if text == "" {
				raw, err := json.Marshal(e.Fields)
				if err != nil {
					t.Fatal(err)
				}
				text = string(raw)
			}
			leaks := strings.Contains(text, "example.invalid") || strings.Contains(text, "Host:")
			switch e.Kind {
			case "session":
				sessions++
				_, has := e.Fields["hostname"]
				if has != include || leaks != include {
					t.Fatalf("include=%v: session record hostname present=%v leaks=%v: %s", include, has, leaks, text)
				}
				if include && e.Fields["hostname"] != "example.invalid" {
					t.Fatalf("session hostname %v", e.Fields["hostname"])
				}
			case "classification":
				classifications++
				if leaks {
					t.Fatalf("include=%v: classification event carries the hostname: %s", include, text)
				}
			default:
				if leaks {
					t.Fatalf("include=%v: %s event carries the hostname: %s", include, e.Kind, text)
				}
			}
		}
		if sessions != 1 || classifications == 0 {
			t.Fatalf("include=%v: %d session and %d classification events", include, sessions, classifications)
		}
	}
}

// SR-32: policy decisions are carried as labels in session records, classification events and the summary; the
// record keeps the action, rule, reasons and predicates and no payload byte. Without a policy there is no decision.
func TestSecurityPolicyDecisionsAreCarriedInRecordsEventsAndSummary(t *testing.T) {
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	example, err := policy.FromPath("../../../policy-example.json", pack)
	if err != nil {
		t.Fatal(err)
	}
	telnet := []byte{0xff, 0xfd, 0x18, 0xff, 0xfb, 0x01}
	c, s, n := uint32(1000), uint32(9000), uint32(len(telnet))
	frames := [][]byte{
		testframes.TCP("192.0.2.10", 52000, "198.51.100.20", 8080, c, 0, 0x02, nil),
		testframes.TCP("198.51.100.20", 8080, "192.0.2.10", 52000, s, c+1, 0x12, nil),
		testframes.TCP("192.0.2.10", 52000, "198.51.100.20", 8080, c+1, s+1, 0x18, telnet),
		testframes.TCP("192.0.2.10", 52000, "198.51.100.20", 8080, c+1+n, s+1, 0x11, nil),
		testframes.TCP("198.51.100.20", 8080, "192.0.2.10", 52000, s+1, c+2+n, 0x11, nil),
	}
	for _, p := range []*policy.Policy{example, nil} {
		var events []Event
		m, err := NewMonitor(pack, Options{MaxConnections: 8, ByteLimit: 16384, IdleTimeout: 5, CRC32CByteLimit: 4096, Observation: "handshake",
			Checksums: "ignore", Policy: p}, "0123456789abcdef", func(e Event) { events = append(events, e) })
		if err != nil {
			t.Fatal(err)
		}
		feed(t, m, frames, 10, 1)
		if err := m.End("stop"); err != nil {
			t.Fatal(err)
		}
		var session, classification map[string]interface{}
		for _, e := range events {
			if e.Kind == "session" && session == nil {
				session = e.Fields
			}
			if e.Kind == "classification" && classification == nil {
				classification = e.Fields
			}
		}
		if session == nil || classification == nil || session["app"] != "telnet" {
			t.Fatalf("policy %v: session %v classification %v", p != nil, session, classification)
		}
		summary := m.Summary(1, true, nil, nil).Fields["policy"].(map[string]interface{})
		if p == nil {
			if _, has := session["policy"]; has || classification["policy"] != nil || len(summary) != 0 {
				t.Fatalf("no policy: session %v classification %v summary %v", session["policy"], classification["policy"], summary)
			}
			continue
		}
		decision, _ := session["policy"].(map[string]interface{})
		if decision["action"] != "deny" || decision["rule"] != "deny-remote-access" ||
			!reflect.DeepEqual(decision["reasons"], []string{"rule 'deny-remote-access' matched telnet"}) {
			t.Fatalf("session decision %v", decision)
		}
		if predicates, _ := decision["predicates"].(map[string]interface{}); predicates["identity_basis"] != "structural" {
			t.Fatalf("predicates %v", decision["predicates"])
		}
		if classification["policy"] != "deny" || summary["deny"] != 1 {
			t.Fatalf("classification %v summary %v", classification["policy"], summary)
		}
		raw, _ := json.Marshal(decision)
		if strings.Contains(string(raw), "\\u00ff") || strings.Contains(string(raw), "fffd") {
			t.Fatalf("decision carries payload bytes: %s", raw)
		}
	}
}

// schemaValidate is tools/schema_check.validate over decoded JSON (json.Number keeps integers distinct): type,
// enum, const, properties, required, additionalProperties, items, minItems, maxItems, minimum, maximum, minLength,
// maxLength, oneOf, anyOf and local $ref. It returns "path: message" problems; none means the value conforms.
func schemaValidate(v interface{}, schema, root map[string]interface{}, path string) []string {
	for {
		ref, ok := schema["$ref"].(string)
		if !ok {
			break
		}
		target := interface{}(root)
		for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			target = target.(map[string]interface{})[part]
		}
		schema = target.(map[string]interface{})
	}
	typeOK := func(kind string) bool {
		switch kind {
		case "string":
			_, ok := v.(string)
			return ok
		case "integer":
			n, ok := v.(json.Number)
			_, err := n.Int64()
			return ok && err == nil
		case "number":
			_, ok := v.(json.Number)
			return ok
		case "boolean":
			_, ok := v.(bool)
			return ok
		case "array":
			_, ok := v.([]interface{})
			return ok
		case "object":
			_, ok := v.(map[string]interface{})
			return ok
		case "null":
			return v == nil
		}
		return false
	}
	if kinds, ok := schema["type"]; ok {
		var list []string
		if s, isString := kinds.(string); isString {
			list = []string{s}
		} else {
			for _, k := range kinds.([]interface{}) {
				list = append(list, k.(string))
			}
		}
		matched := false
		for _, k := range list {
			matched = matched || typeOK(k)
		}
		if !matched {
			return []string{fmt.Sprintf("%s: expected %s, got %T", path, strings.Join(list, "/"), v)}
		}
	}
	var problems []string
	same := func(a, b interface{}) bool { return reflect.DeepEqual(fmt.Sprint(a), fmt.Sprint(b)) }
	if c, ok := schema["const"]; ok && !same(c, v) {
		problems = append(problems, fmt.Sprintf("%s: expected constant %v", path, c))
	}
	if e, ok := schema["enum"].([]interface{}); ok {
		found := false
		for _, item := range e {
			found = found || (same(item, v) && (item == nil) == (v == nil))
		}
		if !found {
			problems = append(problems, fmt.Sprintf("%s: %v not in enum", path, v))
		}
	}
	if n, ok := v.(json.Number); ok {
		f, _ := n.Float64()
		if m, ok := schema["minimum"].(json.Number); ok {
			if lo, _ := m.Float64(); f < lo {
				problems = append(problems, fmt.Sprintf("%s: %v below minimum %v", path, n, m))
			}
		}
		if m, ok := schema["maximum"].(json.Number); ok {
			if hi, _ := m.Float64(); f > hi {
				problems = append(problems, fmt.Sprintf("%s: %v above maximum %v", path, n, m))
			}
		}
	}
	if s, ok := v.(string); ok {
		if m, ok := schema["maxLength"].(json.Number); ok {
			if hi, _ := m.Int64(); int64(len([]rune(s))) > hi {
				problems = append(problems, fmt.Sprintf("%s: longer than %v", path, m))
			}
		}
		if m, ok := schema["minLength"].(json.Number); ok {
			if lo, _ := m.Int64(); int64(len([]rune(s))) < lo {
				problems = append(problems, fmt.Sprintf("%s: shorter than %v", path, m))
			}
		}
	}
	if object, ok := v.(map[string]interface{}); ok {
		properties, _ := schema["properties"].(map[string]interface{})
		if required, ok := schema["required"].([]interface{}); ok {
			for _, key := range required {
				if _, has := object[key.(string)]; !has {
					problems = append(problems, fmt.Sprintf("%s: missing required property %q", path, key))
				}
			}
		}
		for key, value := range object {
			if sub, ok := properties[key].(map[string]interface{}); ok {
				problems = append(problems, schemaValidate(value, sub, root, path+"."+key)...)
			} else if extra, ok := schema["additionalProperties"]; ok {
				if extra == false {
					problems = append(problems, fmt.Sprintf("%s: unexpected property %q", path, key))
				} else if sub, ok := extra.(map[string]interface{}); ok {
					problems = append(problems, schemaValidate(value, sub, root, path+"."+key)...)
				}
			}
		}
	}
	if array, ok := v.([]interface{}); ok {
		if m, ok := schema["minItems"].(json.Number); ok {
			if lo, _ := m.Int64(); int64(len(array)) < lo {
				problems = append(problems, fmt.Sprintf("%s: fewer than %v items", path, m))
			}
		}
		if m, ok := schema["maxItems"].(json.Number); ok {
			if hi, _ := m.Int64(); int64(len(array)) > hi {
				problems = append(problems, fmt.Sprintf("%s: more than %v items", path, m))
			}
		}
		switch items := schema["items"].(type) {
		case []interface{}:
			for i := 0; i < len(array) && i < len(items); i++ {
				problems = append(problems, schemaValidate(array[i], items[i].(map[string]interface{}), root, fmt.Sprintf("%s[%d]", path, i))...)
			}
		case map[string]interface{}:
			for i, item := range array {
				problems = append(problems, schemaValidate(item, items, root, fmt.Sprintf("%s[%d]", path, i))...)
			}
		}
	}
	for _, keyword := range []string{"oneOf", "anyOf"} {
		options, ok := schema[keyword].([]interface{})
		if !ok {
			continue
		}
		matches := 0
		for _, option := range options {
			if len(schemaValidate(v, option.(map[string]interface{}), root, path)) == 0 {
				matches++
			}
		}
		if matches == 0 || (keyword == "oneOf" && matches > 1) {
			problems = append(problems, fmt.Sprintf("%s: %d %s branches matched", path, matches, keyword))
		}
	}
	return problems
}

func loadSchema(t *testing.T, name string) map[string]interface{} {
	t.Helper()
	raw, err := os.ReadFile("../../../schemas/" + name + ".schema.json")
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var schema map[string]interface{}
	if err := decoder.Decode(&schema); err != nil {
		t.Fatal(err)
	}
	return schema
}

func conformLines(t *testing.T, label, schemaName string, lines []string) []map[string]interface{} {
	t.Helper()
	schema := loadSchema(t, schemaName)
	var out []map[string]interface{}
	for i, line := range lines {
		decoder := json.NewDecoder(strings.NewReader(line))
		decoder.UseNumber()
		var value map[string]interface{}
		if err := decoder.Decode(&value); err != nil {
			t.Fatalf("%s line %d: %v: %s", label, i+1, err, line)
		}
		if problems := schemaValidate(value, schema, schema, "$"); len(problems) > 0 {
			t.Fatalf("%s line %d does not conform to %s: %v\n%s", label, i+1, schemaName, problems, line)
		}
		out = append(out, value)
	}
	return out
}

// SR-36: every JSON output line conforms to its published closed schema (additionalProperties false), so no
// undocumented or payload-bearing field can appear in live events, offline rows or session records, under every
// output option. The validator itself refuses an undocumented field.
func TestSecurityJSONOutputConformsToThePublishedClosedSchemas(t *testing.T) {
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	example, err := policy.FromPath("../../../policy-example.json", pack)
	if err != nil {
		t.Fatal(err)
	}
	sample, err := os.ReadFile("../../../sample-expanded.pcap")
	if err != nil {
		t.Fatal(err)
	}
	base := Options{MaxConnections: 4096, ByteLimit: 16384, IdleTimeout: 60, CRC32CByteLimit: 4096, Observation: "handshake", Checksums: "ignore"}
	variants := map[string]func(o *Options){
		"default":    func(o *Options) {},
		"all-events": func(o *Options) { o.AllEvents = true },
		"options": func(o *Options) {
			o.Heuristics, o.Fingerprints, o.IncludeHostnames, o.Certificates = true, true, true, true
		},
		"policy": func(o *Options) { o.Policy = example },
	}
	for name, change := range variants {
		cfg := RunConfig{Options: base, ReplayClock: true, CaptureID: "0123456789abcdef"}
		change(&cfg.Options)
		var lines []string
		if _, err := Run(bytes.NewReader(sample), nil, nil, pack, cfg, func(e Event) { lines = append(lines, JSON(e)) }); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		events := conformLines(t, "live "+name, "live-event", lines)
		if len(events) < 10 || events[len(events)-1]["type"] != "summary" {
			t.Fatalf("live %s: %d events", name, len(events))
		}
		sessions := 0
		for _, e := range events {
			if e["type"] == "session" {
				sessions++
			}
		}
		if sessions == 0 {
			t.Fatalf("live %s: no session event", name)
		}
	}
	offline := map[string]analyze.Options{
		"default":     {},
		"events-only": {EventsOnly: true},
		"sessions":    {Sessions: true},
		"everything":  {EventsOnly: true, Sessions: true, IncludeHostnames: true, Fingerprints: true, Certificates: true},
		"policy":      {Sessions: true, Policy: example, Heuristics: true},
	}
	for name, opts := range offline {
		opts.JSON, opts.Observation, opts.Checksums, opts.CRC32CByteLimit = true, "handshake", "ignore", 4096
		var out bytes.Buffer
		if _, err := analyze.Run("../../../sample-expanded.pcap", pack, opts, &out); err != nil {
			t.Fatalf("offline %s: %v", name, err)
		}
		lines := strings.Split(strings.TrimSpace(out.String()), "\n")
		rows := conformLines(t, "offline "+name, "offline-row", lines)
		var sessionLines []string
		for i, row := range rows {
			if row["type"] == "session" {
				sessionLines = append(sessionLines, lines[i])
				if _, has := row["policy"]; opts.Policy != nil && !has {
					t.Fatalf("offline %s: session without its policy decision", name)
				}
			}
		}
		if opts.Sessions && len(sessionLines) == 0 {
			t.Fatalf("offline %s: no session rows", name)
		}
		conformLines(t, "offline "+name+" sessions", "session", sessionLines)
	}
	schema := loadSchema(t, "session")
	decoder := json.NewDecoder(strings.NewReader(`{"payload": "x"}`))
	decoder.UseNumber()
	var extra map[string]interface{}
	_ = decoder.Decode(&extra)
	if problems := schemaValidate(extra, schema, schema, "$"); len(problems) == 0 {
		t.Fatal("the session schema accepts an undocumented payload field")
	}
}
