package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// schemaRoot is the published schema directory (schemas/*.schema.json).
const schemaRoot = "../../../schemas"

func loadSchema(t *testing.T, name string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(schemaRoot, name+".schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&schema); err != nil {
		t.Fatal(err)
	}
	return schema
}

func decodeLine(line string) (interface{}, error) {
	var v interface{}
	decoder := json.NewDecoder(strings.NewReader(line))
	decoder.UseNumber()
	err := decoder.Decode(&v)
	return v, err
}

// typeOK follows tools/schema_check.py: "integer" is distinct from "number" and booleans are never numbers.
func typeOK(v interface{}, kind string) bool {
	switch kind {
	case "string":
		_, ok := v.(string)
		return ok
	case "integer":
		n, ok := v.(json.Number)
		return ok && !strings.ContainsAny(string(n), ".eE")
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

func resolve(schema, root map[string]interface{}) map[string]interface{} {
	for {
		ref, ok := schema["$ref"].(string)
		if !ok {
			return schema
		}
		target := interface{}(root)
		for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			target = target.(map[string]interface{})[part]
		}
		schema = target.(map[string]interface{})
	}
}

func number(v interface{}) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	return f, err == nil
}

// validate is the Go form of tools/schema_check.py's draft-07 subset: type, enum, const, properties, required,
// additionalProperties, items, minItems, maxItems, minLength, maxLength, minimum, maximum, oneOf, anyOf and local $ref.
func validate(v interface{}, schema, root map[string]interface{}, path string) []string {
	schema = resolve(schema, root)
	var errors []string
	if kinds, ok := schema["type"]; ok {
		list := []interface{}{kinds}
		if many, ok := kinds.([]interface{}); ok {
			list = many
		}
		matched := false
		for _, kind := range list {
			matched = matched || typeOK(v, kind.(string))
		}
		if !matched {
			return []string{fmt.Sprintf("%s: expected %v, got %T", path, kinds, v)}
		}
	}
	if c, ok := schema["const"]; ok && !reflect.DeepEqual(c, v) {
		errors = append(errors, fmt.Sprintf("%s: expected constant %v", path, c))
	}
	if enum, ok := schema["enum"].([]interface{}); ok {
		found := false
		for _, e := range enum {
			found = found || reflect.DeepEqual(e, v)
		}
		if !found {
			errors = append(errors, fmt.Sprintf("%s: %v not in enum", path, v))
		}
	}
	if f, ok := number(v); ok {
		if lo, ok := number(schema["minimum"]); ok && f < lo {
			errors = append(errors, fmt.Sprintf("%s: %v below minimum", path, v))
		}
		if hi, ok := number(schema["maximum"]); ok && f > hi {
			errors = append(errors, fmt.Sprintf("%s: %v above maximum", path, v))
		}
	}
	if s, ok := v.(string); ok {
		if lo, ok := number(schema["minLength"]); ok && float64(len([]rune(s))) < lo {
			errors = append(errors, fmt.Sprintf("%s: shorter than %v", path, lo))
		}
		if hi, ok := number(schema["maxLength"]); ok && float64(len([]rune(s))) > hi {
			errors = append(errors, fmt.Sprintf("%s: longer than %v", path, hi))
		}
	}
	if object, ok := v.(map[string]interface{}); ok {
		properties, _ := schema["properties"].(map[string]interface{})
		if required, ok := schema["required"].([]interface{}); ok {
			for _, key := range required {
				if _, ok := object[key.(string)]; !ok {
					errors = append(errors, fmt.Sprintf("%s: missing required property %q", path, key))
				}
			}
		}
		for key, value := range object {
			if property, ok := properties[key].(map[string]interface{}); ok {
				errors = append(errors, validate(value, property, root, path+"."+key)...)
				continue
			}
			switch extra := schema["additionalProperties"].(type) {
			case bool:
				if !extra {
					errors = append(errors, fmt.Sprintf("%s: unexpected property %q", path, key))
				}
			case map[string]interface{}:
				errors = append(errors, validate(value, extra, root, path+"."+key)...)
			}
		}
	}
	if list, ok := v.([]interface{}); ok {
		if lo, ok := number(schema["minItems"]); ok && float64(len(list)) < lo {
			errors = append(errors, fmt.Sprintf("%s: fewer than %v items", path, lo))
		}
		if hi, ok := number(schema["maxItems"]); ok && float64(len(list)) > hi {
			errors = append(errors, fmt.Sprintf("%s: more than %v items", path, hi))
		}
		switch items := schema["items"].(type) {
		case []interface{}:
			for i := 0; i < len(list) && i < len(items); i++ {
				errors = append(errors, validate(list[i], items[i].(map[string]interface{}), root, fmt.Sprintf("%s[%d]", path, i))...)
			}
		case map[string]interface{}:
			for i, item := range list {
				errors = append(errors, validate(item, items, root, fmt.Sprintf("%s[%d]", path, i))...)
			}
		}
	}
	for _, keyword := range []string{"oneOf", "anyOf"} {
		options, ok := schema[keyword].([]interface{})
		if !ok {
			continue
		}
		matches, closest := 0, []string(nil)
		for _, option := range options {
			outcome := validate(v, option.(map[string]interface{}), root, path)
			if len(outcome) == 0 {
				matches++
			} else if closest == nil || len(outcome) < len(closest) {
				closest = outcome
			}
		}
		if matches == 0 {
			errors = append(errors, fmt.Sprintf("%s: no %s branch matched; closest: %v", path, keyword, closest))
		} else if keyword == "oneOf" && matches > 1 {
			errors = append(errors, fmt.Sprintf("%s: %d oneOf branches matched", path, matches))
		}
	}
	return errors
}

// conform validates every JSON line of output against the named schema and returns the parsed lines.
func conform(t *testing.T, output, name string, schema map[string]interface{}, context string) []map[string]interface{} {
	t.Helper()
	var rows []map[string]interface{}
	for number, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		v, err := decodeLine(line)
		if err != nil {
			t.Fatalf("%s line %d: invalid JSON: %v", context, number+1, err)
		}
		for _, problem := range validate(v, schema, schema, "$") {
			t.Errorf("%s line %d (%s): %s", context, number+1, name, problem)
		}
		row, _ := v.(map[string]interface{})
		rows = append(rows, row)
	}
	return rows
}

var schemaOptionSets = [][]string{
	nil,
	{"--sessions"},
	{"--sessions", "--hostnames", "--fingerprints", "--heuristics", "--certificates"},
	{"--sessions", "--continuation", "64", "--observation", "midstream"},
	{"--sessions", "--policy", "../../../policy-example.json", "--signatures", "../../../signatures-example.json", "--observation", "asymmetric"},
	{"--events-only"},
}

// SR-36: every JSON output line conforms to a published closed schema (additionalProperties false), so no
// undocumented and no payload-bearing field can appear in offline rows, session records or live events.
func TestEveryJSONLineConformsToAClosedSchema(t *testing.T) {
	offline, session, live := loadSchema(t, "offline-row"), loadSchema(t, "session"), loadSchema(t, "live-event")

	// The validator must refuse an undocumented field, so a schema check can never pass vacuously.
	planted := `{"type": "summary", "payload": "secret"}`
	if v, _ := decodeLine(planted); len(validate(v, offline, offline, "$")) == 0 {
		t.Fatal("an undocumented field validated against offline-row")
	}

	captures, err := filepath.Glob("../../../sample*.pcap")
	if err != nil || len(captures) < 4 {
		t.Fatalf("captures %v: %v", captures, err)
	}
	counts := map[string]int{}
	for _, capture := range captures {
		for _, options := range schemaOptionSets {
			var stdout, stderr bytes.Buffer
			args := append(append([]string{"--json"}, options...), capture)
			if status := runAnalyze(args, &stdout, &stderr); status != 0 {
				t.Fatalf("analyze %q: status %d: %s", args, status, stderr.String())
			}
			context := "analyze " + strings.Join(args, " ")
			for _, row := range conform(t, stdout.String(), "offline-row", offline, context) {
				counts["offline-row"]++
				if row["type"] == "session" {
					counts["session"]++
					line, _ := json.Marshal(row)
					conform(t, string(line), "session", session, context)
				}
			}
		}
		data, err := os.ReadFile(capture)
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range [][]string{nil, {"--all-events", "--hostnames", "--fingerprints", "--heuristics", "--certificates"}} {
			var stdout, stderr bytes.Buffer
			args := append([]string{"--stdin", "--replay-clock", "--duration", "0", "--stats-interval", "0", "--json"}, options...)
			if status := runLive(args, bytes.NewReader(data), &stdout, &stderr); status != 0 {
				t.Fatalf("live %q on %s: status %d: %s", args, capture, status, stderr.String())
			}
			counts["live-event"] += len(conform(t, stdout.String(), "live-event", live, "live "+capture+" "+strings.Join(options, " ")))
		}
	}
	t.Logf("validated %v", counts)
	if counts["offline-row"] < 50 || counts["session"] < 10 || counts["live-event"] < 20 {
		t.Fatalf("too few lines validated: %v", counts)
	}
}
