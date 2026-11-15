package framed

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func kasaEncode(text string) []byte {
	out, key := make([]byte, len(text)), byte(kasaKey)
	for i := 0; i < len(text); i++ {
		key ^= text[i]
		out[i] = key
	}
	return out
}

// The grammar is CPython's json.loads, not encoding/json: the literals and the digit limit differ.
func TestJSONDocumentGrammar(t *testing.T) {
	big := strings.Repeat("1", pythonMaxIntDigits)
	for text, want := range map[string]bool{
		`{"a":NaN,"b":Infinity,"c":-Infinity}`: true, `{"a":Nan}`: false, `{"a":-Inf}`: false,
		`[1e5,-0,0.5,1E+2,-1.25e-3,0]`: true, `01`: false, `1.`: false, `1e`: false, `+1`: false, `.5`: false, `-`: false,
		` {"a" : [ 1 , 2 ] } `: true, `{"a":1,}`: false, `[1,]`: false, `{} x`: false, `{`: false, ``: false,
		`"\n\"\/\b\f\r\t\\"`: true, `"\x"`: false, `"\u12"`: false, `"\u12g4"`: false, `"😀"`: true,
		`"\ud800"`: true, `"\ud800\uZZZZ"`: false, `"\ud800A"`: true, "\"a\tb\"": false,
		big: true, big + "1": false, "-" + big + "1": false, big + "1.0": true, big + "1e1": true,
		`{'a':1}`: false, `{"a" 1}`: false, `"open`: false, `nul`: false, `true`: true, `null`: true, `false`: true,
		`[[[[[[[[1]]]]]]]]`: true, `[[[[[[[[[1]]]]]]]]]`: false,
	} {
		if _, ok := jsonDocument([]byte(text), kasaMaxDepth); ok != want {
			t.Errorf("jsonDocument(%.40q) = %v, want %v", text, ok, want)
		}
	}
}

func TestJSONDocumentKeys(t *testing.T) {
	top, ok := jsonDocument([]byte(`{"b":{},"a":1,"system":[],"b":2,"a":{}}`), kasaMaxDepth)
	if !ok || !top.object || strings.Join(top.keys, ",") != "b,a,system" {
		t.Fatalf("keys %v ok %v", top.keys, ok)
	}
	if top.objectValue["b"] || !top.objectValue["a"] || top.objectValue["system"] {
		t.Fatalf("a repeated key keeps its last value: %v", top.objectValue)
	}
}

func TestKasaDatagram(t *testing.T) {
	m, err := kasaDatagram(kasaEncode(`{"system":{"get_sysinfo":{"alias":"x"}},"emeter":{}}`), Limits{})
	if err != nil || m.Protocol != "tplink-smarthome" || m.Evidence[1].Value != "system" || m.Evidence[2].Value != "2" {
		t.Fatalf("match %+v err %v", m, err)
	}
	for _, r := range m.Evidence {
		if strings.Contains(r.Value, "alias") || r.Value == "x" {
			t.Fatalf("a value reached the evidence: %+v", r)
		}
	}
	for text, want := range map[string]string{
		`{"a":1}`:                       "too short",
		"{\"system\":{\"a\":\"\x01\"}}": "printable ASCII",
		`{"system":` + strings.Repeat(`{"a":`, 8) + `1` + strings.Repeat(`}`, 9): "nesting budget",
		`{"system":{},}`:           "not one JSON document",
		`{"system":1,"other":{}}`:  "object of module objects",
		`{"system":{},"other":{}}`: "outside the documented vocabulary",
	} {
		if _, err := kasaDatagram(kasaEncode(text), Limits{}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%.30q: error %v, want %q", text, err, want)
		}
	}
}

// FuzzKasaNeverPanics: no panic on any datagram, and where neither Python-only rule applies (NaN/Infinity literals,
// the integer digit limit, lone surrogates and repeated keys are all accepted by both) the verdict agrees with
// encoding/json on printable ASCII.
func FuzzKasaNeverPanics(f *testing.F) {
	f.Add(kasaEncode(`{"system":{"get_sysinfo":{}},"emeter":{"get_realtime":{}}}`))
	f.Add(kasaEncode(`{"system":{"a":[1e5,-0,"😀",NaN,null]}}`))
	f.Add([]byte{0xd0, 0xf2, 0x81, 0xf8, 0x8b, 0xff, 0x9a, 0xf7})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = kasaDatagram(data, Limits{})
		text, key := make([]byte, len(data)), byte(kasaKey)
		for i, b := range data {
			text[i], key = b^key, b
			if text[i] < 32 || text[i] > 126 {
				return
			}
		}
		_, ours := jsonDocument(text, math.MaxInt32)
		s := string(text)
		if strings.Contains(s, "NaN") || strings.Contains(s, "Infinity") || len(s) > pythonMaxIntDigits {
			return
		}
		if std := json.Valid(text); std != ours {
			t.Fatalf("jsonDocument(%q) = %v, encoding/json says %v", s, ours, std)
		}
	})
}
