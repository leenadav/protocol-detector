package framed

import (
	"strconv"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// TP-Link Smart Home over UDP (smarthome.kasa): a JSON object under the published XOR autokey. The plaintext must be
// printable ASCII, nest at most kasaMaxDepth levels and be exactly one JSON document as Python's json.loads defines
// it; jsonDocument ports that grammar (see its comment) because encoding/json differs on NaN/Infinity literals and
// on the integer digit limit. Only fixed module names are emitted.

const (
	kasaKey      = 171
	kasaMaxDepth = 8
	// The profile's integer digit limit (smarthome.MAX_JSON_INTEGER_DIGITS). It began as CPython's own int() limit
	// (sys.int_info.default_max_str_digits); since review R6 the Python validator enforces it explicitly through a
	// parse_int hook, so the verdict no longer depends on the interpreter's patch release.
	pythonMaxIntDigits = 4300
)

var kasaModules = map[string]bool{"system": true, "emeter": true, "schedule": true, "count_down": true, "anti_theft": true,
	"time": true, "cnCloud": true, "netif": true, "context": true, "smartlife.iot.common.emeter": true,
	"smartlife.iot.smartbulb.lightingservice": true, "smartlife.iot.lightStrip": true, "smartlife.iot.dimmer": true,
	"smartlife.iot.common.schedule": true, "smartlife.iot.common.timesetting": true, "smartlife.iot.common.cloud": true,
	"smartlife.iot.common.softaponboarding": true, "smartlife.iot.LAS": true, "smartlife.iot.PIR": true}

func init() { DatagramValidators["tplink-smarthome"] = kasaDatagram }

func kasaDatagram(data []byte, _ Limits) (*Datagram, error) {
	if len(data) < 8 {
		return nil, parsing.Unsupported("TP-Link Smart Home datagram is too short")
	}
	text := make([]byte, 0, len(data))
	key, depth, quoted, escaped := byte(kasaKey), 0, false, false
	for _, b := range data { // one pass: undo the autokey, check printable ASCII and bound nesting depth
		plain := b ^ key
		key = b
		if plain < 32 || plain > 126 {
			return nil, parsing.Unsupported("TP-Link Smart Home plaintext must be printable ASCII JSON")
		}
		switch {
		case escaped:
			escaped = false
		case quoted:
			escaped, quoted = plain == '\\', plain != '"'
		case plain == '"':
			quoted = true
		case plain == '{' || plain == '[':
			if depth++; depth > kasaMaxDepth {
				return nil, parsing.Malformed("TP-Link Smart Home JSON exceeds the nesting budget")
			}
		case plain == '}' || plain == ']':
			depth--
		}
		text = append(text, plain)
	}
	top, ok := jsonDocument(text, kasaMaxDepth)
	if !ok {
		return nil, parsing.Malformed("TP-Link Smart Home plaintext is not one JSON document")
	}
	if !top.object || len(top.keys) == 0 {
		return nil, parsing.Malformed("TP-Link Smart Home message must be an object of module objects")
	}
	for _, k := range top.keys {
		if !top.objectValue[k] {
			return nil, parsing.Malformed("TP-Link Smart Home message must be an object of module objects")
		}
	}
	for _, k := range top.keys {
		if !kasaModules[k] {
			return nil, parsing.Unsupported("TP-Link Smart Home message names a module outside the documented vocabulary")
		}
	}
	return headerMatch("tplink-smarthome", "TP-Link Smart Home JSON (autokey 171) parsed with documented module names; "+
		"values such as alias, MAC, device ID and location are never emitted",
		[2]string{"tplink_module", top.keys[0]}, [2]string{"tplink_modules", strconv.Itoa(len(top.keys))}), nil
}

// jsonTop is what the validator reads from a parsed document: whether it is an object, its distinct keys in first
// insertion order and, per key, whether its last value is an object (a Python dict keeps the first position and the
// last value of a repeated key).
type jsonTop struct {
	object      bool
	keys        []string
	objectValue map[string]bool
}

// jsonDocument reports whether text is exactly one JSON document under the grammar of CPython's json.loads with its
// defaults (C scanner): the RFC 8259 grammar plus the NaN, Infinity and -Infinity literals, whitespace " \t\n\r",
// \uXXXX escapes with exactly four hex digits (lone surrogates accepted), repeated keys accepted, and an integer
// literal limited to pythonMaxIntDigits digits. maxDepth bounds recursion; the caller has already bounded nesting.
func jsonDocument(text []byte, maxDepth int) (jsonTop, bool) {
	p := jsonScanner{s: text, maxDepth: maxDepth}
	p.space()
	top, ok := p.value(0, true)
	if !ok {
		return jsonTop{}, false
	}
	p.space()
	return top, p.i == len(p.s)
}

type jsonScanner struct {
	s        []byte
	i        int
	maxDepth int
}

func (p *jsonScanner) space() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t' || p.s[p.i] == '\n' || p.s[p.i] == '\r') {
		p.i++
	}
}

func (p *jsonScanner) literal(word string) bool {
	if len(p.s)-p.i >= len(word) && string(p.s[p.i:p.i+len(word)]) == word {
		p.i += len(word)
		return true
	}
	return false
}

// value parses one value at p.i. For the top-level value it also collects the object summary.
func (p *jsonScanner) value(depth int, top bool) (jsonTop, bool) {
	if p.i >= len(p.s) {
		return jsonTop{}, false
	}
	switch c := p.s[p.i]; {
	case c == '"':
		_, ok := p.str()
		return jsonTop{}, ok
	case c == '{':
		return p.object(depth, top)
	case c == '[':
		return jsonTop{}, p.array(depth)
	case c == 'n':
		return jsonTop{}, p.literal("null")
	case c == 't':
		return jsonTop{}, p.literal("true")
	case c == 'f':
		return jsonTop{}, p.literal("false")
	case c == 'N':
		return jsonTop{}, p.literal("NaN")
	case c == 'I':
		return jsonTop{}, p.literal("Infinity")
	case c == '-' && p.i+1 < len(p.s) && p.s[p.i+1] == 'I':
		return jsonTop{}, p.literal("-Infinity")
	default:
		return jsonTop{}, p.number()
	}
}

func (p *jsonScanner) object(depth int, top bool) (jsonTop, bool) {
	if depth >= p.maxDepth {
		return jsonTop{}, false
	}
	out := jsonTop{object: true}
	if top {
		out.objectValue = map[string]bool{}
	}
	p.i++ // '{'
	p.space()
	if p.i < len(p.s) && p.s[p.i] == '}' {
		p.i++
		return out, true
	}
	for {
		if p.i >= len(p.s) || p.s[p.i] != '"' {
			return jsonTop{}, false
		}
		key, ok := p.str()
		if !ok {
			return jsonTop{}, false
		}
		p.space()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return jsonTop{}, false
		}
		p.i++
		p.space()
		child, ok := p.value(depth+1, false)
		if !ok {
			return jsonTop{}, false
		}
		if top {
			if _, seen := out.objectValue[key]; !seen {
				out.keys = append(out.keys, key)
			}
			out.objectValue[key] = child.object
		}
		p.space()
		if p.i >= len(p.s) {
			return jsonTop{}, false
		}
		if p.s[p.i] == '}' {
			p.i++
			return out, true
		}
		if p.s[p.i] != ',' {
			return jsonTop{}, false
		}
		p.i++
		p.space()
	}
}

func (p *jsonScanner) array(depth int) bool {
	if depth >= p.maxDepth {
		return false
	}
	p.i++ // '['
	p.space()
	if p.i < len(p.s) && p.s[p.i] == ']' {
		p.i++
		return true
	}
	for {
		if _, ok := p.value(depth+1, false); !ok {
			return false
		}
		p.space()
		if p.i >= len(p.s) {
			return false
		}
		if p.s[p.i] == ']' {
			p.i++
			return true
		}
		if p.s[p.i] != ',' {
			return false
		}
		p.i++
		p.space()
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// number ports _match_number_unicode: -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?. A fraction or exponent that
// does not complete ends the number before it; the caller then rejects the leftover character.
func (p *jsonScanner) number() bool {
	i := p.i
	if i < len(p.s) && p.s[i] == '-' {
		i++
	}
	start := i
	switch {
	case i < len(p.s) && p.s[i] == '0':
		i++
	case i < len(p.s) && p.s[i] >= '1' && p.s[i] <= '9':
		for i < len(p.s) && isDigit(p.s[i]) {
			i++
		}
	default:
		return false
	}
	digits, float := i-start, false
	if i+1 < len(p.s) && p.s[i] == '.' && isDigit(p.s[i+1]) {
		float = true
		for i += 2; i < len(p.s) && isDigit(p.s[i]); i++ {
		}
	}
	if i < len(p.s) && (p.s[i] == 'e' || p.s[i] == 'E') {
		j := i + 1
		if j < len(p.s) && (p.s[j] == '-' || p.s[j] == '+') {
			j++
		}
		if j < len(p.s) && isDigit(p.s[j]) {
			float = true
			for i = j; i < len(p.s) && isDigit(p.s[i]); i++ {
			}
		}
	}
	if !float && digits > pythonMaxIntDigits {
		return false
	}
	p.i = i
	return true
}

func hexValue(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10, true
	}
	return 0, false
}

func (p *jsonScanner) hex4(at int) (int, bool) {
	if at+4 > len(p.s) {
		return 0, false
	}
	v := 0
	for _, c := range p.s[at : at+4] {
		d, ok := hexValue(c)
		if !ok {
			return 0, false
		}
		v = v<<4 | d
	}
	return v, true
}

// str ports scanstring_unicode in strict mode and returns the decoded text. A lone surrogate becomes U+FFFD here;
// it can never equal a vocabulary word, which is all the caller compares.
func (p *jsonScanner) str() (string, bool) {
	i := p.i + 1 // after the opening quote
	var out []rune
	for {
		if i >= len(p.s) {
			return "", false
		}
		c := p.s[i]
		switch {
		case c == '"':
			p.i = i + 1
			return string(out), true
		case c < 0x20:
			return "", false
		case c != '\\':
			out = append(out, rune(c))
			i++
			continue
		}
		if i+1 >= len(p.s) {
			return "", false
		}
		i++
		switch p.s[i] {
		case '"', '\\', '/':
			out = append(out, rune(p.s[i]))
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			v, ok := p.hex4(i + 1)
			if !ok {
				return "", false
			}
			i += 4
			if v >= 0xd800 && v <= 0xdbff && i+2 < len(p.s) && p.s[i+1] == '\\' && p.s[i+2] == 'u' {
				low, ok := p.hex4(i + 3) // the C scanner rejects a malformed escape right after a high surrogate
				if !ok {
					return "", false
				}
				if low >= 0xdc00 && low <= 0xdfff {
					v = 0x10000 + (v-0xd800)<<10 + (low - 0xdc00)
					i += 6
				}
			}
			if v >= 0xd800 && v <= 0xdfff {
				v = 0xfffd
			}
			out = append(out, rune(v))
		default:
			return "", false
		}
		i++
	}
}
