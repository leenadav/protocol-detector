// Package ojson holds JSON values the way Python's json module does: objects keep their key order (a dict
// keeps insertion order; a repeated key keeps its first position and takes its last value), integers keep
// their exact digits, and floats are the nearest float64. Decode is json.loads; Dumps is
// json.dumps(value, allow_nan=False) with the default separators and ASCII-only strings. The live control
// plane re-emits worker events through this, so its answers are the reference's byte for byte.
package ojson

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/leenadav/protocol-detector/go/internal/pyjson"
)

// Value is nil (null), bool, string, Int, float64, []Value or *Object.
type Value = interface{}

// Int is a JSON integer with its canonical decimal digits (Python's int has no width limit).
type Int string

// Object is a JSON object in insertion order.
type Object struct {
	keys []string
	vals map[string]Value
}

// NewObject builds an object from key, value pairs in order.
func NewObject(pairs ...interface{}) *Object {
	o := &Object{vals: map[string]Value{}}
	for i := 0; i+1 < len(pairs); i += 2 {
		o.Set(pairs[i].(string), pairs[i+1])
	}
	return o
}

// Set assigns key; a new key goes last, an existing key keeps its position.
func (o *Object) Set(key string, v Value) {
	if o.vals == nil {
		o.vals = map[string]Value{}
	}
	if _, ok := o.vals[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.vals[key] = v
}

// Get is dict.get(key): the value and whether the key is present.
func (o *Object) Get(key string) (Value, bool) {
	if o == nil {
		return nil, false
	}
	v, ok := o.vals[key]
	return v, ok
}

// Keys in order.
func (o *Object) Keys() []string { return o.keys }

// Len is the number of keys.
func (o *Object) Len() int { return len(o.keys) }

// Copy is dict(o): a shallow copy.
func (o *Object) Copy() *Object {
	c := &Object{keys: append([]string(nil), o.keys...), vals: make(map[string]Value, len(o.vals))}
	for k, v := range o.vals {
		c.vals[k] = v
	}
	return c
}

// Truthy is Python's bool() of a decoded value.
func Truthy(v Value) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case Int:
		return x != "0"
	case float64:
		return x != 0
	case []Value:
		return len(x) > 0
	case *Object:
		return x.Len() > 0
	}
	return true
}

// IntValue reads an Int that fits in int64.
func IntValue(v Value) (int64, bool) {
	i, ok := v.(Int)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(string(i), 10, 64)
	return n, err == nil
}

// FromInt is the Int for n.
func FromInt(n int64) Int { return Int(strconv.FormatInt(n, 10)) }

// NotFiniteError is json.dumps(allow_nan=False) refusing NaN or an infinity (a ValueError).
type NotFiniteError struct{ Value float64 }

func (e *NotFiniteError) Error() string {
	text := "nan"
	if math.IsInf(e.Value, 1) {
		text = "inf"
	} else if math.IsInf(e.Value, -1) {
		text = "-inf"
	}
	return "Out of range float values are not JSON compliant: " + text
}

// Dumps is json.dumps(v, allow_nan=False).
func Dumps(v Value) (string, error) {
	var b strings.Builder
	if err := write(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

// MustDumps is Dumps for values built from finite numbers only.
func MustDumps(v Value) string {
	s, err := Dumps(v)
	if err != nil {
		panic(err)
	}
	return s
}

func write(b *strings.Builder, v Value) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeString(b, x)
	case Int:
		b.WriteString(string(x))
	case int:
		b.WriteString(strconv.Itoa(x))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return &NotFiniteError{x}
		}
		b.WriteString(pyjson.Float(x))
	case []Value:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteString(", ")
			}
			if err := write(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case *Object:
		if x == nil {
			b.WriteString("null")
			return nil
		}
		b.WriteByte('{')
		for i, k := range x.keys {
			if i > 0 {
				b.WriteString(", ")
			}
			writeString(b, k)
			b.WriteString(": ")
			if err := write(b, x.vals[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		panic("ojson: unsupported value type")
	}
	return nil
}

// writeString is pyjson.String for UTF-8 text that may also carry WTF-8 surrogates (from Decode).
func writeString(b *strings.Builder, s string) {
	if utf8.ValidString(s) {
		pyjson.String(b, s)
		return
	}
	b.WriteByte('"')
	for len(s) > 0 {
		if len(s) >= 3 && s[0] == 0xed && s[1] >= 0xa0 && s[1] <= 0xbf && s[2]&0xc0 == 0x80 {
			r := rune(s[0]&0x0f)<<12 | rune(s[1]&0x3f)<<6 | rune(s[2]&0x3f)
			fmt.Fprintf(b, `\u%04x`, r)
			s = s[3:]
			continue
		}
		_, size := utf8.DecodeRuneInString(s)
		var part strings.Builder
		pyjson.String(&part, s[:size])
		text := part.String()
		b.WriteString(text[1 : len(text)-1])
		s = s[size:]
	}
	b.WriteByte('"')
}

// SyntaxError is a document json.loads refuses, with the reference's str(error): Kind "json" is a
// JSONDecodeError ("msg: line L column C (char P)"), "unicode" a UnicodeDecodeError, "value" any other
// ValueError (the 4300-digit integer limit), "unsupported" an input this port does not decode (UTF-16 or
// UTF-32, which json.loads detects; workers and browsers send UTF-8).
type SyntaxError struct {
	Kind string
	Msg  string
}

func (e *SyntaxError) Error() string { return e.Msg }

// MaxDepth bounds nesting; deeper documents end the reference with RecursionError (not a ValueError).
const MaxDepth = 512

// Decode is json.loads(data) for bytes.
func Decode(data []byte) (Value, error) {
	text, err := decodeBytes(data)
	if err != nil {
		return nil, err
	}
	d := &decoder{s: text}
	idx := d.skipWS(0)
	v, end, err := d.scan(idx, 0)
	if err != nil {
		return nil, err
	}
	end = d.skipWS(end)
	if end != len(d.s) {
		return nil, d.fail("Extra data", end)
	}
	return v, nil
}

type decoder struct {
	s []rune // code points; lone surrogates are kept as such (surrogatepass)
}

type stopIteration struct{ idx int }

func (e *stopIteration) Error() string { return "stop" }

func (d *decoder) fail(msg string, pos int) error {
	line, col := 1, pos+1
	for i := 0; i < pos && i < len(d.s); i++ {
		if d.s[i] == '\n' {
			line++
			col = pos - i
		}
	}
	return &SyntaxError{Kind: "json", Msg: fmt.Sprintf("%s: line %d column %d (char %d)", msg, line, col, pos)}
}

func (d *decoder) skipWS(i int) int {
	for i < len(d.s) {
		switch d.s[i] {
		case ' ', '\t', '\n', '\r':
			i++
		default:
			return i
		}
	}
	return i
}

func (d *decoder) has(i int, word string) bool {
	if i+len(word) > len(d.s) {
		return false
	}
	for k, c := range word {
		if d.s[i+k] != c {
			return false
		}
	}
	return true
}

// scan is scan_once_unicode: the value at idx and the index after it.
func (d *decoder) scan(idx, depth int) (Value, int, error) {
	v, end, err := d.scanOnce(idx, depth)
	if stop, ok := err.(*stopIteration); ok {
		return nil, 0, d.fail("Expecting value", stop.idx)
	}
	return v, end, err
}

func (d *decoder) scanOnce(idx, depth int) (Value, int, error) {
	if depth > MaxDepth {
		return nil, 0, &SyntaxError{Kind: "recursion", Msg: "maximum recursion depth exceeded while decoding a JSON document from a unicode string"}
	}
	if idx >= len(d.s) {
		return nil, 0, &stopIteration{idx}
	}
	switch d.s[idx] {
	case '"':
		str, end, err := d.scanString(idx + 1)
		return str, end, err
	case '{':
		return d.object(idx+1, depth+1)
	case '[':
		return d.array(idx+1, depth+1)
	case 'n':
		if d.has(idx, "null") {
			return nil, idx + 4, nil
		}
	case 't':
		if d.has(idx, "true") {
			return true, idx + 4, nil
		}
	case 'f':
		if d.has(idx, "false") {
			return false, idx + 5, nil
		}
	case 'N':
		if d.has(idx, "NaN") {
			return math.NaN(), idx + 3, nil
		}
	case 'I':
		if d.has(idx, "Infinity") {
			return math.Inf(1), idx + 8, nil
		}
	case '-':
		if d.has(idx, "-Infinity") {
			return math.Inf(-1), idx + 9, nil
		}
	}
	return d.number(idx)
}

func digit(c rune) bool { return c >= '0' && c <= '9' }

// number is _match_number_unicode.
func (d *decoder) number(start int) (Value, int, error) {
	s, endIdx := d.s, len(d.s)-1
	idx := start
	if s[idx] == '-' {
		idx++
		if idx > endIdx {
			return nil, 0, &stopIteration{start}
		}
	}
	switch {
	case s[idx] >= '1' && s[idx] <= '9':
		idx++
		for idx <= endIdx && digit(s[idx]) {
			idx++
		}
	case s[idx] == '0':
		idx++
	default:
		return nil, 0, &stopIteration{start}
	}
	isFloat := false
	if idx < endIdx && s[idx] == '.' && digit(s[idx+1]) {
		isFloat = true
		idx += 2
		for idx <= endIdx && digit(s[idx]) {
			idx++
		}
	}
	if idx < endIdx && (s[idx] == 'e' || s[idx] == 'E') {
		eStart := idx
		idx++
		if idx < endIdx && (s[idx] == '-' || s[idx] == '+') {
			idx++
		}
		for idx <= endIdx && digit(s[idx]) {
			idx++
		}
		if digit(s[idx-1]) {
			isFloat = true
		} else {
			idx = eStart
		}
	}
	text := string(s[start:idx])
	if !isFloat {
		digits := strings.TrimPrefix(text, "-")
		if len(digits) > 4300 {
			return nil, 0, &SyntaxError{Kind: "value", Msg: fmt.Sprintf("Exceeds the limit (4300 digits) for integer string conversion: value has %d digits; use sys.set_int_max_str_digits() to increase the limit", len(digits))}
		}
		if text == "-0" {
			text = "0"
		}
		return Int(text), idx, nil
	}
	f, err := strconv.ParseFloat(text, 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return nil, 0, &stopIteration{start}
	}
	return f, idx, nil // an overflow is ±Inf and an underflow ±0, as float() gives
}

func hexValue(c rune) (rune, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// scanString is scanstring_unicode(pystr, end, strict=True): end is the index after the opening quote.
func (d *decoder) scanString(end int) (string, int, error) {
	s, n := d.s, len(d.s)
	begin := end - 1
	var out []rune
	for {
		var c rune
		next := end
		for ; next < n; next++ {
			c = s[next]
			if c == '"' || c == '\\' {
				break
			} else if c <= 0x1f {
				return "", 0, d.fail("Invalid control character at", next)
			}
		}
		if next >= n || !(c == '"' || c == '\\') {
			return "", 0, d.fail("Unterminated string starting at", begin)
		}
		out = append(out, s[end:next]...)
		next++
		if c == '"' {
			end = next
			break
		}
		if next == n {
			return "", 0, d.fail("Unterminated string starting at", begin)
		}
		c = s[next]
		if c != 'u' {
			end = next + 1
			switch c {
			case '"', '\\', '/':
			case 'b':
				c = '\b'
			case 'f':
				c = '\f'
			case 'n':
				c = '\n'
			case 'r':
				c = '\r'
			case 't':
				c = '\t'
			default:
				return "", 0, d.fail("Invalid \\escape", end-2)
			}
		} else {
			c = 0
			next++
			end = next + 4
			if end > n {
				return "", 0, d.fail("Invalid \\uXXXX escape", next-1)
			}
			for ; next < end; next++ {
				h, ok := hexValue(s[next])
				if !ok {
					return "", 0, d.fail("Invalid \\uXXXX escape", end-5)
				}
				c = c<<4 | h
			}
			if c >= 0xd800 && c <= 0xdbff && end+6 < n && s[next] == '\\' && s[next+1] == 'u' {
				next += 2
				var c2 rune
				end += 6
				for ; next < end; next++ {
					h, ok := hexValue(s[next])
					if !ok {
						return "", 0, d.fail("Invalid \\uXXXX escape", end-5)
					}
					c2 = c2<<4 | h
				}
				if c2 >= 0xdc00 && c2 <= 0xdfff {
					c = 0x10000 + (c-0xd800)<<10 + (c2 - 0xdc00)
				} else {
					end -= 6
				}
			}
		}
		out = append(out, c)
	}
	return wtf8(out), end, nil
}

// wtf8 encodes code points as UTF-8, surrogates included (as their three-byte forms).
func wtf8(runes []rune) string {
	var b strings.Builder
	for _, r := range runes {
		if r >= 0xd800 && r <= 0xdfff {
			b.WriteByte(byte(0xe0 | r>>12))
			b.WriteByte(byte(0x80 | (r>>6)&0x3f))
			b.WriteByte(byte(0x80 | r&0x3f))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (d *decoder) object(idx, depth int) (Value, int, error) {
	s, endIdx := d.s, len(d.s)-1
	out := &Object{vals: map[string]Value{}}
	idx = d.skipWS(idx)
	if idx <= endIdx && s[idx] == '}' {
		return out, idx + 1, nil
	}
	for {
		if idx > endIdx || s[idx] != '"' {
			return nil, 0, d.fail("Expecting property name enclosed in double quotes", idx)
		}
		key, next, err := d.scanString(idx + 1)
		if err != nil {
			return nil, 0, err
		}
		idx = d.skipWS(next)
		if idx > endIdx || s[idx] != ':' {
			return nil, 0, d.fail("Expecting ':' delimiter", idx)
		}
		idx = d.skipWS(idx + 1)
		v, next, err := d.scanOnce(idx, depth)
		if err != nil {
			if stop, ok := err.(*stopIteration); ok {
				return nil, 0, d.fail("Expecting value", stop.idx)
			}
			return nil, 0, err
		}
		out.Set(key, v)
		idx = d.skipWS(next)
		if idx <= endIdx && s[idx] == '}' {
			return out, idx + 1, nil
		}
		if idx > endIdx || s[idx] != ',' {
			return nil, 0, d.fail("Expecting ',' delimiter", idx)
		}
		comma := idx
		idx = d.skipWS(idx + 1)
		if idx <= endIdx && s[idx] == '}' {
			return nil, 0, d.fail("Illegal trailing comma before end of object", comma)
		}
	}
}

func (d *decoder) array(idx, depth int) (Value, int, error) {
	s, endIdx := d.s, len(d.s)-1
	out := []Value{}
	idx = d.skipWS(idx)
	if idx <= endIdx && s[idx] == ']' {
		return out, idx + 1, nil
	}
	for {
		v, next, err := d.scanOnce(idx, depth)
		if err != nil {
			if stop, ok := err.(*stopIteration); ok {
				return nil, 0, d.fail("Expecting value", stop.idx)
			}
			return nil, 0, err
		}
		out = append(out, v)
		idx = d.skipWS(next)
		if idx <= endIdx && s[idx] == ']' {
			return out, idx + 1, nil
		}
		if idx > endIdx || s[idx] != ',' {
			return nil, 0, d.fail("Expecting ',' delimiter", idx)
		}
		comma := idx
		idx = d.skipWS(idx + 1)
		if idx <= endIdx && s[idx] == ']' {
			return nil, 0, d.fail("Illegal trailing comma before end of array", comma)
		}
	}
}
