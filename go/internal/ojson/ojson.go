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
	"unicode/utf16"
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

// ErrNotFinite is json.dumps(allow_nan=False) refusing NaN or an infinity.
var ErrNotFinite = errors.New("Out of range float values are not JSON compliant")

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
			return ErrNotFinite
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

// SyntaxError is a document json.loads refuses (a ValueError in the reference).
type SyntaxError struct{ Msg string }

func (e *SyntaxError) Error() string { return e.Msg }

// MaxDepth bounds nesting; Python's recursion limit refuses deeper documents too (RecursionError).
const MaxDepth = 512

// Decode is json.loads(data) for UTF-8 input: NaN, Infinity and -Infinity are accepted as Python accepts
// them, control characters inside strings are refused (strict mode), surrogate escapes pair up.
func Decode(data []byte) (Value, error) {
	if !utf8.Valid(data) {
		return nil, &SyntaxError{"input is not valid UTF-8"}
	}
	d := &decoder{s: string(data)}
	d.ws()
	v, err := d.value(0)
	if err != nil {
		return nil, err
	}
	d.ws()
	if d.i != len(d.s) {
		return nil, &SyntaxError{"Extra data"}
	}
	return v, nil
}

type decoder struct {
	s string
	i int
}

func (d *decoder) ws() {
	for d.i < len(d.s) {
		switch d.s[d.i] {
		case ' ', '\t', '\n', '\r':
			d.i++
		default:
			return
		}
	}
}

func (d *decoder) fail(msg string) error { return &SyntaxError{msg} }

func (d *decoder) value(depth int) (Value, error) {
	if depth > MaxDepth {
		return nil, d.fail("maximum nesting depth exceeded")
	}
	if d.i >= len(d.s) {
		return nil, d.fail("Expecting value")
	}
	switch c := d.s[d.i]; {
	case c == '{':
		return d.object(depth)
	case c == '[':
		return d.array(depth)
	case c == '"':
		return d.str()
	case strings.HasPrefix(d.s[d.i:], "null"):
		d.i += 4
		return nil, nil
	case strings.HasPrefix(d.s[d.i:], "true"):
		d.i += 4
		return true, nil
	case strings.HasPrefix(d.s[d.i:], "false"):
		d.i += 5
		return false, nil
	case strings.HasPrefix(d.s[d.i:], "NaN"):
		d.i += 3
		return math.NaN(), nil
	case strings.HasPrefix(d.s[d.i:], "Infinity"):
		d.i += 8
		return math.Inf(1), nil
	case strings.HasPrefix(d.s[d.i:], "-Infinity"):
		d.i += 9
		return math.Inf(-1), nil
	case c == '-' || (c >= '0' && c <= '9'):
		return d.number()
	}
	return nil, d.fail("Expecting value")
}

func digitsAt(s string, i int) int {
	j := i
	for j < len(s) && s[j] >= '0' && s[j] <= '9' {
		j++
	}
	return j
}

// number follows Python's NUMBER_RE: -?(0|[1-9]\d*)(\.\d+)?([eE][-+]?\d+)?, matched greedily, the rest left
// to the caller (so "01" is 0 followed by extra data, as in the reference).
func (d *decoder) number() (Value, error) {
	start := d.i
	j := d.i
	if d.s[j] == '-' {
		j++
	}
	if j >= len(d.s) || d.s[j] < '0' || d.s[j] > '9' {
		return nil, d.fail("Expecting value")
	}
	if d.s[j] == '0' {
		j++
	} else {
		j = digitsAt(d.s, j)
	}
	intEnd := j
	isFloat := false
	if j+1 < len(d.s) && d.s[j] == '.' && d.s[j+1] >= '0' && d.s[j+1] <= '9' {
		j = digitsAt(d.s, j+1)
		isFloat = true
	}
	if j < len(d.s) && (d.s[j] == 'e' || d.s[j] == 'E') {
		k := j + 1
		if k < len(d.s) && (d.s[k] == '+' || d.s[k] == '-') {
			k++
		}
		if e := digitsAt(d.s, k); e > k {
			j = e
			isFloat = true
		}
	}
	d.i = j
	if !isFloat {
		text := d.s[start:intEnd]
		if text == "-0" {
			text = "0"
		}
		return Int(text), nil
	}
	f, err := strconv.ParseFloat(d.s[start:j], 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return nil, d.fail("invalid number")
	}
	return f, nil // an overflow is ±Inf and an underflow ±0, as float() gives
}

func (d *decoder) str() (string, error) {
	d.i++ // opening quote
	var b strings.Builder
	for {
		if d.i >= len(d.s) {
			return "", d.fail("Unterminated string")
		}
		c := d.s[d.i]
		switch {
		case c == '"':
			d.i++
			return b.String(), nil
		case c < 0x20:
			return "", d.fail("Invalid control character")
		case c == '\\':
			if d.i+1 >= len(d.s) {
				return "", d.fail("Unterminated string")
			}
			e := d.s[d.i+1]
			d.i += 2
			switch e {
			case '"', '\\', '/':
				b.WriteByte(e)
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'u':
				r, ok := d.hex4()
				if !ok {
					return "", d.fail("Invalid \\uXXXX escape")
				}
				if utf16.IsSurrogate(r) && r < 0xdc00 && strings.HasPrefix(d.s[d.i:], `\u`) {
					save := d.i
					d.i += 2
					if lo, ok := d.hex4(); ok && lo >= 0xdc00 && lo <= 0xdfff {
						r = utf16.DecodeRune(r, lo)
					} else {
						d.i = save
					}
				}
				if utf16.IsSurrogate(r) {
					// A lone surrogate is a valid Python str but not UTF-8: it is kept as its WTF-8 bytes, which
					// writeString turns back into the same \uXXXX escape.
					b.WriteByte(byte(0xe0 | r>>12))
					b.WriteByte(byte(0x80 | (r>>6)&0x3f))
					b.WriteByte(byte(0x80 | r&0x3f))
				} else {
					b.WriteRune(r)
				}
			default:
				return "", d.fail("Invalid \\escape")
			}
		default:
			r, size := utf8.DecodeRuneInString(d.s[d.i:])
			b.WriteRune(r)
			d.i += size
		}
	}
}

func (d *decoder) hex4() (rune, bool) {
	if d.i+4 > len(d.s) {
		return 0, false
	}
	n, err := strconv.ParseUint(d.s[d.i:d.i+4], 16, 32)
	if err != nil || strings.ContainsAny(d.s[d.i:d.i+4], "+-xX_") {
		return 0, false
	}
	d.i += 4
	return rune(n), true
}

func (d *decoder) array(depth int) (Value, error) {
	d.i++
	out := []Value{}
	d.ws()
	if d.i < len(d.s) && d.s[d.i] == ']' {
		d.i++
		return out, nil
	}
	for {
		d.ws()
		v, err := d.value(depth + 1)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		d.ws()
		if d.i >= len(d.s) {
			return nil, d.fail("Expecting ',' delimiter")
		}
		switch d.s[d.i] {
		case ',':
			d.i++
		case ']':
			d.i++
			return out, nil
		default:
			return nil, d.fail("Expecting ',' delimiter")
		}
	}
}

func (d *decoder) object(depth int) (Value, error) {
	d.i++
	out := &Object{vals: map[string]Value{}}
	d.ws()
	if d.i < len(d.s) && d.s[d.i] == '}' {
		d.i++
		return out, nil
	}
	for {
		d.ws()
		if d.i >= len(d.s) || d.s[d.i] != '"' {
			return nil, d.fail("Expecting property name enclosed in double quotes")
		}
		key, err := d.str()
		if err != nil {
			return nil, err
		}
		d.ws()
		if d.i >= len(d.s) || d.s[d.i] != ':' {
			return nil, d.fail("Expecting ':' delimiter")
		}
		d.i++
		d.ws()
		v, err := d.value(depth + 1)
		if err != nil {
			return nil, err
		}
		out.Set(key, v)
		d.ws()
		if d.i >= len(d.s) {
			return nil, d.fail("Expecting ',' delimiter")
		}
		switch d.s[d.i] {
		case ',':
			d.i++
		case '}':
			d.i++
			return out, nil
		default:
			return nil, d.fail("Expecting ',' delimiter")
		}
	}
}
