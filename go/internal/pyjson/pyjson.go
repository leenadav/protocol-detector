// Package pyjson writes values exactly as Python's json.dumps does with its defaults: ", " and ": "
// separators, ASCII-only strings, repr() floats, and object keys in a stated order (Python dicts keep
// insertion order, Go maps do not). The Go command-line rows are byte-identical to the reference's this way,
// so a consumer that matched on the text of a row (`"type": "session"`) keeps working.
package pyjson

import (
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Orders gives the key order of the object at a path ("session", "session.layers.outer", "frame.events[]"):
// keys named there come first in that order, any other key follows in sorted order.
type Orders func(path string) []string

// Dumps is json.dumps(value) for the JSON-shaped Go values the engine builds.
func Dumps(value interface{}, root string, orders Orders) string {
	var b strings.Builder
	write(&b, reflect.ValueOf(value), root, orders)
	return b.String()
}

func write(b *strings.Builder, v reflect.Value, path string, orders Orders) {
	if !v.IsValid() {
		b.WriteString("null")
		return
	}
	switch v.Kind() {
	case reflect.Interface, reflect.Ptr:
		if v.IsNil() {
			b.WriteString("null")
			return
		}
		write(b, v.Elem(), path, orders)
	case reflect.Bool:
		if v.Bool() {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case reflect.String:
		String(b, v.String())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		b.WriteString(strconv.FormatInt(v.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		b.WriteString(strconv.FormatUint(v.Uint(), 10))
	case reflect.Float32, reflect.Float64:
		b.WriteString(Float(v.Float()))
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			b.WriteString("[]") // the engine's nil slices stand for Python's empty lists and tuples
			return
		}
		b.WriteByte('[')
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				b.WriteString(", ")
			}
			write(b, v.Index(i), path+"[]", orders)
		}
		b.WriteByte(']')
	case reflect.Map:
		keys := make([]string, 0, v.Len())
		for _, k := range v.MapKeys() {
			keys = append(keys, k.String())
		}
		sort.Strings(keys)
		var ordered []string
		present := map[string]bool{}
		for _, k := range keys {
			present[k] = true
		}
		if orders != nil {
			for _, k := range orders(path) {
				if present[k] {
					ordered = append(ordered, k)
					delete(present, k)
				}
			}
		}
		for _, k := range keys {
			if present[k] {
				ordered = append(ordered, k)
			}
		}
		b.WriteByte('{')
		for i, k := range ordered {
			if i > 0 {
				b.WriteString(", ")
			}
			String(b, k)
			b.WriteString(": ")
			write(b, v.MapIndex(reflect.ValueOf(k).Convert(v.Type().Key())), path+"."+k, orders)
		}
		b.WriteByte('}')
	default:
		String(b, fmt.Sprint(v.Interface()))
	}
}

// String writes a JSON string with ensure_ascii: everything outside space..tilde is escaped.
func String(b *strings.Builder, s string) {
	b.WriteByte('"')
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		s = s[size:]
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r < 0x20 || r > 0x7e:
			if r > 0xffff {
				hi, lo := utf16.EncodeRune(r)
				fmt.Fprintf(b, `\u%04x\u%04x`, hi, lo)
			} else {
				fmt.Fprintf(b, `\u%04x`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

// Float is Python's repr(float) as json.dumps writes it: shortest round-trip digits, fixed notation for
// 1e-4 <= |x| < 1e16, always with a fractional part or an exponent; NaN and the infinities as Python names them.
func Float(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	case f == 0:
		if math.Signbit(f) {
			return "-0.0"
		}
		return "0.0"
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // d.ddde±XX
	mantissa, expText, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expText)
	sign := ""
	if strings.HasPrefix(mantissa, "-") {
		sign, mantissa = "-", mantissa[1:]
	}
	digits := strings.Replace(mantissa, ".", "", 1)
	decpt := exp + 1
	if -4 < decpt && decpt <= 16 {
		switch {
		case decpt <= 0:
			return sign + "0." + strings.Repeat("0", -decpt) + digits
		case decpt >= len(digits):
			return sign + digits + strings.Repeat("0", decpt-len(digits)) + ".0"
		default:
			return sign + digits[:decpt] + "." + digits[decpt:]
		}
	}
	out := digits[:1]
	if len(digits) > 1 {
		out += "." + digits[1:]
	}
	es := "+"
	if exp < 0 {
		es, exp = "-", -exp
	}
	return fmt.Sprintf("%s%se%s%02d", sign, out, es, exp)
}

// Round is Python's round(x, digits) for a float: correctly rounded on the exact binary value.
func Round(x float64, digits int) float64 {
	v, _ := strconv.ParseFloat(strconv.FormatFloat(x, 'f', digits, 64), 64)
	return v
}
