package serve

import (
	"fmt"
	"math/big"
	"strings"
	"unicode/utf8"
)

// The request line and header values reach the reference as ISO-8859-1 text: one code point per byte. Here
// they stay as their bytes (a Go string), and latin1 turns them into UTF-8 text only where they are shown.

func latin1(raw string) string {
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		b.WriteRune(rune(raw[i]))
	}
	return b.String()
}

// isPrintable is str.isprintable() for a code point of ISO-8859-1.
func isPrintable(c byte) bool { return (c >= 0x20 && c < 0x7f) || (c > 0xa0 && c != 0xad) }

// pyRepr is repr() of an ISO-8859-1 string, as UTF-8 text.
func pyRepr(raw string) string {
	quote := byte('\'')
	if strings.IndexByte(raw, '\'') >= 0 && strings.IndexByte(raw, '"') < 0 {
		quote = '"'
	}
	var b strings.Builder
	b.WriteByte(quote)
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c == quote || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c == '\t':
			b.WriteString(`\t`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case isPrintable(c):
			b.WriteRune(rune(c))
		default:
			fmt.Fprintf(&b, `\x%02x`, c)
		}
	}
	b.WriteByte(quote)
	return b.String()
}

// truncateRunes is Python's %.200R: the first n code points of a text.
func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

func intSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\v', '\f', '\r', 0x85, 0xa0:
		return true
	}
	return false
}

// pyInt is int(text) on an ISO-8859-1 string: the value, or the reference's ValueError text.
func pyInt(raw string) (*big.Int, string) {
	invalid := "invalid literal for int() with base 10: " + truncateRunes(pyRepr(raw), 200)
	s := raw
	for len(s) > 0 && intSpace(s[0]) {
		s = s[1:]
	}
	for len(s) > 0 && intSpace(s[len(s)-1]) {
		s = s[:len(s)-1]
	}
	negative := false
	if len(s) > 0 && (s[0] == '+' || s[0] == '-') {
		negative = s[0] == '-'
		s = s[1:]
	}
	if s == "" || s[0] == '_' || s[len(s)-1] == '_' || strings.Contains(s, "__") {
		return nil, invalid
	}
	digits := 0
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] >= '0' && s[i] <= '9':
			digits++
		case s[i] == '_':
		default:
			return nil, invalid
		}
	}
	if digits > 4300 {
		return nil, fmt.Sprintf("Exceeds the limit (4300 digits) for integer string conversion: value has %d digits; use sys.set_int_max_str_digits() to increase the limit", digits)
	}
	v, _ := new(big.Int).SetString(strings.ReplaceAll(s, "_", ""), 10)
	if negative {
		v.Neg(v)
	}
	return v, ""
}

// --- urllib.parse.urlsplit (Python 3.13), the path and query only -------------------------------------

const schemeChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-."

// urlsplit returns the path and query of urlsplit(url), or ok=false where it raises ValueError (a bracket
// that does not close in the network location). The netloc's NFKC check for non-ASCII text is not ported.
func urlsplit(url string) (path, query string, ok bool) {
	i := 0
	for i < len(url) && url[i] <= 0x20 {
		i++
	}
	url = url[i:]
	url = strings.NewReplacer("\t", "", "\r", "", "\n", "").Replace(url)
	if c := strings.IndexByte(url, ':'); c > 0 && url[0] < 0x80 && isAlpha(url[0]) {
		valid := true
		for k := 0; k < c; k++ {
			if strings.IndexByte(schemeChars, url[k]) < 0 {
				valid = false
				break
			}
		}
		if valid {
			url = url[c+1:]
		}
	}
	if strings.HasPrefix(url, "//") {
		end := len(url)
		for _, sep := range "/?#" {
			if k := strings.IndexRune(url[2:], sep); k >= 0 && k+2 < end {
				end = k + 2
			}
		}
		netloc := url[2:end]
		url = url[end:]
		open, close := strings.Contains(netloc, "["), strings.Contains(netloc, "]")
		if open != close {
			return "", "", false
		}
	}
	if k := strings.IndexByte(url, '#'); k >= 0 {
		url = url[:k]
	}
	if k := strings.IndexByte(url, '?'); k >= 0 {
		return url[:k], url[k+1:], true
	}
	return url, "", true
}

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// --- base64.b64decode(s, validate=True), Python 3.13 (binascii.a2b_base64 strict mode) ------------------

func b64value(c byte) (byte, bool) {
	switch {
	case c >= 'A' && c <= 'Z':
		return c - 'A', true
	case c >= 'a' && c <= 'z':
		return c - 'a' + 26, true
	case c >= '0' && c <= '9':
		return c - '0' + 52, true
	case c == '+':
		return 62, true
	case c == '/':
		return 63, true
	}
	return 0, false
}

// b64decodeStrict returns the bytes or the reference's error text.
func b64decodeStrict(s string) ([]byte, string) {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return nil, "string argument should contain only ASCII characters"
		}
	}
	if len(s) > 0 && s[0] == '=' {
		return nil, "Leading padding not allowed"
	}
	out := make([]byte, 0, len(s)*3/4)
	quad, pads := 0, 0
	var left byte
	padding := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '=' {
			padding = true
			if quad == 0 {
				return nil, "Excess padding not allowed"
			}
			pads++
			if quad >= 2 && quad+pads >= 4 {
				if i+1 < len(s) {
					return nil, "Excess data after padding"
				}
				return out, ""
			}
			continue
		}
		v, ok := b64value(c)
		if !ok {
			return nil, "Only base64 data is allowed"
		}
		if padding {
			return nil, "Discontinuous padding not allowed"
		}
		pads = 0
		switch quad {
		case 0:
			quad, left = 1, v
		case 1:
			quad = 2
			out = append(out, left<<2|v>>4)
			left = v & 0x0f
		case 2:
			quad = 3
			out = append(out, left<<4|v>>2)
			left = v & 0x03
		case 3:
			quad = 0
			out = append(out, left<<6|v)
			left = 0
		}
	}
	switch quad {
	case 0:
		return out, ""
	case 1:
		return nil, fmt.Sprintf("Invalid base64-encoded string: number of data characters (%d) cannot be 1 more than a multiple of 4", len(out)/3*4+1)
	}
	return nil, "Incorrect padding"
}
