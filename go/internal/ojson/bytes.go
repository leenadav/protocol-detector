package ojson

import "fmt"

// decodeBytes is json.loads' bytes path: detect_encoding, then bytes.decode(encoding, "surrogatepass"). Only
// UTF-8 (with or without its BOM) is decoded here; UTF-16 and UTF-32 input is refused as unsupported.
func decodeBytes(b []byte) ([]rune, error) {
	switch {
	case hasPrefix(b, "\x00\x00\xfe\xff"), hasPrefix(b, "\xff\xfe\x00\x00"),
		hasPrefix(b, "\xfe\xff"), hasPrefix(b, "\xff\xfe"):
		return nil, unsupported()
	case hasPrefix(b, "\xef\xbb\xbf"):
		return decodeUTF8(b[3:], 3, "utf-8-sig")
	case len(b) >= 4 && (b[0] == 0 || b[1] == 0):
		return nil, unsupported()
	case len(b) == 2 && (b[0] == 0 || b[1] == 0):
		return nil, unsupported()
	}
	return decodeUTF8(b, 0, "utf-8")
}

func unsupported() error {
	return &SyntaxError{Kind: "unsupported", Msg: "JSON in UTF-16 or UTF-32 is not decoded"}
}

func hasPrefix(b []byte, p string) bool { return len(b) >= len(p) && string(b[:len(p)]) == p }

func cont(c byte) bool { return c&0xc0 == 0x80 }

// decodeUTF8 is CPython's UTF-8 decoder with the surrogatepass handler: an encoded surrogate (ED A0..BF xx)
// is accepted as that code point; any other error is the UnicodeDecodeError CPython raises, positions in
// bytes of the original input (offset is the length of a stripped BOM).
func decodeUTF8(b []byte, offset int, codec string) ([]rune, error) {
	out := make([]rune, 0, len(b))
	fail := func(start, end int, reason string) error {
		start += offset
		end += offset
		msg := ""
		if end-start == 1 {
			msg = fmt.Sprintf("'%s' codec can't decode byte 0x%02x in position %d: %s", codec, b[start-offset], start, reason)
		} else {
			msg = fmt.Sprintf("'%s' codec can't decode bytes in position %d-%d: %s", codec, start, end-1, reason)
		}
		return &SyntaxError{Kind: "unicode", Msg: msg}
	}
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case c < 0x80:
			out = append(out, rune(c))
			i++
			continue
		case c < 0xc2 || c > 0xf4:
			return nil, fail(i, i+1, "invalid start byte")
		}
		need := 1
		lo, hi := byte(0x80), byte(0xbf) // the range of the second byte
		switch {
		case c >= 0xf0:
			need = 3
			if c == 0xf0 {
				lo = 0x90
			} else if c == 0xf4 {
				hi = 0x8f
			}
		case c >= 0xe0:
			need = 2
			if c == 0xe0 {
				lo = 0xa0
			}
		}
		surrogate := c == 0xed && i+2 < len(b) && b[i+1] >= 0xa0 && b[i+1] <= 0xbf && cont(b[i+2])
		if surrogate {
			out = append(out, rune(c&0x0f)<<12|rune(b[i+1]&0x3f)<<6|rune(b[i+2]&0x3f))
			i += 3
			continue
		}
		if c == 0xed {
			hi = 0x9f
		}
		// The second byte: out of range is an invalid continuation at once; at the end, unexpected end.
		if i+1 >= len(b) {
			return nil, fail(i, len(b), "unexpected end of data")
		}
		if b[i+1] < lo || b[i+1] > hi {
			return nil, fail(i, i+1, "invalid continuation byte")
		}
		for k := 2; k <= need; k++ {
			if i+k >= len(b) {
				return nil, fail(i, len(b), "unexpected end of data")
			}
			if !cont(b[i+k]) {
				return nil, fail(i, i+k, "invalid continuation byte")
			}
		}
		var r rune
		switch need {
		case 1:
			r = rune(c&0x1f)<<6 | rune(b[i+1]&0x3f)
		case 2:
			r = rune(c&0x0f)<<12 | rune(b[i+1]&0x3f)<<6 | rune(b[i+2]&0x3f)
		case 3:
			r = rune(c&0x07)<<18 | rune(b[i+1]&0x3f)<<12 | rune(b[i+2]&0x3f)<<6 | rune(b[i+3]&0x3f)
		}
		out = append(out, r)
		i += need + 1
	}
	return out, nil
}
