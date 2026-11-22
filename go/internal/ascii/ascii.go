// Package ascii is ASCII-only case mapping, the semantics of Python's bytes.lower() and bytes.upper() that the
// reference applies to wire bytes. Go's strings and bytes case mappings are Unicode-aware: they rewrite valid UTF-8
// sequences (U+017F LONG S upper-cases to "S", U+212A KELVIN SIGN lower-cases to "k") and can change a value's
// length, so a non-ASCII token could compare equal to an ASCII keyword the reference would reject.
package ascii

// Lower maps A..Z to a..z and leaves every other byte unchanged.
func Lower(s string) string { return string(LowerBytes([]byte(s))) }

// Upper maps a..z to A..Z and leaves every other byte unchanged.
func Upper(s string) string { return string(UpperBytes([]byte(s))) }

// LowerBytes returns a lowered copy of b.
func LowerBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

// UpperBytes returns an uppered copy of b.
func UpperBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		out[i] = c
	}
	return out
}
