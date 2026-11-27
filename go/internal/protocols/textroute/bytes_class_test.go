package textroute

import "testing"

// Go regexp classes match runes, not bytes: `[\x80-\xff]` is U+0080..U+00FF, so a raw obs-text byte (invalid UTF-8)
// never matched the reason-phrase class and a negated class accepted it. The reference's byte classes (re on bytes)
// are the contract: RFC 9112 reason-phrase = *( HTAB / SP / VCHAR / obs-text ), and an IMAP atom is ASCII only.
// Found by the recorded requirement cases (SR-27/SR-28, test_shift at python-final).
func TestByteClassesAreBytesNotRunes(t *testing.T) {
	for line, want := range map[string]bool{
		"HTTP/1.1 101 Switching Protocols":    true,
		"HTTP/1.1 101 Switching\xc5Protocols": true, // one obs-text byte, invalid UTF-8
		"HTTP/1.1 200 \xff\x80\xfe":           true,
		"HTTP/1.1 200 caf\xc3\xa9":            true, // UTF-8 bytes are obs-text too
		"HTTP/1.1 200 \tOK":                   true,
		"HTTP/1.1 200 ":                       true,
		"HTTP/1.1 200 O\x7fK":                 false,
		"HTTP/1.1 200 O\x00K":                 false,
		"HTTP/1.1 200 O\x1bK":                 false,
		"HTTP/1.1 200":                        false,
		"HTTP/1.2 200 OK":                     false,
		"HTTP/1.1 600 OK":                     false,
		"HTTP/1.1 20 OK":                      false,
		"xHTTP/1.1 200 OK":                    false,
	} {
		if got := statusLine([]byte(line)); got != want {
			t.Errorf("statusLine(%q) = %v, want %v", line, got, want)
		}
	}
	for atom, want := range map[string]bool{
		"INBOX": true, "a1": true, "x.y-z": true,
		"": false, "caf\xc3\xa9": false, "\xc4\x80": false, "a\xff": false, "a\x80b": false, "a b": false, "a(": false,
		"a)": false, "a{": false, "a%": false, "a*": false, "a\"": false, "a\\": false, "a]": false, "a\x7f": false, "a\x00": false,
	} {
		if got := isIMAPAtom([]byte(atom)); got != want {
			t.Errorf("isIMAPAtom(%q) = %v, want %v", atom, got, want)
		}
	}
}
