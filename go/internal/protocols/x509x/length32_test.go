package x509x

import (
	"strings"
	"testing"
)

// SEC-X509-1 (Codex PRO-15): a four-octet DER length near 2^31 must be rejected against its container on every
// architecture. On 32-bit Go, pos+length overflowed int, so the container check passed and element returned a
// negative end that later slicing panicked on.
func TestElementFourOctetLengthBeyondContainerIsMalformed(t *testing.T) {
	for _, raw := range [][]byte{
		{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff, 0x00, 0x00},
		{0x30, 0x84, 0x7f, 0xff, 0xff, 0xfa, 0x00, 0x00},
		{0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00},
	} {
		_, start, end, err := element(raw, 0, len(raw))
		if err == nil || !strings.Contains(err.Error(), "DER element exceeds its container") {
			t.Fatalf("% x: got start=%d end=%d err=%v, want the container error", raw, start, end, err)
		}
		if _, err := LeafProfile(raw); err == nil || !strings.Contains(err.Error(), "exceeds its container") {
			t.Fatalf("% x: LeafProfile err=%v, want the container error", raw, err)
		}
	}
}
