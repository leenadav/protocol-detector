package tlsx

import (
	"fmt"
	"testing"
)

// PRO-596: cipherHex replaced fmt.Sprintf("0x%04x", ...) on the ServerHello path; the text must not change.
func TestCipherHexMatchesSprintf(t *testing.T) {
	for c := 0; c <= 0xffff; c++ {
		if got, want := cipherHex(c), fmt.Sprintf("0x%04x", c); got != want {
			t.Fatalf("cipherHex(%d) = %q, want %q", c, got, want)
		}
	}
}

// PRO-596: duplicate extensions are found on both sides of the bitset/map split at 4096, and distinct kinds that
// share a bit position in the other half are not mistaken for duplicates.
func TestHelloDuplicateExtensionAcrossSplit(t *testing.T) {
	prefix := []byte{3, 3}
	prefix = append(prefix, make([]byte, 32)...)
	prefix = append(prefix, 0, 0, 2, 0x13, 0x01, 1, 0) // empty session, one cipher, null compression
	hello := func(kinds ...int) []byte {
		body := append([]byte(nil), prefix...)
		body = append(body, byte(len(kinds)*4>>8), byte(len(kinds)*4))
		for _, k := range kinds {
			body = append(body, byte(k>>8), byte(k), 0, 0)
		}
		return body
	}
	for _, c := range []struct {
		kinds []int
		dup   bool
	}{
		{[]int{0x0fff, 0x0fff}, true}, {[]int{0x1000, 0x1000}, true}, {[]int{0xff01, 0x0a0a, 0xff01}, true},
		{[]int{0x0fff, 0x1000}, false}, {[]int{0x0001, 0x1001, 0xf001}, false}, {[]int{0x003f, 0x0040, 0x0000}, false},
		{[]int{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0x8a8a}, true},
	} {
		for _, collect := range []bool{false, true} {
			_, err := parseHello(hello(c.kinds...), collect)
			got := err != nil && err.Error() == "malformed: Duplicate TLS extension"
			if got != c.dup {
				t.Errorf("kinds %x (collect %v): err %v, want duplicate %v", c.kinds, collect, err, c.dup)
			}
		}
	}
}
