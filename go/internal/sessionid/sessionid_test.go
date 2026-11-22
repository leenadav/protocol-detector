package sessionid

import (
	"bytes"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/transport"
)

// Vectors from hashlib.blake2s(data, digest_size=8) and protocol_adapters.events.session_identity.
func TestBlake2s8AndIdentity(t *testing.T) {
	for _, c := range []struct {
		data []byte
		want string
	}{
		{nil, "ef2a8b78dd80da9c"},
		{[]byte("abc"), "972e9d2cd6de6402"},
		{bytes.Repeat([]byte("a"), 64), "50ebb69474dcd48c"},
		{bytes.Repeat([]byte("b"), 65), "60ae3690d47e7d9b"},
		{bytes.Repeat([]byte("c"), 200), "cc0ccf2cd1bedd4c"},
	} {
		if got := Blake2s8(c.data); got != c.want {
			t.Errorf("Blake2s8(%d bytes) = %s, want %s", len(c.data), got, c.want)
		}
	}
	a, b := transport.Endpoint{Addr: "192.0.2.10", Port: 51000}, transport.Endpoint{Addr: "198.51.100.20", Port: 443}
	if Identity("tcp", a, b) != "7fd9ce94bce0c261" || Identity("tcp", b, a) != "7fd9ce94bce0c261" {
		t.Errorf("identity: %s %s", Identity("tcp", a, b), Identity("tcp", b, a))
	}
}
