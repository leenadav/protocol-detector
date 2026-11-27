package transport

import (
	"encoding/binary"
	"math/rand"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/testframes"
)

func securityIPv6(payload []byte) []byte {
	h := make([]byte, 40)
	binary.BigEndian.PutUint32(h[0:4], 6<<28)
	binary.BigEndian.PutUint16(h[4:6], uint16(len(payload)))
	h[6], h[7] = 17, 64
	copy(h[8:24], []byte{0x20, 0x01, 0x0d, 0xb8, 15: 1})
	copy(h[24:40], []byte{0x20, 0x01, 0x0d, 0xb8, 15: 2})
	return append(h, payload...)
}

// SR-11: an IPv6 packet is rejected as IPv4-only on every supported link wrapper (raw, Ethernet with and without
// a VLAN tag, Linux cooked v1 and v2, both loopback headers in both byte orders and every BSD IPv6 family value),
// an unsupported link type is rejected, and an IPv4 fragment is rejected rather than decoded.
func TestSecurityIPv6IsRejectedOnEveryLinkWrapper(t *testing.T) {
	dns := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1}
	udp := append([]byte{0xd9, 0x03, 0xd9, 0x04, 0, byte(8 + len(dns)), 0, 0}, dns...)
	raw := securityIPv6(udp)
	cat := func(parts ...[]byte) []byte {
		var out []byte
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	type form struct {
		link int
		data []byte
	}
	forms := []form{{229, raw}, {101, raw}, {228, raw},
		{1, cat(make([]byte, 12), []byte{0x86, 0xdd}, raw)},
		{1, cat(make([]byte, 12), []byte{0x81, 0, 0, 1, 0x86, 0xdd}, raw)},
		{113, cat(make([]byte, 14), []byte{0x86, 0xdd}, raw)},
		{276, cat([]byte{0x86, 0xdd}, make([]byte, 18), raw)}}
	for _, family := range []uint32{24, 28, 30} {
		le, be := make([]byte, 4), make([]byte, 4)
		binary.LittleEndian.PutUint32(le, family)
		binary.BigEndian.PutUint32(be, family)
		forms = append(forms, form{0, cat(le, raw)}, form{0, cat(be, raw)}, form{108, cat(be, raw)})
	}
	for _, f := range forms {
		got, err := Decode(f.data, f.link, Ignore)
		r, ok := err.(*Reject)
		if !ok || !strings.Contains(r.Message, "IPv4 only") || (r.Kind != KindLink && r.Kind != KindNetwork) {
			t.Fatalf("linktype %d prefix %x: decoded %v, err %v", f.link, f.data[:4], got, err)
		}
	}
	// Every IPv4 fragment form (more-fragments, a non-zero offset, the reserved flag) is a fragment rejection.
	frame := testframes.UDP("192.0.2.10", 5000, "192.0.2.20", 53, dns)
	for _, flags := range [][2]byte{{0x20, 0}, {0, 1}, {0x80, 0}, {0x3f, 0xff}} {
		f := append([]byte{}, frame...)
		f[14+6], f[14+7] = flags[0], flags[1]
		if _, err := Decode(f, 1, Ignore); err == nil || err.(*Reject).Kind != KindFragment {
			t.Fatalf("fragment flags %x accepted: %v", flags, err)
		}
	}
	for _, link := range []int{2, 9, 105, 127, 999, -1} {
		if _, err := Decode(frame, link, Ignore); err == nil || err.(*Reject).Kind != KindLink {
			t.Fatalf("unsupported linktype %d accepted: %v", link, err)
		}
	}
	// Seeded noise on every link type returns a value or a typed rejection, never a panic.
	rng := rand.New(rand.NewSource(6006))
	for length := 0; length < 200; length++ {
		data := make([]byte, length)
		rng.Read(data)
		for _, link := range []int{0, 1, 101, 108, 113, 228, 229, 276} {
			if _, err := Decode(data, link, Verify); err != nil {
				if _, ok := err.(*Reject); !ok {
					t.Fatalf("untyped error %T on linktype %d", err, link)
				}
			}
		}
	}
}
