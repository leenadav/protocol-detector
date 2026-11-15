package transport

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/parity"
	"github.com/leenadav/protocol-detector/go/internal/testframes"
)

var a, b = Endpoint{"192.0.2.10", 52000}, Endpoint{"192.0.2.20", 8080}

func mustTCP(t *testing.T, frame []byte, policy string) *TCP {
	t.Helper()
	got, err := Decode(frame, 1, policy)
	if err != nil {
		t.Fatal(err)
	}
	return got.(*TCP)
}

func TestEthernetTCPWithValidChecksums(t *testing.T) {
	frame := testframes.TCP(a.Addr, a.Port, b.Addr, b.Port, 1000, 9000, ACK|8, []byte("GET / HTTP/1.1\r\n"))
	for _, policy := range []string{Ignore, Audit, Verify} {
		p := mustTCP(t, frame, policy)
		if p.Source != a || p.Destination != b || p.Sequence != 1000 || p.Ack != 9000 || p.Flags != 24 || !bytes.Equal(p.Payload, []byte("GET / HTTP/1.1\r\n")) {
			t.Fatalf("%s: decoded %+v", policy, p)
		}
		if len(p.ChecksumFailures) != 0 {
			t.Fatalf("%s: failures %v", policy, p.ChecksumFailures)
		}
	}
}

func TestChecksumPolicies(t *testing.T) {
	frame := testframes.TCP(a.Addr, a.Port, b.Addr, b.Port, 1, 2, SYN, nil)
	frame[14+20+16] ^= 0xff // corrupt the TCP checksum
	if p := mustTCP(t, frame, Ignore); len(p.ChecksumFailures) != 0 {
		t.Fatal("ignore computed checksums")
	}
	if p := mustTCP(t, frame, Audit); len(p.ChecksumFailures) != 1 || p.ChecksumFailures[0] != "tcp" {
		t.Fatalf("audit: %v", p.ChecksumFailures)
	}
	_, err := Decode(frame, 1, Verify)
	r, ok := err.(*Reject)
	if !ok || r.Kind != KindChecksum || r.Endpoints == nil || r.Endpoints[0] != a {
		t.Fatalf("verify: %v", err)
	}
	udp := testframes.UDP(a.Addr, a.Port, b.Addr, 53, []byte("dns"))
	if p, err := Decode(udp, 1, Verify); err != nil || len(p.(*UDP).ChecksumFailures) != 0 {
		t.Fatalf("udp verify: %v %v", p, err)
	}
}

func TestRejectKinds(t *testing.T) {
	tcp := testframes.TCP(a.Addr, a.Port, b.Addr, b.Port, 1, 2, SYN, nil)
	cases := map[string]struct {
		frame    []byte
		linktype int
		kind     string
	}{
		"short ethernet":  {tcp[:10], 1, KindLink},
		"ipv6 ethertype":  {append(append([]byte{}, tcp[:12]...), append([]byte{0x86, 0xdd}, tcp[14:]...)...), 1, KindNetwork},
		"unknown link":    {tcp, 999, KindLink},
		"short ipv4":      {tcp[:14+10], 1, KindLength},
		"bad total":       {func() []byte { f := append([]byte{}, tcp...); f[14+2], f[14+3] = 0xff, 0xff; return f }(), 1, KindLength},
		"fragment":        {func() []byte { f := append([]byte{}, tcp...); f[14+6] = 0x20; f[14+7] = 0x01; return f }(), 1, KindFragment},
		"icmp":            {func() []byte { f := append([]byte{}, tcp...); f[14+9] = 1; return f }(), 1, KindTransport},
		"tcp header size": {func() []byte { f := append([]byte{}, tcp...); f[14+20+12] = 0x20; return f }(), 1, KindLength},
	}
	for name, c := range cases {
		_, err := Decode(c.frame, c.linktype, Ignore)
		r, ok := err.(*Reject)
		if !ok || r.Kind != c.kind {
			t.Fatalf("%s: want %s got %v", name, c.kind, err)
		}
	}
	// A first fragment still names its flow so the owner can mark it.
	f := append([]byte{}, tcp...)
	f[14+6] = 0x20
	_, err := Decode(f, 1, Ignore)
	if r := err.(*Reject); r.Endpoints == nil || r.Endpoints[0] != a || r.Endpoints[1] != b {
		t.Fatalf("fragment endpoints: %+v", r)
	}
	udp := testframes.UDP(a.Addr, a.Port, b.Addr, 53, []byte("x"))
	udp[14+20+5] = 3 // UDP length 3 < 8
	if _, err := Decode(udp, 1, Ignore); err.(*Reject).Kind != KindLength {
		t.Fatal(err)
	}
}

func TestOtherLinkTypes(t *testing.T) {
	eth := testframes.TCP(a.Addr, a.Port, b.Addr, b.Port, 7, 8, ACK, []byte("hi"))
	ip := eth[14:]
	loop := append([]byte{0, 0, 0, 2}, ip...)
	if p := mustLink(t, loop, 0); p.Payload[0] != 'h' {
		t.Fatal("loopback")
	}
	loopLE := append([]byte{2, 0, 0, 0}, ip...)
	mustLink(t, loopLE, 0)
	sll := append(append(make([]byte, 14), 0x08, 0x00), ip...)
	mustLink(t, sll, 113)
	sll2 := append(append([]byte{0x08, 0x00}, make([]byte, 18)...), ip...)
	mustLink(t, sll2, 276)
	mustLink(t, ip, 101)
	vlan := append(append(append([]byte{}, eth[:12]...), 0x81, 0x00, 0, 5, 0x08, 0x00), ip...)
	mustLink(t, vlan, 1)
	three := append(append(append([]byte{}, eth[:12]...), 0x81, 0x00, 0, 5, 0x88, 0xa8, 0, 6, 0x81, 0x00, 0, 7, 0x08, 0x00), ip...)
	if _, err := Decode(three, 1, Ignore); err.(*Reject).Kind != KindLink {
		t.Fatal("three VLAN tags accepted")
	}
}

func mustLink(t *testing.T, frame []byte, linktype int) *TCP {
	t.Helper()
	got, err := Decode(frame, linktype, Ignore)
	if err != nil {
		t.Fatalf("linktype %d: %v", linktype, err)
	}
	return got.(*TCP)
}

func TestEndpointOrderMatchesPythonTuples(t *testing.T) {
	if !(Endpoint{"192.0.2.9", 1}).Less(Endpoint{"192.0.2.10", 1}) == ("192.0.2.9" < "192.0.2.10") {
		t.Fatal("string order")
	}
	if !(Endpoint{"a", 1}).Less(Endpoint{"a", 2}) || (Endpoint{"a", 2}).Less(Endpoint{"a", 2}) {
		t.Fatal("port order")
	}
}

func TestEveryFixtureFrameDecodes(t *testing.T) {
	doc, err := parity.Load(context.Background(), "../../../migration/fixtures/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	frames := 0
	for _, c := range doc.Cases {
		if c.Kind != "session" {
			continue
		}
		for _, p := range c.Packets {
			frame, _ := hex.DecodeString(p.Frame)
			if _, err := Decode(frame, p.Linktype, Verify); err != nil {
				t.Fatalf("%s: %v", c.ID, err)
			}
			frames++
		}
	}
	if frames < 1000 {
		t.Fatalf("decoded only %d frames", frames)
	}
}

func FuzzDecodeNeverPanics(f *testing.F) {
	f.Add(testframes.TCP(a.Addr, a.Port, b.Addr, b.Port, 1, 2, SYN, []byte("x")), 1)
	f.Add(testframes.UDP(a.Addr, a.Port, b.Addr, 53, []byte("dns")), 1)
	f.Fuzz(func(t *testing.T, frame []byte, linktype int) {
		for _, policy := range []string{Ignore, Audit, Verify} {
			got, err := Decode(frame, linktype%300, policy)
			if (got == nil) == (err == nil) {
				t.Fatal("exactly one of result and error")
			}
			if err != nil {
				if _, ok := err.(*Reject); !ok {
					t.Fatalf("untyped error %v", err)
				}
			}
		}
	})
}
