package tlsx_test

import (
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/parsertest"
	"github.com/leenadav/protocol-detector/go/internal/protocols/fingerprint"
	"github.com/leenadav/protocol-detector/go/internal/protocols/tlsx"
)

func clientHelloALPN(offer []byte) []byte {
	entry := append([]byte{byte(len(offer))}, offer...)
	exts := ext(16, append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)...)
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)
	return record(append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...))
}

// SEC-FP-1 (PRO-392/PRO-394): the JA4/JA4S ALPN code is computed from the wire bytes. A printable offer that
// starts with "hex:" is text, so it is never decoded as hex; the display string is unchanged.
func TestALPNCodeReadsRawBytes(t *testing.T) {
	cases := []struct {
		offer   string
		code    string
		display string
	}{
		{"hex:zz", "hz", "hex:zz"},
		{"hex:4", "h4", "hex:4"},
		{"hex:7a7a", "ha", "hex:7a7a"},
		{"zz", "zz", "zz"},
		{"\x00\xff", "0f", "hex:00ff"},
	}
	for _, c := range cases {
		offer, err := tlsx.ParseClientHello(clientHelloALPN([]byte(c.offer))[9:], true)
		if err != nil {
			t.Fatal(err)
		}
		if got := fingerprint.JA4(offer.Info, "t"); !strings.HasPrefix(got, "t12i0101"+c.code+"_") {
			t.Errorf("client %q: want ALPN code %s in %s", c.offer, c.code, got)
		}
		for _, step := range []int{0, 1} {
			p, err := tlsx.New(tlsx.Options{MaxBytes: 65536, MaxHeaders: 128, Fingerprints: true})
			if err != nil {
				t.Fatal(err)
			}
			hello := clientHelloALPN([]byte(c.offer))
			got := parsertest.Drive(p, hello, step)
			if !strings.Contains(got, `alpn=["`+c.display+`"]`) {
				t.Errorf("client %q: display %q missing in %s", c.offer, c.display, got)
			}
			s, err := tlsx.New(tlsx.Options{MaxBytes: 65536, MaxHeaders: 128, Fingerprints: true})
			if err != nil {
				t.Fatal(err)
			}
			entry := append([]byte{byte(len(c.offer))}, c.offer...)
			got = parsertest.Drive(s, serverHello(0xc02f, ext(16, append([]byte{0, byte(len(entry))}, entry...)...)), step)
			if !strings.Contains(got, `"ja4s" "t1201`+c.code+`_c02f_`) {
				t.Errorf("server %q step %d: want ALPN code %s in %s", c.offer, step, c.code, got)
			}
			if !strings.Contains(got, `"selected_alpn" "`+c.display+`"`) {
				t.Errorf("server %q: display %q missing in %s", c.offer, c.display, got)
			}
		}
	}
}

// clientHelloOffers is a ClientHello body (no record or handshake header) offering each value, in order.
func clientHelloOffers(offers ...string) []byte {
	var list []byte
	for _, o := range offers {
		list = append(append(list, byte(len(o))), o...)
	}
	exts := ext(16, append([]byte{byte(len(list) >> 8), byte(len(list))}, list...)...)
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0, byte(len(exts)>>8), byte(len(exts)))
	return append(body, exts...)
}

// PRO-596: JA4 reads only the first offer, so only the first offer's wire bytes are kept, as one owned copy (the
// info outlives the caller's buffer), and a further offer costs no wire-byte copy. PRO-394 copied every offer
// into a growing [][]byte, which cost three allocations more per TLS flow.
func TestALPNFirstOfferIsTheOnlyWireCopy(t *testing.T) {
	body := clientHelloOffers("h2", "http/1.1")
	offer, err := tlsx.ParseClientHello(body, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(offer.Info.ALPNFirst) != "h2" || strings.Join(offer.Info.ALPN, ",") != "h2,http/1.1" {
		t.Fatalf("ALPN %q, first offer %q", offer.Info.ALPN, offer.Info.ALPNFirst)
	}
	for i := range body {
		body[i] = 'x' // the caller reuses its buffer: the kept bytes must not change with it
	}
	if string(offer.Info.ALPNFirst) != "h2" {
		t.Fatalf("ALPNFirst aliases the caller's buffer: %q", offer.Info.ALPNFirst)
	}
	if got := fingerprint.JA4(offer.Info, "t"); !strings.HasPrefix(got, "t12i0101h2_") {
		t.Fatalf("JA4 %s", got)
	}
	one, two := clientHelloOffers("h2"), clientHelloOffers("h2", "http/1.1")
	parse := func(b []byte) func() {
		return func() {
			if _, err := tlsx.ParseClientHello(b, true); err != nil {
				t.Fatal(err)
			}
		}
	}
	// A second offer adds its display string and the growth of the string slice, and nothing else.
	if extra := testing.AllocsPerRun(100, parse(two)) - testing.AllocsPerRun(100, parse(one)); extra > 2 {
		t.Fatalf("a second ALPN offer costs %.0f allocations, want at most 2", extra)
	}
}
