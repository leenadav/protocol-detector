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
