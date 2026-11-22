package analyze

import (
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
)

// fuzzFrame is an Ethernet/IPv4 frame carrying TCP (protocol 6) or UDP (17) between two fixed endpoints.
func fuzzFrame(protocol byte, client bool, sequence, acknowledgement uint32, flags byte, payload string) []byte {
	header := 20
	if protocol == 17 {
		header = 8
	}
	out := make([]byte, 34+header, 34+header+len(payload))
	out[12], out[13] = 8, 0
	ip := out[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, protocol
	binary.BigEndian.PutUint16(ip[2:], uint16(20+header+len(payload)))
	a, b := []byte{192, 0, 2, 10}, []byte{198, 51, 100, 20}
	from, to := uint16(51000), uint16(53)
	if protocol == 6 {
		to = 80
	}
	if !client {
		a, b, from, to = b, a, to, from
	}
	copy(ip[12:], a)
	copy(ip[16:], b)
	l4 := out[34:]
	binary.BigEndian.PutUint16(l4[0:], from)
	binary.BigEndian.PutUint16(l4[2:], to)
	if protocol == 6 {
		binary.BigEndian.PutUint32(l4[4:], sequence)
		binary.BigEndian.PutUint32(l4[8:], acknowledgement)
		l4[12], l4[13] = 5<<4, flags
	} else {
		binary.BigEndian.PutUint16(l4[4:], uint16(8+len(payload)))
	}
	return append(out, payload...)
}

func fuzzCapture(frames ...[]byte) []byte {
	out := []byte{0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0}
	for i, f := range frames {
		header := make([]byte, 16)
		binary.LittleEndian.PutUint32(header[0:], uint32(1700000000+i))
		binary.LittleEndian.PutUint32(header[8:], uint32(len(f)))
		binary.LittleEndian.PutUint32(header[12:], uint32(len(f)))
		out = append(append(out, header...), f...)
	}
	return out
}

// FuzzPresentNeverPanics drives a whole capture through the decoder, the tracker, every inspector and the
// record builder with every option on (contract C16: malformed input is refused or classified, never a crash,
// and a result is always well-formed JSON).
func FuzzPresentNeverPanics(f *testing.F) {
	dns := "\x124\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01"
	f.Add(fuzzCapture(
		fuzzFrame(6, true, 999, 0, 2, ""), fuzzFrame(6, false, 8999, 1000, 18, ""),
		fuzzFrame(6, true, 1000, 9000, 24, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"),
		fuzzFrame(6, false, 9000, 1039, 24, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
		fuzzFrame(17, true, 0, 0, 0, dns), fuzzFrame(6, true, 1039, 9038, 17, "")))
	f.Add(fuzzCapture(fuzzFrame(6, true, 999, 0, 2, ""), fuzzFrame(6, false, 8999, 1000, 18, ""),
		fuzzFrame(6, true, 1000, 9000, 24, "\x16\x03\x01\x00\x2f\x01\x00\x00\x2b\x03\x03")))
	f.Add(fuzzCapture(fuzzFrame(17, true, 0, 0, 0, "\xc0\x00\x00\x00\x01\x08\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00")))
	f.Add([]byte("not a capture"))
	pack, err := content.Embedded()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			return
		}
		text, err := Present(data, pack, Limits{Frames: 2000, Sessions: 200, Events: 2000}, func() float64 { return 0 })
		if err == nil && !json.Valid([]byte(text)) {
			t.Fatalf("invalid JSON result: %.400s", text)
		}
	})
}
