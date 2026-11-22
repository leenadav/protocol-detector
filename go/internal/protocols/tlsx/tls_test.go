package tlsx_test

import (
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/parsertest"
	"github.com/leenadav/protocol-detector/go/internal/parsing"
	"github.com/leenadav/protocol-detector/go/internal/protocols/tlsx"
)

const fixtures = "../../../../migration/fixtures/cases.json"

func fresh(t testing.TB) parsing.Parser {
	p, err := tlsx.New(tlsx.Options{MaxBytes: 65536, MaxHeaders: 128})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func record(handshake []byte) []byte {
	return append([]byte{22, 3, 3, byte(len(handshake) >> 8), byte(len(handshake))}, handshake...)
}

func serverHello(cipher int, extensions []byte) []byte {
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, byte(cipher>>8), byte(cipher), 0, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)
	return record(append([]byte{2, 0, byte(len(body) >> 8), byte(len(body))}, body...))
}

func ext(kind int, value ...byte) []byte {
	return append([]byte{byte(kind >> 8), byte(kind), byte(len(value) >> 8), byte(len(value))}, value...)
}

// Server-hello decisions at the parser. The work item #4 and #5 rows (post-quantum hybrids, unnamed and GREASE
// values) are not on main: they leave with those fixes, which need a Go-only change (see LANE-BRIEF-culvert.md).
func TestServerHelloSelections(t *testing.T) {
	tls13 := ext(43, 3, 4)
	share := func(group, size int, first byte) []byte {
		key := make([]byte, size)
		if size > 0 {
			key[0] = first
		}
		return ext(51, append([]byte{byte(group >> 8), byte(group), byte(size >> 8), byte(size)}, key...)...)
	}
	cases := []struct {
		name  string
		data  []byte
		wants []string
	}{
		{"x25519", serverHello(0x1301, append(tls13, share(29, 32, 7)...)), []string{`done=true`, `"selected_key_exchange" "ecdhe"`}},
		{"p256 without point byte", serverHello(0x1301, append(tls13, share(23, 65, 7)...)), []string{`error="malformed: Server key share encoding length or point format invalid"`}},
		{"tls13 unknown extension", serverHello(0x1301, append(append(tls13, share(29, 32, 7)...), ext(1234)...)), []string{`error="unsupported: Extension outside supported TLS 1.3 server hello context"`}},
		{"tls12 duplicate extension", serverHello(0xc02f, append(ext(1234), ext(1234)...)), []string{`error="malformed: Duplicate ServerHello extension"`}},
		{"not a handshake record", []byte{23, 3, 3, 0, 1, 0}, []string{`error="malformed: Expected plaintext TLS handshake record"`}},
	}
	for _, c := range cases {
		got := parsertest.Drive(fresh(t), c.data, 0)
		for _, want := range c.wants {
			if !strings.Contains(got, want) {
				t.Errorf("%s: want %s in %s", c.name, want, got)
			}
		}
		if bytewise := parsertest.Drive(fresh(t), c.data, 1); bytewise != got {
			t.Errorf("%s: byte by byte differs:\n whole %s\n bytes %s", c.name, got, bytewise)
		}
	}
}

// Every stream fixture gives the same answer whole, byte by byte and in 7-byte pieces.
func TestFixturesAreSplitInvariant(t *testing.T) {
	streams, err := parsertest.Streams(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	identified := 0
	for _, data := range streams {
		whole := parsertest.Drive(fresh(t), data, 0)
		if strings.HasPrefix(whole, "BROKEN") {
			t.Fatalf("%x: %s", data, whole)
		}
		if strings.Contains(whole, `error="" done=true`) {
			identified++
		}
		for _, step := range []int{1, 7} {
			if got := parsertest.Drive(fresh(t), data, step); got != whole {
				t.Fatalf("%x in %d-byte pieces:\n whole %s\n split %s", data, step, whole, got)
			}
		}
	}
	if identified < 15 { // main's fixture set completes 20 hellos with the default options
		t.Fatalf("only %d fixtures completed a hello; the fixture path or labels changed", identified)
	}
}

// FuzzSplitInvariance: arbitrary bytes never panic, never over-consume, and give one answer however they are split.
func FuzzSplitInvariance(f *testing.F) {
	streams, err := parsertest.Streams(fixtures, "tls")
	if err != nil {
		f.Fatal(err)
	}
	for i, data := range streams {
		f.Add(data, uint8(i))
	}
	f.Fuzz(func(t *testing.T, data []byte, step uint8) {
		whole := parsertest.Drive(fresh(t), data, 0)
		split := parsertest.Drive(fresh(t), data, int(step%64)+1)
		if strings.HasPrefix(whole, "BROKEN") || whole != split {
			t.Fatalf("step %d:\n whole %s\n split %s", int(step%64)+1, whole, split)
		}
	})
}
