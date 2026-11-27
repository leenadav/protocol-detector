package tlsx_test

import (
	"reflect"
	"runtime"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/parsertest"
	"github.com/leenadav/protocol-detector/go/internal/parsing"
	"github.com/leenadav/protocol-detector/go/internal/protocols/tlsx"
)

// PRO-596 (Lee: "the share must not be copied"): a hello that arrives whole, in one record and one Feed, is read
// where it lies instead of being copied into the reassembly buffer, so a 1,120-byte post-quantum key share costs
// no bytes per flow. The result must not alias the caller's buffer, which the caller may reuse after Feed.

func serverHelloWithShare(group, size int) []byte {
	return serverHello(0x1301, append(append([]byte{}, ext(43, 3, 4)...), hybridShare(group, size, 0x55)...))
}

func hybridServerHelloRecord() []byte { return serverHelloWithShare(0x11ec, 1088+32) }

func clientHelloWithShare(group, size int) []byte {
	sni := ext(0, append([]byte{0, 18, 0, 0, 15}, "www.example.com"...)...)
	alpn := ext(16, 0, 3, 2, 'h', '2')
	versions := ext(43, 4, 3, 4, 3, 3)
	key := make([]byte, size)
	for i := range key {
		key[i] = byte(i*13 + 5)
	}
	shares := append([]byte{byte(group >> 8), byte(group), byte(len(key) >> 8), byte(len(key))}, key...)
	keyShare := ext(51, append([]byte{byte(len(shares) >> 8), byte(len(shares))}, shares...)...)
	extensions := append(append(append(append([]byte{}, sni...), alpn...), versions...), keyShare...)
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)
	return record(append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...))
}

func hybridClientHelloRecord() []byte { return clientHelloWithShare(0x11ec, 1184+32) }

func inPlaceOptions() tlsx.Options {
	return tlsx.Options{MaxBytes: 65536, MaxHeaders: 128, Fingerprints: true, RetainContexts: true}
}

func freshInPlace(t testing.TB) parsing.Parser {
	p, err := tlsx.New(inPlaceOptions())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func feedWhole(t testing.TB, data []byte) *parsing.Result { return feedWith(t, inPlaceOptions(), data) }

func feedWith(t testing.TB, opts tlsx.Options, data []byte) *parsing.Result {
	p, err := tlsx.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	p.SetCredit(parsing.NewCredit(1 << 20))
	if n, err := p.Feed(data); err != nil || n != len(data) || !p.Done() {
		t.Fatalf("whole hello: consumed %d of %d, err %v, done %v", n, len(data), err, p.Done())
	}
	return p.Result()
}

func TestWholeHelloResultDoesNotAliasTheInput(t *testing.T) {
	for name, data := range map[string][]byte{"server": hybridServerHelloRecord(), "client": hybridClientHelloRecord()} {
		input := append([]byte(nil), data...)
		got := feedWhole(t, input)
		want := feedWhole(t, append([]byte(nil), data...))
		for i := range input {
			input[i] = 0xee // the caller reuses its buffer
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: the result changed when the input buffer was reused:\n got %+v\nwant %+v", name, got, want)
		}
		if split := parsertest.Drive(freshInPlace(t), data, 7); split != parsertest.Drive(freshInPlace(t), data, 0) {
			t.Fatalf("%s: a split feed differs from the whole one", name)
		}
	}
}

// A whole X25519MLKEM768 hello must cost what a whole X25519 one costs: the 1,088 or 1,184 extra share bytes
// are read in place, never copied.
func TestWholeHybridHelloDoesNotCopyTheShare(t *testing.T) {
	// RetainContexts off: with it on, the contexts keep an owned copy of the whole ClientHello for signatures, on
	// purpose; the engine enables it only when signatures need it.
	opts := tlsx.Options{MaxBytes: 65536, MaxHeaders: 128, Fingerprints: true}
	if raceEnabled {
		// The race runtime allocates per call in proportion to the bytes it watches, so a byte count says nothing
		// about a copy there; the plain `go test` runs (and the coverage job) hold this check.
		t.Log("byte counts are not comparable under -race; TestWholeHelloResultDoesNotAliasTheInput still runs")
		return
	}
	cost := func(data []byte) int64 {
		const runs = 400
		feedWith(t, opts, data) // warm: the allocator's size-class table and the parser's lazy state
		best := int64(-1)
		for round := 0; round < 5; round++ { // the least of five rounds: the runtime allocates beside the test
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			for i := 0; i < runs; i++ {
				feedWith(t, opts, data)
			}
			runtime.ReadMemStats(&after)
			if n := int64(after.TotalAlloc-before.TotalAlloc) / runs; best < 0 || n < best {
				best = n
			}
		}
		return best
	}
	for _, c := range []struct {
		name              string
		classical, hybrid []byte
	}{
		{"server", serverHelloWithShare(29, 32), hybridServerHelloRecord()},
		{"client", clientHelloWithShare(29, 32), hybridClientHelloRecord()},
	} {
		classical, hybrid := cost(c.classical), cost(c.hybrid)
		t.Logf("%s: classical %d B, hybrid %d B per whole hello", c.name, classical, hybrid)
		if hybrid-classical > 512 { // a copy adds at least the 1,088-byte difference in share size
			t.Errorf("%s: a hybrid hello allocates %d bytes more than a classical one (%d vs %d): the share is copied",
				c.name, hybrid-classical, hybrid, classical)
		}
	}
}
