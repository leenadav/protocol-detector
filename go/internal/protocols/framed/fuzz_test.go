package framed

import (
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

type feeder interface {
	Feed([]byte) (int, error)
	Done() bool
	Result() *parsing.Result
}

func parsers() []feeder {
	return []feeder{NewPostgreSQL(4096), NewRFB(4096), NewBitTorrent(4096), NewMemcached(4096), NewRsync(512, 16), NewFINS(4096),
		NewAFP(4096), NewZMTP(4096), NewBolt(4096), NewSTOMP(512, 16), NewGIOP(4096, 512, 16), NewX11(4096), NewX11Reply(4096),
		NewSPICE(4096), NewMySQL(4096), NewMongoDB(MongoConfig{MaxBytes: 4096, MaxHeaders: 16, MaxLine: 512, MaxCRC32CBytes: 4096}),
		NewTDS(4096), NewTNS(4096), NewCQL(4096), NewKafka(4096)}
}

// FuzzFramedNeverPanics feeds arbitrary bytes, in two chunks, to every framed parser (including the hint-only
// MySQL, MongoDB/BSON and X11 reply profiles that the dispatcher never selects): no panic, consumption within the
// input, and a result only once done.
func FuzzFramedNeverPanics(f *testing.F) {
	f.Add([]byte("GIOP\x01\x02\x00\x00\x00\x00\x00\x18"), 3)
	f.Add([]byte("\x1d\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xdd\x07\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x10a\x00\x01"), 7)
	f.Add([]byte("@RSYNCD: 31.0\n"), 1)
	f.Fuzz(func(t *testing.T, data []byte, cut int) {
		if cut < 0 || cut > len(data) {
			cut = len(data) / 2
		}
		for _, p := range parsers() {
			n, err := p.Feed(data[:cut])
			if n < 0 || n > cut {
				t.Fatalf("%T consumed %d of %d", p, n, cut)
			}
			if err == nil && !p.Done() {
				m, _ := p.Feed(data[cut:])
				if m < 0 || m > len(data)-cut {
					t.Fatalf("%T consumed %d of %d", p, m, len(data)-cut)
				}
			}
			if p.Done() != (p.Result() != nil) {
				t.Fatalf("%T done %v with result %v", p, p.Done(), p.Result())
			}
		}
	})
}
