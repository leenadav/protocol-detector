package decrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"runtime"
	"testing"
)

// PRO-119 (PRO-459): the cases of the duplicate PR #147 that this branch's own tests did not cover, ported by
// behaviour: bulk heap measures fed the way a coordinator feeds (1460-byte segments, work after each), a fully
// decoded live connection, the handshake epoch's secret once the application epoch starts, and the hello buffers
// once the hellos are negotiated (TLS 1.3 and TLS 1.2).

const bulkRecord = 16000 // application bytes per record, under the 16384 plaintext limit

// bulkTLS13 is tls13Session's handshake with n application records of bulkRecord bytes in each direction.
func bulkTLS13(n int) session {
	random := bytes.Repeat([]byte{0x5a}, 32)
	secret := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	hello := append(append([]byte{3, 3}, random...), 0, 0, 2, 0x13, 0x01, 1, 0, 0, 0)
	sh := append(append([]byte{3, 3}, bytes.Repeat([]byte{0x11}, 32)...), 0, 0x13, 0x01, 0, 0, 6, 0, 43, 0, 2, 3, 4)
	cw, sw := newWriter13(0x1301, secret(1), secret(3)), newWriter13(0x1301, secret(2), secret(4))
	finished := handshake(20, bytes.Repeat([]byte{9}, 32))
	var s session
	s.server = append(plainRecord(22, handshake(2, sh)), plainRecord(20, []byte{1})...)
	s.server = append(s.server, sw.record(22, finished)...)
	sw.application()
	s.client = append(plainRecord(22, handshake(1, hello)), cw.record(22, finished)...)
	cw.application()
	payload := bytes.Repeat([]byte{'a'}, bulkRecord)
	for i := 0; i < n; i++ {
		s.client = append(s.client, cw.record(23, payload)...)
		s.server = append(s.server, sw.record(23, payload)...)
	}
	r := hex.EncodeToString(random)
	for i, name := range []string{"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"} {
		s.keylog += fmt.Sprintf("%s %s %s\n", name, r, hex.EncodeToString(secret(byte(i+1))))
	}
	return s
}

// retainedPerConnection builds n connections with build and returns the live heap each one holds afterwards.
func retainedPerConnection(n int, build func() *Connection) float64 {
	conns := make([]*Connection, n)
	runtime.GC()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := range conns {
		conns[i] = build()
	}
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(conns)
	return (float64(after.HeapAlloc) - float64(before.HeapAlloc)) / float64(n)
}

// feedChunked feeds both directions in 1460-byte segments, doing the work a coordinator would after each one.
func feedChunked(c *Connection, s session) {
	for _, side := range []struct {
		endpoint string
		data     []byte
	}{{"c", s.client}, {"s", s.server}} {
		for i := 0; i < len(side.data); i += 1460 {
			c.Feed(side.endpoint, side.data[i:min(i+1460, len(side.data))])
			for c.HasWork() {
				c.Advance(256)
			}
		}
	}
}

// SEC-DEC-1 (from #147): a connection waiting for keys holds each byte about once when fed in segments, both
// while the bytes wait in the framer and after a new key version frames them all into the queue in one pass.
func TestSegmentedAwaitingKeysConnectionHoldsItsBytesOnce(t *testing.T) {
	s := bulkTLS13(14)
	fed := float64(len(s.client) + len(s.server))
	retained := retainedPerConnection(16, func() *Connection {
		c := NewConnection(NewKeyProvider(), "c", "s")
		feedChunked(c, s)
		if c.State != StateAwaitingKeys {
			t.Fatalf("state %s", c.State)
		}
		return c
	})
	// An unrelated secret moves the provider's version: the waiting connection frames all it has buffered.
	other := "CLIENT_RANDOM " + hex.EncodeToString(bytes.Repeat([]byte{1}, 32)) + " " + hex.EncodeToString(bytes.Repeat([]byte{2}, 48)) + "\n"
	framed := retainedPerConnection(16, func() *Connection {
		keys := NewKeyProvider()
		c := NewConnection(keys, "c", "s")
		feedChunked(c, s)
		if _, err := keys.Append(other); err != nil {
			t.Fatal(err)
		}
		if !c.HasWork() {
			t.Fatal("a new key version is work")
		}
		c.Advance(256)
		if c.State != StateAwaitingKeys || len(c.queued[0]) == 0 {
			t.Fatalf("state %s, %d queued", c.State, len(c.queued[0]))
		}
		return c
	})
	for name, got := range map[string]float64{"framed as it arrived": retained, "framed in one pass": framed} {
		if limit := 1.15*fed + 16384; got > limit {
			t.Errorf("%s: a waiting connection holds %.0f bytes for %.0f fed (limit %.0f)", name, got, fed, limit)
		}
	}
}

// SEC-DEC-1 (from #147): a live connection that has decoded every record holds almost nothing: neither the
// processed records nor the hello buffers.
func TestFullyDecodedLiveConnectionHoldsNoRecords(t *testing.T) {
	s := bulkTLS13(14)
	keys, err := ReadKeys(s.keylog)
	if err != nil {
		t.Fatal(err)
	}
	retained := retainedPerConnection(16, func() *Connection {
		c := NewConnection(keys, "c", "s")
		c.Feed("c", s.client)
		c.Feed("s", s.server)
		released := 0
		for c.HasWork() {
			for _, d := range c.Advance(3) {
				released += len(d.Data)
			}
		}
		if c.State != StateDecrypting || released != 2*14*bulkRecord {
			t.Fatalf("state %s, %d bytes released", c.State, released)
		}
		return c // not finished: release() has not run
	})
	if retained > 16384 {
		t.Errorf("a connection with nothing left to decode holds %.0f bytes", retained)
	}
}

// SEC-KEY-1 (from #147): the handshake epoch's secret and IV are overwritten and dropped once the application
// epoch starts, not only when the connection ends; the application secret stays live and decryption completes.
func TestHandshakeSecretIsZeroedWhenTheApplicationEpochStarts(t *testing.T) {
	s := tls13Session(0x1301)
	keys, err := ReadKeys(s.keylog)
	if err != nil {
		t.Fatal(err)
	}
	c := NewConnection(keys, "c", "s")
	c.Feed("c", s.client)
	c.Feed("s", s.server)
	c.Advance(0) // negotiates and derives both directions; decodes nothing
	var secrets, ivs [2][]byte
	for side, dir := range c.dirs {
		d := dir.(*tls13Direction)
		secrets[side], ivs[side] = d.secrets[phaseHandshake], d.ivs[phaseHandshake]
		if len(secrets[side]) == 0 || len(ivs[side]) == 0 {
			t.Fatalf("side %d holds no handshake secret", side)
		}
	}
	plain := map[string]*bytes.Buffer{"c": {}, "s": {}}
	for c.HasWork() {
		for _, d := range c.Advance(1) {
			plain[d.Endpoint].Write(d.Data)
		}
	}
	for side, dir := range c.dirs {
		d := dir.(*tls13Direction)
		if d.phase != phaseApplication {
			t.Fatalf("side %d still in %s", side, d.phase)
		}
		for name, b := range map[string][]byte{"handshake secret": secrets[side], "handshake IV": ivs[side]} {
			if !bytes.Equal(b, make([]byte, len(b))) {
				t.Errorf("side %d: %s not zeroed: %x", side, name, b)
			}
		}
		if _, ok := d.secrets[phaseHandshake]; ok {
			t.Errorf("side %d keeps a handshake secret", side)
		}
		if _, ok := d.ciphers[phaseHandshake]; ok {
			t.Errorf("side %d keeps a handshake AEAD", side)
		}
		if live := d.secrets[phaseApplication]; len(live) == 0 || bytes.Equal(live, make([]byte, len(live))) {
			t.Errorf("side %d: application secret %x", side, live)
		}
	}
	logged, _ := keys.Lookup("CLIENT_"+phaseHandshake, bytes.Repeat([]byte{0x5a}, 32))
	if bytes.Equal(logged, make([]byte, len(logged))) {
		t.Fatal("the key provider's own handshake secret was overwritten")
	}
	if c.Finish() != StateComplete || plain["c"].String() != string(s.request) || plain["s"].String() != string(s.reply) {
		t.Fatalf("finish: %s %s %q %q", c.State, c.Reason, plain["c"], plain["s"])
	}
}

// SEC-DEC-1 (from #147): once the hellos are negotiated the connection keeps no hello buffer (each up to
// MaxStream), only the done flags and, for TLS 1.2, a small copy of the 34 ServerHello bytes its key expansion reads.
func TestHelloBuffersAreDroppedOnceNegotiated(t *testing.T) {
	t13, t12 := tls13Session(0x1301), tls12Session()
	for _, tc := range []struct {
		name     string
		s        session
		maxBody1 int
	}{{"TLS 1.3", t13, 0}, {"TLS 1.2", t12, 34}} {
		keys, err := ReadKeys(tc.s.keylog)
		if err != nil {
			t.Fatal(err)
		}
		c := NewConnection(keys, "c", "s")
		c.Feed("c", tc.s.client)
		c.Feed("s", tc.s.server)
		c.Advance(0)
		if c.Version != tc.name {
			t.Fatalf("%s: negotiated %q (%s %s)", tc.name, c.Version, c.State, c.Reason)
		}
		for side, h := range c.hellos {
			if !h.done || h.data != nil || h.records != nil {
				t.Errorf("%s side %d: done %v, %d data bytes, %d records kept", tc.name, side, h.done, len(h.data), len(h.records))
			}
		}
		if len(c.hellos[0].body) != 0 || len(c.hellos[1].body) != tc.maxBody1 || cap(c.hellos[1].body) > 64 {
			t.Errorf("%s: hello bodies kept: %d and %d (cap %d)", tc.name, len(c.hellos[0].body), len(c.hellos[1].body), cap(c.hellos[1].body))
		}
		plain := map[string]*bytes.Buffer{"c": {}, "s": {}}
		for c.HasWork() {
			for _, d := range c.Advance(64) {
				plain[d.Endpoint].Write(d.Data)
			}
		}
		if c.Finish() != StateComplete || plain["c"].String() != string(tc.s.request) || plain["s"].String() != string(tc.s.reply) {
			t.Fatalf("%s: %s %s %q %q", tc.name, c.State, c.Reason, plain["c"], plain["s"])
		}
	}
}

// writer12 seals TLS 1.2 AES-128-GCM records (explicit nonce = sequence number).
type writer12 struct {
	aead cipher.AEAD
	iv   []byte
	seq  uint64
}

func (w *writer12) record(kind byte, content []byte) []byte {
	explicit := binary.BigEndian.AppendUint64(nil, w.seq)
	aad := binary.BigEndian.AppendUint64(nil, w.seq)
	aad = append(aad, kind, 3, 3)
	aad = binary.BigEndian.AppendUint16(aad, uint16(len(content)))
	w.seq++
	body := append(explicit, w.aead.Seal(nil, append(append([]byte{}, w.iv...), explicit...), content, aad)...)
	return plainRecord(kind, body)
}

// tls12Session builds an ECDHE-RSA AES-128-GCM (0xc02f) session.
func tls12Session() session {
	clientRandom, serverRandom := bytes.Repeat([]byte{0x5a}, 32), bytes.Repeat([]byte{0x11}, 32)
	master := bytes.Repeat([]byte{0x33}, 48)
	block := prf(master, append(append([]byte("key expansion"), serverRandom...), clientRandom...), 40, "sha256")
	gcm := func(key []byte) cipher.AEAD {
		b, _ := aes.NewCipher(key)
		a, _ := cipher.NewGCM(b)
		return a
	}
	cw, sw := &writer12{aead: gcm(block[:16]), iv: block[32:36]}, &writer12{aead: gcm(block[16:32]), iv: block[36:40]}
	hello := append(append([]byte{3, 3}, clientRandom...), 0, 0, 2, 0xc0, 0x2f, 1, 0)
	sh := append(append([]byte{3, 3}, serverRandom...), 0, 0xc0, 0x2f, 0, 0, 0)
	finished := handshake(20, bytes.Repeat([]byte{9}, 12))
	s := session{request: []byte("GET / HTTP/1.1\r\n\r\n"), reply: []byte("HTTP/1.1 204 No Content\r\n\r\n")}
	s.client = append(plainRecord(22, handshake(1, hello)), plainRecord(22, handshake(16, []byte{1, 4}))...)
	s.client = append(s.client, plainRecord(20, []byte{1})...)
	s.client = append(s.client, cw.record(22, finished)...)
	s.client = append(s.client, cw.record(23, s.request)...)
	s.server = append(plainRecord(22, handshake(2, sh)), plainRecord(22, handshake(14, nil))...)
	s.server = append(s.server, plainRecord(20, []byte{1})...)
	s.server = append(s.server, sw.record(22, finished)...)
	s.server = append(s.server, sw.record(23, s.reply)...)
	s.keylog = "CLIENT_RANDOM " + hex.EncodeToString(clientRandom) + " " + hex.EncodeToString(master) + "\n"
	return s
}
