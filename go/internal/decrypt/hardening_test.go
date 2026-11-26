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

// PRO-119: the A2 security review's decrypt hardening (SEC-DEC-1 heap retention, SEC-KEY-1 key zeroing).

const bulkRecord = 16000 // application bytes per record, under the 16384 plaintext limit

// bulkTLS13 is tls13Session with n application records of bulkRecord bytes in each direction.
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

// SEC-DEC-1: a connection that waits for keys holds each buffered byte once. Before the fix a framing pass
// copied every record into the queue while the framer's buffer kept the consumed prefix alive behind its
// (empty) tail, so the connection held its bytes twice; 64 such connections held about 32 MiB.
func TestAwaitingKeysConnectionHoldsItsBytesOnce(t *testing.T) {
	s := bulkTLS13(14)
	fed := float64(len(s.client) + len(s.server))
	retained := retainedPerConnection(16, func() *Connection {
		c := NewConnection(NewKeyProvider(), "c", "s")
		feedChunked(c, s) // the hellos are framed, then the wait for keys leaves the rest in the framer
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

// SEC-DEC-1: a record is released once it is decoded. Before the fix the queue's array kept every processed
// record (queued[1:] and the zero-length slice left at the end still pointed at it).
func TestDecodedRecordsAreNotRetained(t *testing.T) {
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
		return c // not finished: a live connection that has decoded everything
	})
	if retained > 16384 {
		t.Errorf("a connection with nothing left to decode holds %.0f bytes", retained)
	}
}

// SEC-KEY-1: the traffic secret a KeyUpdate replaces is overwritten, and so is the handshake epoch's secret once
// the application epoch starts.
func TestReplacedSecretsAreZeroed(t *testing.T) {
	s := tls13Session(0x1301)
	keys, err := ReadKeys(s.keylog)
	if err != nil {
		t.Fatal(err)
	}
	c := NewConnection(keys, "c", "s")
	c.Feed("c", s.client)
	c.Feed("s", s.server)
	c.Advance(0) // negotiates and derives both directions; decodes nothing
	client := c.dirs[0].(*tls13Direction)
	handshakeSecret, handshakeIV := client.secrets[phaseHandshake], client.ivs[phaseHandshake]
	var replaced [][]byte
	for c.HasWork() {
		secret, iv, updates := client.secrets[phaseApplication], client.ivs[phaseApplication], client.updates
		c.Advance(1)
		if client.updates != updates {
			replaced = append(replaced, secret, iv)
		}
	}
	if len(replaced) != 2 {
		t.Fatalf("%d KeyUpdates seen", len(replaced)/2)
	}
	for name, b := range map[string][]byte{"handshake secret": handshakeSecret, "handshake IV": handshakeIV,
		"replaced traffic secret": replaced[0], "replaced IV": replaced[1]} {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Errorf("%s not zeroed: %x", name, b)
		}
	}
	if _, ok := client.secrets[phaseHandshake]; ok || bytes.Equal(client.secrets[phaseApplication], make([]byte, 32)) {
		t.Errorf("live secrets: %v", client.secrets)
	}
	if c.Finish() != StateComplete {
		t.Fatalf("finish: %s %s", c.State, c.Reason)
	}
}

// SEC-KEY-1: a terminal connection overwrites its directions' secrets and IVs (TLS 1.3) and IVs (TLS 1.2), and the
// TLS 1.2 key block is overwritten as soon as the record keys are derived.
func TestTerminalConnectionsZeroTheirRecordKeys(t *testing.T) {
	s := tls13Session(0x1302)
	keys, err := ReadKeys(s.keylog)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte{}, s.server...)
	tampered[len(tampered)-3] ^= 1
	for _, tc := range []struct {
		name, state string
		server      []byte
	}{{"complete", StateComplete, s.server}, {"failed", StateFailed, tampered}} {
		c := NewConnection(keys, "c", "s")
		c.Feed("c", s.client)
		c.Feed("s", tc.server)
		c.Advance(0)
		var held [][]byte
		for _, dir := range c.dirs {
			d := dir.(*tls13Direction)
			held = append(held, d.secrets[phaseApplication], d.ivs[phaseApplication])
		}
		if c.Finish() != tc.state {
			t.Fatalf("%s: %s %s", tc.name, c.State, c.Reason)
		}
		for i, b := range held {
			if len(b) == 0 || !bytes.Equal(b, make([]byte, len(b))) {
				t.Errorf("%s: buffer %d not zeroed: %x", tc.name, i, b)
			}
		}
	}

	t12 := tls12Session()
	keys, err = ReadKeys(t12.keylog)
	if err != nil {
		t.Fatal(err)
	}
	c := NewConnection(keys, "c", "s")
	c.Feed("c", t12.client)
	c.Feed("s", t12.server)
	c.Advance(0)
	ivs := [][]byte{c.dirs[0].(*tls12Direction).iv, c.dirs[1].(*tls12Direction).iv}
	var plain bytes.Buffer
	for c.HasWork() {
		for _, d := range c.Advance(64) {
			plain.Write(d.Data)
		}
	}
	if c.Finish() != StateComplete || plain.String() != string(t12.request)+string(t12.reply) {
		t.Fatalf("TLS 1.2: %s %s %q", c.State, c.Reason, plain.String())
	}
	for i, b := range ivs {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Errorf("TLS 1.2 IV %d not zeroed: %x", i, b)
		}
	}
}

// SEC-KEY-1 (second A2 run): Expire overwrites a secret before it forgets it, as Release does.
func TestExpireZeroesTheSecretsItDrops(t *testing.T) {
	now, age := 100.0, 10.0
	p := NewKeyProvider()
	p.MaxAge, p.Clock = &age, func() float64 { return now }
	random := bytes.Repeat([]byte{7}, 32)
	if _, err := p.Append("CLIENT_RANDOM " + hex.EncodeToString(random) + " " + hex.EncodeToString(bytes.Repeat([]byte{9}, 48)) + "\n"); err != nil {
		t.Fatal(err)
	}
	held, _ := p.Lookup("CLIENT_RANDOM", random)
	if len(held) != 48 {
		t.Fatalf("secret %x", held)
	}
	later := now + age + 1
	if p.Expire(&later) != 1 || p.Len() != 0 {
		t.Fatalf("expiry: %s", p)
	}
	if !bytes.Equal(held, make([]byte, 48)) {
		t.Errorf("an expired secret was dropped without being overwritten: %x", held)
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
