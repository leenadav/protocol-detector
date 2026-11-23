package decrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// Vectors computed by the Python reference (poc_decryption.tls12.prf and poc_decryption.expand).
func TestKeyScheduleMatchesTheReference(t *testing.T) {
	seed := append([]byte("key expansion"), seq(100, 164)...)
	if got := hex.EncodeToString(prf(seq(0, 48), seed, 40, "sha256")); got != "28685edb204ecc92242de5440cbbaab263b26917badda780ffac162c8d5a190db504e2223d7549b8" {
		t.Errorf("prf sha256: %s", got)
	}
	if got := hex.EncodeToString(prf(seq(0, 48), seed, 72, "sha384")); got != "1ef6cb01527c4d5a83d5dc42afa62a9c27b940128ab240da3008c18b191d6cb911854353158b4b09047f65222a9e79e2a9484d3fc2388fcec5cd7a5cf1323e93599425a430ec6306" {
		t.Errorf("prf sha384: %s", got)
	}
	if got := hex.EncodeToString(expand(seq(0, 48), "key", 32, "sha384")); got != "6877d022f1c61d24ebb7487c16752d9a4798e40431c75b39320e537c90e23225" {
		t.Errorf("expand: %s", got)
	}
}

func seq(from, to int) []byte {
	out := make([]byte, 0, to-from)
	for i := from; i < to; i++ {
		out = append(out, byte(i))
	}
	return out
}

// --- an independent TLS 1.3 record writer (standard-library HKDF and AEADs) --------------------------------

func hashFor(suite int) func() hash.Hash {
	if suite == 0x1302 {
		return sha512.New384
	}
	return sha256.New
}

func label(suite int, secret []byte, name string, length int) []byte {
	full := "tls13 " + name
	info := binary.BigEndian.AppendUint16(nil, uint16(length))
	info = append(append(append(info, byte(len(full))), full...), 0)
	out, err := hkdf.Expand(hashFor(suite), secret, string(info), length)
	if err != nil {
		panic(err)
	}
	return out
}

type writer13 struct {
	suite   int
	secrets [2][]byte
	phase   int
	seq     uint64
	aead    cipher.AEAD
	iv      []byte
}

func newWriter13(suite int, hs, app []byte) *writer13 {
	w := &writer13{suite: suite, secrets: [2][]byte{hs, app}}
	w.install()
	return w
}

func (w *writer13) install() {
	size := 16
	if w.suite != 0x1301 {
		size = 32
	}
	key := label(w.suite, w.secrets[w.phase], "key", size)
	if w.suite == 0x1303 {
		w.aead, _ = chacha20poly1305.New(key)
	} else {
		block, _ := aes.NewCipher(key)
		w.aead, _ = cipher.NewGCM(block)
	}
	w.iv = label(w.suite, w.secrets[w.phase], "iv", 12)
}

func (w *writer13) record(kind byte, content []byte) []byte {
	inner := append(append([]byte{}, content...), kind)
	header := []byte{23, 3, 3, 0, 0}
	binary.BigEndian.PutUint16(header[3:], uint16(len(inner)+16))
	nonce := append([]byte{}, w.iv...)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= byte(w.seq >> (56 - 8*i))
	}
	w.seq++
	return append(header, w.aead.Seal(nil, nonce, inner, header)...)
}

func (w *writer13) application() { w.phase, w.seq = 1, 0; w.install() }

func (w *writer13) update() {
	size := 32
	if w.suite == 0x1302 {
		size = 48
	}
	w.secrets[1] = label(w.suite, w.secrets[1], "traffic upd", size)
	w.seq = 0
	w.install()
}

func handshake(kind byte, body []byte) []byte {
	return append([]byte{kind, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

func plainRecord(kind byte, body []byte) []byte {
	return append([]byte{kind, 3, 3, byte(len(body) >> 8), byte(len(body))}, body...)
}

type session struct {
	client, server []byte
	keylog         string
	request, reply []byte
}

func tls13Session(suite int) session {
	size := 32
	if suite == 0x1302 {
		size = 48
	}
	random := bytes.Repeat([]byte{0x5a}, 32)
	secret := func(b byte) []byte { return bytes.Repeat([]byte{b}, size) }
	hello := append(append([]byte{3, 3}, random...), 0, 0, 2, 0x13, 0x01, 1, 0, 0, 0)
	sh := append(append([]byte{3, 3}, bytes.Repeat([]byte{0x11}, 32)...), 0, byte(suite>>8), byte(suite), 0, 0, 6, 0, 43, 0, 2, 3, 4)
	cw, sw := newWriter13(suite, secret(1), secret(3)), newWriter13(suite, secret(2), secret(4))
	finished := handshake(20, bytes.Repeat([]byte{9}, size))
	s := session{request: []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"), reply: []byte("HTTP/1.1 204 No Content\r\n\r\n")}
	s.server = append(plainRecord(22, handshake(2, sh)), plainRecord(20, []byte{1})...)
	s.server = append(s.server, sw.record(22, append(append(handshake(8, []byte{0, 0}), handshake(11, []byte("cert"))...), finished...))...)
	sw.application()
	s.client = append(plainRecord(22, handshake(1, hello)), cw.record(22, finished)...)
	cw.application()
	s.client = append(s.client, cw.record(23, s.request[:10])...)
	s.client = append(s.client, cw.record(22, handshake(24, []byte{1}))...) // KeyUpdate
	cw.update()
	s.client = append(s.client, cw.record(23, s.request[10:])...)
	s.server = append(s.server, sw.record(23, s.reply)...)
	s.server = append(s.server, sw.record(21, []byte{1, 0})...)
	r := hex.EncodeToString(random)
	for i, name := range []string{"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"} {
		s.keylog += fmt.Sprintf("%s %s %s\n", name, r, hex.EncodeToString(secret(byte(i+1))))
	}
	return s
}

func TestTLS13SessionsDecryptAcrossSuites(t *testing.T) {
	for _, suite := range []int{0x1301, 0x1302, 0x1303} {
		s := tls13Session(suite)
		keys, err := ReadKeys(s.keylog)
		if err != nil {
			t.Fatal(err)
		}
		client, server, meta, err := DecryptStreams(s.client, s.server, keys)
		if err != nil {
			t.Fatalf("suite %#x: %v", suite, err)
		}
		if !bytes.Equal(client, s.request) || !bytes.Equal(server, s.reply) {
			t.Fatalf("suite %#x: plaintext %q / %q", suite, client, server)
		}
		if meta["version"] != "TLS 1.3" || meta["cipher_suite"] != fmt.Sprintf("0x%x", suite) || meta["authenticated_records"] != 8 {
			t.Fatalf("suite %#x: %v", suite, meta)
		}
	}
}

func TestIncrementalConnectionWaitsForKeysAndReleasesEpochs(t *testing.T) {
	s := tls13Session(0x1301)
	keys := NewKeyProvider()
	c := NewConnection(keys, "c", "s")
	for i := 0; i < len(s.client); i += 7 {
		c.Feed("c", s.client[i:min(i+7, len(s.client))])
	}
	c.Feed("s", s.server)
	if out := c.Advance(64); len(out) != 0 || c.State != StateAwaitingKeys || c.HasWork() {
		t.Fatalf("before keys: %v %s work=%v", out, c.State, c.HasWork())
	}
	if _, err := keys.Append(s.keylog); err != nil {
		t.Fatal(err)
	}
	if !c.HasWork() {
		t.Fatal("a new key version is work")
	}
	var epochs []string
	for c.HasWork() {
		for _, d := range c.Advance(1) {
			epochs = append(epochs, d.Endpoint+":"+d.Epoch)
		}
	}
	if got := strings.Join(epochs, ","); got != "c:application,c:application+1,s:application" {
		t.Fatalf("epochs %s", got)
	}
	if c.Finish() != StateComplete {
		t.Fatalf("finish: %s %s", c.State, c.Reason)
	}
}

// A terminal connection keeps only what its metadata needs: framers, hello buffers, queued records, the
// client random and the directions' record keys are released (Codex PRO-13 P2).
func TestTerminalConnectionsReleaseTheirHeavyState(t *testing.T) {
	s := tls13Session(0x1301)
	keys, err := ReadKeys(s.keylog)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte{}, s.server...)
	tampered[len(tampered)-3] ^= 1
	for _, c := range []struct {
		name, state    string
		client, server []byte
	}{{"complete", StateComplete, s.client, s.server}, {"failed", StateFailed, s.client, tampered}} {
		conn := NewConnection(keys, "c", "s")
		conn.Feed("c", c.client)
		conn.Feed("s", c.server)
		for conn.HasWork() {
			conn.Advance(64)
		}
		before := conn.Metadata()
		if conn.Finish() != c.state {
			t.Fatalf("%s: %s %s", c.name, conn.State, conn.Reason)
		}
		if conn.framers != [2]*recordFramer{} || conn.hellos != [2]*helloCollector{} || conn.dirs != [2]direction{} ||
			conn.queued[0] != nil || conn.queued[1] != nil || conn.random != nil || conn.keys != nil {
			t.Errorf("%s: heavy state retained after %s", c.name, conn.State)
		}
		after := conn.Metadata()
		if after["authenticated_records"] != before["authenticated_records"] || after["version"] != "TLS 1.3" || after["cipher_suite"] != "0x1301" {
			t.Errorf("%s: metadata changed: %v -> %v", c.name, before, after)
		}
		conn.Feed("c", []byte{0x17, 3, 3, 0, 1, 0}) // terminal: ignored, no panic
		if conn.HasWork() || conn.Advance(1) != nil || conn.Finish() != c.state {
			t.Errorf("%s: a terminal connection did more work", c.name)
		}
	}
}

func TestTypedFailures(t *testing.T) {
	s := tls13Session(0x1303)
	keys, _ := ReadKeys(s.keylog)
	tampered := append([]byte{}, s.server...)
	tampered[len(tampered)-3] ^= 1
	if _, _, _, err := DecryptStreams(s.client, tampered, keys); err == nil || err.(*Error).Code != AuthenticationFailed {
		t.Fatalf("tampered: %v", err)
	}
	if _, _, _, err := DecryptStreams(s.client, s.server[:len(s.server)-4], keys); err == nil || err.(*Error).Code != Incomplete ||
		err.Error() != "Incomplete TLS record body." {
		t.Fatalf("truncated: %v", err)
	}
	if _, _, _, err := DecryptStreams(s.client, s.server, Index{}); err == nil || err.(*Error).Code != AwaitingKeys {
		t.Fatalf("no keys: %v", err)
	}
	big := NewConnection(Index{}, "c", "s")
	big.Feed("c", make([]byte, MaxStream+1))
	if big.State != StateFailed || big.ReasonCode != BudgetExhausted {
		t.Fatalf("budget: %s %s", big.State, big.ReasonCode)
	}
}

func TestKeyProviderBoundsAndRelease(t *testing.T) {
	p := NewKeyProvider()
	random := strings.Repeat("ab", 32)
	if n, err := p.Append("# comment\r\nCLIENT_RANDOM " + random + " " + strings.Repeat("01", 48) + " EXPORTER_SECRET x y\n"); n != 1 || err != nil || p.Version() != 1 {
		t.Fatalf("append: %d %v v%d", n, err, p.Version())
	}
	if _, err := p.Append("CLIENT_RANDOM " + random + " " + strings.Repeat("02", 48)); err == nil || err.Error() != "Conflicting secrets for the same connection." {
		t.Fatalf("conflict: %v", err)
	}
	if _, err := p.Append("CLIENT_RANDOM " + random + " " + strings.Repeat("02", 32)); err == nil || err.Error() != "TLS 1.2 master secret must contain 48 bytes." {
		t.Fatalf("length: %v", err)
	}
	if p.String() != "<KeyProvider entries=1 randoms=1 version=1 released=False>" || strings.Contains(p.String(), "01") {
		t.Fatalf("repr %s", p.String())
	}
	p.Release()
	if _, err := p.Lookup("CLIENT_RANDOM", nil); err == nil || err.(*Error).Code != BudgetExhausted {
		t.Fatalf("released lookup: %v", err)
	}
	if _, err := NewKeyProvider().Append(strings.Repeat("#", MaxKeyLog+1)); err == nil || err.Error() != "Key log exceeds 256 KiB." {
		t.Fatalf("size: %v", err)
	}
}

// An append is atomic (contract C16, Codex PRO-13 P2, PRO-201): a fragment with a malformed line indexes none of
// its lines and leaves the version alone, so direct lookups and version-gated waiters see the same key set.
func TestRejectedAppendIndexesNothing(t *testing.T) {
	first, second := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	line := func(random, secret string) string { return "CLIENT_RANDOM " + random + " " + secret + "\n" }
	cases := []struct{ name, tail, message string }{
		{"malformed line", "CLIENT_RANDOM x\n", "Invalid key-log line (secret values are not displayed)."},
		{"bad hex", line(second, "zz"), "Invalid key-log hexadecimal encoding."},
		{"conflict inside the fragment", line(first, strings.Repeat("02", 48)), "Conflicting secrets for the same connection."},
	}
	for _, c := range cases {
		p := NewKeyProvider()
		n, err := p.Append(line(first, strings.Repeat("01", 48)) + line(first, strings.Repeat("01", 48)) + c.tail)
		if err == nil || err.Error() != c.message {
			t.Fatalf("%s: error %v", c.name, err)
		}
		secret, _ := p.Lookup("CLIENT_RANDOM", bytes.Repeat([]byte{0xab}, 32))
		if n != 0 || p.Len() != 0 || p.Version() != 0 || secret != nil || p.Has(bytes.Repeat([]byte{0xab}, 32)) {
			t.Fatalf("%s: rejected append left %d added, len %d, v%d, lookup %x", c.name, n, p.Len(), p.Version(), secret)
		}
		// The provider still accepts a later valid fragment.
		if n, err := p.Append(line(first, strings.Repeat("01", 48))); n != 1 || err != nil || p.Version() != 1 {
			t.Fatalf("%s: later append %d %v v%d", c.name, n, err, p.Version())
		}
	}
	// The entry cap counts the fragment's own new entries too.
	p := NewKeyProvider()
	var fragment strings.Builder
	for i := 0; i <= MaxEntries; i++ {
		fragment.WriteString(line(fmt.Sprintf("%064x", i), strings.Repeat("01", 48)))
	}
	if n, err := p.Append(fragment.String()); err == nil || err.Error() != "Too many key-log entries." || n != 0 || p.Len() != 0 || p.Version() != 0 {
		t.Fatalf("cap: %d %v len %d v%d", n, err, p.Len(), p.Version())
	}
}

func TestKeyExpiry(t *testing.T) {
	now, age := 0.0, 5.0
	p := NewKeyProvider()
	p.MaxAge, p.Clock = &age, func() float64 { return now }
	p.Append("CLIENT_RANDOM " + strings.Repeat("ab", 32) + " " + strings.Repeat("01", 48))
	now = 6
	if n := p.Expire(nil); n != 1 || p.Len() != 0 || p.Version() != 2 || p.Has(bytes.Repeat([]byte{0xab}, 32)) {
		t.Fatalf("expire: %d len %d v%d", n, p.Len(), p.Version())
	}
}

func FuzzConnectionNeverPanics(f *testing.F) {
	s := tls13Session(0x1301)
	f.Add(s.client, s.server, s.keylog)
	f.Fuzz(func(t *testing.T, client, server []byte, keylog string) {
		keys := NewKeyProvider()
		keys.Append(keylog)
		c := NewConnection(keys, "c", "s")
		c.Feed("c", client)
		c.Feed("s", server)
		for i := 0; i < 8 && c.HasWork(); i++ {
			c.Advance(3)
		}
		c.Finish()
		c.Metadata()
	})
}
