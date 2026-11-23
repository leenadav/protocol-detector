package decrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// MaxRecordsPerConnection bounds the records one direction frames.
const MaxRecordsPerConnection = 65536

var hrrRandom = []byte{0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c}

type suite struct {
	digest  string
	keySize int
}

var suites13 = map[int]suite{0x1301: {"sha256", 16}, 0x1302: {"sha384", 32}, 0x1303: {"sha256", 32}}
var suites12 = map[int]suite{0xc02f: {"sha256", 16}, 0xc030: {"sha384", 32}}

// PlaintextDelta is authenticated application plaintext released by one direction, in order, exactly once.
type PlaintextDelta struct {
	Endpoint string
	Epoch    string
	Data     []byte
}

type record struct{ header, body []byte }

// recordFramer splits one direction's bytes into TLS records once; it retains only an incomplete tail.
type recordFramer struct {
	pending []byte
	total   int
	count   int
}

func (f *recordFramer) feed(data []byte) *Error {
	f.total += len(data)
	if f.total > MaxStream {
		return fail("TLS stream exceeds 256 KiB profile.", BudgetExhausted)
	}
	f.pending = append(f.pending, data...)
	return nil
}

// ready is true when at least one complete record is buffered (an incomplete tail is not work).
func (f *recordFramer) ready() bool {
	return len(f.pending) >= 5 && len(f.pending) >= 5+int(binary.BigEndian.Uint16(f.pending[3:5]))
}

// next frames one record: ok false when only an incomplete tail remains.
func (f *recordFramer) next() (record, bool, *Error) {
	if len(f.pending) < 5 {
		return record{}, false, nil
	}
	header := append([]byte{}, f.pending[:5]...)
	size := int(binary.BigEndian.Uint16(header[3:5]))
	if header[0] < 20 || header[0] > 23 || !(header[1] == 3 && (header[2] == 1 || header[2] == 3)) || size > 16640 {
		return record{}, false, fail("Unsupported TLS record framing.", UnsupportedProfile)
	}
	if len(f.pending) < 5+size {
		return record{}, false, nil
	}
	body := append([]byte{}, f.pending[5:5+size]...)
	f.pending = f.pending[5+size:]
	f.count++
	if f.count > MaxRecordsPerConnection {
		return record{}, false, fail("TLS record count exceeds profile.", BudgetExhausted)
	}
	return record{header, body}, true, nil
}

func (f *recordFramer) finish() *Error {
	if len(f.pending) > 0 {
		if len(f.pending) < 5 {
			return fail("Incomplete TLS record header.", Incomplete)
		}
		return fail("Incomplete TLS record body.", Incomplete)
	}
	return nil
}

// helloCollector accumulates handshake records until the first handshake message is complete.
type helloCollector struct {
	expected byte
	data     []byte
	records  []record
	body     []byte
	done     bool
	trailing bool
}

func (h *helloCollector) add(r record) *Error {
	if r.header[0] != 22 {
		return fail("Capture must include complete ClientHello and ServerHello.", UnsupportedProfile)
	}
	h.data = append(h.data, r.body...)
	h.records = append(h.records, r)
	if len(h.data) > MaxStream {
		return fail("Handshake exceeds profile limit.", BudgetExhausted)
	}
	if len(h.data) >= 4 {
		end := 4 + be24(h.data[1:4])
		if len(h.data) >= end {
			if h.data[0] != h.expected {
				return fail("Unsupported initial TLS handshake layout.", UnsupportedProfile)
			}
			h.body, h.done, h.trailing = h.data[4:end], true, len(h.data) != end
		}
	}
	return nil
}

func be24(b []byte) int { return int(b[0])<<16 | int(b[1])<<8 | int(b[2]) }

type direction interface {
	record(r record) ([]byte, *Error)
	epoch() string
	finish() *Error
}

// tls13Direction decodes one sender's protected records with its handshake and application traffic secrets.
type tls13Direction struct {
	digest   string
	keySize  int
	chacha   bool
	phase    string
	sequence uint64
	pending  []byte
	count    int
	updates  int
	secrets  map[string][]byte
	ciphers  map[string]cipher.AEAD
	ivs      map[string][]byte
	plain    int
}

const (
	phaseHandshake   = "HANDSHAKE_TRAFFIC_SECRET"
	phaseApplication = "TRAFFIC_SECRET_0"
)

// newTLS13Direction returns (nil, nil) when a secret is not available yet (the reference's KeyError).
func newTLS13Direction(sender string, suiteID int, random []byte, keys Keys) (*tls13Direction, *Error) {
	s := suites13[suiteID]
	d := &tls13Direction{digest: s.digest, keySize: s.keySize, chacha: suiteID == 0x1303, phase: phaseHandshake,
		secrets: map[string][]byte{}, ciphers: map[string]cipher.AEAD{}, ivs: map[string][]byte{}}
	for _, phase := range []string{phaseHandshake, phaseApplication} {
		secret, err := keys.Lookup(sender+"_"+phase, random)
		if err != nil {
			return nil, err.(*Error)
		}
		if secret == nil {
			return nil, nil
		}
		if len(secret) != digestSize(d.digest) {
			return nil, fail("Secret length does not match cipher suite.", UnsupportedProfile)
		}
		d.secrets[phase] = append([]byte{}, secret...)
		d.install(phase)
	}
	return d, nil
}

func newAEAD(key []byte, chacha bool) cipher.AEAD {
	if chacha {
		a, _ := chacha20poly1305.New(key)
		return a
	}
	block, _ := aes.NewCipher(key)
	a, _ := cipher.NewGCM(block)
	return a
}

func (d *tls13Direction) install(phase string) {
	secret := d.secrets[phase]
	d.ciphers[phase] = newAEAD(expand(secret, "key", d.keySize, d.digest), d.chacha)
	d.ivs[phase] = expand(secret, "iv", 12, d.digest)
}

func (d *tls13Direction) epoch() string {
	if d.phase == phaseHandshake {
		return "handshake"
	}
	if d.updates == 0 {
		return "application"
	}
	return fmt.Sprintf("application+%d", d.updates)
}

func (d *tls13Direction) record(r record) ([]byte, *Error) {
	if r.header[0] == 20 && bytes.Equal(r.body, []byte{1}) {
		return nil, nil
	}
	if r.header[0] != 23 || r.header[1] != 3 || r.header[2] != 3 {
		return nil, fail("Unexpected record after hello; early data and renegotiation are unsupported.", UnsupportedProfile)
	}
	aead, iv := d.ciphers[d.phase], d.ivs[d.phase]
	nonce := append([]byte{}, iv...)
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], d.sequence)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= seq[i]
	}
	if len(r.body) < aead.Overhead() {
		return nil, fail("TLS authentication failed: wrong keys, missing records or modified ciphertext. "+
			"No plaintext classification published.", AuthenticationFailed)
	}
	decoded, err := aead.Open(nil, nonce, r.body, r.header)
	if err != nil {
		return nil, fail("TLS authentication failed: wrong keys, missing records or modified ciphertext. "+
			"No plaintext classification published.", AuthenticationFailed)
	}
	d.sequence++
	d.count++
	content := bytes.TrimRight(decoded, "\x00")
	if len(content) == 0 {
		return nil, fail("TLS inner content type is missing.", UnsupportedProfile)
	}
	kind := content[len(content)-1]
	content = content[:len(content)-1]
	if len(content) > 16384 {
		return nil, fail("TLS inner plaintext exceeds record limit.", UnsupportedProfile)
	}
	switch kind {
	case 22:
		d.pending = append(d.pending, content...)
		if len(d.pending) > MaxStream {
			return nil, fail("Handshake exceeds profile limit.", BudgetExhausted)
		}
		for len(d.pending) >= 4 {
			size := be24(d.pending[1:4])
			if len(d.pending) < 4+size {
				break
			}
			message := d.pending[:4+size]
			d.pending = d.pending[4+size:]
			if message[0] == 24 {
				if d.phase != phaseApplication || size != 1 || message[4] > 1 || len(d.pending) > 0 || d.updates >= 32 {
					return nil, fail("Invalid TLS KeyUpdate boundary or update budget exceeded.", UnsupportedProfile)
				}
				d.secrets[d.phase] = expand(d.secrets[d.phase], "traffic upd", digestSize(d.digest), d.digest)
				d.install(d.phase)
				d.sequence = 0
				d.updates++
			}
			if message[0] == 20 {
				if d.phase != phaseHandshake || size != digestSize(d.digest) || len(d.pending) > 0 {
					return nil, fail("Unexpected Finished message.", UnsupportedProfile)
				}
				d.phase, d.sequence = phaseApplication, 0
			}
		}
		return nil, nil
	case 23:
		if d.phase != phaseApplication || len(d.pending) > 0 {
			return nil, fail("Application data before handshake completion.", UnsupportedProfile)
		}
		d.plain += len(content)
		if d.plain > MaxStream {
			return nil, fail("Decrypted payload exceeds 256 KiB profile.", BudgetExhausted)
		}
		return content, nil
	}
	if kind != 21 || len(content) != 2 {
		return nil, fail("Unsupported TLS inner content.", UnsupportedProfile)
	}
	return nil, nil
}

func (d *tls13Direction) finish() *Error {
	if len(d.pending) > 0 || d.phase != phaseApplication {
		return fail("Incomplete encrypted handshake.", Incomplete)
	}
	return nil
}

// tls12Direction decodes one sender's TLS 1.2 ECDHE AES-GCM records.
type tls12Direction struct {
	aead             cipher.AEAD
	iv               []byte
	active, finished bool
	seq              uint64
	count, plain     int
	pending          []byte
}

func (d *tls12Direction) epoch() string {
	if d.finished {
		return "application"
	}
	return "handshake"
}

func (d *tls12Direction) record(r record) ([]byte, *Error) {
	kind := r.header[0]
	if !d.active {
		if kind == 20 {
			if !bytes.Equal(r.body, []byte{1}) || len(d.pending) > 0 {
				return nil, fail("Invalid TLS 1.2 ChangeCipherSpec boundary.", UnsupportedProfile)
			}
			d.active = true
			return nil, nil
		}
		if kind != 22 {
			return nil, fail("Unexpected plaintext TLS 1.2 record.", UnsupportedProfile)
		}
		d.pending = append(d.pending, r.body...)
		for len(d.pending) >= 4 {
			length := be24(d.pending[1:4])
			if length > MaxStream {
				return nil, fail("TLS 1.2 handshake exceeds profile.", BudgetExhausted)
			}
			if len(d.pending) < length+4 {
				break
			}
			d.pending = d.pending[length+4:]
		}
		return nil, nil
	}
	if r.header[1] != 3 || r.header[2] != 3 || kind < 21 || kind > 23 || len(r.body) < 24 {
		return nil, fail("Unsupported protected TLS 1.2 record.", UnsupportedProfile)
	}
	length := len(r.body) - 24
	if length > 16384 {
		return nil, fail("TLS 1.2 plaintext exceeds record limit.", UnsupportedProfile)
	}
	aad := binary.BigEndian.AppendUint64(nil, d.seq)
	aad = append(aad, r.header[:3]...)
	aad = binary.BigEndian.AppendUint16(aad, uint16(length))
	nonce := append(append([]byte{}, d.iv...), r.body[:8]...)
	content, err := d.aead.Open(nil, nonce, r.body[8:], aad)
	if err != nil {
		return nil, fail("TLS authentication failed: wrong keys, missing records or modified ciphertext.", AuthenticationFailed)
	}
	d.seq++
	d.count++
	switch kind {
	case 22:
		if d.finished {
			return nil, fail("TLS 1.2 renegotiation is outside the profile.", UnsupportedProfile)
		}
		d.pending = append(d.pending, content...)
		if len(d.pending) >= 4 {
			if !bytes.Equal(d.pending[:4], []byte{0x14, 0, 0, 0x0c}) || len(d.pending) > 16 {
				return nil, fail("Unexpected TLS 1.2 encrypted handshake.", UnsupportedProfile)
			}
			if len(d.pending) == 16 {
				d.finished, d.pending = true, nil
			}
		}
		return nil, nil
	case 23:
		if !d.finished || len(d.pending) > 0 {
			return nil, fail("TLS 1.2 application data before Finished.", UnsupportedProfile)
		}
		d.plain += len(content)
		if d.plain > MaxStream {
			return nil, fail("Decrypted payload exceeds 256 KiB profile.", BudgetExhausted)
		}
		return content, nil
	}
	if len(content) != 2 || len(d.pending) > 0 {
		return nil, fail("Invalid TLS 1.2 alert.", UnsupportedProfile)
	}
	return nil, nil
}

func (d *tls12Direction) finish() *Error {
	if !d.finished || len(d.pending) > 0 {
		return fail("Incomplete TLS 1.2 handshake.", Incomplete)
	}
	return nil
}

// serverExtensions walks a ServerHello extension block; duplicates and overruns are errors.
func serverExtensions(data []byte, forbid43 bool) (map[int][]byte, *Error) {
	seen := map[int][]byte{}
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, fail("Truncated ServerHello extension.", UnsupportedProfile)
		}
		kind, size := int(binary.BigEndian.Uint16(data[:2])), int(binary.BigEndian.Uint16(data[2:4]))
		_, dup := seen[kind]
		if size > len(data)-4 || dup || (forbid43 && kind == 43) {
			return nil, fail("Invalid ServerHello extension.", UnsupportedProfile)
		}
		seen[kind] = data[4 : 4+size]
		data = data[4+size:]
	}
	return seen, nil
}

// Connection states.
const (
	StateAwaitingHello = "awaiting_hello"
	StateAwaitingKeys  = "awaiting_keys"
	StateDecrypting    = "decrypting"
	StateComplete      = "complete"
	StateFailed        = "failed"
)

// Connection is TlsConnection: the incremental decoder of one TCP connection. Bytes arrive as deltas per
// direction; records are framed once, decrypted once and released as authenticated PlaintextDelta values.
// A failed or complete connection never publishes further plaintext.
type Connection struct {
	keys                 Keys
	client, server       string
	framers              [2]*recordFramer
	hellos               [2]*helloCollector
	queued               [2][]record
	dirs                 [2]direction
	State                string
	processed            int
	ReasonCode, Reason   string // "" while not failed
	Version              string // "", "TLS 1.2" or "TLS 1.3"
	Suite                int    // -1 until negotiated
	random               []byte
	RecordsAuthenticated int
	Plaintext            [2]int
	keysVersion          int
	keysVersioned        bool
	keysAsked            bool
}

// NewConnection names the two endpoints (client first).
func NewConnection(keys Keys, client, server string) *Connection {
	return &Connection{keys: keys, client: client, server: server,
		framers: [2]*recordFramer{{}, {}}, hellos: [2]*helloCollector{{expected: 1}, {expected: 2}},
		State: StateAwaitingHello, Suite: -1}
}

func (c *Connection) side(endpoint string) int {
	if endpoint == c.client {
		return 0
	}
	return 1
}

func (c *Connection) endpoint(side int) string {
	if side == 0 {
		return c.client
	}
	return c.server
}

// Terminal reports complete or failed.
func (c *Connection) Terminal() bool { return c.State == StateComplete || c.State == StateFailed }

func (c *Connection) fail(err *Error) {
	if !c.Terminal() {
		c.State, c.ReasonCode, c.Reason = StateFailed, err.Code, err.Message
		c.release()
	}
}

// release drops what only a live connection needs once it is terminal: the framers' buffered bytes, the hello
// buffers, queued records, the client random and the directions' record keys. A terminal connection does no
// more work (Feed, HasWork, Advance and Finish return first), and Metadata reads only the counters and labels
// kept here. Reports may keep a closed connection for a long time (Go-only; Codex PRO-13 P2).
func (c *Connection) release() {
	c.keys, c.random = nil, nil
	c.framers, c.hellos = [2]*recordFramer{}, [2]*helloCollector{}
	c.queued, c.dirs = [2][]record{}, [2]direction{}
}

// Fail ends the connection with a typed reason the owner established (a gap in the reassembled stream).
func (c *Connection) Fail(message, code string) { c.fail(fail(message, code)) }

// Feed adds bytes of one direction.
func (c *Connection) Feed(endpoint string, data []byte) {
	if c.Terminal() {
		return
	}
	if err := c.framers[c.side(endpoint)].feed(data); err != nil {
		c.fail(err)
	}
}

func (c *Connection) currentKeysVersion() (int, bool) { return c.keys.KeysVersion() }

// HasWork reports whether Advance could make progress.
func (c *Connection) HasWork() bool {
	if c.Terminal() {
		return false
	}
	if c.State == StateAwaitingKeys {
		v, ok := c.currentKeysVersion()
		// The reference compares getattr(keys, "version", None) with the version seen at the last attempt.
		return ok != c.keysVersioned || (ok && v != c.keysVersion)
	}
	if c.framers[0].ready() || c.framers[1].ready() {
		return true
	}
	// Records queued behind an incomplete peer hello are not work yet: nothing can decode them.
	return c.dirs[0] != nil && (len(c.queued[0]) > 0 || len(c.queued[1]) > 0)
}

func (c *Connection) frame() *Error {
	for side, framer := range c.framers {
		for {
			r, ok, err := framer.next()
			if err != nil {
				return err
			}
			if !ok {
				break
			}
			c.processed++
			if hello := c.hellos[side]; !hello.done {
				if err := hello.add(r); err != nil {
					return err
				}
			} else {
				c.queued[side] = append(c.queued[side], r)
			}
		}
	}
	return nil
}

func (c *Connection) negotiate() *Error {
	ch, sh := c.hellos[0].body, c.hellos[1].body
	if c.hellos[0].trailing {
		return fail("Unsupported initial TLS handshake layout.", UnsupportedProfile)
	}
	if len(ch) < 35 || len(sh) < 40 || !bytes.Equal(ch[:2], []byte{3, 3}) || !bytes.Equal(sh[:2], []byte{3, 3}) {
		return fail("Unsupported TLS hello.", UnsupportedProfile)
	}
	c.random = append([]byte{}, ch[2:34]...)
	sid := int(sh[34])
	offset := 35 + sid
	if sid > 32 || offset+5 > len(sh) {
		return fail("Malformed ServerHello.", UnsupportedProfile)
	}
	suiteID := int(binary.BigEndian.Uint16(sh[offset : offset+2]))
	if sh[offset+2] != 0 {
		return fail("TLS compression is unsupported.", UnsupportedProfile)
	}
	extensions := sh[offset+5:]
	if int(binary.BigEndian.Uint16(sh[offset+3:offset+5])) != len(extensions) {
		return fail("Malformed ServerHello extensions.", UnsupportedProfile)
	}
	if _, ok := suites12[suiteID]; ok {
		if _, err := serverExtensions(extensions, true); err != nil {
			return err
		}
		c.Version, c.Suite = "TLS 1.2", suiteID
		// TLS 1.2 directions consume the plaintext handshake from the start, hellos included.
		for side := range c.queued {
			c.queued[side] = append(append([]record{}, c.hellos[side].records...), c.queued[side]...)
		}
		return nil
	}
	if _, ok := suites13[suiteID]; !ok {
		return fail("Unsupported TLS cipher suite; supported: TLS 1.3 AEAD and TLS 1.2 ECDHE-RSA AES-GCM.", UnsupportedProfile)
	}
	if c.hellos[1].trailing {
		return fail("Unsupported initial TLS handshake layout.", UnsupportedProfile)
	}
	if bytes.Equal(sh[2:34], hrrRandom) {
		return fail("HelloRetryRequest is outside the POC profile.", UnsupportedProfile)
	}
	seen, err := serverExtensions(extensions, false)
	if err != nil {
		return err
	}
	if v, ok := seen[43]; !ok || !bytes.Equal(v, []byte{3, 4}) {
		return fail("TLS 1.3 was not selected.", UnsupportedProfile)
	}
	c.Version, c.Suite = "TLS 1.3", suiteID
	return nil
}

// startDirections derives both directions' keys; false while the secrets are not there yet.
func (c *Connection) startDirections() (bool, *Error) {
	c.keysVersion, c.keysVersioned = c.currentKeysVersion()
	c.keysAsked = true
	if c.Version == "TLS 1.2" {
		master, err := c.keys.Lookup("CLIENT_RANDOM", c.random)
		if err != nil {
			return false, err.(*Error)
		}
		if master == nil {
			return false, nil
		}
		if len(master) != 48 {
			return false, fail("TLS 1.2 requires a matching CLIENT_RANDOM master secret.", UnsupportedProfile)
		}
		s := suites12[c.Suite]
		sh := c.hellos[1].body
		seed := append(append([]byte("key expansion"), sh[2:34]...), c.random...)
		block := prf(master, seed, 2*s.keySize+8, s.digest)
		c.dirs[0] = &tls12Direction{aead: newAEAD(block[:s.keySize], false), iv: block[2*s.keySize : 2*s.keySize+4]}
		c.dirs[1] = &tls12Direction{aead: newAEAD(block[s.keySize:2*s.keySize], false), iv: block[2*s.keySize+4:]}
		return true, nil
	}
	clientDir, err := newTLS13Direction("CLIENT", c.Suite, c.random, c.keys)
	if err != nil {
		return false, err
	}
	if clientDir == nil {
		return false, nil
	}
	serverDir, err := newTLS13Direction("SERVER", c.Suite, c.random, c.keys)
	if err != nil {
		return false, err
	}
	if serverDir == nil {
		return false, nil
	}
	c.dirs[0], c.dirs[1] = clientDir, serverDir
	return true, nil
}

// Advance does at most budget records of work and returns the plaintext released (possibly none).
func (c *Connection) Advance(budget int) []PlaintextDelta {
	if c.Terminal() {
		return nil
	}
	released, err := c.advance(budget)
	if err != nil {
		c.fail(err)
		return nil
	}
	return released
}

func (c *Connection) advance(budget int) ([]PlaintextDelta, *Error) {
	if err := c.frame(); err != nil {
		return nil, err
	}
	if c.Suite < 0 {
		if !c.hellos[0].done || !c.hellos[1].done {
			c.State = StateAwaitingHello
			return nil, nil
		}
		if err := c.negotiate(); err != nil {
			return nil, err
		}
	}
	if c.dirs[0] == nil {
		ok, err := c.startDirections()
		if err != nil {
			return nil, err
		}
		if !ok {
			c.State = StateAwaitingKeys
			return nil, nil
		}
	}
	c.State = StateDecrypting
	var released []PlaintextDelta
	for budget > 0 && (len(c.queued[0]) > 0 || len(c.queued[1]) > 0) {
		for side := 0; side < 2; side++ {
			if len(c.queued[side]) == 0 || budget <= 0 {
				continue
			}
			r := c.queued[side][0]
			c.queued[side] = c.queued[side][1:]
			budget--
			c.processed++
			dir := c.dirs[side]
			content, err := dir.record(r)
			if err != nil {
				return nil, err
			}
			c.RecordsAuthenticated++
			if len(content) > 0 {
				c.Plaintext[side] += len(content)
				released = append(released, PlaintextDelta{c.endpoint(side), dir.epoch(), content})
			}
		}
	}
	return released, nil
}

// Finish says the stream ended: complete, or fail with a typed reason. Idempotent; returns the state.
func (c *Connection) Finish() string {
	if c.Terminal() {
		return c.State
	}
	if err := c.finish(); err != nil {
		c.fail(err)
	}
	return c.State
}

func (c *Connection) finish() *Error {
	for _, framer := range c.framers {
		if err := framer.finish(); err != nil {
			return err
		}
	}
	for !c.Terminal() {
		before := c.processed
		c.Advance(4096)
		if c.processed == before {
			break
		}
	}
	if c.Terminal() {
		return nil
	}
	if c.Suite < 0 {
		return fail("Capture must include complete ClientHello and ServerHello.", Incomplete)
	}
	if c.dirs[0] == nil {
		if c.Version == "TLS 1.3" {
			return fail("Matching handshake and application secrets are required for both directions.", AwaitingKeys)
		}
		return fail("TLS 1.2 requires a matching CLIENT_RANDOM master secret.", AwaitingKeys)
	}
	for _, dir := range c.dirs {
		if err := dir.finish(); err != nil {
			return err
		}
	}
	c.State = StateComplete
	c.release()
	return nil
}

// Metadata is TlsConnection.metadata: labels and counts only.
func (c *Connection) Metadata() map[string]interface{} {
	out := map[string]interface{}{"version": nil, "cipher_suite": nil, "authenticated_records": c.RecordsAuthenticated,
		"client_plaintext_bytes": c.Plaintext[0], "server_plaintext_bytes": c.Plaintext[1], "state": c.State}
	if c.Version != "" {
		out["version"] = c.Version
	}
	if c.Suite >= 0 {
		out["cipher_suite"] = fmt.Sprintf("0x%x", c.Suite)
	}
	if c.ReasonCode != "" {
		out["reason_code"] = c.ReasonCode
	}
	return out
}

// DecryptStreams decodes two complete directions (decrypt_streams); the error carries a reason code.
func DecryptStreams(client, server []byte, keys Keys) ([]byte, []byte, map[string]interface{}, error) {
	c := NewConnection(keys, "client", "server")
	var plain [2][]byte
	c.Feed("client", client)
	c.Feed("server", server)
	for c.HasWork() && !c.Terminal() {
		for _, d := range c.Advance(4096) {
			side := c.side(d.Endpoint)
			plain[side] = append(plain[side], d.Data...)
		}
		if c.State == StateAwaitingKeys {
			break
		}
	}
	c.Finish()
	if c.State != StateComplete {
		reason, code := c.Reason, c.ReasonCode
		if reason == "" {
			reason = "Decryption did not complete."
		}
		if code == "" {
			code = Incomplete
		}
		return nil, nil, nil, fail(reason, code)
	}
	metadata := c.Metadata()
	delete(metadata, "state")
	return plain[0], plain[1], metadata, nil
}
