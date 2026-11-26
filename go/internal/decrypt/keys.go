// Package decrypt ports presentation/poc_decryption (stage 4: A02, A07, A09; M7): offline, bounded TLS
// key-log decryption with supplied secrets. It is not a TLS endpoint or a trust validator: records are
// authenticated with the logged secrets, while Finished transcripts and certificate trust are never verified
// or claimed. Nothing here reads a clock, a file or a socket; the key provider is injected.
package decrypt

import (
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
	"unicode"

	"crypto/sha256"
	"crypto/sha512"
)

// Bounds of the reference profile.
const (
	MaxStream  = 262144 // bytes per direction, handshake and decrypted payload
	MaxKeyLog  = 262144 // characters of appended key-log text
	MaxEntries = 1024   // indexed secrets
)

// Reason codes (REASON_CODES).
const (
	AwaitingHello        = "awaiting_hello"
	AwaitingKeys         = "awaiting_keys"
	AwaitingBytes        = "awaiting_bytes"
	UnsupportedProfile   = "unsupported_profile"
	AuthenticationFailed = "authentication_failed"
	Gap                  = "gap"
	BudgetExhausted      = "budget_exhausted"
	Incomplete           = "incomplete"
	Complete             = "complete"
)

// Error is DecryptionError: a typed failure whose message never carries key or payload bytes.
type Error struct {
	Message string
	Code    string
}

func (e *Error) Error() string { return e.Message }

func fail(message, code string) *Error { return &Error{message, code} }

var labels = map[string]bool{"CLIENT_HANDSHAKE_TRAFFIC_SECRET": true, "SERVER_HANDSHAKE_TRAFFIC_SECRET": true,
	"CLIENT_TRAFFIC_SECRET_0": true, "SERVER_TRAFFIC_SECRET_0": true, "CLIENT_RANDOM": true}

type keyID struct{ label, random string }

// Keys is what a connection reads secrets from: the append-oriented KeyProvider, or a fixed index (read_keys).
type Keys interface {
	// Lookup returns the secret for (label, client random); an error only when the store can no longer be used.
	Lookup(label string, random []byte) ([]byte, error)
	// KeysVersion is the provider's version; ok is false for a store without one (a plain index).
	KeysVersion() (version int, ok bool)
}

// KeyProvider is the NSS key-log store: each line is parsed once and lookups are by (label, client random).
// Version increases whenever a secret is indexed or expired, so a connection waiting for keys asks again only
// when something changed. Bounds: 256 KiB of appended text and 1024 indexed entries in total.
type KeyProvider struct {
	keys      map[keyID][]byte
	order     []keyID // insertion order, for expiry
	randoms   map[string]bool
	version   int
	consumed  int
	released  bool
	MaxAge    *float64       // seconds a secret stays usable after it was indexed (nil: the run)
	Clock     func() float64 // nil: no clock, secrets never age
	indexedAt map[keyID]float64
}

// NewKeyProvider returns an empty store.
func NewKeyProvider() *KeyProvider {
	return &KeyProvider{keys: map[keyID][]byte{}, randoms: map[string]bool{}, indexedAt: map[keyID]float64{}}
}

// String never shows secrets, only counts (KeyProvider.__repr__).
func (p *KeyProvider) String() string {
	return fmt.Sprintf("<KeyProvider entries=%d randoms=%d version=%d released=%s>", len(p.keys), len(p.randoms), p.version, pyBool(p.released))
}

func pyBool(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

// Len is the number of indexed secrets.
func (p *KeyProvider) Len() int { return len(p.keys) }

// Version is the store's change counter.
func (p *KeyProvider) Version() int { return p.version }

// KeysVersion implements Keys.
func (p *KeyProvider) KeysVersion() (int, bool) { return p.version, true }

// Released reports whether Release ran.
func (p *KeyProvider) Released() bool { return p.released }

// Release drops every reference to secret material; the provider is unusable afterwards. Go cannot promise
// zeroization of copies the runtime made; the indexed buffers are overwritten before they are dropped (directions
// that already started hold their own copies, so a running connection is unaffected, as in the reference).
func (p *KeyProvider) Release() {
	for _, secret := range p.keys {
		zero(secret)
	}
	p.keys, p.order, p.randoms, p.indexedAt = map[keyID][]byte{}, nil, map[string]bool{}, map[keyID]float64{}
	p.released = true
}

// Expire forgets secrets older than MaxAge (a no-op without MaxAge or a time) and returns how many it dropped.
// now nil reads Clock.
func (p *KeyProvider) Expire(now *float64) int {
	if p.MaxAge == nil {
		return 0
	}
	if now == nil && p.Clock != nil {
		t := p.Clock()
		now = &t
	}
	if now == nil {
		return 0
	}
	var kept []keyID
	stale := 0
	for _, id := range p.order {
		if at, ok := p.indexedAt[id]; ok && *now-at > *p.MaxAge {
			zero(p.keys[id]) // SEC-KEY-1 (PRO-119): overwritten before it is forgotten, as Release does
			delete(p.keys, id)
			delete(p.indexedAt, id)
			stale++
			continue
		}
		if _, ok := p.keys[id]; ok {
			kept = append(kept, id)
		}
	}
	p.order = kept
	p.randoms = map[string]bool{}
	for id := range p.keys {
		p.randoms[id.random] = true
	}
	if stale > 0 {
		p.version++
	}
	return stale
}

// isPySpace is str.isspace for the characters str.split()/strip() treat as whitespace.
func isPySpace(r rune) bool {
	switch r {
	case '\x1c', '\x1d', '\x1e', '\x1f', '\x85':
		return true
	}
	return unicode.IsSpace(r)
}

// pySplitLines is str.splitlines() (line boundaries \n \r \r\n \v \f \x1c \x1d \x1e \x85    ).
func pySplitLines(text string) []string {
	var lines []string
	runes := []rune(text)
	start := 0
	for i := 0; i < len(runes); i++ {
		switch runes[i] {
		case '\n', '\v', '\f', '\x1c', '\x1d', '\x1e', '\x85', ' ', ' ':
			lines = append(lines, string(runes[start:i]))
			start = i + 1
		case '\r':
			lines = append(lines, string(runes[start:i]))
			if i+1 < len(runes) && runes[i+1] == '\n' {
				i++
			}
			start = i + 1
		}
	}
	if start < len(runes) {
		lines = append(lines, string(runes[start:]))
	}
	return lines
}

// fromHex is bytes.fromhex for a token without whitespace.
func fromHex(text string) ([]byte, bool) {
	for _, r := range text {
		if r > 0x7f {
			return nil, false
		}
	}
	out, err := hex.DecodeString(text)
	return out, err == nil
}

// Append indexes the lines of a key-log fragment (KeyProvider.append) and returns how many secrets it added.
func (p *KeyProvider) Append(text string) (int, error) {
	if p.released {
		return 0, fail("Key provider was released.", BudgetExhausted)
	}
	p.consumed += len([]rune(text))
	if p.consumed > MaxKeyLog {
		return 0, fail("Key log exceeds 256 KiB.", BudgetExhausted)
	}
	// Contract C16 (Codex PRO-13 P2, PRO-201): an append is atomic. Every line is validated into a staged set
	// first, and only a fully accepted fragment is indexed and moves the version, so a rejected fragment leaves
	// no secret visible to Lookup that version-gated waiters would skip. This is a Go-only divergence: the
	// reference (poc_decryption.KeyProvider.append) keeps the secrets indexed before the failing line.
	type staged struct {
		id     keyID
		secret []byte
	}
	var pending []staged
	fresh := map[keyID][]byte{}
	for _, line := range pySplitLines(text) {
		line = strings.TrimFunc(line, isPySpace)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.FieldsFunc(line, isPySpace)
		if len(parts) != 3 {
			return 0, fail("Invalid key-log line (secret values are not displayed).", UnsupportedProfile)
		}
		label := parts[0]
		if !labels[label] {
			continue
		}
		random, ok1 := fromHex(parts[1])
		secret, ok2 := fromHex(parts[2])
		if !ok1 || !ok2 {
			return 0, fail("Invalid key-log hexadecimal encoding.", UnsupportedProfile)
		}
		if len(random) != 32 || (len(secret) != 32 && len(secret) != 48) {
			return 0, fail("Invalid TLS 1.3 secret length.", UnsupportedProfile)
		}
		if label == "CLIENT_RANDOM" && len(secret) != 48 {
			return 0, fail("TLS 1.2 master secret must contain 48 bytes.", UnsupportedProfile)
		}
		id := keyID{label, string(random)}
		previous, ok := p.keys[id]
		if !ok {
			previous, ok = fresh[id]
		}
		if ok {
			if !hmac.Equal(previous, secret) {
				return 0, fail("Conflicting secrets for the same connection.", UnsupportedProfile)
			}
			continue
		}
		if len(p.keys)+len(pending) >= MaxEntries {
			return 0, fail("Too many key-log entries.", BudgetExhausted)
		}
		fresh[id] = secret
		pending = append(pending, staged{id, secret})
	}
	for _, s := range pending {
		p.keys[s.id] = s.secret
		p.order = append(p.order, s.id)
		p.randoms[s.id.random] = true
		if p.Clock != nil {
			p.indexedAt[s.id] = p.Clock()
		}
	}
	if len(pending) > 0 {
		p.version++
	}
	return len(pending), nil
}

// Lookup implements Keys (KeyProvider.get).
func (p *KeyProvider) Lookup(label string, random []byte) ([]byte, error) {
	if p.released {
		return nil, fail("Key provider was released.", BudgetExhausted)
	}
	return p.keys[keyID{label, string(random)}], nil
}

// Has reports whether any secret for this client random is indexed.
func (p *KeyProvider) Has(random []byte) bool { return p.randoms[string(random)] }

// Index is a fixed (label, client random) -> secret index without a version (read_keys).
type Index map[[2]string][]byte

// Lookup implements Keys.
func (x Index) Lookup(label string, random []byte) ([]byte, error) {
	return x[[2]string{label, string(random)}], nil
}

// KeysVersion implements Keys: a plain index has no version.
func (x Index) KeysVersion() (int, bool) { return 0, false }

// ReadKeys validates a whole key log like Append and returns the plain index.
func ReadKeys(text string) (Index, error) {
	p := NewKeyProvider()
	if _, err := p.Append(text); err != nil {
		return nil, err
	}
	out := Index{}
	for id, secret := range p.keys {
		out[[2]string{id.label, id.random}] = secret
	}
	return out, nil
}

func newHash(digest string) func() hash.Hash {
	if digest == "sha384" {
		return sha512.New384
	}
	return sha256.New
}

func digestSize(digest string) int {
	if digest == "sha384" {
		return 48
	}
	return 32
}

// expand is HKDF-Expand-Label (RFC 8446 7.1) with an empty context.
func expand(secret []byte, label string, length int, digest string) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	var out, block []byte
	size := digestSize(digest)
	for counter := 1; counter <= (length+size-1)/size; counter++ {
		mac := hmac.New(newHash(digest), secret)
		mac.Write(block)
		mac.Write(info)
		mac.Write([]byte{byte(counter)})
		block = mac.Sum(nil)
		out = append(out, block...)
	}
	return out[:length]
}

// prf is the TLS 1.2 PRF (P_hash) over the suite's digest.
func prf(secret, seed []byte, length int, digest string) []byte {
	var out []byte
	a := seed
	for len(out) < length {
		mac := hmac.New(newHash(digest), secret)
		mac.Write(a)
		a = mac.Sum(nil)
		mac = hmac.New(newHash(digest), secret)
		mac.Write(a)
		mac.Write(seed)
		out = append(out, mac.Sum(nil)...)
	}
	return out[:length]
}
