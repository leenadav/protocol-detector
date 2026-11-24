// Package quicx ports protocol_engine/quic.py: QUIC v1/v2 (RFC 9000, 9001, 9369) Initial and Version Negotiation
// recognition. With Config.quic_decrypt the client Initial packet protection is removed with keys derived from
// public values (version salt, Destination Connection ID), the frames are validated (PADDING, PING, ACK, CRYPTO,
// CONNECTION_CLOSE only) and the CRYPTO stream is assembled into a TLS ClientHello for SNI and ALPN. This recovers
// what the client sent in the clear by design; server Initials, later packets and 0-RTT stay opaque. The only
// connection state is the bounded, scoped CRYPTO Assembler. Crypto is the Go standard library (AES, GCM, HKDF).
package quicx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
	"github.com/leenadav/protocol-detector/go/internal/protocols/fingerprint"
	"github.com/leenadav/protocol-detector/go/internal/protocols/tlsx"
)

// Supported versions.
const (
	V1 uint32 = 0x00000001
	V2 uint32 = 0x6b3343cf
)

var salts = map[uint32][]byte{
	V1: {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a},
	V2: {0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9},
}

var labels = map[uint32][3]string{V1: {"quic key", "quic iv", "quic hp"}, V2: {"quicv2 key", "quicv2 iv", "quicv2 hp"}}
var initialType = map[uint32]byte{V1: 0, V2: 1}
var versionName = map[uint32]string{V1: "1", V2: "2"}

// Probe is quic.quic_probe: a long header with a supported version and the Initial type, or Version Negotiation.
func Probe(data []byte) bool {
	if len(data) < 7 || data[0]&0xc0 != 0xc0 {
		return false
	}
	version := binary.BigEndian.Uint32(data[1:5])
	if version == 0 {
		return true
	}
	t, ok := initialType[version]
	return ok && (data[0]>>4)&3 == t && data[0]&0x40 != 0
}

func varint(data []byte, pos, limit int) (uint64, int, error) {
	if pos >= limit {
		return 0, pos, parsing.Malformed("Truncated QUIC variable-length integer")
	}
	size := 1 << (data[pos] >> 6)
	if pos+size > limit {
		return 0, pos, parsing.Malformed("Truncated QUIC variable-length integer")
	}
	value := uint64(data[pos] & 0x3f)
	for _, b := range data[pos+1 : pos+size] {
		value = value<<8 | uint64(b)
	}
	return value, pos + size, nil
}

// Row is one evidence item with its exact source (the QUIC validator names sources such as "wire" or "quic_sni").
type Row struct{ Field, Value, Source, Strength string }

// Match is quic's DatagramMatch: an identification, or (Retracts) the withdrawal of a connection's evidence.
type Match struct {
	Hostname string
	HasHost  bool
	ALPN     []string
	Evidence []Row
	Reason   string
	Retracts bool
	Contexts parsing.Contexts // signature contexts (family tls); nil unless retained
}

// Options are the Config fields the validator reads.
type Options struct {
	MaxHeaders     int
	MaxBytes       int
	Decrypt        bool // Config.quic_decrypt
	Fingerprints   bool // JA4 (protocol code q) over a complete ClientHello
	RetainContexts bool // signature contexts of a complete ClientHello (family tls)
}

func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := []byte{byte(length >> 8), byte(length), byte(len(full))}
	info = append(info, full...)
	info = append(info, 0) // empty context
	out, err := hkdf.Expand(sha256.New, secret, string(info), length)
	if err != nil {
		panic(err) // lengths are constants well inside the HKDF limit
	}
	return out
}

func initialKeys(version uint32, dcid []byte) (key, iv, hp []byte) {
	prk, err := hkdf.Extract(sha256.New, dcid, salts[version])
	if err != nil {
		panic(err)
	}
	secret := hkdfExpandLabel(prk, "client in", 32)
	l := labels[version]
	return hkdfExpandLabel(secret, l[0], 16), hkdfExpandLabel(secret, l[1], 12), hkdfExpandLabel(secret, l[2], 16)
}

// unprotect is quic.unprotect: header protection and AEAD removal on one Initial packet; ok is false when it does
// not open (an empty plaintext is a valid opening).
func unprotect(data []byte, pnOffset, length int, version uint32, dcid []byte) (plaintext []byte, ok bool) {
	key, iv, hp := initialKeys(version, dcid)
	block, _ := aes.NewCipher(hp)
	mask := make([]byte, 16)
	block.Encrypt(mask, data[pnOffset+4:pnOffset+20])
	first := data[0] ^ (mask[0] & 0x0f)
	pnLength := int(first&3) + 1
	if first&0x0c != 0 {
		return nil, false // reserved bits must be zero once unprotected
	}
	header := append([]byte{}, data[:pnOffset+pnLength]...)
	header[0] = first
	var packetNumber uint64
	for i := 0; i < pnLength; i++ {
		header[pnOffset+i] ^= mask[1+i]
		packetNumber = packetNumber<<8 | uint64(header[pnOffset+i])
	}
	nonce := append([]byte{}, iv...)
	for i := 0; i < 8; i++ {
		nonce[11-i] ^= byte(packetNumber >> (8 * i))
	}
	payload := data[pnOffset+pnLength : pnOffset+length]
	if len(payload) < 16 {
		return nil, false
	}
	aead, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(aead)
	plaintext, err := gcm.Open(nil, nonce, payload, header)
	if err != nil {
		return nil, false
	}
	return plaintext, true
}

// frames is quic.frames: validates Initial-permitted frames and returns the CRYPTO fragments.
func frames(plaintext []byte, maxHeaders int) ([]Fragment, error) {
	pos, limit, count := 0, len(plaintext), 0
	budget := maxHeaders
	if budget > 128 {
		budget = 128
	}
	var fragments []Fragment
	var err error
	skip := func(n int) error {
		for i := 0; i < n; i++ {
			if _, pos, err = varint(plaintext, pos, limit); err != nil {
				return err
			}
		}
		return nil
	}
	for pos < limit {
		kind := plaintext[pos]
		if kind == 0 { // PADDING
			pos++
			continue
		}
		count++
		if count > budget {
			return nil, parsing.Budget("QUIC Initial frame count exceeds budget")
		}
		pos++
		switch {
		case kind == 1: // PING
		case kind == 2 || kind == 3: // ACK
			if err := skip(2); err != nil {
				return nil, err
			}
			var ranges uint64
			if ranges, pos, err = varint(plaintext, pos, limit); err != nil {
				return nil, err
			}
			if err := skip(1); err != nil {
				return nil, err
			}
			if ranges > uint64(budget) {
				return nil, parsing.Budget("QUIC ACK range count exceeds budget")
			}
			if err := skip(2 * int(ranges)); err != nil {
				return nil, err
			}
			if kind == 3 {
				if err := skip(3); err != nil {
					return nil, err
				}
			}
		case kind == 6: // CRYPTO
			var offset, size uint64
			if offset, pos, err = varint(plaintext, pos, limit); err != nil {
				return nil, err
			}
			if size, pos, err = varint(plaintext, pos, limit); err != nil {
				return nil, err
			}
			if offset+size > MaxCrypto {
				return nil, parsing.Budget("QUIC CRYPTO offset exceeds assembly budget")
			}
			if uint64(pos)+size > uint64(limit) {
				return nil, parsing.Malformed("QUIC CRYPTO frame exceeds packet")
			}
			fragments = append(fragments, Fragment{offset, plaintext[pos : pos+int(size)]})
			pos += int(size)
		case kind == 0x1c || kind == 0x1d: // CONNECTION_CLOSE
			if err := skip(1); err != nil {
				return nil, err
			}
			if kind == 0x1c {
				if err := skip(1); err != nil {
					return nil, err
				}
			}
			var size uint64
			if size, pos, err = varint(plaintext, pos, limit); err != nil {
				return nil, err
			}
			if uint64(pos)+size > uint64(limit) {
				return nil, parsing.Malformed("QUIC CONNECTION_CLOSE reason exceeds packet")
			}
			pos += int(size)
		default:
			return nil, parsing.Malformed("Frame type not permitted in a QUIC Initial packet")
		}
	}
	return fragments, nil
}

func wire(field, value, strength string) Row { return Row{field, value, "wire", strength} }

// Validate is quic.quic. asm may be nil (no cross-datagram state); scope names the datagram's flow; now drives
// the assembler's idle expiry when the host supplies time.
func Validate(data []byte, opts Options, asm *Assembler, scope string, now *float64) (*Match, error) {
	if !Probe(data) {
		return nil, parsing.Unsupported("Outside QUIC long-header Initial/Version Negotiation profile")
	}
	version := binary.BigEndian.Uint32(data[1:5])
	pos := 5
	dcil := int(data[pos])
	pos++
	if dcil > 20 || pos+dcil > len(data) {
		return nil, parsing.Malformed("Invalid QUIC Destination Connection ID length")
	}
	dcid := data[pos : pos+dcil]
	pos += dcil
	if pos >= len(data) {
		return nil, parsing.Malformed("Truncated QUIC Source Connection ID length")
	}
	scil := int(data[pos])
	pos++
	if scil > 20 || pos+scil > len(data) {
		return nil, parsing.Malformed("Invalid QUIC Source Connection ID length")
	}
	pos += scil
	evidence := []Row{wire("encryption", "quic", "structural")}
	limit := opts.MaxHeaders
	if limit > 128 {
		limit = 128
	}
	if version == 0 {
		rest := len(data) - pos
		if rest < 4 || rest%4 != 0 {
			return nil, parsing.Malformed("QUIC Version Negotiation requires a list of 32-bit versions")
		}
		if rest/4 > limit {
			return nil, parsing.Budget("QUIC Version Negotiation list exceeds budget")
		}
		evidence = append(evidence, wire("packet_type", "version_negotiation", "structural"))
		return &Match{Evidence: evidence, Reason: "QUIC Version Negotiation framing validated; offered versions are server assertions"}, nil
	}
	tokenLength, pos, err := varint(data, pos, len(data))
	if err != nil {
		return nil, err
	}
	if tokenLength > uint64(len(data)-pos) {
		return nil, parsing.Malformed("QUIC Initial token exceeds datagram")
	}
	pos += int(tokenLength)
	length, pos, err := varint(data, pos, len(data))
	if err != nil {
		return nil, err
	}
	pnOffset := pos
	// Packet number (1..4 bytes) plus a 16-byte AEAD tag are the minimum payload.
	if length < 17 || uint64(pnOffset)+length > uint64(len(data)) || pnOffset+20 > len(data) {
		return nil, parsing.Malformed("QUIC Initial length field disagrees with datagram")
	}
	evidence = append(evidence, wire("quic_version", versionName[version], "structural"), wire("packet_type", "initial", "structural"))
	if tokenLength > 0 {
		evidence = append(evidence, wire("initial_token", "present", "structural"))
	}
	// A contradiction already invalidated this connection: every further Initial of it keeps the invalidation. The
	// marker is looked up here but refreshed only once the datagram may count (Codex PRO-312 P2, PRO-315): a client
	// Initial under the RFC 9000 section 14.1 minimum is discarded by a server, so it neither refreshes the marker
	// nor yields invalidation evidence.
	var conflicted *entry
	if asm != nil {
		conflicted = asm.marker(dcid, scope, version, now)
	}
	stillConflicted := func() (*Match, error) {
		asm.refresh(conflicted, now)
		evidence = append(evidence, wire("crypto_assembly", "conflict", "structural"))
		return &Match{Evidence: evidence, Retracts: true,
			Reason: "QUIC connection invalidated by an earlier CRYPTO contradiction; later datagrams of it stay withdrawn"}, nil
	}
	if conflicted != nil && (!opts.Decrypt || len(data) > opts.MaxBytes) {
		return stillConflicted() // not opened, so not known to be a client Initial: the marker binds it as before
	}
	if !opts.Decrypt {
		evidence = append(evidence, wire("initial_protection", "skipped", "context"))
		return &Match{Evidence: evidence, Reason: "QUIC Initial framing validated; protection removal disabled by configuration"}, nil
	}
	if len(data) > opts.MaxBytes {
		return nil, parsing.Budget("QUIC Initial exceeds byte budget")
	}
	plaintext, opened := unprotect(data, pnOffset, int(length), version, dcid)
	if opened && len(data) < MinClientDatagram {
		// SEC-QUIC-3 (PRO-47, PRO-123; a Go-only divergence Lee approved on PRO-124): the payload opened with the
		// client Initial keys, so this is a client Initial, and RFC 9000 section 14.1 has a server discard one in a
		// datagram under 1200 bytes. It is checked before frame decoding and before a conflict marker counts the
		// datagram (PRO-315), so nothing in it is evidence: it neither enters the assembler (where a decoy would
		// contradict the real Initial), nor names the flow's server, nor refreshes or reports an invalidation.
		return nil, parsing.Malformed("QUIC client Initial datagram below the RFC 9000 section 14.1 minimum of 1200 bytes; a server discards it")
	}
	if conflicted != nil {
		return stillConflicted()
	}
	if !opened {
		evidence = append(evidence, wire("initial_protection", "unverified", "context"))
		return &Match{Evidence: evidence,
			Reason: "QUIC Initial framing validated; client Initial keys did not open the payload (server packet, retry token flow or damaged datagram)"}, nil
	}
	fragments, err := frames(plaintext, opts.MaxHeaders)
	if err != nil {
		if e, ok := err.(*parsing.Error); ok && e.Kind == "budget" {
			return nil, err // budgets are reported as budget_exhausted, never hidden as unverified protection
		}
		evidence = append(evidence, wire("initial_protection", "unverified", "context"))
		return &Match{Evidence: evidence, Reason: "QUIC Initial opened but frames outside the Initial profile: " + err.(*parsing.Error).Message}, nil
	}
	evidence = append(evidence, wire("initial_protection", "removed", "structural"))
	status, hello := Assemble(fragments)
	if asm != nil && len(fragments) > 0 {
		// The connection's store decides: it also sees earlier datagrams of this flow scope and reports a
		// contradiction with them even when this datagram is complete on its own.
		var stored []byte
		status, stored = asm.Add(dcid, fragments, scope, version, now)
		hello = nil
		if status == Complete {
			hello = stored
		}
	}
	if status == Exhausted {
		return nil, parsing.Budget("QUIC CRYPTO assembly exceeds its fragment or byte budget")
	}
	if status == Conflict {
		evidence = append(evidence, wire("crypto_assembly", "conflict", "structural"))
		return &Match{Evidence: evidence, Retracts: true, Reason: "QUIC CRYPTO retransmission contradicts earlier bytes of this connection; " +
			"ClientHello evidence (server name, ALPN, fingerprints) for it is withdrawn"}, nil
	}
	if hello == nil {
		evidence = append(evidence, wire("crypto_assembly", "partial", "structural"))
		return &Match{Evidence: evidence, Reason: "QUIC Initial protection removed; ClientHello incomplete in this datagram"}, nil
	}
	offer, err := tlsx.ParseClientHello(hello[4:], opts.Fingerprints || opts.RetainContexts)
	if err != nil {
		evidence = append(evidence, wire("crypto_assembly", "invalid", "structural"))
		return &Match{Evidence: evidence, Reason: "QUIC Initial protection removed; CRYPTO stream is not a supported ClientHello"}, nil
	}
	if asm != nil && !asm.SameServerName(dcid, scope, version, offer.HasHost && offer.Hostname != "", offer.Hostname) {
		// SEC-QUIC-3: a second complete ClientHello of this flow (on another DCID, which the assembler keeps
		// apart) names another server, so neither name is the flow's identity.
		evidence = append(evidence, wire("crypto_assembly", "conflict", "structural"))
		return &Match{Evidence: evidence, Retracts: true, Reason: "QUIC ClientHello names a different server than an earlier ClientHello of this flow; " +
			"ClientHello evidence (server name, ALPN, fingerprints) for it is withdrawn"}, nil
	}
	evidence = append(evidence, wire("crypto_assembly", "complete", "structural"))
	if offer.HasHost && offer.Hostname != "" {
		evidence = append(evidence, Row{"hostname", offer.Hostname, "quic_sni", "asserted"})
	}
	if len(offer.ALPN) > 0 {
		evidence = append(evidence, Row{"offered_alpn", strings.Join(offer.ALPN, ","), "quic_alpn", "asserted"})
	}
	if offer.ECH != "" {
		evidence = append(evidence, Row{"tls_ech", offer.ECH, "quic_client_hello", "offered"})
	}
	var contexts parsing.Contexts
	if offer.Info != nil {
		offer.Info.Version = 0x0304 // QUIC requires TLS 1.3; supported_versions carries it
		if opts.Fingerprints {
			evidence = append(evidence, Row{"ja4", fingerprint.JA4(offer.Info, "q"), "wire:quic_client_hello", "derived"})
		}
		if opts.RetainContexts {
			contexts = tlsx.HelloContexts(hello[4:], offer.Info, offer.Hostname, offer.HasHost, offer.ALPN)
		}
	}
	alpn := offer.ALPN
	if alpn == nil {
		alpn = []string{}
	}
	return &Match{Hostname: offer.Hostname, HasHost: offer.HasHost && offer.Hostname != "", ALPN: alpn, Evidence: evidence, Contexts: contexts,
		Reason: "QUIC Initial protection removed and ClientHello validated; SNI/ALPN are client offers, handshake not completed"}, nil
}
