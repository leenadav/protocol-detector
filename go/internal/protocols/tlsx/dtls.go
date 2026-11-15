package tlsx

import (
	"bytes"
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// dtls.go ports protocol_engine/dtls.py (RFC 6347): one epoch-zero record holding one complete DTLS 1.2
// ClientHello, HelloVerifyRequest or ServerHello. No fragment, replay or association state; the cookie, random
// and session ID stay opaque. The TLS-shaped ClientHello and ServerHello tails share the TLS structural decoders
// (SNI/ALPN syntax, server selections), not TLS state.

// DTLSMatch is one validated DTLS datagram. Rows carry their exact evidence source in Provenance.
type DTLSMatch struct {
	Hostname string
	HasHost  bool
	ALPN     []string
	Rows     []parsing.Row
	Reason   string
}

func uint24(b []byte) int { return int(b[0])<<16 | int(b[1])<<8 | int(b[2]) }

// DTLS is dtls.dtls. fingerprints (JA4 with protocol code d) is not ported: a valid ClientHello answers NotPorted.
func DTLS(data []byte, maxBytes, maxHeaders int, fingerprints bool) (*DTLSMatch, error) {
	if len(data) < 25 {
		return nil, parsing.Malformed("Incomplete DTLS record/handshake headers")
	}
	if data[0] != 22 || !(bytes.Equal(data[1:3], []byte{0xfe, 0xff}) || bytes.Equal(data[1:3], []byte{0xfe, 0xfd})) {
		return nil, parsing.Unsupported("Outside supported DTLS plaintext handshake record versions")
	}
	if data[3] != 0 || data[4] != 0 {
		return nil, parsing.Unsupported("DTLS encrypted epochs are outside the ClientHello profile")
	}
	recordSize := int(data[11])<<8 | int(data[12])
	if recordSize < 12 || recordSize > 16384 || len(data) < 13+recordSize {
		return nil, parsing.Malformed("Invalid or truncated DTLS plaintext record length")
	}
	if len(data) != 13+recordSize {
		return nil, parsing.Unsupported("DTLS profile requires exactly one record per datagram")
	}
	if data[13] == 2 || data[13] == 3 {
		return dtlsServerFlight(data, recordSize, maxHeaders)
	}
	if data[13] != 1 {
		return nil, parsing.Unsupported("DTLS profile supports ClientHello, HelloVerifyRequest and ServerHello only")
	}
	length, offset, fragment := uint24(data[14:17]), uint24(data[19:22]), uint24(data[22:25])
	if length < 42 || offset+fragment > length || fragment > recordSize-12 {
		return nil, parsing.Malformed("Invalid DTLS handshake or fragment length")
	}
	if length+25 > maxBytes {
		return nil, parsing.Budget("DTLS declared ClientHello exceeds byte budget")
	}
	if offset != 0 || fragment != length {
		return nil, parsing.Unsupported("Fragmented DTLS ClientHello is unsupported; datagrams are not joined")
	}
	if fragment != recordSize-12 {
		return nil, parsing.Unsupported("DTLS profile requires exactly one handshake per record")
	}
	body := data[25:]
	r := &reader{data: body}
	version, err := r.take(2)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(version, []byte{0xfe, 0xfd}) {
		return nil, parsing.Unsupported("DTLS ClientHello legacy version outside the 1.2 profile")
	}
	if _, err := r.take(32); err != nil {
		return nil, err
	}
	session, err := r.vector(1)
	if err != nil {
		return nil, err
	}
	if len(session) > 32 {
		return nil, parsing.Malformed("DTLS session ID exceeds maximum")
	}
	cookieStart := r.pos
	if _, err := r.vector(1); err != nil {
		return nil, err
	}
	cookieEnd := r.pos
	ciphers, err := r.vector(2)
	if err != nil {
		return nil, err
	}
	if len(ciphers) < 2 || len(ciphers)%2 != 0 {
		return nil, parsing.Malformed("Invalid DTLS cipher vector")
	}
	compression, err := r.vector(1)
	if err != nil {
		return nil, err
	}
	if len(compression) == 0 || bytes.IndexByte(compression, 0) < 0 {
		return nil, parsing.Malformed("Invalid DTLS compression vector")
	}
	if !bytes.Equal(compression, []byte{0}) {
		return nil, parsing.Unsupported("DTLS profile requires a sole null-compression offer")
	}
	// Count before shared TLS decoding, bounding its extension set and metadata.
	if r.pos < len(body) {
		block, err := r.vector(2)
		if err != nil {
			return nil, err
		}
		if err := r.end(); err != nil {
			return nil, err
		}
		limit := maxHeaders
		if limit > 128 {
			limit = 128
		}
		ext := &reader{data: block}
		for count := 1; ext.pos < len(ext.data); count++ {
			if count > limit {
				return nil, parsing.Budget("DTLS extension count exceeds budget")
			}
			kind, err := ext.take(2)
			if err != nil {
				return nil, err
			}
			if _, err := ext.vector(2); err != nil {
				return nil, err
			}
			if kind[0] == 0 && kind[1] == 43 {
				return nil, parsing.Unsupported("DTLS supported_versions negotiation is outside this 1.2 profile")
			}
		}
	}
	// Translate only the wire layout for the shared structural decoder; this selects no version.
	translated := append(append([]byte{3, 3}, body[2:cookieStart]...), body[cookieEnd:]...)
	fields, err := parseHello(translated)
	if err != nil {
		return nil, err
	}
	if fingerprints {
		return nil, &parsing.NotPorted{What: "option fingerprints (DTLS JA4)"}
	}
	m := &DTLSMatch{Rows: []parsing.Row{{Field: "encryption", Value: "dtls", Provenance: "wire", Strength: "structural"},
		{Field: "handshake", Value: "client_hello", Provenance: "wire", Strength: "structural"},
		{Field: "offered_dtls_version", Value: "1.2", Provenance: "dtls_client_hello", Strength: "asserted"}},
		Reason: "DTLS ClientHello structure validated; client offers and cookie unverified; no inner application identification"}
	if fields.hasHost && fields.hostname != "" {
		m.Hostname, m.HasHost = fields.hostname, true
		m.Rows = append(m.Rows, parsing.Row{Field: "hostname", Value: fields.hostname, Provenance: "dtls_sni", Strength: "asserted"})
	}
	m.ALPN = fields.alpn
	if m.ALPN == nil {
		m.ALPN = []string{}
	}
	if len(fields.alpn) > 0 {
		m.Rows = append(m.Rows, parsing.Row{Field: "offered_alpn", Value: strings.Join(fields.alpn, ","), Provenance: "dtls_alpn", Strength: "asserted"})
	}
	return m, nil
}

// dtlsServerFlight is dtls._server_flight: a DTLS 1.2 HelloVerifyRequest or ServerHello as the only handshake.
func dtlsServerFlight(data []byte, recordSize, maxHeaders int) (*DTLSMatch, error) {
	kind := data[13]
	length, offset, fragment := uint24(data[14:17]), uint24(data[19:22]), uint24(data[22:25])
	if offset != 0 || fragment != length || fragment != recordSize-12 {
		return nil, parsing.Unsupported("DTLS profile requires one complete handshake per record")
	}
	body := data[25:]
	encryption := parsing.Row{Field: "encryption", Value: "dtls", Provenance: "wire", Strength: "structural"}
	if kind == 3 {
		if len(body) < 3 || !(bytes.Equal(body[:2], []byte{0xfe, 0xff}) || bytes.Equal(body[:2], []byte{0xfe, 0xfd})) {
			return nil, parsing.Malformed("DTLS HelloVerifyRequest requires a server version and cookie")
		}
		cookie := int(body[2])
		if cookie < 1 || cookie > 32 || len(body) != 3+cookie {
			return nil, parsing.Malformed("DTLS HelloVerifyRequest cookie must be 1..32 bytes filling the message")
		}
		return &DTLSMatch{ALPN: []string{}, Rows: []parsing.Row{encryption, {Field: "handshake", Value: "hello_verify_request", Provenance: "wire", Strength: "structural"}},
			Reason: "DTLS HelloVerifyRequest validated; cookie opaque and not emitted, no session claim"}, nil
	}
	if len(body) < 2 || !bytes.Equal(body[:2], []byte{0xfe, 0xfd}) {
		return nil, parsing.Unsupported("DTLS ServerHello version outside the 1.2 profile")
	}
	rows, _, _, err := parseServerHello(append([]byte{3, 3}, body[2:]...), Options{MaxHeaders: maxHeaders}, 1<<3, 0)
	if err != nil {
		return nil, err
	}
	m := &DTLSMatch{ALPN: []string{}, Rows: []parsing.Row{encryption, {Field: "handshake", Value: "server_hello", Provenance: "wire", Strength: "structural"},
		{Field: "selected_dtls_version", Value: "1.2", Provenance: "dtls_server_hello", Strength: "asserted"}},
		Reason: "DTLS ServerHello structure validated; selections unauthenticated, handshake completion unverified"}
	for _, row := range rows {
		if row.Field == "tls_handshake" || row.Field == "selected_tls_version" || row.Strength == "derived" {
			continue // the TLS labels and the TLS-prefixed JA4S/JA3S do not describe a DTLS flight
		}
		m.Rows = append(m.Rows, parsing.Row{Field: row.Field, Value: row.Value, Provenance: "dtls_server_hello", Strength: row.Strength})
	}
	return m, nil
}
