// Package tlsx ports the TLS hello profiles (protocol_engine/parsers.py TLSParser/parse_hello and
// tls_server.parse_server_hello): ClientHello structure with SNI/ALPN as assertions, bounded TLS 1.2/1.3
// ServerHello and HelloRetryRequest profiles. Nothing is decrypted or authenticated. Fingerprints,
// signature contexts, the certificate watch and the continuation are not ported (NotPorted).
package tlsx

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/names"
	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

const (
	errField    = "TLS field exceeds enclosing length"
	errTrailing = "Trailing bytes in TLS structure"
	echExt      = 0xfe0d
)

// Options mirrors the Config fields the TLS parser reads.
type Options struct {
	MaxBytes     int
	MaxHeaders   int
	Fingerprints bool
	Certificates bool
	Continuation int
}

type reader struct {
	data []byte
	pos  int
}

func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || r.pos+n > len(r.data) {
		return nil, parsing.Malformed(errField)
	}
	v := r.data[r.pos : r.pos+n]
	r.pos += n
	return v, nil
}

func (r *reader) vector(width int) ([]byte, error) {
	l, err := r.take(width)
	if err != nil {
		return nil, err
	}
	n := 0
	for _, b := range l {
		n = n<<8 | int(b)
	}
	return r.take(n)
}

func (r *reader) end() error {
	if r.pos != len(r.data) {
		return parsing.Malformed(errTrailing)
	}
	return nil
}

var versionNames = map[int]string{0x0300: "SSL 3.0", 0x0301: "1.0", 0x0302: "1.1", 0x0303: "1.2", 0x0304: "1.3"}

func offeredMaxVersion(legacy int, supported []int) string {
	best := 0
	for _, v := range supported {
		if _, ok := versionNames[v]; ok && v > best {
			best = v
		}
	}
	if best == 0 {
		best = legacy
	}
	if name, ok := versionNames[best]; ok {
		return name
	}
	return "unknown"
}

func echType(value []byte) (string, error) {
	if len(value) == 0 {
		return "", parsing.Malformed("Empty encrypted_client_hello extension")
	}
	if value[0] == 1 {
		if len(value) != 1 {
			return "", parsing.Malformed("Inner encrypted_client_hello carries no fields")
		}
		return "inner", nil
	}
	if value[0] != 0 {
		return "", parsing.Malformed("Unknown encrypted_client_hello type")
	}
	if len(value) < 10 {
		return "", parsing.Malformed("Outer encrypted_client_hello shorter than its fixed fields")
	}
	kdf := int(value[1])<<8 | int(value[2])
	aead := int(value[3])<<8 | int(value[4])
	if !(kdf >= 1 && kdf <= 3) || !(aead >= 1 && aead <= 3 || aead == 0xffff) {
		return "", parsing.Malformed("Unknown HPKE cipher suite in encrypted_client_hello")
	}
	encLength := int(value[6])<<8 | int(value[7])
	pos := 8 + encLength
	if pos+2 > len(value) {
		return "", parsing.Malformed("encrypted_client_hello enc exceeds the extension")
	}
	payloadLength := int(value[pos])<<8 | int(value[pos+1])
	if payloadLength < 1 || pos+2+payloadLength != len(value) {
		return "", parsing.Malformed("encrypted_client_hello payload length disagrees with the extension")
	}
	return "outer", nil
}

type helloFields struct {
	hostname      string
	hasHost       bool
	alpn          []string
	legacyVersion int
	supported     []int
	ech           string
	ciphers       []byte
}

// parseHello ports parse_hello without info collection (fingerprints/contexts are NotPorted upstream).
func parseHello(body []byte) (*helloFields, error) {
	size := len(body)
	out := &helloFields{}
	if size < 2 {
		return nil, parsing.Malformed(errField)
	}
	out.legacyVersion = int(body[0])<<8 | int(body[1])
	if !(body[0] == 3 && (body[1] == 1 || body[1] == 2 || body[1] == 3)) {
		return nil, parsing.Malformed("Unsupported ClientHello version")
	}
	pos := 34
	if pos+1 > size {
		return nil, parsing.Malformed(errField)
	}
	sessionLength := int(body[pos])
	pos++
	if pos+sessionLength > size {
		return nil, parsing.Malformed(errField)
	}
	if sessionLength > 32 {
		return nil, parsing.Malformed("Session ID exceeds maximum")
	}
	pos += sessionLength
	if pos+2 > size {
		return nil, parsing.Malformed(errField)
	}
	cipherLength := int(body[pos])<<8 | int(body[pos+1])
	pos += 2
	if pos+cipherLength > size {
		return nil, parsing.Malformed(errField)
	}
	ciphers := body[pos : pos+cipherLength]
	pos += cipherLength
	if pos+1 > size {
		return nil, parsing.Malformed(errField)
	}
	compressionLength := int(body[pos])
	pos++
	if pos+compressionLength > size {
		return nil, parsing.Malformed(errField)
	}
	compression := body[pos : pos+compressionLength]
	pos += compressionLength
	if cipherLength < 2 || cipherLength%2 != 0 || len(compression) == 0 || bytes.IndexByte(compression, 0) < 0 {
		return nil, parsing.Malformed("Invalid cipher or compression vector")
	}
	out.ciphers = ciphers
	if pos == size {
		return out, nil
	}
	if pos+2 > size {
		return nil, parsing.Malformed(errField)
	}
	extLength := int(body[pos])<<8 | int(body[pos+1])
	pos += 2
	if pos+extLength > size {
		return nil, parsing.Malformed(errField)
	}
	if pos+extLength != size {
		return nil, parsing.Malformed(errTrailing)
	}
	seen := map[int]bool{}
	for pos < size {
		if pos+2 > size {
			return nil, parsing.Malformed(errField)
		}
		kind := int(body[pos])<<8 | int(body[pos+1])
		pos += 2
		if pos+2 > size {
			return nil, parsing.Malformed(errField)
		}
		length := int(body[pos])<<8 | int(body[pos+1])
		pos += 2
		if pos+length > size {
			return nil, parsing.Malformed(errField)
		}
		value := body[pos : pos+length]
		pos += length
		if seen[kind] {
			return nil, parsing.Malformed("Duplicate TLS extension")
		}
		seen[kind] = true
		switch kind {
		case 43:
			if len(value) == 0 || int(value[0]) != len(value)-1 || value[0]%2 != 0 {
				return nil, parsing.Malformed("Invalid supported_versions extension")
			}
			for i := 1; i+1 < len(value); i += 2 {
				out.supported = append(out.supported, int(value[i])<<8|int(value[i+1]))
			}
		case echExt:
			ech, err := echType(value)
			if err != nil {
				return nil, err
			}
			out.ech = ech
		case 0:
			envelope := &reader{data: value}
			list, err := envelope.vector(2)
			if err != nil {
				return nil, err
			}
			if err := envelope.end(); err != nil {
				return nil, err
			}
			if len(list) == 0 {
				return nil, parsing.Malformed("Empty SNI list")
			}
			namesR := &reader{data: list}
			types := map[byte]bool{}
			for namesR.pos < len(namesR.data) {
				t, err := namesR.take(1)
				if err != nil {
					return nil, err
				}
				name, err := namesR.vector(2)
				if err != nil {
					return nil, err
				}
				if types[t[0]] || len(name) == 0 {
					return nil, parsing.Malformed("Duplicate or empty SNI name")
				}
				types[t[0]] = true
				if t[0] != 0 {
					return nil, parsing.Malformed("Unsupported SNI name type")
				}
				if !isASCII(name) {
					return nil, parsing.Malformed("Invalid SNI DNS hostname")
				}
				host, err := names.Normalize(string(name))
				if err != nil {
					return nil, parsing.Malformed("Invalid SNI DNS hostname")
				}
				out.hostname, out.hasHost = host, true
			}
		case 16:
			envelope := &reader{data: value}
			list, err := envelope.vector(2)
			if err != nil {
				return nil, err
			}
			if err := envelope.end(); err != nil {
				return nil, err
			}
			if len(list) == 0 {
				return nil, parsing.Malformed("Empty ALPN list")
			}
			offers := &reader{data: list}
			var protocols []string
			for offers.pos < len(offers.data) {
				p, err := offers.vector(1)
				if err != nil {
					return nil, err
				}
				if len(p) == 0 || len(protocols) >= 64 {
					return nil, parsing.Malformed("Invalid ALPN offer or offer-count limit")
				}
				protocols = append(protocols, alpnText(p))
			}
			out.alpn = protocols
		}
	}
	return out, nil
}

func isASCII(b []byte) bool {
	for _, c := range b {
		if c >= 128 {
			return false
		}
	}
	return true
}

func alpnText(p []byte) string {
	printable := true
	for _, c := range p {
		if c < 32 || c >= 127 {
			printable = false
		}
	}
	if printable {
		return string(p)
	}
	return "hex:" + fmt.Sprintf("%x", p)
}

// Parser is the TLSParser port for the initial hello of one direction.
type Parser struct {
	opts            Options
	recordHeader    []byte
	recordRemaining int
	recordVersions  int
	handshake       []byte
	helloSize       int
	hasHelloSize    bool
	done            bool
	result          *parsing.Result
}

// New creates the parser; options the Go backend lacks fail at construction with NotPorted.
func New(opts Options) (*Parser, error) {
	if opts.Fingerprints {
		return nil, &parsing.NotPorted{What: "option fingerprints (TLS)"}
	}
	if opts.Certificates {
		return nil, &parsing.NotPorted{What: "option certificates (TLS)"}
	}
	if opts.Continuation != 0 {
		return nil, &parsing.NotPorted{What: "option continuation (TLS)"}
	}
	return &Parser{opts: opts}, nil
}

func (p *Parser) Done() bool              { return p.done }
func (p *Parser) Result() *parsing.Result { return p.result }

// Feed ports TLSParser.feed for the hello (no watch, no continuation).
func (p *Parser) Feed(data []byte) (int, error) {
	pos := 0
	for pos < len(data) && !p.done {
		if p.recordRemaining == 0 {
			amount := 5 - len(p.recordHeader)
			if amount > len(data)-pos {
				amount = len(data) - pos
			}
			p.recordHeader = append(p.recordHeader, data[pos:pos+amount]...)
			pos += amount
			if len(p.recordHeader) < 5 {
				break
			}
			h := p.recordHeader
			if h[0] != 22 || h[1] != 3 || (h[2] != 1 && h[2] != 2 && h[2] != 3) {
				return pos, parsing.Malformed("Expected plaintext TLS handshake record")
			}
			p.recordVersions |= 1 << int(h[2])
			p.recordRemaining = int(h[3])<<8 | int(h[4])
			p.recordHeader = p.recordHeader[:0]
			if p.recordRemaining < 1 || p.recordRemaining > 16384 {
				return pos, parsing.Malformed("Invalid TLS record length")
			}
		}
		needed := 4 - len(p.handshake)
		if p.hasHelloSize {
			needed = 4 + p.helloSize - len(p.handshake)
		}
		amount := needed
		if p.recordRemaining < amount {
			amount = p.recordRemaining
		}
		if len(data)-pos < amount {
			amount = len(data) - pos
		}
		p.handshake = append(p.handshake, data[pos:pos+amount]...)
		pos += amount
		p.recordRemaining -= amount
		if !p.hasHelloSize && len(p.handshake) == 4 {
			if p.handshake[0] != 1 && p.handshake[0] != 2 {
				return pos, parsing.Malformed("Initial handshake is not ClientHello or ServerHello")
			}
			p.helloSize = int(p.handshake[1])<<16 | int(p.handshake[2])<<8 | int(p.handshake[3])
			p.hasHelloSize = true
			min := 38
			if p.handshake[0] == 1 {
				min = 41
			}
			if p.helloSize < min {
				return pos, parsing.Malformed("TLS hello length invalid")
			}
			if p.helloSize > p.opts.MaxBytes-9 {
				return pos, parsing.Budget("TLS hello exceeds configured byte budget")
			}
		}
		if p.hasHelloSize && len(p.handshake) == p.helloSize+4 {
			body := p.handshake[4:]
			if p.handshake[0] == 1 {
				fields, err := parseHello(body)
				if err != nil {
					return pos, err
				}
				extra := []parsing.Row{{Field: "tls_offered_max_version", Value: offeredMaxVersion(fields.legacyVersion, fields.supported), Provenance: "client_hello", Strength: "offered"}}
				if fields.ech != "" {
					extra = append(extra, parsing.Row{Field: "tls_ech", Value: fields.ech, Provenance: "client_hello", Strength: "offered"})
				}
				for _, label := range offeredWeakClasses(fields.ciphers) {
					extra = append(extra, parsing.Row{Field: "tls_weak_cipher_offered", Value: label, Provenance: "client_hello", Strength: "offered"})
				}
				alpn := fields.alpn
				if alpn == nil {
					alpn = []string{}
				}
				p.result = &parsing.Result{Host: fields.hostname, HasHost: fields.hasHost, ALPN: alpn, Extra: extra,
					Reason: "ClientHello structure validated; SNI/ALPN are client assertions, not decrypted content"}
			} else {
				rows, scope, reason, err := parseServerHello(body, p.opts, p.recordVersions, p.recordRemaining)
				if err != nil {
					return pos, err
				}
				p.result = &parsing.Result{ALPN: []string{}, Extra: rows, Scope: scope, Reason: reason}
			}
			p.handshake = nil
			p.done = true
		}
	}
	return pos, nil
}

// --- ServerHello ----------------------------------------------------------------------------------

var hrrRandom = []byte{0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c}

// keySizes is the server key-share length of each supported named group (tls_server._KEY_SIZES). The
// post-quantum hybrids (integration work item #4, 2026-11-14) carry the classical share plus the ML-KEM
// ciphertext: 4587 SecP256r1MLKEM768 (65 + 1088), 4588 X25519MLKEM768 (1088 + 32), 4589 SecP384r1MLKEM1024
// (97 + 1568).
var keySizes = map[int]int{23: 65, 24: 97, 25: 133, 29: 32, 30: 56, 256: 256, 257: 384, 258: 512, 259: 768, 260: 1024,
	4587: 1153, 4588: 1120, 4589: 1665}

// hybridGroup reports a post-quantum hybrid group; pointFirstGroup a group whose share starts with an
// uncompressed SEC1 point (first byte 4).
func hybridGroup(g int) bool     { return g == 4587 || g == 4588 || g == 4589 }
func pointFirstGroup(g int) bool { return g == 23 || g == 24 || g == 25 || g == 4587 || g == 4589 }

func tls12Cipher(c int) bool { return c == 0x002f || (c >= 0xc023 && c < 0xc033) }
func tls12ECC(c int) bool    { return c >= 0xc023 && c < 0xc033 }
func tls12AEAD(c int) bool   { return c >= 0xc02b && c < 0xc033 }
func tls12StaticECDH(c int) bool {
	return c == 0xc025 || c == 0xc026 || c == 0xc029 || c == 0xc02a || c == 0xc02d || c == 0xc02e || c == 0xc031 || c == 0xc032
}
func tls12KeyExchange(c int) string {
	if c == 0x002f {
		return "static-rsa"
	}
	if tls12StaticECDH(c) {
		return "static-ecdh"
	}
	return "ecdhe"
}

type ext struct {
	kind  int
	value []byte
}

func parseServerHello(body []byte, opts Options, recordVersions, recordRemaining int) ([]parsing.Row, string, string, error) {
	r := &reader{data: body}
	v, err := r.take(2)
	if err != nil {
		return nil, "", "", err
	}
	if !bytes.Equal(v, []byte{3, 3}) {
		return nil, "", "", parsing.Unsupported("ServerHello profile requires TLS 1.2 or 1.3 legacy version")
	}
	random, err := r.take(32)
	if err != nil {
		return nil, "", "", err
	}
	retry := bytes.Equal(random, hrrRandom)
	session, err := r.vector(1)
	if err != nil {
		return nil, "", "", err
	}
	if len(session) > 32 {
		return nil, "", "", parsing.Malformed("ServerHello session ID exceeds maximum")
	}
	cb, err := r.take(2)
	if err != nil {
		return nil, "", "", err
	}
	cipher := int(cb[0])<<8 | int(cb[1])
	comp, err := r.take(1)
	if err != nil {
		return nil, "", "", err
	}
	if comp[0] != 0 {
		return nil, "", "", parsing.Unsupported("ServerHello compression outside null-compression profile")
	}
	var extensions []ext
	index := map[int][]byte{}
	if r.pos < len(body) {
		blockData, err := r.vector(2)
		if err != nil {
			return nil, "", "", err
		}
		if err := r.end(); err != nil {
			return nil, "", "", err
		}
		block := &reader{data: blockData}
		limit := opts.MaxHeaders
		if limit > 128 {
			limit = 128
		}
		for block.pos < len(block.data) {
			if len(extensions) >= limit {
				return nil, "", "", parsing.Budget("ServerHello extension count exceeds budget")
			}
			kb, err := block.take(2)
			if err != nil {
				return nil, "", "", err
			}
			kind := int(kb[0])<<8 | int(kb[1])
			if _, dup := index[kind]; dup {
				return nil, "", "", parsing.Malformed("Duplicate ServerHello extension")
			}
			value, err := block.vector(2)
			if err != nil {
				return nil, "", "", err
			}
			extensions = append(extensions, ext{kind, value})
			index[kind] = value
		}
	}
	_, tls13 := index[43]
	source := "server_hello"
	if retry {
		source = "hello_retry_request"
	}
	rowsOf := func(field, value, strength string) parsing.Row {
		return parsing.Row{Field: field, Value: value, Provenance: source, Strength: strength}
	}
	rows := []parsing.Row{rowsOf("tls_handshake", source, "structural")}
	version := "1.2"
	if tls13 {
		if !bytes.Equal(index[43], []byte{3, 4}) {
			return nil, "", "", parsing.Unsupported("ServerHello selected version outside TLS 1.3 profile")
		}
		if cipher < 0x1301 || cipher >= 0x1306 {
			return nil, "", "", parsing.Unsupported("TLS 1.3 cipher outside RFC8446 profile")
		}
		if recordVersions != 1<<3 || recordRemaining != 0 {
			return nil, "", "", parsing.Malformed("TLS 1.3 server hello requires 0303 records and a record boundary")
		}
		allowed := map[int]bool{43: true, 41: true, 51: true}
		if retry {
			allowed = map[int]bool{43: true, 44: true, 51: true}
		}
		for kind := range index {
			if !allowed[kind] {
				return nil, "", "", parsing.Unsupported("Extension outside supported TLS 1.3 server hello context")
			}
		}
		if retry {
			_, has44 := index[44]
			_, has51 := index[51]
			if !has44 && !has51 {
				return nil, "", "", parsing.Malformed("HelloRetryRequest must request a change")
			}
			if has44 {
				cookie := &reader{data: index[44]}
				c, err := cookie.vector(2)
				if err != nil {
					return nil, "", "", err
				}
				if len(c) == 0 {
					return nil, "", "", parsing.Malformed("Empty retry cookie")
				}
				if err := cookie.end(); err != nil {
					return nil, "", "", err
				}
			}
			if has51 {
				value := index[51]
				if len(value) != 2 {
					return nil, "", "", parsing.Malformed("Retry key_share must contain one selected group")
				}
				group := int(value[0])<<8 | int(value[1])
				if _, ok := keySizes[group]; !ok {
					return nil, "", "", parsing.Unsupported("Retry group outside supported named groups")
				}
				rows = append(rows, rowsOf("requested_group", fmt.Sprint(group), "asserted"))
			}
		} else {
			_, has41 := index[41]
			_, has51 := index[51]
			if !has41 && !has51 {
				return nil, "", "", parsing.Malformed("TLS 1.3 ServerHello requires PSK or key share")
			}
			if has41 && len(index[41]) != 2 {
				return nil, "", "", parsing.Malformed("Server PSK selection requires a two-byte index")
			}
			exchange := "psk"
			if has51 {
				value := &reader{data: index[51]}
				gb, err := value.take(2)
				if err != nil {
					return nil, "", "", err
				}
				group := int(gb[0])<<8 | int(gb[1])
				key, err := value.vector(2)
				if err != nil {
					return nil, "", "", err
				}
				if err := value.end(); err != nil {
					return nil, "", "", err
				}
				size, ok := keySizes[group]
				if !ok {
					return nil, "", "", parsing.Unsupported("Server key share group outside supported profile")
				}
				if len(key) != size || (pointFirstGroup(group) && key[0] != 4) {
					return nil, "", "", parsing.Malformed("Server key share encoding length or point format invalid")
				}
				rows = append(rows, rowsOf("selected_group", fmt.Sprint(group), "asserted"))
				exchange = "ecdhe"
				if group >= 256 && group <= 260 {
					exchange = "dhe"
				} else if hybridGroup(group) {
					exchange = "hybrid"
				}
			}
			rows = append(rows, rowsOf("selected_key_exchange", exchange, "asserted"), rowsOf("selected_cipher_mode", "aead", "asserted"))
		}
		version = "1.3"
	} else {
		if retry {
			return nil, "", "", parsing.Malformed("HelloRetryRequest requires TLS 1.3 supported_versions")
		}
		if !tls12Cipher(cipher) {
			return nil, "", "", parsing.Unsupported("TLS 1.2 cipher outside supported ServerHello profile")
		}
		for _, e := range extensions {
			switch e.kind {
			case 0, 5, 23, 35:
				if len(e.value) != 0 {
					return nil, "", "", parsing.Malformed("ServerHello acknowledgement extension must be empty")
				}
			case 65281:
				if !bytes.Equal(e.value, []byte{0}) {
					return nil, "", "", parsing.Unsupported("Only initial-handshake renegotiation_info supported")
				}
			case 11:
				if !tls12ECC(cipher) {
					return nil, "", "", parsing.Malformed("EC point formats require an ECC cipher suite")
				}
				formats := &reader{data: e.value}
				values, err := formats.vector(1)
				if err != nil {
					return nil, "", "", err
				}
				if err := formats.end(); err != nil {
					return nil, "", "", err
				}
				bad := len(values) == 0 || bytes.IndexByte(values, 0) < 0
				for _, x := range values {
					if x > 2 {
						bad = true
					}
				}
				if bad {
					return nil, "", "", parsing.Malformed("Invalid server EC point formats")
				}
			case 16:
				alpn := &reader{data: e.value}
				list, err := alpn.vector(2)
				if err != nil {
					return nil, "", "", err
				}
				if err := alpn.end(); err != nil {
					return nil, "", "", err
				}
				namesR := &reader{data: list}
				name, err := namesR.vector(1)
				if err != nil {
					return nil, "", "", err
				}
				if err := namesR.end(); err != nil {
					return nil, "", "", err
				}
				if len(name) == 0 {
					return nil, "", "", parsing.Malformed("Empty server ALPN selection")
				}
				rows = append(rows, rowsOf("selected_alpn", alpnText(name), "asserted"))
			default:
				return nil, "", "", parsing.Unsupported("TLS 1.2 ServerHello extension outside supported profile")
			}
		}
		mode := "cbc"
		if tls12AEAD(cipher) {
			mode = "aead"
		}
		rows = append(rows, rowsOf("selected_key_exchange", tls12KeyExchange(cipher), "asserted"), rowsOf("selected_cipher_mode", mode, "asserted"))
	}
	rows = append(rows, rowsOf("selected_tls_version", version, "asserted"), rowsOf("selected_cipher", fmt.Sprintf("0x%04x", cipher), "asserted"))
	reason := "ServerHello structure validated; server selections unauthenticated, handshake completion unverified"
	if retry {
		reason = "HelloRetryRequest structure validated; requested changes unverified"
	}
	_ = strings.ToLower
	return rows, source, reason, nil
}
