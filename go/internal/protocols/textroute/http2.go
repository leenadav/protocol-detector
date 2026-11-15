package textroute

import (
	"bytes"
	"encoding/binary"
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/names"
	"github.com/leenadav/protocol-detector/go/internal/parsing"
	"github.com/leenadav/protocol-detector/go/internal/protocols/hpack"
)

// http2.go ports protocol_engine/extended.HTTP2Parser and HTTP2ServerParser: the client preface and the complete
// initial SETTINGS identify the connection (published at once); the parser then keeps reading a bounded number of
// frames until the first HEADERS block ends, decodes it with HPACK and adds bounded, enumerated evidence (method,
// scheme, content-type class, the :authority host, an extended CONNECT's :protocol; the server's :status). Any frame
// outside the profile ends the continuation quietly; the identification stands. DATA payloads are never read.

// Preface is the HTTP/2 client connection preface (RFC 9113 3.4).
var Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

const (
	h2Headers, h2Priority, h2Settings, h2Ping, h2WindowUpdate, h2Continuation = 1, 2, 4, 6, 8, 9
	h2EndStream, h2EndHeaders, h2Padded, h2PriorityFlag                       = 0x1, 0x4, 0x8, 0x20
	maxH2HeaderBlock                                                          = 16384
	maxH2PreambleFrames                                                       = 8
	maxH2BlockFrames                                                          = 8
)

func byteSet(chars string) [256]bool {
	var s [256]bool
	for i := 0; i < len(chars); i++ {
		s[chars[i]] = true
	}
	return s
}

var (
	h2Token            = byteSet("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz")
	h2Method           = byteSet("!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
	h2PseudoRequest    = map[string]bool{":method": true, ":scheme": true, ":authority": true, ":path": true, ":protocol": true}
	h2ConnectionFields = map[string]bool{"connection": true, "keep-alive": true, "proxy-connection": true, "transfer-encoding": true, "upgrade": true}
)

func validPortBytes(port []byte) bool {
	if len(port) == 0 || len(port) > 5 {
		return false
	}
	n := 0
	for _, c := range port {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n > 0 && n <= 65535
}

// authorityHost is extended._authority_host: the DNS host of an :authority value, "" for IP literals; userinfo and
// bad ports are errors.
func authorityHost(value []byte) (string, error) {
	if len(value) == 0 || bytes.IndexByte(value, '@') >= 0 {
		return "", parsing.Malformed("HTTP/2 :authority must be host[:port] without userinfo")
	}
	if value[0] == '[' {
		end := bytes.IndexByte(value, ']')
		if end < 0 {
			return "", parsing.Malformed("Invalid HTTP/2 :authority IP literal")
		}
		inner := value[1:end]
		for _, c := range inner {
			if c >= 128 {
				return "", parsing.Malformed("Invalid HTTP/2 :authority IP literal")
			}
		}
		if !names.IsIPv6(string(inner)) {
			return "", parsing.Malformed("Invalid HTTP/2 :authority IP literal")
		}
		if rest := value[end+1:]; len(rest) > 0 && (rest[0] != ':' || !validPortBytes(rest[1:])) {
			return "", parsing.Malformed("Invalid HTTP/2 :authority port")
		}
		return "", nil
	}
	host := value
	if i := bytes.LastIndexByte(value, ':'); i >= 0 {
		if !validPortBytes(value[i+1:]) {
			return "", parsing.Malformed("Invalid HTTP/2 :authority port")
		}
		host = value[:i]
	}
	for _, c := range host {
		if c >= 128 {
			return "", parsing.Malformed("HTTP/2 :authority must be ASCII")
		}
	}
	normalized, err := names.Normalize(string(host))
	if err != nil {
		for _, c := range host {
			if (c < '0' || c > '9') && c != '.' {
				return "", parsing.Malformed("Invalid HTTP/2 :authority host")
			}
		}
		return "", nil // IPv4 literal: structurally fine, never an application identity
	}
	return normalized, nil
}

// HTTP2Parser is the client (request) or server (response, after an h2c upgrade or prior knowledge) direction.
type HTTP2Parser struct {
	opts           Options
	request        bool
	prefacePos     int
	header         []byte
	payload        []byte
	length         int
	done           bool
	continues      bool
	consumed       int
	extra          []parsing.Row
	refined        bool
	host           string
	hasHost        bool
	frame          []byte
	body           []byte
	block          []byte
	blockStream    uint32
	inBlock        bool
	preambleFrames int
	blockFrames    int
	reason         string
	scope          string
}

// NewHTTP2 creates the client parser; NewHTTP2Server the server parser (no preface). Options.Fingerprints is not
// read here: the engine refuses the fingerprints option for the client direction (the SETTINGS fingerprint).
func NewHTTP2(opts Options) *HTTP2Parser {
	return &HTTP2Parser{opts: opts, request: true, reason: "Waiting for complete HTTP/2 client preface and initial SETTINGS"}
}

// NewHTTP2Server creates the server-direction parser: the first frame is SETTINGS without any preface.
func NewHTTP2Server(opts Options) *HTTP2Parser {
	return &HTTP2Parser{opts: opts, prefacePos: len(Preface), reason: "Waiting for the server's initial HTTP/2 SETTINGS after the h2c upgrade"}
}

func (p *HTTP2Parser) Done() bool    { return p.done }
func (p *HTTP2Parser) Refined() bool { return p.refined }

func (p *HTTP2Parser) Result() *parsing.Result {
	return &parsing.Result{ProtocolName: "http/2", Host: p.host, HasHost: p.hasHost, ALPN: []string{}, Extra: p.extra, Reason: p.reason,
		Scope: p.scope, Continues: p.continues}
}

func (p *HTTP2Parser) prefaceLen() int {
	if p.request {
		return len(Preface)
	}
	return 0
}

// Feed ports HTTP2Parser.feed.
func (p *HTTP2Parser) Feed(data []byte) (int, error) {
	if p.done {
		return p.frames(data)
	}
	pos := 0
	if p.prefacePos < len(Preface) {
		amount := minInt(len(Preface)-p.prefacePos, len(data))
		if !bytes.Equal(data[:amount], Preface[p.prefacePos:p.prefacePos+amount]) {
			return 0, parsing.Malformed("Invalid HTTP/2 client preface")
		}
		p.prefacePos += amount
		pos += amount
		if p.prefacePos < len(Preface) {
			p.consumed += pos
			return pos, nil
		}
	}
	if len(p.header) < 9 {
		amount := minInt(9-len(p.header), len(data)-pos)
		p.header = append(p.header, data[pos:pos+amount]...)
		pos += amount
		if len(p.header) < 9 {
			p.consumed += pos
			return pos, nil
		}
		p.length = int(p.header[0])<<16 | int(p.header[1])<<8 | int(p.header[2])
		stream := binary.BigEndian.Uint32(p.header[5:9]) & 0x7fffffff
		if p.header[3] != h2Settings || p.header[4]&1 != 0 || stream != 0 {
			return pos, parsing.Malformed("Initial HTTP/2 frame must be non-ACK SETTINGS on stream zero")
		}
		if p.length > 16384 || p.length%6 != 0 {
			return pos, parsing.Malformed("Invalid initial SETTINGS payload length")
		}
		if p.prefaceLen()+9+p.length > p.opts.MaxBytes {
			return pos, parsing.Budget("Initial HTTP/2 SETTINGS exceeds byte budget")
		}
	}
	amount := minInt(p.length-len(p.payload), len(data)-pos)
	p.payload = append(p.payload, data[pos:pos+amount]...)
	pos += amount
	p.consumed += pos
	if len(p.payload) == p.length {
		if err := checkSettings(p.payload); err != nil {
			return pos, err
		}
		p.done, p.continues = true, true
		if p.request {
			p.reason = "HTTP/2 client preface and initial SETTINGS validated; no HEADERS frame decoded yet"
		} else {
			p.reason = "HTTP/2 server SETTINGS after the h2c upgrade validated; no HEADERS frame decoded yet"
		}
	}
	return pos, nil
}

func checkSettings(payload []byte) error {
	for offset := 0; offset+6 <= len(payload); offset += 6 {
		setting := binary.BigEndian.Uint16(payload[offset:])
		value := binary.BigEndian.Uint32(payload[offset+2:])
		switch {
		case setting == 2 && value != 0 && value != 1:
			return parsing.Malformed("Invalid SETTINGS_ENABLE_PUSH")
		case setting == 4 && value > 0x7fffffff:
			return parsing.Malformed("Invalid SETTINGS_INITIAL_WINDOW_SIZE")
		case setting == 5 && (value < 16384 || value > 0xffffff):
			return parsing.Malformed("Invalid SETTINGS_MAX_FRAME_SIZE")
		}
	}
	return nil
}

func (p *HTTP2Parser) frames(data []byte) (int, error) {
	pos := 0
	for pos < len(data) && p.continues {
		if len(p.frame) < 9 {
			amount := minInt(9-len(p.frame), len(data)-pos)
			p.frame = append(p.frame, data[pos:pos+amount]...)
			pos += amount
			p.consumed += amount
			if len(p.frame) < 9 {
				break
			}
			p.length = int(p.frame[0])<<16 | int(p.frame[1])<<8 | int(p.frame[2])
			if p.consumed+p.length > p.opts.MaxBytes {
				return pos, parsing.Budget("HTTP/2 frame exceeds the byte budget")
			}
			inProfile, err := p.frameHeader(p.frame[3], p.frame[4], binary.BigEndian.Uint32(p.frame[5:9])&0x7fffffff)
			if err != nil {
				return pos, err
			}
			if !inProfile {
				p.continues = false // outside the profile: keep the identification, stop reading
				break
			}
		}
		amount := minInt(p.length-len(p.body), len(data)-pos)
		p.body = append(p.body, data[pos:pos+amount]...)
		pos += amount
		p.consumed += amount
		if len(p.body) == p.length {
			if err := p.frameComplete(p.frame[3], p.frame[4], binary.BigEndian.Uint32(p.frame[5:9])&0x7fffffff, p.body); err != nil {
				return pos, err
			}
			p.frame, p.body = nil, nil
		}
	}
	return pos, nil
}

func (p *HTTP2Parser) frameHeader(kind, flags byte, stream uint32) (bool, error) {
	if p.inBlock {
		if kind != h2Continuation || stream != p.blockStream || flags&^h2EndHeaders != 0 {
			return false, parsing.Malformed("HTTP/2 header block interrupted by another frame")
		}
		p.blockFrames++
		if p.blockFrames >= maxH2BlockFrames {
			return false, parsing.Budget("HTTP/2 CONTINUATION frame count exceeds budget")
		}
		if len(p.block)+p.length > maxH2HeaderBlock {
			return false, parsing.Budget("HTTP/2 header block exceeds the size budget")
		}
		return true, nil
	}
	if kind == h2Headers {
		if stream&1 == 0 || flags&^(h2EndStream|h2EndHeaders|h2Padded|h2PriorityFlag) != 0 {
			return false, parsing.Malformed("HTTP/2 HEADERS must open a client-initiated stream with known flags")
		}
		if p.length > maxH2HeaderBlock {
			return false, parsing.Budget("HTTP/2 HEADERS frame exceeds the size budget")
		}
		p.blockStream, p.inBlock = stream, true
		return true, nil
	}
	if kind != h2Settings && kind != h2WindowUpdate && kind != h2Priority && kind != h2Ping {
		return false, nil
	}
	p.preambleFrames++
	if p.preambleFrames > maxH2PreambleFrames {
		return false, parsing.Budget("HTTP/2 frame count before HEADERS exceeds budget")
	}
	switch kind {
	case h2Settings:
		if stream != 0 || flags&^1 != 0 || (flags&1 != 0 && p.length != 0) || (flags&1 == 0 && (p.length%6 != 0 || p.length > 16384)) {
			return false, parsing.Malformed("Invalid HTTP/2 SETTINGS frame")
		}
	case h2WindowUpdate:
		if p.length != 4 || flags != 0 {
			return false, parsing.Malformed("Invalid HTTP/2 WINDOW_UPDATE frame")
		}
	case h2Priority:
		if p.length != 5 || flags != 0 || stream == 0 {
			return false, parsing.Malformed("Invalid HTTP/2 PRIORITY frame")
		}
	default:
		if p.length != 8 || stream != 0 || flags&^1 != 0 {
			return false, parsing.Malformed("Invalid HTTP/2 PING frame")
		}
	}
	return true, nil
}

func (p *HTTP2Parser) frameComplete(kind, flags byte, stream uint32, body []byte) error {
	switch {
	case kind == h2Settings && flags&1 == 0:
		return checkSettings(body)
	case kind == h2WindowUpdate:
		if binary.BigEndian.Uint32(body)&0x7fffffff == 0 {
			return parsing.Malformed("HTTP/2 WINDOW_UPDATE increment must be positive")
		}
	case kind == h2Priority:
		if binary.BigEndian.Uint32(body[:4])&0x7fffffff == stream {
			return parsing.Malformed("HTTP/2 PRIORITY frame depends on its own stream")
		}
	case kind == h2Headers || kind == h2Continuation:
		fragment := body
		if kind == h2Headers {
			if flags&h2Padded != 0 {
				if len(fragment) == 0 {
					return parsing.Malformed("Padded HTTP/2 HEADERS frame without a pad length")
				}
				pad := int(fragment[0])
				fragment = fragment[1:]
				reserved := 0
				if flags&h2PriorityFlag != 0 {
					reserved = 5
				}
				if pad > len(fragment)-reserved {
					return parsing.Malformed("HTTP/2 HEADERS padding exceeds the frame")
				}
				fragment = fragment[:len(fragment)-pad]
			}
			if flags&h2PriorityFlag != 0 {
				if len(fragment) < 5 || binary.BigEndian.Uint32(fragment[:4])&0x7fffffff == stream {
					return parsing.Malformed("Invalid HTTP/2 HEADERS priority fields")
				}
				fragment = fragment[5:]
			}
		}
		p.block = append(p.block, fragment...)
		if flags&h2EndHeaders != 0 {
			if err := p.headers(p.block); err != nil {
				return err
			}
			p.continues = false
		}
	}
	return nil
}

type h2Field struct{ name, value []byte }

func (p *HTTP2Parser) headers(block []byte) error {
	maxFields, maxString := p.opts.MaxHeaders, p.opts.MaxLine
	if maxFields > 128 {
		maxFields = 128
	}
	if maxString > 8192 {
		maxString = 8192
	}
	decoded, err := hpack.NewDecoder(hpack.DefaultTableSize, maxFields, maxString, maxH2HeaderBlock).Decode(block)
	if err != nil {
		return err
	}
	pseudo := map[string][]byte{}
	var regular []h2Field
	for _, f := range decoded {
		name, value := f.Name, f.Value
		bare := name
		if len(name) > 0 && name[0] == ':' {
			bare = name[1:]
		}
		if len(bare) == 0 {
			return parsing.Malformed("HTTP/2 field name must be a lowercase token")
		}
		for _, b := range bare {
			if !h2Token[b] {
				return parsing.Malformed("HTTP/2 field name must be a lowercase token")
			}
		}
		for _, b := range value {
			if b == 0 || b == 10 || b == 13 {
				return parsing.Malformed("HTTP/2 field value contains forbidden bytes or edge whitespace")
			}
		}
		if len(value) > 0 && (value[0] == ' ' || value[0] == '\t' || value[len(value)-1] == ' ' || value[len(value)-1] == '\t') {
			return parsing.Malformed("HTTP/2 field value contains forbidden bytes or edge whitespace")
		}
		if name[0] == ':' {
			if len(regular) > 0 {
				return parsing.Malformed("HTTP/2 pseudo-header after a regular field")
			}
			if _, seen := pseudo[string(name)]; seen {
				return parsing.Malformed("Duplicate HTTP/2 pseudo-header")
			}
			allowed := string(name) == ":status"
			if p.request {
				allowed = h2PseudoRequest[string(name)]
			}
			if !allowed {
				return parsing.Malformed("HTTP/2 pseudo-header outside this message direction")
			}
			pseudo[string(name)] = value
			continue
		}
		if h2ConnectionFields[string(name)] || (string(name) == "te" && strings.ToLower(string(value)) != "trailers") {
			return parsing.Malformed("HTTP/2 connection-specific field")
		}
		regular = append(regular, h2Field{name, value})
	}
	var evidence []parsing.Row
	if p.request {
		evidence, err = p.requestEvidence(pseudo)
	} else {
		evidence, err = p.responseEvidence(pseudo)
	}
	if err != nil {
		return err
	}
	row := func(field, value, strength string) parsing.Row {
		return parsing.Row{Field: field, Value: value, Provenance: "headers_frame", Strength: strength}
	}
	for _, f := range regular {
		if string(f.name) == "content-type" {
			evidence = append(evidence, row("http2_content_type", ContentTypeClass(f.value), "asserted"))
			break
		}
	}
	for _, f := range regular {
		if string(f.name) == "accept" {
			if acceptClass(f.value) == "dns" {
				evidence = append(evidence, row("http2_accept", "dns", "asserted"))
			}
			break
		}
	}
	var schemes, offered []string
	for _, f := range regular {
		switch string(f.name) {
		case "authorization", "proxy-authorization":
			label := authSchemeClass(f.value)
			if !contains(schemes, label) {
				schemes = append(schemes, label)
				evidence = append(evidence, row("http2_auth_scheme", label, "asserted"))
			}
		case "www-authenticate", "proxy-authenticate":
			for _, label := range challengeSchemeClasses(f.value) {
				if !contains(offered, label) {
					offered = append(offered, label)
					evidence = append(evidence, row("http2_auth_challenge", label, "asserted"))
				}
			}
		}
	}
	p.extra = append(p.extra, evidence...)
	if p.request {
		p.scope = "request_headers"
	} else {
		p.scope = "response_headers"
	}
	p.refined = true
	return nil
}

func (p *HTTP2Parser) requestEvidence(pseudo map[string][]byte) ([]parsing.Row, error) {
	method, ok := pseudo[":method"]
	if !ok {
		return nil, parsing.Malformed("HTTP/2 request without :method")
	}
	if len(method) == 0 || len(method) > 32 {
		return nil, parsing.Malformed("Invalid HTTP/2 :method")
	}
	for _, b := range method {
		if !h2Method[b] {
			return nil, parsing.Malformed("Invalid HTTP/2 :method")
		}
	}
	label := "extension"
	if methods[string(method)] {
		label = string(method)
	}
	row := func(field, value, strength string) parsing.Row {
		return parsing.Row{Field: field, Value: value, Provenance: "headers_frame", Strength: strength}
	}
	evidence := []parsing.Row{row("http2_message", "request", "structural"), row("http2_method", label, "structural")}
	_, hasProtocol := pseudo[":protocol"]
	_, hasScheme := pseudo[":scheme"]
	_, hasPath := pseudo[":path"]
	authority, hasAuthority := pseudo[":authority"]
	if string(method) == "CONNECT" && !hasProtocol {
		if hasScheme || hasPath || !hasAuthority {
			return nil, parsing.Malformed("HTTP/2 CONNECT requires :authority alone")
		}
	} else {
		if !hasScheme || len(pseudo[":path"]) == 0 {
			return nil, parsing.Malformed("HTTP/2 request requires :scheme and a non-empty :path")
		}
		scheme := strings.ToLower(string(pseudo[":scheme"]))
		if scheme != "http" && scheme != "https" {
			scheme = "other"
		}
		evidence = append(evidence, row("http2_scheme", scheme, "structural"))
		if hasProtocol {
			if string(method) != "CONNECT" || !hasAuthority {
				return nil, parsing.Malformed("HTTP/2 :protocol requires an extended CONNECT with :authority")
			}
			protocol := "other"
			if strings.ToLower(string(pseudo[":protocol"])) == "websocket" {
				protocol = "websocket"
			}
			evidence = append(evidence, row("http2_protocol", protocol, "asserted"))
		}
	}
	if hasAuthority {
		host, err := authorityHost(authority)
		if err != nil {
			return nil, err
		}
		p.host, p.hasHost = host, host != ""
	}
	p.reason = "HTTP/2 client preface, SETTINGS and first request HEADERS validated (HPACK decoded); " +
		"only method, scheme, authority host, extended-CONNECT protocol and content-type class are emitted"
	return evidence, nil
}

func (p *HTTP2Parser) responseEvidence(pseudo map[string][]byte) ([]parsing.Row, error) {
	status, ok := pseudo[":status"]
	valid := ok && len(status) == 3
	for _, c := range status {
		valid = valid && c >= '0' && c <= '9'
	}
	if valid {
		n := int(status[0]-'0')*100 + int(status[1]-'0')*10 + int(status[2]-'0')
		valid = n >= 100 && n <= 599
	}
	if !valid {
		return nil, parsing.Malformed("HTTP/2 response requires a three-digit :status")
	}
	p.reason = "HTTP/2 server SETTINGS and first response HEADERS validated (HPACK decoded); " +
		"only the status code and content-type class are emitted"
	return []parsing.Row{{Field: "http2_message", Value: "response", Provenance: "headers_frame", Strength: "structural"},
		{Field: "http2_status", Value: string(status), Provenance: "headers_frame", Strength: "structural"}}, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
