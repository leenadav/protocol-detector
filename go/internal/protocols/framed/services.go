package framed

import (
	"bytes"
	"encoding/hex"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/leenadav/protocol-detector/go/internal/names"
	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// --- Connection-oriented DCE/RPC 5.0 bind, bind_ack, bind_nak (dcerpc.py) ------------------------------------

// dceSyntaxes maps the 20-byte wire form (UUID then version) of the two transfer syntaxes, per byte order.
var dceSyntaxes = map[bool]map[string]string{}

func init() {
	for _, little := range []bool{false, true} {
		values := map[string]string{}
		for _, s := range []struct {
			uuid    string
			version int
			name    string
		}{{"8a885d041ceb11c99fe808002b104860", 2, "ndr/2.0"}, {"71710533beba49378319b5dbef9ccc36", 1, "ndr64/1.0"}} {
			raw, _ := hex.DecodeString(s.uuid)
			version := []byte{0, 0, 0, byte(s.version)}
			if little {
				raw = append([]byte{raw[3], raw[2], raw[1], raw[0], raw[5], raw[4], raw[7], raw[6]}, raw[8:]...)
				version = []byte{byte(s.version), 0, 0, 0}
			}
			values[string(append(raw, version...))] = s.name
		}
		dceSyntaxes[little] = values
	}
}

// NewDCERPC creates the parser.
func NewDCERPC(maxBytes, maxHeaders int) *Parser {
	var little order
	var ptype byte
	budget := maxHeaders
	if budget > 128 {
		budget = 128
	}
	minimum := map[byte]int{0x0b: 72, 0x0c: 52, 0x0d: 21}
	return newParser(maxBytes, spec{header: 16,
		size: func(d []byte) (int, error) {
			if d[0] != 5 || d[1] != 0 || (d[2] != 0x0b && d[2] != 0x0c && d[2] != 0x0d) {
				return 0, parsing.Unsupported("DCE/RPC profile requires version 5.0 Bind, Bind_ack or Bind_nak")
			}
			ptype = d[2]
			if d[3]&3 != 3 || d[3]&^0x17 != 0 {
				return 0, parsing.Unsupported("DCE/RPC profile requires unfragmented bind flags")
			}
			if !allZero(d[5:8]) || (d[4] != 0 && d[4] != 0x10) {
				return 0, parsing.Unsupported("DCE/RPC profile requires ASCII/IEEE data representation")
			}
			little = d[4] == 0x10
			if little.uint(d[10:12]) != 0 {
				return 0, parsing.Unsupported("DCE/RPC authentication verifier outside profile")
			}
			size := little.uint(d[8:10])
			if size < minimum[ptype] {
				return 0, parsing.Malformed("DCE/RPC PDU too short for its type")
			}
			return size, nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			syntaxes := dceSyntaxes[bool(little)]
			switch ptype {
			case 0x0c:
				return dceBindAck(d, little, syntaxes, budget)
			case 0x0d:
				return dceBindNak(d, little)
			}
			count := int(d[24])
			if count == 0 || !allZero(d[25:28]) {
				return nil, parsing.Malformed("Invalid DCE/RPC context list count or reserved fields")
			}
			if count > budget {
				return nil, parsing.Budget("DCE/RPC presentation context count exceeds budget")
			}
			if count > (len(d)-28)/44 {
				return nil, parsing.Malformed("Truncated DCE/RPC context list")
			}
			pos := 28
			identifiers := map[int]bool{}
			offered := map[string]bool{}
			for i := 0; i < count; i++ {
				if len(d)-pos < 24 {
					return nil, parsing.Malformed("Truncated DCE/RPC presentation context")
				}
				id := little.uint(d[pos : pos+2])
				if identifiers[id] {
					return nil, parsing.Malformed("Duplicate DCE/RPC context identifier")
				}
				identifiers[id] = true
				transfers := int(d[pos+2])
				if d[pos+3] != 0 || transfers == 0 {
					return nil, parsing.Malformed("Invalid DCE/RPC transfer list or reserved field")
				}
				if transfers > 2 {
					return nil, parsing.Unsupported("DCE/RPC profile permits two standard transfer syntaxes per context")
				}
				if allZero(d[pos+4 : pos+20]) {
					return nil, parsing.Unsupported("Nil DCE/RPC abstract syntax outside profile")
				}
				pos += 24
				if transfers > (len(d)-pos)/20 {
					return nil, parsing.Malformed("Truncated DCE/RPC transfer syntaxes")
				}
				seen := map[string]bool{}
				for j := 0; j < transfers; j++ {
					syntax := string(d[pos : pos+20])
					name, ok := syntaxes[syntax]
					if !ok {
						return nil, parsing.Unsupported("DCE/RPC transfer syntax outside NDR 2.0 / NDR64 1.0 profile")
					}
					if seen[syntax] {
						return nil, parsing.Malformed("Duplicate DCE/RPC transfer syntax")
					}
					seen[syntax] = true
					offered[name] = true
					pos += 20
				}
			}
			if pos != len(d) {
				return nil, parsing.Malformed("Unexpected bytes after DCE/RPC bind context list")
			}
			evidence := []parsing.Row{row("dcerpc_pdu", "bind", "header", "structural")}
			for _, name := range sortedKeys(offered) {
				evidence = append(evidence, row("offered_transfer_syntax", name, "bind_request", "offered"))
			}
			return &parsing.Result{ProtocolName: "dcerpc/5.0", Scope: "bind_request", Extra: evidence,
				Reason: "DCE/RPC bind presentation offers validated; interface identity, server and negotiation unverified"}, nil
		}})
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func dceBindAck(d []byte, little order, syntaxes map[string]string, budget int) (*parsing.Result, error) {
	if little.uint(d[16:18]) == 0 || little.uint(d[18:20]) == 0 {
		return nil, parsing.Malformed("DCE/RPC bind_ack transfer sizes must be nonzero")
	}
	addressLength := little.uint(d[24:26])
	pos := 26 + addressLength
	if addressLength > 256 || pos > len(d) || (addressLength > 0 && (d[pos-1] != 0 || !printable(d[26:pos-1]))) {
		return nil, parsing.Malformed("DCE/RPC secondary address outside the profile")
	}
	pos = (pos + 3) &^ 3
	if pos+4 > len(d) {
		return nil, parsing.Malformed("Truncated DCE/RPC result list header")
	}
	count := int(d[pos])
	if count == 0 || !allZero(d[pos+1:pos+4]) {
		return nil, parsing.Malformed("Invalid DCE/RPC result list count or reserved fields")
	}
	if count > budget {
		return nil, parsing.Budget("DCE/RPC result count exceeds budget")
	}
	pos += 4
	if len(d)-pos != 24*count {
		return nil, parsing.Malformed("DCE/RPC result list length disagrees with its count")
	}
	accepted := map[string]bool{}
	for i := 0; i < count; i++ {
		result := little.uint(d[pos : pos+2])
		syntax := d[pos+4 : pos+24]
		if result > 3 {
			return nil, parsing.Malformed("DCE/RPC context result outside the specification")
		}
		if result == 0 || result == 3 {
			name, ok := syntaxes[string(syntax)]
			if !ok {
				return nil, parsing.Unsupported("DCE/RPC accepted transfer syntax outside NDR 2.0 / NDR64 1.0 profile")
			}
			accepted[name] = true
		} else if !allZero(syntax) {
			return nil, parsing.Malformed("DCE/RPC rejected context must carry a nil transfer syntax")
		}
		pos += 24
	}
	evidence := []parsing.Row{row("dcerpc_pdu", "bind-ack", "header", "structural")}
	for _, name := range sortedKeys(accepted) {
		evidence = append(evidence, row("accepted_transfer_syntax", name, "bind_ack", "asserted"))
	}
	return &parsing.Result{ProtocolName: "dcerpc/5.0", Scope: "bind_response", Extra: evidence,
		Reason: "DCE/RPC bind_ack result list validated; secondary address not emitted, interface identity unverified"}, nil
}

func dceBindNak(d []byte, little order) (*parsing.Result, error) {
	reason := little.uint(d[16:18])
	if reason > 9 && reason != 0xffff {
		return nil, parsing.Malformed("DCE/RPC bind_nak reason outside the specification")
	}
	count := int(d[18])
	if count == 0 || count > 32 {
		return nil, parsing.Malformed("DCE/RPC bind_nak version count outside the profile")
	}
	end := 19 + 2*count
	trailing := len(d) - end
	if end > len(d) || !(trailing <= 3 || (trailing >= 16 && trailing <= 19)) {
		return nil, parsing.Malformed("DCE/RPC bind_nak version list disagrees with the PDU length")
	}
	for at := 19; at < end; at += 2 {
		if d[at] != 5 {
			return nil, parsing.Unsupported("DCE/RPC bind_nak lists versions other than 5")
		}
	}
	return &parsing.Result{ProtocolName: "dcerpc/5.0", Scope: "bind_response", Extra: []parsing.Row{row("dcerpc_pdu", "bind-nak", "header", "structural")},
		Reason: "DCE/RPC bind_nak validated; reject reason not emitted"}, nil
}

// --- WebSocket frame header after the upgrade boundary (upgrade.py) ----------------------------------------------

var websocketOpcodes = map[byte]string{1: "text", 2: "binary", 8: "close", 9: "ping", 10: "pong"}

// WebSocket validates exactly one frame header.
type WebSocket struct {
	buffer []byte
	done   bool
	result *parsing.Result
}

// NewWebSocket creates the parser.
func NewWebSocket() *WebSocket { return &WebSocket{} }

func (p *WebSocket) Done() bool              { return p.done }
func (p *WebSocket) Result() *parsing.Result { return p.result }

// Feed ports WebSocketParser.feed (one byte at a time; at most 14 bytes are buffered).
func (p *WebSocket) Feed(data []byte) (int, error) {
	pos := 0
	for !p.done && pos < len(data) {
		p.buffer = append(p.buffer, data[pos])
		pos++
		if len(p.buffer) < 2 {
			continue
		}
		first, second := p.buffer[0], p.buffer[1]
		if first&0x70 != 0 {
			return pos, parsing.Malformed("WebSocket RSV bits set without a negotiated extension")
		}
		opcode := first & 0x0f
		if opcode == 0 {
			return pos, parsing.Unsupported("A WebSocket continuation frame cannot open a stream")
		}
		label, ok := websocketOpcodes[opcode]
		if !ok {
			return pos, parsing.Malformed("WebSocket reserved opcode")
		}
		masked, short := second&0x80 != 0, int(second&0x7f)
		extra := 0
		if short == 126 {
			extra = 2
		} else if short == 127 {
			extra = 8
		}
		needed := 2 + extra
		if masked {
			needed += 4
		}
		if len(p.buffer) < needed {
			continue
		}
		length := uint64(short)
		switch extra {
		case 2:
			length = uint64(be(p.buffer[2:4]))
			if length < 126 {
				return pos, parsing.Malformed("WebSocket 16-bit length must be minimal")
			}
		case 8:
			length = 0
			for _, b := range p.buffer[2:10] {
				length = length<<8 | uint64(b)
			}
			if length>>63 != 0 || length < 65536 {
				return pos, parsing.Malformed("WebSocket 64-bit length must be minimal with the high bit clear")
			}
		}
		if opcode >= 8 && (first&0x80 == 0 || length > 125) {
			return pos, parsing.Malformed("WebSocket control frames must be unfragmented and at most 125 bytes")
		}
		p.done = true
		maskedLabel := "false"
		if masked {
			maskedLabel = "true"
		}
		p.result = &parsing.Result{ProtocolName: "websocket", Scope: "frame_header", ALPN: []string{},
			Extra:  []parsing.Row{row("websocket_opcode", label, "frame_header", "structural"), row("websocket_masked", maskedLabel, "frame_header", "structural")},
			Reason: "WebSocket frame header validated after the upgrade boundary; payload not decoded"}
	}
	return pos, nil
}

// --- XMPP stream header (xmpp.py) ---------------------------------------------------------------------------

const xmppStreamTag = "<stream:stream"

var xmppNamespaces = map[string]string{"jabber:client": "client", "jabber:server": "server", "jabber:component:accept": "component"}

// The declaration's quote pairs are spelled out because RE2 has no backreferences.
var xmppProlog = regexp.MustCompile(`^<\?xml[ \t\r\n]+version[ \t\r\n]*=[ \t\r\n]*(?:'1\.[0-9]'|"1\.[0-9]")` +
	`(?:[ \t\r\n]+encoding[ \t\r\n]*=[ \t\r\n]*(?:'[Uu][Tt][Ff]-8'|"[Uu][Tt][Ff]-8"))?` +
	`(?:[ \t\r\n]+standalone[ \t\r\n]*=[ \t\r\n]*(?:'(?:yes|no)'|"(?:yes|no)"))?[ \t\r\n]*\?>`)
var xmppVersion = regexp.MustCompile(`^[0-9]{1,2}\.[0-9]{1,2}$`)

func xmlSpace(b byte) bool { return b == ' ' || b == '\t' || b == '\r' || b == '\n' }

func xmppNameStart(b byte) bool { return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || b == '_' }

func xmppNameByte(b byte) bool {
	return xmppNameStart(b) || (b >= '0' && b <= '9') || b == '.' || b == ':' || b == '-'
}

func xmppValueByte(b, quote byte) bool {
	return b != quote && b != '<' && b != '&' && !(b <= 0x08 || b == 0x0b || b == 0x0c || (b >= 0x0e && b <= 0x1f))
}

// xmppAttribute ports the _ATTRIBUTE regex anchored at pos, byte by byte (the bounds count bytes, as in Python).
func xmppAttribute(a []byte, pos int) (name, value []byte, end int, ok bool) {
	i := pos
	for i < len(a) && xmlSpace(a[i]) {
		i++
	}
	if i == pos || i == len(a) || !xmppNameStart(a[i]) {
		return nil, nil, 0, false
	}
	start := i
	for i < len(a) && xmppNameByte(a[i]) {
		i++
	}
	if i-start > 64 {
		return nil, nil, 0, false
	}
	name = a[start:i]
	for i < len(a) && xmlSpace(a[i]) {
		i++
	}
	if i == len(a) || a[i] != '=' {
		return nil, nil, 0, false
	}
	i++
	for i < len(a) && xmlSpace(a[i]) {
		i++
	}
	if i == len(a) || (a[i] != '\'' && a[i] != '"') {
		return nil, nil, 0, false
	}
	quote := a[i]
	i++
	start = i
	for i < len(a) && xmppValueByte(a[i], quote) {
		i++
	}
	if i-start > 1023 || i == len(a) || a[i] != quote {
		return nil, nil, 0, false
	}
	return name, a[start:i], i + 1, true
}

// XMPP parses the initial stream header in either direction.
type XMPP struct {
	limit  int
	buffer []byte
	quote  byte
	done   bool
	result *parsing.Result
}

// NewXMPP creates the parser (header bounded by min(max_line, 4096)).
func NewXMPP(maxLine int) *XMPP {
	if maxLine > 4096 {
		maxLine = 4096
	}
	return &XMPP{limit: maxLine}
}

func (p *XMPP) Done() bool              { return p.done }
func (p *XMPP) Result() *parsing.Result { return p.result }

func (p *XMPP) tagEnd(data []byte, pos int) int {
	quote := p.quote
	for i := pos; i < len(data); i++ {
		b := data[i]
		switch {
		case quote != 0:
			if b == quote {
				quote = 0
			}
		case b == '"' || b == '\'':
			quote = b
		case b == '>':
			p.quote = 0
			return i
		}
	}
	p.quote = quote
	return -1
}

// Feed ports XMPPParser.feed.
func (p *XMPP) Feed(data []byte) (int, error) {
	pos := 0
	for !p.done && pos < len(data) {
		closing := p.tagEnd(data, pos)
		end := len(data)
		if closing >= 0 {
			end = closing + 1
		}
		if len(p.buffer)+end-pos > p.limit {
			return pos, parsing.Budget("XMPP stream header exceeds the line budget")
		}
		p.buffer = append(p.buffer, data[pos:end]...)
		pos = end
		if closing >= 0 {
			if err := p.tagClosed(); err != nil {
				return pos, err
			}
		}
	}
	return pos, nil
}

func (p *XMPP) tagClosed() error {
	text := bytes.TrimLeft(p.buffer, " \t\r\n")
	if bytes.HasPrefix(text, []byte("<?xml")) {
		loc := xmppProlog.FindIndex(text)
		if loc == nil {
			if bytes.Contains(text, []byte("?>")) {
				return parsing.Unsupported("XML declaration outside the XMPP profile")
			}
			return nil
		}
		text = bytes.TrimLeft(text[loc[1]:], " \t\r\n")
		if len(text) == 0 {
			return nil
		}
	}
	after := len(xmppStreamTag)
	follows := len(text) > after && (xmlSpace(text[after]) || text[after] == '>' || text[after] == '/')
	if !bytes.HasPrefix(text, []byte(xmppStreamTag)) || !follows {
		if strings.HasPrefix(xmppStreamTag, string(text)) {
			return nil
		}
		return parsing.Unsupported("XMPP profile requires a stream:stream open tag")
	}
	if !bytes.HasSuffix(text, []byte(">")) {
		return nil
	}
	if bytes.HasSuffix(text, []byte("/>")) {
		return parsing.Malformed("XMPP stream header must not be self-closing")
	}
	return p.header(text[after : len(text)-1])
}

func (p *XMPP) header(attributes []byte) error {
	pos := 0
	found := map[string][]byte{}
	for pos < len(attributes) {
		name, value, end, ok := xmppAttribute(attributes, pos)
		if !ok {
			if len(bytes.Trim(attributes[pos:], " \t\r\n")) == 0 {
				break
			}
			return parsing.Malformed("Invalid XMPP stream header attribute")
		}
		if _, dup := found[string(name)]; dup {
			return parsing.Malformed("Duplicate XMPP stream header attribute")
		}
		if len(found) >= 16 {
			return parsing.Budget("XMPP stream header attribute count exceeds budget")
		}
		found[string(name)] = value
		pos = end
	}
	namespace, ok := xmppNamespaces[string(found["xmlns"])]
	if !ok {
		return parsing.Unsupported("XMPP content namespace outside client, server and component streams")
	}
	if streams, ok := found["xmlns:stream"]; !ok || string(streams) != "http://etherx.jabber.org/streams" {
		return parsing.Malformed("XMPP stream header requires the streams namespace")
	}
	version, hasVersion := found["version"]
	if hasVersion && !xmppVersion.Match(version) {
		return parsing.Malformed("Invalid XMPP stream version")
	}
	id, response := found["id"]
	if response && len(id) == 0 {
		return parsing.Malformed("Empty XMPP stream id")
	}
	domain := found["to"]
	if response {
		domain = found["from"]
	}
	r := &parsing.Result{ProtocolName: "xmpp", HostSource: "xmpp_stream", ALPN: []string{}}
	if len(domain) > 0 {
		for _, b := range domain {
			if b >= 0x80 {
				return parsing.Malformed("XMPP stream address must be ASCII")
			}
		}
		host, err := names.Normalize(string(domain))
		if err == nil {
			r.Host, r.HasHost = host, true
		} else {
			for _, b := range domain {
				if (b < '0' || b > '9') && b != '.' {
					return parsing.Malformed("Invalid XMPP stream address")
				}
			}
		}
	}
	versionLabel := "legacy"
	if hasVersion {
		versionLabel = "other"
		if bytes.HasPrefix(version, []byte("1.")) {
			versionLabel = "1.0"
		}
	}
	direction := "initiating"
	r.Scope = "initial_message"
	r.Reason = "XMPP initiating stream header validated; features, STARTTLS, authentication and stanzas not inspected"
	if response {
		direction = "response"
		r.Scope = "negotiation_response"
		r.Reason = "XMPP receiving-entity stream header validated; stream id, features and stanzas not inspected"
	}
	r.Extra = []parsing.Row{row("xmpp_stream", direction, "stream_header", "structural"), row("xmpp_namespace", namespace, "stream_header", "structural"),
		row("xmpp_version", versionLabel, "stream_header", "structural")}
	p.done = true
	p.result = r
	return nil
}

// --- RFC 5424 syslog over RFC 6587 TCP framing (syslog.py) -----------------------------------------------------

var syslogPriority = regexp.MustCompile(`^<(0|[1-9][0-9]{0,2})>1$`)
var syslogTimestamp = regexp.MustCompile(`^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$`)

// syslogDateValid reproduces datetime.fromisoformat's value checks as the reference runs them (Python 3.11+:
// any 1-6 digit fraction; Python 3.9 additionally rejects 1, 2, 4 and 5 digits, a reference discrepancy).
func syslogDateValid(m [][]byte) bool {
	n := make([]int, 6)
	for i := range n {
		n[i], _ = strconv.Atoi(string(m[i+1]))
	}
	year, month, day, hour, minute, second := n[0], n[1], n[2], n[3], n[4], n[5]
	if year < 1 || month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59 {
		return false
	}
	days := []int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}[month-1]
	if month == 2 && year%4 == 0 && (year%100 != 0 || year%400 == 0) {
		days = 29
	}
	return day >= 1 && day <= days
}

func sdName(b []byte) bool {
	if len(b) < 1 || len(b) > 32 {
		return false
	}
	for _, c := range b {
		if c <= 0x20 || c >= 0x7f || c == '=' || c == ']' || c == '"' {
			return false
		}
	}
	return true
}

// syslogMessage ports syslog.syslog: the RFC 5424 header and structured data; returns the reason.
func syslogMessage(data []byte) (string, error) {
	parts := bytes.SplitN(data, []byte(" "), 7)
	if len(parts) != 7 {
		return "", parsing.Malformed("Incomplete RFC5424 header")
	}
	priority := syslogPriority.FindSubmatch(parts[0])
	if priority == nil {
		return "", parsing.Malformed("Invalid syslog priority/version")
	}
	if value, _ := strconv.Atoi(string(priority[1])); value > 191 {
		return "", parsing.Malformed("Invalid syslog priority/version")
	}
	if timestamp := parts[1]; string(timestamp) != "-" {
		m := syslogTimestamp.FindSubmatch(timestamp)
		if m == nil {
			return "", parsing.Malformed("Invalid syslog timestamp framing")
		}
		if !syslogDateValid(m) {
			return "", parsing.Malformed("Invalid syslog timestamp value")
		}
	}
	for i, limit := range []int{255, 48, 128, 32} {
		value := parts[2+i]
		if len(value) < 1 || len(value) > limit || !printableASCII(value, 33) {
			return "", parsing.Malformed("Invalid syslog header field")
		}
	}
	sd := parts[6]
	if string(sd) == "-" || bytes.HasPrefix(sd, []byte("- ")) {
		return "RFC5424 header and NIL structured-data framing validated; log content unverified", nil
	}
	pos, count := 0, 0
	ids := map[string]bool{}
	for pos < len(sd) && sd[pos] == '[' {
		pos++
		start := pos
		for pos < len(sd) && sd[pos] != ' ' && sd[pos] != ']' {
			pos++
		}
		identifier := sd[start:pos]
		if !sdName(identifier) || ids[string(identifier)] {
			return "", parsing.Malformed("Invalid or duplicate syslog SD-ID")
		}
		ids[string(identifier)] = true
		params := map[string]bool{}
		for pos < len(sd) && sd[pos] == ' ' {
			count++
			if count > 128 {
				return "", parsing.Budget("Syslog structured-data field budget exhausted")
			}
			pos++
			start := pos
			for pos < len(sd) && sd[pos] != '=' {
				pos++
			}
			name := sd[start:pos]
			if !sdName(name) || params[string(name)] {
				return "", parsing.Malformed("Invalid or duplicate syslog parameter name")
			}
			params[string(name)] = true
			if !bytes.HasPrefix(sd[pos:], []byte(`="`)) {
				return "", parsing.Malformed("Syslog parameter requires quoted value")
			}
			pos += 2
			var value []byte
			for pos < len(sd) && sd[pos] != '"' {
				b := sd[pos]
				pos++
				if b == '\\' {
					if pos < len(sd) && (sd[pos] == '"' || sd[pos] == '\\' || sd[pos] == ']') {
						b = sd[pos]
						pos++
					}
				} else if b == ']' {
					return "", parsing.Malformed("Unescaped syslog closing bracket")
				}
				value = append(value, b)
			}
			if pos == len(sd) {
				return "", parsing.Malformed("Unterminated syslog parameter")
			}
			if !utf8.Valid(value) {
				return "", parsing.Malformed("Invalid syslog structured-data UTF-8")
			}
			pos++
		}
		if pos == len(sd) || sd[pos] != ']' {
			return "", parsing.Malformed("Unterminated syslog structured-data element")
		}
		pos++
		if len(ids) > 128 {
			return "", parsing.Budget("Syslog element budget exhausted")
		}
	}
	if len(ids) == 0 || (pos < len(sd) && sd[pos] != ' ') {
		return "", parsing.Malformed("Invalid syslog structured-data boundary")
	}
	return "RFC5424 header and structured-data framing validated; log content unverified", nil
}

// Syslog ports SyslogStreamParser: octet counting or non-transparent framing of one message.
type Syslog struct {
	limit             int
	buffer            []byte
	counting, decided bool
	length            int
	haveLength        bool
	done              bool
	result            *parsing.Result
}

// NewSyslog creates the parser (message bounded by min(max_line, 8192)).
func NewSyslog(maxLine int) *Syslog {
	if maxLine > 8192 {
		maxLine = 8192
	}
	return &Syslog{limit: maxLine}
}

func (p *Syslog) Done() bool              { return p.done }
func (p *Syslog) Result() *parsing.Result { return p.result }

// Feed ports SyslogStreamParser.feed.
func (p *Syslog) Feed(data []byte) (int, error) {
	pos := 0
	for !p.done && pos < len(data) {
		if !p.decided {
			p.counting, p.decided = data[pos] != '<', true
		}
		if p.counting {
			if !p.haveLength {
				var err error
				if pos, err = p.octetCount(data, pos); err != nil {
					return pos, err
				}
				if !p.haveLength {
					return pos, nil
				}
			}
			amount := p.length - len(p.buffer)
			if amount > len(data)-pos {
				amount = len(data) - pos
			}
			p.buffer = append(p.buffer, data[pos:pos+amount]...)
			pos += amount
			if len(p.buffer) == p.length {
				if err := p.message(p.buffer); err != nil {
					return pos, err
				}
			}
			continue
		}
		newline := bytes.IndexByte(data[pos:], '\n')
		end := len(data)
		if newline >= 0 {
			end = pos + newline + 1
		}
		if len(p.buffer)+end-pos > p.limit {
			return pos, parsing.Budget("Syslog message exceeds the line budget")
		}
		p.buffer = append(p.buffer, data[pos:end]...)
		pos = end
		if newline >= 0 {
			message := p.buffer[:len(p.buffer)-1]
			if err := p.message(bytes.TrimSuffix(message, []byte("\r"))); err != nil {
				return pos, err
			}
		}
	}
	return pos, nil
}

func (p *Syslog) octetCount(data []byte, pos int) (int, error) {
	for pos < len(data) {
		b := data[pos]
		pos++
		if b == ' ' {
			if len(p.buffer) == 0 {
				return pos, parsing.Malformed("Syslog octet count missing")
			}
			length, _ := strconv.Atoi(string(p.buffer))
			p.buffer = nil
			if length < 16 {
				return pos, parsing.Malformed("Syslog octet count below the shortest RFC 5424 header")
			}
			if length > p.limit {
				return pos, parsing.Budget("Syslog octet count exceeds the line budget")
			}
			p.length, p.haveLength = length, true
			return pos, nil
		}
		if b < '0' || b > '9' || len(p.buffer) >= 5 || (len(p.buffer) == 0 && b == '0') {
			return pos, parsing.Malformed("Invalid syslog octet count")
		}
		p.buffer = append(p.buffer, b)
	}
	return pos, nil
}

func (p *Syslog) message(message []byte) error {
	reason, err := syslogMessage(message)
	if err != nil {
		return err
	}
	framing := "non-transparent"
	if p.counting {
		framing = "octet-counting"
	}
	p.done = true
	p.buffer = nil
	p.result = &parsing.Result{ProtocolName: "syslog/5424", Scope: "initial_message", ALPN: []string{},
		Extra:  []parsing.Row{row("syslog_framing", framing, "frame", "structural")},
		Reason: reason + "; TCP " + framing + " framing"}
	return nil
}
