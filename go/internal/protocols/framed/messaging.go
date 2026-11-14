package framed

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// --- MQTT CONNECT (messaging.MQTTParser) -------------------------------------------------------------------

type mqttFields struct {
	data []byte
	pos  int
}

func (f *mqttFields) take(size int) ([]byte, error) {
	end := f.pos + size
	if end > len(f.data) {
		return nil, parsing.Malformed("Truncated MQTT CONNECT field")
	}
	out := f.data[f.pos:end]
	f.pos = end
	return out, nil
}

func (f *mqttFields) vector() ([]byte, error) {
	size, err := f.take(2)
	if err != nil {
		return nil, err
	}
	return f.take(be(size))
}

func (f *mqttFields) text() (string, error) {
	value, err := f.vector()
	if err != nil {
		return "", err
	}
	if !utf8.Valid(value) {
		return "", parsing.Malformed("Invalid MQTT UTF-8 field")
	}
	if bytes.IndexByte(value, 0) >= 0 {
		return "", parsing.Malformed("NUL in MQTT UTF-8 field")
	}
	return string(value), nil
}

func (f *mqttFields) varint() (int, error) {
	value := 0
	for index := 0; index < 4; index++ {
		b, err := f.take(1)
		if err != nil {
			return 0, err
		}
		value |= int(b[0]&127) << (7 * index)
		if b[0] < 128 {
			if index > 0 && b[0] == 0 {
				return 0, parsing.Malformed("Nonminimal MQTT variable integer")
			}
			return value, nil
		}
	}
	return 0, parsing.Malformed("MQTT variable integer exceeds four bytes")
}

var mqttConnectProperties = map[int]bool{0x11: true, 0x21: true, 0x27: true, 0x22: true, 0x19: true, 0x17: true, 0x26: true, 0x15: true, 0x16: true}
var mqttWillProperties = map[int]bool{0x18: true, 0x01: true, 0x02: true, 0x03: true, 0x08: true, 0x09: true, 0x26: true}

func mqttProperties(fields *mqttFields, will bool) (int, error) {
	size, err := fields.varint()
	if err != nil {
		return 0, err
	}
	raw, err := fields.take(size)
	if err != nil {
		return 0, err
	}
	block := &mqttFields{data: raw}
	allowed := mqttConnectProperties
	if will {
		allowed = mqttWillProperties
	}
	seen := map[int]bool{}
	count, payloadFormat := 0, 0
	for block.pos < len(block.data) {
		count++
		if count > 128 {
			return 0, parsing.Budget("MQTT property count exceeds inspection limit")
		}
		code, err := block.varint()
		if err != nil {
			return 0, err
		}
		if !allowed[code] || (seen[code] && code != 0x26) {
			return 0, parsing.Malformed("Unknown, misplaced or duplicate MQTT CONNECT/Will property")
		}
		seen[code] = true
		switch code {
		case 0x01, 0x17, 0x19:
			b, err := block.take(1)
			if err != nil {
				return 0, err
			}
			if b[0] > 1 {
				return 0, parsing.Malformed("Invalid MQTT boolean property")
			}
			if code == 1 {
				payloadFormat = int(b[0])
			}
		case 0x21, 0x22:
			b, err := block.take(2)
			if err != nil {
				return 0, err
			}
			if code == 0x21 && be(b) == 0 {
				return 0, parsing.Malformed("MQTT Receive Maximum must be nonzero")
			}
		case 0x11, 0x27, 0x18, 0x02:
			b, err := block.take(4)
			if err != nil {
				return 0, err
			}
			if code == 0x27 && be(b) == 0 {
				return 0, parsing.Malformed("MQTT Maximum Packet Size must be nonzero")
			}
		case 0x15, 0x03, 0x08:
			value, err := block.text()
			if err != nil {
				return 0, err
			}
			if code == 0x08 && (value == "" || strings.ContainsAny(value, "+#")) {
				return 0, parsing.Malformed("Invalid MQTT Response Topic")
			}
		case 0x16, 0x09:
			if _, err := block.vector(); err != nil {
				return 0, err
			}
		default:
			if _, err := block.text(); err != nil {
				return 0, err
			}
			if _, err := block.text(); err != nil {
				return 0, err
			}
		}
	}
	if !will && seen[0x16] && !seen[0x15] {
		return 0, parsing.Malformed("MQTT Authentication Data requires Authentication Method")
	}
	return payloadFormat, nil
}

// MQTT parses one MQTT 3.1.1/5.0 CONNECT packet.
type MQTT struct {
	maxBytes            int
	started, bodyReady  bool
	length, lengthBytes int
	body                []byte
	done                bool
	result              *parsing.Result
}

// NewMQTT creates the parser.
func NewMQTT(maxBytes int) *MQTT { return &MQTT{maxBytes: maxBytes} }

func (p *MQTT) Done() bool              { return p.done }
func (p *MQTT) Result() *parsing.Result { return p.result }

// Feed ports MQTTParser.feed.
func (p *MQTT) Feed(data []byte) (int, error) {
	pos := 0
	if !p.started && len(data) > 0 {
		if data[0] != 0x10 {
			return pos, parsing.Malformed("Invalid MQTT CONNECT control byte")
		}
		p.started, pos = true, 1
	}
	for !p.bodyReady && pos < len(data) {
		b := data[pos]
		pos++
		p.length |= int(b&127) << (7 * p.lengthBytes)
		p.lengthBytes++
		if b&128 != 0 {
			if p.lengthBytes == 4 {
				return pos, parsing.Malformed("MQTT Remaining Length exceeds four bytes")
			}
			continue
		}
		if p.lengthBytes > 1 && b == 0 {
			return pos, parsing.Malformed("Nonminimal MQTT Remaining Length (strict profile)")
		}
		if p.length < 12 {
			return pos, parsing.Malformed("MQTT CONNECT body is too short")
		}
		if 1+p.lengthBytes+p.length > p.maxBytes {
			return pos, parsing.Budget("MQTT CONNECT exceeds byte budget")
		}
		p.bodyReady = true
	}
	if p.bodyReady {
		amount := p.length - len(p.body)
		if amount > len(data)-pos {
			amount = len(data) - pos
		}
		p.body = append(p.body, data[pos:pos+amount]...)
		pos += amount
		if len(p.body) == p.length {
			name, err := p.validate()
			if err != nil {
				return pos, err
			}
			p.done = true
			p.body = nil
			p.result = &parsing.Result{ProtocolName: name, Scope: "initial_message", ALPN: []string{},
				Reason: strings.ToUpper(name) + " CONNECT fields validated; broker reply and later packets not inspected"}
		}
	}
	return pos, nil
}

func (p *MQTT) validate() (string, error) {
	fields := &mqttFields{data: p.body}
	name, err := fields.vector()
	if err != nil {
		return "", err
	}
	if string(name) != "MQTT" {
		return "", parsing.Unsupported("Unsupported MQTT protocol name")
	}
	head, err := fields.take(2)
	if err != nil {
		return "", err
	}
	level, flags := head[0], head[1]
	if level != 4 && level != 5 {
		return "", parsing.Unsupported("Only MQTT protocol levels 4 and 5 are supported")
	}
	protocol := "mqtt/3.1.1"
	if level == 5 {
		protocol = "mqtt/5.0"
	}
	will := flags&4 != 0
	qos := (flags >> 3) & 3
	if flags&1 != 0 || qos == 3 || (!will && flags&0x38 != 0) || (level == 4 && flags&64 != 0 && flags&128 == 0) {
		return "", parsing.Malformed("Invalid MQTT CONNECT flags")
	}
	if _, err := fields.take(2); err != nil { // Keep Alive
		return "", err
	}
	if level == 5 {
		if _, err := mqttProperties(fields, false); err != nil {
			return "", err
		}
	}
	client, err := fields.text()
	if err != nil {
		return "", err
	}
	if level == 4 && client == "" && flags&2 == 0 {
		return "", parsing.Malformed("Empty MQTT ClientId requires Clean Session")
	}
	if will {
		payloadFormat := 0
		if level == 5 {
			if payloadFormat, err = mqttProperties(fields, true); err != nil {
				return "", err
			}
		}
		topic, err := fields.text()
		if err != nil {
			return "", err
		}
		if topic == "" || strings.ContainsAny(topic, "+#") {
			return "", parsing.Malformed("Invalid MQTT Will Topic")
		}
		payload, err := fields.vector()
		if err != nil {
			return "", err
		}
		if payloadFormat != 0 && !utf8.Valid(payload) {
			return "", parsing.Malformed("MQTT Will Payload violates declared UTF-8 format")
		}
	}
	if flags&128 != 0 {
		if _, err := fields.text(); err != nil {
			return "", err
		}
	}
	if flags&64 != 0 {
		if _, err := fields.vector(); err != nil {
			return "", err
		}
	}
	if fields.pos != len(p.body) {
		return "", parsing.Malformed("Extra bytes inside MQTT CONNECT")
	}
	return protocol, nil
}

// --- RESP command array (messaging.RESPParser) ---------------------------------------------------------------

var respCommand = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]*$`)

const respHuge = 1 << 62 // stands in for numbers beyond int64; every comparison it meets is a budget bound

// RESP parses one command array of non-null bulk strings.
type RESP struct {
	maxBytes                       int
	stage                          string
	line, command                  []byte
	remainingItems, remainingBytes int
	first                          bool
	trailer, total                 int
	done                           bool
	result                         *parsing.Result
}

// NewRESP creates the parser.
func NewRESP(maxBytes int) *RESP { return &RESP{maxBytes: maxBytes, stage: "array", first: true} }

func (p *RESP) Done() bool              { return p.done }
func (p *RESP) Result() *parsing.Result { return p.result }

func respNumber(digits []byte) int {
	trimmed := bytes.TrimLeft(digits, "0")
	if len(trimmed) > 18 {
		return respHuge
	}
	if len(trimmed) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(string(trimmed))
	return n
}

func (p *RESP) header() error {
	marker := byte('*')
	if p.stage != "array" {
		marker = '$'
	}
	line := p.line
	p.line = nil
	ok := len(line) >= 3 && line[0] == marker && bytes.HasSuffix(line, []byte("\r\n"))
	if ok {
		for _, c := range line[1 : len(line)-2] {
			if c < '0' || c > '9' {
				ok = false
			}
		}
	}
	if !ok || len(line) == 3 {
		return parsing.Malformed("Invalid RESP request length header")
	}
	number := respNumber(line[1 : len(line)-2])
	if p.stage == "array" {
		if number == 0 {
			return parsing.Malformed("RESP command array must not be empty")
		}
		if number > 1024 {
			return parsing.Budget("RESP argument count exceeds inspection limit")
		}
		p.remainingItems = number
		p.stage = "bulk"
		return nil
	}
	if p.total+number+2 > p.maxBytes {
		return parsing.Budget("RESP bulk string exceeds byte budget")
	}
	if p.first && (number < 1 || number > 128) {
		return parsing.Unsupported("RESP command token outside supported length")
	}
	p.remainingBytes = number
	if number > 0 {
		p.stage = "data"
	} else {
		p.stage = "trailer"
	}
	return nil
}

// Feed ports RESPParser.feed (numeric headers are capped at 24 bytes).
func (p *RESP) Feed(data []byte) (int, error) {
	pos := 0
	for pos < len(data) && !p.done {
		switch p.stage {
		case "array", "bulk":
			end := find(data, '\n', pos, pos+24-len(p.line))
			amount := len(data) - pos
			if room := 24 - len(p.line); amount > room {
				amount = room
			}
			if end >= 0 {
				amount = end + 1 - pos
			}
			p.line = append(p.line, data[pos:pos+amount]...)
			pos += amount
			p.total += amount
			if end >= 0 {
				if err := p.header(); err != nil {
					return pos, err
				}
			} else if len(p.line) == 24 {
				return pos, parsing.Budget("RESP numeric header exceeds inspection limit")
			}
		case "data":
			amount := p.remainingBytes
			if amount > len(data)-pos {
				amount = len(data) - pos
			}
			if p.first {
				p.command = append(p.command, data[pos:pos+amount]...)
			}
			pos += amount
			p.total += amount
			p.remainingBytes -= amount
			if p.remainingBytes == 0 {
				if p.first && !respCommand.Match(p.command) {
					return pos, parsing.Unsupported("RESP first bulk string is not a supported command token")
				}
				p.stage = "trailer"
			}
		default:
			if data[pos] != "\r\n"[p.trailer] {
				return pos, parsing.Malformed("Invalid RESP bulk string terminator")
			}
			pos++
			p.total++
			p.trailer++
			if p.trailer == 2 {
				p.remainingItems--
				p.first = false
				p.command = nil
				p.trailer = 0
				if p.remainingItems == 0 {
					p.done = true
					p.result = &parsing.Result{ProtocolName: "resp", Scope: "initial_message", ALPN: []string{},
						Reason: "RESP command array framing validated; compatible server identity and command semantics unverified"}
				} else {
					p.stage = "bulk"
				}
			}
		}
	}
	return pos, nil
}

// --- AMQP version header or Connection.Start (messaging.AMQPParser) -----------------------------------------------

// AMQP parses the eight-byte protocol header or the broker's Connection.Start frame.
type AMQP struct {
	header []byte
	needed int
	done   bool
	result *parsing.Result
}

// NewAMQP creates the parser.
func NewAMQP() *AMQP { return &AMQP{needed: 8} }

func (p *AMQP) Done() bool              { return p.done }
func (p *AMQP) Result() *parsing.Result { return p.result }

// Feed ports AMQPParser.feed.
func (p *AMQP) Feed(data []byte) (int, error) {
	amount := p.needed - len(p.header)
	if amount > len(data) {
		amount = len(data)
	}
	p.header = append(p.header, data[:amount]...)
	if len(p.header) < p.needed {
		return amount, nil
	}
	if p.header[0] == 1 {
		if p.needed == 8 {
			size := be(p.header[3:7])
			if p.header[1] != 0 || p.header[2] != 0 || size < 14 {
				return amount, parsing.Malformed("AMQP frame header outside the Connection.Start profile")
			}
			if size > 4096 {
				return amount, parsing.Budget("AMQP Connection.Start frame exceeds the profile size")
			}
			p.needed = 8 + size
			if len(data) > amount {
				n, err := p.Feed(data[amount:])
				return amount + n, err
			}
			return amount, nil
		}
		if err := amqpConnectionStart(p.header[7:len(p.header)-1], p.header[len(p.header)-1]); err != nil {
			return amount, err
		}
		p.done = true
		p.result = &parsing.Result{ProtocolName: "amqp/0-9-1", Scope: "negotiation_response", ALPN: []string{},
			Extra:  []parsing.Row{row("amqp_message", "connection-start", "frame", "structural")},
			Reason: "AMQP 0-9-1 Connection.Start frame validated; server properties, mechanisms and locales not emitted"}
		return amount, nil
	}
	var protocol string
	switch string(p.header) {
	case "AMQP\x00\x00\x09\x01":
		protocol = "amqp/0-9-1"
	case "AMQP\x00\x01\x00\x00":
		protocol = "amqp/1.0"
	default:
		return amount, parsing.Unsupported("Unsupported AMQP protocol version header")
	}
	p.done = true
	p.result = &parsing.Result{ProtocolName: protocol, Scope: "protocol_header", ALPN: []string{},
		Extra:  []parsing.Row{row("amqp_message", "protocol-header", "header", "structural")},
		Reason: "AMQP version header validated; negotiation, frames and peer identity unverified"}
	return amount, nil
}

func amqpConnectionStart(payload []byte, frameEnd byte) error {
	if frameEnd != 0xce {
		return parsing.Malformed("AMQP frame-end octet missing")
	}
	if !bytes.Equal(payload[:4], []byte{0, 0x0a, 0, 0x0a}) || payload[4] != 0 || payload[5] != 9 {
		return parsing.Unsupported("AMQP frame is not Connection.Start for version 0-9")
	}
	pos := 6
	table := be(payload[pos : pos+4])
	pos += 4
	if pos+table > len(payload) {
		return parsing.Malformed("AMQP server-properties table exceeds the frame")
	}
	pos += table
	for _, what := range []string{"mechanisms", "locales"} {
		if pos+4 > len(payload) {
			return parsing.Malformed("AMQP Connection.Start " + what + " length truncated")
		}
		size := be(payload[pos : pos+4])
		pos += 4
		if size == 0 || pos+size > len(payload) || !printableASCII(payload[pos:pos+size], 0x20) {
			return parsing.Malformed("AMQP Connection.Start " + what + " must be non-empty printable text")
		}
		pos += size
	}
	if pos != len(payload) {
		return parsing.Malformed("Trailing bytes in AMQP Connection.Start")
	}
	return nil
}
