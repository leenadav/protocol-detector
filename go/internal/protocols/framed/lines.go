package framed

import (
	"bytes"
	"regexp"
	"strconv"
	"unicode/utf8"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// --- rsync daemon greeting (rsync.py) ----------------------------------------------------------------

var rsyncGreeting = regexp.MustCompile(`^@RSYNCD: ([0-9]{2})(?:\.([0-9]{1,3}))?(?: ([a-z0-9-]+(?: [a-z0-9-]+)*))?\n$`)

// Rsync parses the one greeting line.
type Rsync struct {
	maxLine, maxHeaders int
	line                []byte
	done                bool
	result              *parsing.Result
}

// NewRsync creates the parser.
func NewRsync(maxLine, maxHeaders int) *Rsync {
	return &Rsync{maxLine: maxLine, maxHeaders: maxHeaders}
}

func (p *Rsync) Done() bool              { return p.done }
func (p *Rsync) Result() *parsing.Result { return p.result }

// Feed ports RsyncParser.feed (the amount is measured from the start of each call, as in Python).
func (p *Rsync) Feed(data []byte) (int, error) {
	newline := bytes.IndexByte(data, '\n')
	amount := len(data)
	if newline >= 0 {
		amount = newline + 1
	}
	limit := p.maxLine
	if limit > 512 {
		limit = 512
	}
	if len(p.line)+amount > limit {
		return amount, parsing.Budget("Rsync daemon greeting exceeds line budget")
	}
	p.line = append(p.line, data[:amount]...)
	if newline < 0 {
		return amount, nil
	}
	m := rsyncGreeting.FindSubmatch(p.line)
	if m == nil {
		return amount, parsing.Malformed("Invalid rsync daemon greeting framing")
	}
	version, _ := strconv.Atoi(string(m[1]))
	hasSub, hasDigests := m[2] != nil, m[3] != nil
	sub := 0
	if hasSub {
		sub, _ = strconv.Atoi(string(m[2]))
	}
	if version < 27 || version > 32 || (hasSub && sub != 0) {
		return amount, parsing.Unsupported("Rsync profile supports final daemon protocols 27 through 32")
	}
	if version >= 30 && !hasSub {
		return amount, parsing.Malformed("Rsync protocol 30 and above require subprotocol")
	}
	if version >= 32 && !hasDigests {
		return amount, parsing.Malformed("Rsync protocol 32 requires authentication digest offers")
	}
	if hasDigests {
		names := bytes.Split(m[3], []byte(" "))
		budget := p.maxHeaders
		if budget > 16 {
			budget = 16
		}
		wide := false
		seen := map[string]bool{}
		duplicate := false
		for _, n := range names {
			if len(n) > 32 {
				wide = true
			}
			if seen[string(n)] {
				duplicate = true
			}
			seen[string(n)] = true
		}
		if len(names) > budget || wide {
			return amount, parsing.Budget("Rsync digest offer count or width exceeds budget")
		}
		if duplicate {
			return amount, parsing.Unsupported("Duplicate rsync digest offers outside conservative profile")
		}
	}
	p.line = nil
	p.done = true
	p.result = &parsing.Result{ProtocolName: "rsync", Scope: "protocol_header", ALPN: []string{},
		Extra:  []parsing.Row{row("rsync_protocol", strconv.Itoa(version), "daemon_greeting", "offered")},
		Reason: "Rsync daemon greeting validated; version/digest offers only, no authentication or file transfer validation"}
	return amount, nil
}

// --- STOMP handshake (stomp.py) ------------------------------------------------------------------------

// STOMP parses one CONNECT/STOMP/CONNECTED frame with an empty body.
type STOMP struct {
	maxLine, maxHeaders int
	line                []byte
	command             string
	headers             map[string][]byte
	count               int
	awaitNull           bool
	done                bool
	result              *parsing.Result
}

// NewSTOMP creates the parser.
func NewSTOMP(maxLine, maxHeaders int) *STOMP {
	return &STOMP{maxLine: maxLine, maxHeaders: maxHeaders, headers: map[string][]byte{}}
}

func (p *STOMP) Done() bool              { return p.done }
func (p *STOMP) Result() *parsing.Result { return p.result }

var stompEscapes = map[byte]byte{'r': '\r', 'n': '\n', 'c': ':', '\\': '\\'}

func stompUnescape(value []byte) ([]byte, error) {
	if bytes.IndexByte(value, '\\') < 0 {
		return value, nil
	}
	var out []byte
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b == '\\' {
			i++
			if i == len(value) {
				return nil, parsing.Malformed("Undefined STOMP escape")
			}
			repl, ok := stompEscapes[value[i]]
			if !ok {
				return nil, parsing.Malformed("Undefined STOMP escape")
			}
			b = repl
		}
		out = append(out, b)
	}
	return out, nil
}

func isDigits(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// Feed ports STOMPParser.feed.
func (p *STOMP) Feed(data []byte) (int, error) {
	pos := 0
	for pos < len(data) && !p.done {
		if p.awaitNull {
			if data[pos] != 0 {
				return pos, parsing.Malformed("STOMP handshake must have an empty body and NUL terminator")
			}
			p.done = true
			p.headers = map[string][]byte{}
			p.result = &parsing.Result{ProtocolName: "stomp", Scope: "protocol_header", ALPN: []string{},
				Reason: "STOMP handshake frame validated; version offers, authentication and later messages unverified"}
			return pos + 1, nil
		}
		newline := bytes.IndexByte(data[pos:], '\n')
		end := len(data)
		if newline >= 0 {
			end = pos + newline + 1
		}
		if len(p.line)+end-pos > p.maxLine {
			return pos, parsing.Budget("STOMP line length exceeds budget")
		}
		p.line = append(p.line, data[pos:end]...)
		pos = end
		if newline < 0 {
			break
		}
		line := append([]byte{}, p.line[:len(p.line)-1]...)
		p.line = p.line[:0]
		line = bytes.TrimSuffix(line, []byte("\r"))
		if bytes.IndexByte(line, '\r') >= 0 || bytes.IndexByte(line, 0) >= 0 {
			return pos, parsing.Malformed("Invalid STOMP line framing")
		}
		if err := p.consume(line); err != nil {
			return pos, err
		}
	}
	return pos, nil
}

func (p *STOMP) consume(line []byte) error {
	if p.command == "" {
		switch string(line) {
		case "CONNECT", "STOMP", "CONNECTED":
			p.command = string(line)
			return nil
		}
		return parsing.Malformed("Unsupported STOMP initial command")
	}
	if len(line) == 0 {
		if p.command == "CONNECTED" {
			v := string(p.headers["version"])
			if _, ok := p.headers["version"]; !ok || (v != "1.1" && v != "1.2") {
				return parsing.Malformed("Unsupported STOMP server version")
			}
		} else {
			versions := bytes.Split(p.headers["accept-version"], []byte(","))
			supported, unknown := false, false
			for _, v := range versions {
				switch string(v) {
				case "1.1", "1.2":
					supported = true
				case "1.0":
				default:
					unknown = true
				}
			}
			if len(p.headers["host"]) == 0 || !supported || unknown {
				return parsing.Malformed("STOMP handshake needs host and supported accept-version list")
			}
		}
		length, ok := p.headers["content-length"]
		if !ok {
			length = []byte("0")
		}
		zeros := len(length) > 0
		for _, b := range length {
			if b != '0' {
				zeros = false
			}
		}
		if !zeros {
			return parsing.Malformed("STOMP handshake content-length must be zero")
		}
		if heartbeat, ok := p.headers["heart-beat"]; ok {
			parts := bytes.Split(heartbeat, []byte(","))
			bad := len(parts) != 2
			for _, part := range parts {
				if !isDigits(part) || len(part) > 20 {
					bad = true
				}
			}
			if bad {
				return parsing.Malformed("Invalid STOMP heart-beat pair")
			}
		}
		p.awaitNull = true
		return nil
	}
	p.count++
	if p.count > p.maxHeaders {
		return parsing.Budget("STOMP header count exceeds budget")
	}
	name, value, sep := bytes.Cut(line, []byte(":"))
	if !sep || len(name) == 0 {
		return parsing.Malformed("Invalid STOMP header")
	}
	if p.command == "STOMP" {
		if bytes.IndexByte(value, ':') >= 0 {
			return parsing.Malformed("Unescaped colon in STOMP header")
		}
		var err error
		if name, err = stompUnescape(name); err != nil {
			return err
		}
		if value, err = stompUnescape(value); err != nil {
			return err
		}
	}
	if !utf8.Valid(name) || !utf8.Valid(value) {
		return parsing.Malformed("Invalid STOMP UTF-8 header")
	}
	switch string(name) {
	case "host", "version", "accept-version", "content-length", "heart-beat":
		if _, seen := p.headers[string(name)]; !seen {
			p.headers[string(name)] = append([]byte{}, value...)
		}
	}
	return nil
}
