package textroute

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// IRC first-line grammar (protocol_engine/irc.py): registration lines, unprefixed server opening lines and
// the ':'-prefixed server lines of the dispatched irc family. Only the closed command class is reported.

const ircLineLimit = 512

var (
	ircNick     = regexp.MustCompile(`^[A-Za-z\[\]\\` + "`" + `_^{|}][A-Za-z0-9\[\]\\` + "`" + `_^{|}\-]{0,63}$`)
	ircUser     = regexp.MustCompile(`^[^\x00\x0a\x0d\x20@]{1,64}$`)
	ircHost     = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9\-.:_/]{0,254})$`)
	ircMiddle   = regexp.MustCompile(`^[^\x00\x0a\x0d\x20:][^\x00\x0a\x0d\x20]{0,509}$`)
	ircTrailing = regexp.MustCompile(`^[^\x00\x0a\x0d]{0,510}$`)
	ircCommand  = regexp.MustCompile(`^[A-Za-z]{1,20}$`)
	ircNumeric  = regexp.MustCompile(`^[0-9]{3}$`)
	ircUserMode = regexp.MustCompile(`^(?:[0-9]{1,3}|[^\x20]{1,64})$`)
	ircUnused   = regexp.MustCompile(`^(?:\*|[^\x20]{1,255})$`)
	ircCapVer   = regexp.MustCompile(`^[0-9]{3}$`)
)

var capSubcommands = set("LS LIST REQ ACK NAK END NEW DEL")
var ircClientCommands = map[string]string{"NICK": "nick", "USER": "user", "CAP": "cap", "PASS": "pass"}
var ircServerCommands = map[string]string{"NOTICE": "notice", "PING": "ping", "ERROR": "error", "CAP": "cap", "PONG": "pong",
	"MODE": "mode", "PRIVMSG": "privmsg", "NICK": "nick", "JOIN": "join", "AUTHENTICATE": "authenticate"}

const ircMaxParams = 15

func ircReason(label string) string {
	return "IRC message grammar validated (" + label + "); nicknames, hosts, channels and text are never emitted"
}

// splitMessage ports irc.split_message: (prefix, hasPrefix, command upper, params).
func splitMessage(line []byte) ([]byte, bool, string, [][]byte, error) {
	if len(line) == 0 || len(line) > ircLineLimit-2 {
		return nil, false, "", nil, parsing.Malformed("IRC line empty or longer than 510 bytes")
	}
	for _, b := range line {
		if b == 0 || b == 10 || b == 13 {
			return nil, false, "", nil, parsing.Malformed("IRC line contains NUL, CR or LF")
		}
	}
	var prefix []byte
	hasPrefix := false
	rest := line
	if len(rest) > 0 && rest[0] == ':' {
		p, after, sep := bytes.Cut(rest[1:], []byte(" "))
		if !sep || len(p) == 0 {
			return nil, false, "", nil, parsing.Malformed("IRC prefix must be followed by a command")
		}
		if !validPrefix(p) {
			return nil, false, "", nil, parsing.Malformed("IRC prefix is neither a server name nor nick!user@host")
		}
		prefix, hasPrefix, rest = p, true, after
	}
	if len(rest) == 0 || rest[0] == ' ' {
		return nil, false, "", nil, parsing.Malformed("IRC command missing or preceded by extra space")
	}
	command, after, sep := bytes.Cut(rest, []byte(" "))
	if !ircCommand.Match(command) && !ircNumeric.Match(command) {
		return nil, false, "", nil, parsing.Malformed("IRC command must be letters or three digits")
	}
	var params [][]byte
	rest = after
	for sep {
		if len(rest) > 0 && rest[0] == ':' {
			if !ircTrailing.Match(rest[1:]) {
				return nil, false, "", nil, parsing.Malformed("IRC trailing parameter outside its profile")
			}
			params = append(params, rest[1:])
			break
		}
		var middle []byte
		middle, rest, sep = bytes.Cut(rest, []byte(" "))
		if !ircMiddle.Match(middle) {
			return nil, false, "", nil, parsing.Malformed("IRC parameter empty or outside its profile")
		}
		params = append(params, middle)
		if len(params) > ircMaxParams {
			return nil, false, "", nil, parsing.Budget("IRC message exceeds 15 parameters")
		}
	}
	return prefix, hasPrefix, strings.ToUpper(string(command)), params, nil
}

func validPrefix(prefix []byte) bool {
	if bytes.ContainsAny(prefix, "!@") {
		nick, rest, _ := bytes.Cut(prefix, []byte("!"))
		user, host, at := bytes.Cut(rest, []byte("@"))
		return ircNick.Match(nick) && at && ircUser.Match(user) && ircHost.Match(host)
	}
	return ircHost.Match(prefix) || ircNick.Match(prefix)
}

// ircClientLine ports irc.irc_client_line: a label, "" when the line is not IRC, or an error.
func ircClientLine(line []byte) (string, error) {
	if len(line) < 4 || len(line) > ircLineLimit-2 || line[0] == ':' {
		return "", nil
	}
	verbB, _, _ := bytes.Cut(line, []byte(" "))
	verb := strings.ToUpper(string(verbB))
	if verb != "NICK" && verb != "USER" && verb != "CAP" {
		return "", nil
	}
	if verb == "USER" && len(bytes.Split(line, []byte(" "))) < 5 {
		return "", nil
	}
	_, _, command, params, err := splitMessage(line)
	if err != nil {
		return "", err
	}
	switch command {
	case "NICK":
		if len(params) != 1 || !ircNick.Match(params[0]) {
			return "", parsing.Malformed("IRC NICK takes one nickname of up to 64 nickname characters")
		}
	case "USER":
		if len(params) != 4 || !ircUser.Match(params[0]) || !ircUserMode.Match(params[1]) || !ircUnused.Match(params[2]) || len(params[3]) > 255 {
			return "", parsing.Malformed("IRC USER takes user, mode, unused and realname parameters")
		}
	default:
		if len(params) == 0 || !capSubcommands[strings.ToUpper(string(params[0]))] || len(params) > 3 {
			return "", parsing.Malformed("IRC CAP needs a subcommand LS/LIST/REQ/ACK/NAK/END/NEW/DEL")
		}
		if strings.ToUpper(string(params[0])) == "LS" && len(params) == 2 && !ircCapVer.Match(params[1]) {
			return "", parsing.Malformed("IRC CAP LS version must be three digits")
		}
	}
	return ircClientCommands[command], nil
}

// ircServerNotice ports irc.irc_server_notice.
func ircServerNotice(line []byte) (string, error) {
	verbB, _, _ := bytes.Cut(line, []byte(" "))
	verb := strings.ToUpper(string(verbB))
	if verb != "NOTICE" && verb != "PING" {
		return "", nil
	}
	_, _, command, params, err := splitMessage(line)
	if err != nil {
		return "", err
	}
	if command == "NOTICE" {
		if len(params) != 2 || (strings.ToUpper(string(params[0])) != "AUTH" && string(params[0]) != "*") {
			return "", parsing.Malformed("Unprefixed IRC NOTICE before registration targets AUTH or *")
		}
		return "notice", nil
	}
	if len(params) < 1 || len(params) > 2 {
		return "", parsing.Malformed("IRC PING takes one or two parameters")
	}
	return "ping", nil
}

// IRC is the dispatched irc family parser (irc.IRCParser): ':'-prefixed server lines, and registration
// lines when the irc hint selected it.
type IRC struct {
	maxLine int
	line    []byte
	done    bool
	result  *parsing.Result
}

// NewIRC creates the parser.
func NewIRC(maxLine int) *IRC { return &IRC{maxLine: maxLine} }

func (p *IRC) Done() bool              { return p.done }
func (p *IRC) Result() *parsing.Result { return p.result }

// Feed ports LineParser.feed for protocol "irc".
func (p *IRC) Feed(data []byte) (int, error) {
	pos := 0
	for pos < len(data) && !p.done {
		newline := bytes.IndexByte(data[pos:], '\n')
		end := len(data)
		if newline >= 0 {
			end = pos + newline + 1
		}
		piece := data[pos:end]
		limit := p.maxLine
		if limit > ircLineLimit {
			limit = ircLineLimit
		}
		if len(p.line)+len(piece) > limit {
			if limit == ircLineLimit {
				return pos, parsing.Malformed("IRC line exceeds 512 bytes")
			}
			return pos, parsing.Budget("Line length budget exceeded")
		}
		p.line = append(p.line, piece...)
		pos = end
		if newline < 0 {
			break
		}
		if !bytes.HasSuffix(p.line, []byte("\r\n")) {
			return pos, parsing.Malformed("Expected CRLF line ending")
		}
		line := append([]byte{}, p.line[:len(p.line)-2]...)
		p.line = p.line[:0]
		if err := p.consume(line); err != nil {
			return pos, err
		}
	}
	return pos, nil
}

func (p *IRC) consume(line []byte) error {
	_, hasPrefix, command, params, err := splitMessage(line)
	if err != nil {
		return err
	}
	var label, scope string
	if !hasPrefix {
		label, err = ircClientLine(line)
		if err != nil {
			return err
		}
		if label == "" {
			label, err = ircServerNotice(line)
			if err != nil {
				return err
			}
		}
		if label == "" && command == "PASS" && len(params) == 1 {
			label = "pass"
		}
		if label == "" {
			return parsing.Unsupported("Only IRC registration and server opening lines are supported")
		}
		scope = "protocol_header"
		if label == "nick" || label == "user" || label == "cap" || label == "pass" {
			scope = "initial_message"
		}
	} else {
		if ircNumeric.MatchString(command) {
			if len(params) == 0 || (!ircNick.Match(params[0]) && string(params[0]) != "*") {
				return parsing.Malformed("IRC numeric reply must name its target nickname or *")
			}
			label = "numeric"
		} else if l, ok := ircServerCommands[command]; ok {
			label = l
			if (command == "NOTICE" || command == "PRIVMSG") && len(params) != 2 {
				return parsing.Malformed("IRC NOTICE/PRIVMSG take a target and a text parameter")
			}
			if command == "PING" && (len(params) < 1 || len(params) > 2) {
				return parsing.Malformed("IRC PING takes one or two parameters")
			}
			if command == "CAP" && (len(params) < 2 || !capSubcommands[strings.ToUpper(string(params[1]))]) {
				return parsing.Malformed("IRC CAP reply needs a target and a subcommand")
			}
		} else {
			return parsing.Unsupported("Prefixed IRC command outside the opening-line profile")
		}
		scope = "protocol_header"
	}
	p.result = &parsing.Result{Family: "irc", ProtocolName: "irc", ALPN: []string{}, Scope: scope, Reason: ircReason(label),
		Extra: []parsing.Row{{Field: "irc_message", Value: label, Provenance: "irc_line", Strength: "structural"}}}
	p.done = true
	return nil
}

// Telnet ports session_text.TelnetParser (two complete IAC commands identify the stream).
type Telnet struct {
	buffer   []byte
	commands int
	done     bool
	result   *parsing.Result
}

// NewTelnet creates the parser.
func NewTelnet() *Telnet { return &Telnet{} }

func (p *Telnet) Done() bool              { return p.done }
func (p *Telnet) Result() *parsing.Result { return p.result }

// Feed ports TelnetParser.feed byte by byte.
func (p *Telnet) Feed(data []byte) (int, error) {
	pos := 0
	for pos < len(data) && !p.done {
		p.buffer = append(p.buffer, data[pos])
		pos++
		if len(p.buffer) > 64 {
			return pos, parsing.Budget("Telnet command exceeds 64-byte profile")
		}
		if p.buffer[0] != 255 {
			return pos, parsing.Malformed("Telnet negotiation requires IAC")
		}
		if len(p.buffer) < 2 {
			continue
		}
		kind := p.buffer[1]
		switch {
		case kind >= 251 && kind <= 254:
			if len(p.buffer) == 3 {
				p.complete()
			}
		case kind == 250:
			if len(p.buffer) >= 5 && bytes.HasSuffix(p.buffer, []byte{0xff, 0xf0}) {
				p.complete()
			}
		case kind >= 241 && kind <= 249, kind == 255:
			p.complete()
		default:
			return pos, parsing.Malformed("Telnet command byte outside negotiation profile")
		}
	}
	return pos, nil
}

func (p *Telnet) complete() {
	p.buffer = p.buffer[:0]
	p.commands++
	if p.commands >= 2 {
		p.done = true
		p.result = &parsing.Result{ProtocolName: "telnet", ALPN: []string{}, Scope: "negotiation_request",
			Reason: "Telnet option negotiation validated; terminal data and credentials not inspected"}
	}
}
