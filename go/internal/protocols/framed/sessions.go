package framed

import (
	"net/netip"
	"strconv"

	"github.com/leenadav/protocol-detector/go/internal/names"
	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// --- NetBIOS Session Service request (windows.NetBIOSSessionParser) -----------------------------------------

// NewNetBIOSSession creates the session-request parser (two first-level encoded names).
func NewNetBIOSSession(maxBytes int) *Parser {
	return newParser(maxBytes, spec{header: 4,
		size: func(h []byte) (int, error) {
			if h[0] != 0x81 || h[1]&0xfe != 0 {
				return 0, parsing.Malformed("Invalid NetBIOS session request header")
			}
			if int(h[1]&1)<<16|be(h[2:4]) != 68 {
				return 0, parsing.Malformed("NetBIOS session request requires two 34-byte encoded names")
			}
			return 72, nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			for _, offset := range []int{4, 38} {
				if d[offset] != 32 || d[offset+33] != 0 {
					return nil, parsing.Malformed("NetBIOS name label framing invalid")
				}
				for _, b := range d[offset+1 : offset+33] {
					if b < 0x41 || b > 0x50 {
						return nil, parsing.Malformed("NetBIOS first-level encoding requires letters A-P")
					}
				}
			}
			return &parsing.Result{ProtocolName: "netbios-ss", Scope: "negotiation_request",
				Reason: "NetBIOS session request names validated (first-level encoding); names are not emitted"}, nil
		}})
}

// --- TACACS+ packet header (windows.TACACSParser) ----------------------------------------------------------------

var tacacsTypes = map[byte]string{1: "authentication", 2: "authorization", 3: "accounting"}

// NewTACACS creates the header parser (seq_no 1 and 2).
func NewTACACS(maxBytes int) *Parser {
	return newParser(maxBytes, spec{header: 12,
		size: func(h []byte) (int, error) {
			if h[0] != 0xc0 && h[0] != 0xc1 {
				return 0, parsing.Malformed("TACACS+ major version must be 0xc")
			}
			if _, ok := tacacsTypes[h[1]]; !ok {
				return 0, parsing.Unsupported("TACACS+ type outside authentication/authorization/accounting")
			}
			if h[2] != 1 && h[2] != 2 {
				return 0, parsing.Unsupported("TACACS+ profile covers the first two packets of a session (seq_no 1 and 2)")
			}
			if h[3]&0xfa != 0 {
				return 0, parsing.Malformed("TACACS+ reserved flag bits set")
			}
			size := be(h[8:12])
			if size < 1 || size > 65535 {
				return 0, parsing.Malformed("TACACS+ body length outside profile")
			}
			return 12 + size, nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			kind := tacacsTypes[d[1]]
			body := d[12:]
			unencrypted := d[3]&1 != 0
			if d[2] == 2 {
				if unencrypted {
					if err := tacacsReply(kind, body); err != nil {
						return nil, err
					}
				}
				return &parsing.Result{ProtocolName: "tacacs-plus", Scope: "negotiation_response", Extra: []parsing.Row{row("tacacs_packet", "reply", "header", "structural"),
					row("tacacs_type", kind, "header", "structural")}, Reason: "TACACS+ reply header validated; body is encrypted or opaque, status and messages not emitted"}, nil
			}
			if unencrypted && d[1] == 1 {
				if len(body) < 8 {
					return nil, parsing.Malformed("TACACS+ authentication START body too short")
				}
				if body[0] < 1 || body[0] > 4 || body[2] < 1 || body[2] > 9 {
					return nil, parsing.Malformed("TACACS+ START action or authen_type invalid")
				}
				if 8+int(body[4])+int(body[5])+int(body[6])+int(body[7]) != len(body) {
					return nil, parsing.Malformed("TACACS+ START field lengths disagree with body")
				}
			}
			return &parsing.Result{ProtocolName: "tacacs-plus", Scope: "protocol_header", Extra: []parsing.Row{row("tacacs_packet", "start", "header", "structural"),
				row("tacacs_type", kind, "header", "structural")}, Reason: "TACACS+ header validated; body is encrypted or opaque, no authentication claim"}, nil
		}})
}

func tacacsReply(kind string, body []byte) error {
	switch kind {
	case "authentication":
		ok := len(body) >= 6
		if ok {
			switch body[0] {
			case 1, 2, 3, 4, 5, 6, 7, 0x21:
			default:
				ok = false
			}
		}
		if !ok || 6+be(body[2:4])+be(body[4:6]) != len(body) {
			return parsing.Malformed("TACACS+ authentication REPLY status or lengths invalid")
		}
	case "authorization":
		ok := len(body) >= 6
		if ok {
			switch body[0] {
			case 1, 2, 16, 17, 33:
			default:
				ok = false
			}
		}
		if ok {
			args := int(body[1])
			end := 6 + args
			if end > len(body) {
				end = len(body) // Python's slice clamps before the explicit length check below
			}
			sum := 0
			for _, b := range body[6:end] {
				sum += int(b)
			}
			ok = 6+args+be(body[2:4])+be(body[4:6])+sum == len(body) && len(body) >= 6+args
		}
		if !ok {
			return parsing.Malformed("TACACS+ authorization REPLY status or lengths invalid")
		}
	default:
		if len(body) < 5 || body[4] < 1 || body[4] > 3 || 5+be(body[0:2])+be(body[2:4]) != len(body) {
			return parsing.Malformed("TACACS+ accounting REPLY status or lengths invalid")
		}
	}
	return nil
}

// --- SOCKS5 initial exchange (extended.Socks5Parser) -------------------------------------------------------------

const socksMaxBytes = 2 + 255 + 4 + 1 + 255 + 2

var socksReplies = []string{"succeeded", "general-failure", "not-allowed", "network-unreachable", "host-unreachable",
	"connection-refused", "ttl-expired", "command-not-supported", "address-type-not-supported"}
var socksCommands = map[byte]string{1: "CONNECT", 2: "BIND", 3: "UDP_ASSOCIATE"}

// SOCKS5 parses one direction's greeting plus request, or method selection plus reply.
type SOCKS5 struct {
	buffer []byte
	done   bool
	result *parsing.Result
}

// NewSOCKS5 creates the parser.
func NewSOCKS5() *SOCKS5 { return &SOCKS5{} }

func (p *SOCKS5) Done() bool              { return p.done }
func (p *SOCKS5) Result() *parsing.Result { return p.result }

// Feed ports Socks5Parser.feed: buffer at most the longest exchange, parse once complete.
func (p *SOCKS5) Feed(data []byte) (int, error) {
	if p.done {
		return 0, nil
	}
	before := len(p.buffer)
	take := socksMaxBytes - before
	if take > len(data) {
		take = len(data)
	}
	p.buffer = append(p.buffer, data[:take]...)
	end, result, err := p.parse(p.buffer)
	if err != nil {
		return len(p.buffer) - before, err
	}
	if end < 0 {
		if len(p.buffer) >= socksMaxBytes {
			return len(p.buffer) - before, parsing.Malformed("SOCKS5 exchange exceeds its maximum size")
		}
		return len(p.buffer) - before, nil
	}
	p.done, p.result, p.buffer = true, result, nil
	return end - before, nil
}

func (p *SOCKS5) parse(buf []byte) (int, *parsing.Result, error) {
	if len(buf) < 2 {
		return -1, nil, nil
	}
	if buf[0] != 5 {
		return 0, nil, parsing.Malformed("Invalid SOCKS5 version")
	}
	second := buf[1]
	if second == 0 || (second == 2 && len(buf) >= 5 && buf[2] == 5 && buf[4] == 0) {
		return socksServer(buf)
	}
	if second == 2 && len(buf) < 5 {
		return -1, nil, nil
	}
	return socksClient(buf)
}

// socksAddress returns the address text and the position after the port, or end -1 while incomplete.
func socksAddress(buf []byte, pos int, what string) (string, int, error) {
	if pos+1 > len(buf) {
		return "", -1, nil
	}
	atyp := buf[pos-1]
	length := 16
	switch atyp {
	case 3:
		length = int(buf[pos])
		if length == 0 {
			return "", 0, parsing.Malformed("Empty SOCKS5 " + what)
		}
		pos++
	case 1:
		length = 4
	}
	if pos+length+2 > len(buf) {
		return "", -1, nil
	}
	field := buf[pos : pos+length]
	var address string
	if atyp == 3 {
		for _, b := range field {
			if b >= 0x80 {
				return "", 0, parsing.Malformed("Invalid or unsupported SOCKS5 " + what)
			}
		}
		host, err := names.Normalize(string(field))
		if err != nil {
			return "", 0, parsing.Malformed("Invalid or unsupported SOCKS5 " + what)
		}
		address = host
	} else {
		ip, _ := netip.AddrFromSlice(field)
		address = ip.String()
	}
	return address, pos + length + 2, nil
}

func socksClient(buf []byte) (int, *parsing.Result, error) {
	count := int(buf[1])
	if len(buf) < 2+count {
		return -1, nil, nil
	}
	none := false
	for _, m := range buf[2 : 2+count] {
		if m == 255 {
			return 0, nil, parsing.Malformed("No-acceptable-methods is a server response, not a client method")
		}
		if m == 0 {
			none = true
		}
	}
	if !none {
		return 0, nil, parsing.Unsupported("SOCKS5 authentication subnegotiation is not supported")
	}
	request := 2 + count
	if len(buf) < request+4 {
		return -1, nil, nil
	}
	command, known := socksCommands[buf[request+1]]
	atyp := buf[request+3]
	if buf[request] != 5 || !known || buf[request+2] != 0 || (atyp != 1 && atyp != 3 && atyp != 4) {
		return 0, nil, parsing.Malformed("Invalid SOCKS5 request header")
	}
	address, end, err := socksAddress(buf, request+4, "destination")
	if err != nil || end < 0 {
		return end, nil, err
	}
	port := be(buf[end-2 : end])
	return end, &parsing.Result{ProtocolName: "socks5", Scope: "initial_message", ALPN: []string{},
		Extra: []parsing.Row{row("socks_command", command, "socks_request", "asserted"), row("socks_target", address, "socks_request", "asserted"),
			row("socks_port", strconv.Itoa(port), "socks_request", "asserted")},
		Reason: "SOCKS5 client greeting and request validated; method selection, server reply and tunneled protocol unverified"}, nil
}

func socksServer(buf []byte) (int, *parsing.Result, error) {
	if len(buf) < 6 {
		return -1, nil, nil
	}
	atyp := buf[5]
	if buf[2] != 5 || buf[3] > 8 || buf[4] != 0 || (atyp != 1 && atyp != 3 && atyp != 4) {
		return 0, nil, parsing.Malformed("Invalid SOCKS5 server reply header")
	}
	_, end, err := socksAddress(buf, 6, "bound address")
	if err != nil || end < 0 {
		return end, nil, err
	}
	method := "username-password"
	if buf[1] == 0 {
		method = "no-authentication"
	}
	return end, &parsing.Result{ProtocolName: "socks5", Scope: "negotiation_response", ALPN: []string{},
		Extra:  []parsing.Row{row("socks_method", method, "socks_reply", "structural"), row("socks_reply", socksReplies[buf[3]], "socks_reply", "asserted")},
		Reason: "SOCKS5 server method selection and reply validated; bound address not emitted, tunneled protocol unverified"}, nil
}
