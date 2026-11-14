package framed

import (
	"bytes"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// --- BGP OPEN (network.BGPParser) -----------------------------------------------------------------------

// NewBGP creates the BGPv4 OPEN parser.
func NewBGP(maxBytes int) *Parser {
	return newParser(maxBytes, spec{header: 19,
		size: func(h []byte) (int, error) {
			if !bytes.Equal(h[:16], bytes.Repeat([]byte{0xff}, 16)) {
				return 0, parsing.Malformed("Invalid BGP marker")
			}
			size := be(h[16:18])
			if h[18] != 1 {
				return 0, parsing.Unsupported("Only BGP OPEN is supported")
			}
			if size < 29 || size > 4096 {
				return 0, parsing.Malformed("Invalid BGP OPEN length")
			}
			return size, nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			if d[19] != 4 {
				return nil, parsing.Unsupported("Only BGP version 4 is supported")
			}
			if hold := be(d[22:24]); hold == 1 || hold == 2 {
				return nil, parsing.Malformed("Invalid BGP hold time")
			}
			if d[28] == 255 {
				return nil, parsing.Unsupported("Extended BGP OPEN parameter lengths unsupported")
			}
			if len(d) != 29+int(d[28]) {
				return nil, parsing.Malformed("BGP optional parameter length mismatch")
			}
			pos, count := 29, 0
			for pos < len(d) {
				if pos+2 > len(d) {
					return nil, parsing.Malformed("Truncated BGP optional parameter")
				}
				kind, size := d[pos], int(d[pos+1])
				pos += 2
				end := pos + size
				if end > len(d) {
					return nil, parsing.Malformed("BGP parameter exceeds message")
				}
				if kind != 2 {
					return nil, parsing.Unsupported("Only BGP capability parameters supported")
				}
				if size == 0 {
					return nil, parsing.Malformed("Empty BGP capability parameter")
				}
				for pos < end {
					count++
					if count > 128 {
						return nil, parsing.Budget("BGP capability count exceeds limit")
					}
					if pos+2 > end {
						return nil, parsing.Malformed("Truncated BGP capability")
					}
					code, length := d[pos], int(d[pos+1])
					pos += 2
					if pos+length > end {
						return nil, parsing.Malformed("BGP capability exceeds parameter")
					}
					if ((code == 1 || code == 65) && length != 4) || ((code == 2 || code == 6) && length != 0) {
						return nil, parsing.Malformed("Invalid known BGP capability size")
					}
					if code == 1 && d[pos+2] != 0 {
						return nil, parsing.Malformed("Invalid multiprotocol BGP reserved field")
					}
					pos += length
				}
			}
			return &parsing.Result{ProtocolName: "bgp/4", Scope: "negotiation_request",
				Reason: "BGPv4 OPEN and capability framing validated; peer identity and session unverified"}, nil
		}})
}

// --- OpenVPN over TCP and PPTP (vpn.py) ------------------------------------------------------------------

var openvpnHMAC = []int{0, 16, 20, 28, 32, 48, 64}

// openvpnControl ports vpn._openvpn_control: the tls-auth HMAC width and the role of a hard-reset packet.
func openvpnControl(d []byte) (int, string, error) {
	if len(d) < 14 {
		return 0, "", parsing.Malformed("OpenVPN control packet too short")
	}
	opcode, keyID := d[0]>>3, d[0]&7
	if opcode != 7 && opcode != 8 && opcode != 10 {
		return 0, "", parsing.Unsupported("OpenVPN profile covers client and server hard-reset control packets")
	}
	if keyID != 0 {
		return 0, "", parsing.Malformed("OpenVPN initial key id must be zero")
	}
	if allZero(d[1:9]) {
		return 0, "", parsing.Malformed("OpenVPN session id must be nonzero")
	}
	role := "client"
	if opcode == 8 {
		role = "server"
	}
	for _, width := range openvpnHMAC {
		offset := 9 + width
		if width > 0 {
			offset += 8
		}
		if offset+5 > len(d) {
			continue
		}
		if opcode == 8 {
			acked := int(d[offset])
			remote := offset + 1 + 4*acked
			if acked >= 1 && acked <= 8 && len(d) == remote+8+4 && !allZero(d[remote:remote+8]) {
				return width, role, nil
			}
			continue
		}
		if d[offset] == 0 && len(d) == offset+5 {
			return width, role, nil
		}
		if opcode == 10 && d[offset] == 0 && len(d) > offset+5 {
			return width, role, nil
		}
	}
	return 0, "", parsing.Malformed("OpenVPN control framing does not match plain or tls-auth layouts")
}

// NewOpenVPN creates the TCP (two-byte length) control-packet parser.
func NewOpenVPN(maxBytes int) *Parser {
	return newParser(maxBytes, spec{header: 2,
		size: func(h []byte) (int, error) {
			size := be(h)
			if size < 14 || size > 1500 {
				return 0, parsing.Malformed("OpenVPN TCP frame length outside control profile")
			}
			return 2 + size, nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			width, role, err := openvpnControl(d[2:])
			if err != nil {
				return nil, err
			}
			auth := "absent"
			if width > 0 {
				auth = "present"
			}
			r := &parsing.Result{ProtocolName: "openvpn", Extra: []parsing.Row{row("tls_auth", auth, "control_packet", "structural"),
				row("openvpn_control", role+"-hard-reset", "control_packet", "structural")},
				Reason: "OpenVPN TCP " + role + " hard-reset control packet validated; no key exchange or tunnel claim"}
			if role == "server" {
				r.Scope = "negotiation_response"
			}
			return r, nil
		}})
}

var pptpResults = map[byte]string{1: "ok", 2: "general-error", 3: "already-connected", 4: "not-authorized", 5: "bad-version"}

// NewPPTP creates the Start-Control-Connection-Request/Reply parser (156 bytes).
func NewPPTP(maxBytes int) *Parser {
	return newParser(maxBytes, spec{header: 12,
		size: func(h []byte) (int, error) {
			length, kind, cookie, control := be(h[0:2]), be(h[2:4]), be(h[4:8]), be(h[8:10])
			if cookie != 0x1a2b3c4d || kind != 1 {
				return 0, parsing.Malformed("PPTP control header magic or message type invalid")
			}
			if control != 1 && control != 2 {
				return 0, parsing.Unsupported("PPTP profile covers Start-Control-Connection-Request and -Reply")
			}
			if length != 156 {
				return 0, parsing.Malformed("PPTP SCCRQ/SCCRP must be 156 bytes")
			}
			return 156, nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			control := be(d[8:10])
			reserved0, version := be(d[10:12]), be(d[12:14])
			framing, bearer := be(d[16:20]), be(d[20:24])
			result, code := d[14], d[15]
			if control == 2 {
				if reserved0 != 0 || version != 0x0100 || result < 1 || result > 5 || code > 6 || (result != 2 && code != 0) {
					return nil, parsing.Malformed("PPTP SCCRP reserved field, version, result or error code invalid")
				}
			} else if reserved0 != 0 || be(d[14:16]) != 0 || version != 0x0100 {
				return nil, parsing.Malformed("PPTP SCCRQ reserved fields or protocol version invalid")
			}
			if framing&^3 != 0 || bearer&^3 != 0 {
				return nil, parsing.Malformed("PPTP capability bits outside RFC 2637")
			}
			for _, field := range [][]byte{d[28:92], d[92:156]} {
				text := field
				if end := bytes.IndexByte(field, 0); end >= 0 {
					text = field[:end]
				}
				if !printableASCII(text, 32) {
					return nil, parsing.Malformed("PPTP host/vendor name outside printable ASCII")
				}
			}
			if control == 2 {
				return &parsing.Result{ProtocolName: "pptp", Scope: "negotiation_response", Extra: []parsing.Row{row("pptp_message", "sccrp", "control", "structural"),
					row("pptp_result", pptpResults[result], "control", "asserted")},
					Reason: "PPTP start-control-connection reply validated; names are not emitted, no call or tunnel claim"}, nil
			}
			return &parsing.Result{ProtocolName: "pptp", Scope: "negotiation_request", Extra: []parsing.Row{row("pptp_message", "sccrq", "control", "structural")},
				Reason: "PPTP start-control-connection request validated; names are not emitted, no call or tunnel claim"}, nil
		}})
}

// --- FastCGI BEGIN_REQUEST + PARAMS stream, or one application-server record (fastcgi.py) -----------------------

// FastCGI ports FastCGIParser.
type FastCGI struct {
	maxBytes, maxHeaders  int
	header, begin, params []byte
	requestID, currentID  int
	haveRequest, active   bool
	remaining, padding    int
	contentSize, wireSize int
	records, responseKind int
	extra                 []parsing.Row
	done                  bool
	result                *parsing.Result
}

// NewFastCGI creates the parser.
func NewFastCGI(maxBytes, maxHeaders int) *FastCGI {
	if maxHeaders > 128 {
		maxHeaders = 128
	}
	return &FastCGI{maxBytes: maxBytes, maxHeaders: maxHeaders}
}

func (p *FastCGI) Done() bool              { return p.done }
func (p *FastCGI) Result() *parsing.Result { return p.result }

func (p *FastCGI) parseHeader() error {
	h := p.header
	p.header = nil
	version, kind, requestID, size, padding, reserved := h[0], h[1], be(h[2:4]), be(h[4:6]), int(h[6]), h[7]
	if version != 1 || reserved != 0 {
		return parsing.Unsupported("FastCGI profile requires version 1 and zero reserved header")
	}
	if requestID == 0 {
		return parsing.Unsupported("FastCGI management records are outside this profile")
	}
	switch {
	case !p.haveRequest && (kind == 3 || kind == 6 || kind == 7) && p.records == 0:
		if kind == 3 && size != 8 {
			return parsing.Malformed("FastCGI END_REQUEST body must contain eight bytes")
		}
		if kind != 3 && size == 0 {
			return parsing.Unsupported("An empty FastCGI stream terminator alone is outside the profile")
		}
		p.responseKind = int(kind)
	case !p.haveRequest:
		if kind != 1 {
			return parsing.Unsupported("FastCGI stream must begin with BEGIN_REQUEST")
		}
		if size != 8 {
			return parsing.Malformed("FastCGI BEGIN_REQUEST body must contain eight bytes")
		}
	case kind != 4 || requestID != p.requestID:
		return parsing.Unsupported("FastCGI profile requires one uninterrupted PARAMS stream")
	}
	p.records++
	if p.records > p.maxHeaders {
		return parsing.Budget("FastCGI record count exceeds budget")
	}
	p.wireSize += 8 + size + padding
	if p.wireSize > p.maxBytes {
		return parsing.Budget("Advertised FastCGI record exceeds remaining byte budget")
	}
	p.currentID = requestID
	p.contentSize, p.remaining = size, size
	p.padding = padding
	p.active = true
	return nil
}

func (p *FastCGI) complete() error {
	if p.responseKind != 0 {
		if p.responseKind == 3 && (p.begin[4] > 3 || !allZero(p.begin[5:8])) {
			return parsing.Malformed("FastCGI END_REQUEST protocol status or reserved bytes invalid")
		}
		name := map[int]string{3: "end-request", 6: "stdout", 7: "stderr"}[p.responseKind]
		p.begin = nil
		p.done, p.active = true, false
		p.result = &parsing.Result{ProtocolName: "fastcgi/1", Scope: "response_record", ALPN: []string{},
			Extra:  []parsing.Row{row("fastcgi_record", name, "record", "structural")},
			Reason: "FastCGI application-server record validated; content and exit status not emitted"}
		return nil
	}
	if !p.haveRequest {
		role := be(p.begin[:2])
		if role < 1 || role > 3 || p.begin[2]&^1 != 0 || !allZero(p.begin[3:]) {
			return parsing.Unsupported("FastCGI role, flags or reserved body outside supported profile")
		}
		p.requestID, p.haveRequest = p.currentID, true
		p.begin = nil
		p.extra = []parsing.Row{row("fastcgi_record", "begin-request", "record", "structural"),
			row("fastcgi_role", []string{"responder", "authorizer", "filter"}[role-1], "begin_request", "offered")}
	} else if p.contentSize == 0 {
		if err := p.validateParams(); err != nil {
			return err
		}
		p.params = nil
		p.done = true
		p.result = &parsing.Result{ProtocolName: "fastcgi/1", Scope: "initial_params", ALPN: []string{}, Extra: p.extra,
			Reason: "FastCGI BEGIN_REQUEST and PARAMS framing validated; values, response and request completion unverified"}
	}
	p.active = false
	return nil
}

func (p *FastCGI) validateParams() error {
	pos, count, size := 0, 0, len(p.params)
	for pos < size {
		count++
		if count > p.maxHeaders {
			return parsing.Budget("FastCGI parameter count exceeds budget")
		}
		var lengths [2]int
		for i := range lengths {
			if pos == size {
				return parsing.Malformed("Truncated FastCGI parameter length")
			}
			length := int(p.params[pos])
			pos++
			if length&128 != 0 {
				if size-pos < 3 {
					return parsing.Malformed("Truncated FastCGI four-byte parameter length")
				}
				length = (length&127)<<24 | be(p.params[pos:pos+3])
				pos += 3
			}
			lengths[i] = length
		}
		if lengths[0]+lengths[1] > p.maxBytes {
			return parsing.Budget("FastCGI parameter lengths exceed byte budget")
		}
		if lengths[0]+lengths[1] > size-pos {
			return parsing.Malformed("FastCGI parameter exceeds completed PARAMS stream")
		}
		pos += lengths[0] + lengths[1]
	}
	return nil
}

// Feed ports FastCGIParser.feed.
func (p *FastCGI) Feed(data []byte) (int, error) {
	pos := 0
	for pos < len(data) && !p.done {
		if !p.active {
			amount := 8 - len(p.header)
			if amount > len(data)-pos {
				amount = len(data) - pos
			}
			p.header = append(p.header, data[pos:pos+amount]...)
			pos += amount
			if len(p.header) < 8 {
				break
			}
			if err := p.parseHeader(); err != nil {
				return pos, err
			}
		}
		if p.remaining > 0 {
			amount := p.remaining
			if amount > len(data)-pos {
				amount = len(data) - pos
			}
			if !p.haveRequest {
				p.begin = append(p.begin, data[pos:pos+amount]...)
			} else {
				p.params = append(p.params, data[pos:pos+amount]...)
			}
			p.remaining -= amount
			pos += amount
		}
		if p.remaining == 0 && p.padding > 0 {
			amount := p.padding
			if amount > len(data)-pos {
				amount = len(data) - pos
			}
			p.padding -= amount
			pos += amount
		}
		if p.remaining == 0 && p.padding == 0 {
			if err := p.complete(); err != nil {
				return pos, err
			}
		}
	}
	return pos, nil
}
