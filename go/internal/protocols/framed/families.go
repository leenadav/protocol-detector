package framed

import (
	"bytes"
	"regexp"
	"strconv"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// --- PostgreSQL (binary.PostgreSQLParser) --------------------------------------------------------

var pgServerTypes = map[byte]int{0x52: 4, 0x45: 2, 0x76: 8}
var pgAuth = map[int]string{0: "ok", 2: "kerberos", 3: "cleartext-password", 5: "md5-password", 6: "scm-credentials", 7: "gss", 8: "gss-continue",
	9: "sspi", 10: "sasl", 11: "sasl-continue", 12: "sasl-final"}
var pgKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)
var pgSASLName = regexp.MustCompile(`^[A-Z0-9-]{1,20}$`)
var pgSQLState = regexp.MustCompile(`^[0-9A-Z]{5}$`)

// NewPostgreSQL creates the parser.
func NewPostgreSQL(maxBytes int) *Parser {
	return newParser(maxBytes, spec{header: 8,
		size: func(h []byte) (int, error) {
			if fixed, ok := pgServerTypes[h[0]]; ok {
				size := be(h[1:5])
				if size < 4+fixed {
					return 0, parsing.Malformed("PostgreSQL server message shorter than its fixed fields")
				}
				return 1 + size, nil
			}
			return be(h[:4]), nil
		},
		validate: pgValidate})
}

func pgValidate(data []byte) (*parsing.Result, error) {
	if _, server := pgServerTypes[data[0]]; server {
		return pgServer(data)
	}
	r := &parsing.Result{ProtocolName: "postgresql"}
	code := be(data[4:8])
	if code == 80877103 || code == 80877104 {
		if len(data) != 8 {
			return nil, parsing.Malformed("PostgreSQL encryption request length must be eight")
		}
		r.Scope = "negotiation_request"
		r.Reason = "PostgreSQL SSL/GSS negotiation request validated; encryption not established"
		if code == 80877103 {
			r.Shift = &parsing.Shift{Boundary: "postgresql-sslrequest", Expected: "tls"}
		}
		return r, nil
	}
	if code>>16 != 3 || code&65535 > 2 {
		return nil, parsing.Unsupported("Unsupported PostgreSQL startup version")
	}
	if !bytes.HasSuffix(data, []byte{0, 0}) {
		return nil, parsing.Malformed("PostgreSQL startup parameters require final terminator")
	}
	fields := bytes.Split(data[8:len(data)-1], []byte{0})
	if len(fields[len(fields)-1]) != 0 || len(fields)%2 != 1 {
		return nil, parsing.Malformed("Invalid PostgreSQL startup name/value pairs")
	}
	if len(fields) > 257 {
		return nil, parsing.Budget("PostgreSQL startup parameter count exceeds limit")
	}
	seen := map[string]bool{}
	user := false
	for i := 0; i < len(fields)-1; i += 2 {
		key, value := fields[i], fields[i+1]
		if !pgKey.Match(key) || seen[string(key)] {
			return nil, parsing.Malformed("Invalid or duplicate PostgreSQL parameter name")
		}
		seen[string(key)] = true
		if string(key) == "user" {
			user = len(value) > 0
		}
	}
	if !user {
		return nil, parsing.Malformed("PostgreSQL startup requires a user")
	}
	r.Reason = "PostgreSQL v3 startup parameter framing validated; authentication and queries unverified"
	r.Extra = []parsing.Row{row("postgresql_message", "startup", "client", "structural")}
	return r, nil
}

func pgServer(data []byte) (*parsing.Result, error) {
	kind, body := data[0], data[5:]
	r := &parsing.Result{ProtocolName: "postgresql", Scope: "negotiation_response"}
	switch kind {
	case 0x52:
		method := be(body[:4])
		label, ok := pgAuth[method]
		if !ok {
			return nil, parsing.Unsupported("PostgreSQL authentication method outside the profile")
		}
		payload := body[4:]
		switch method {
		case 0, 2, 3, 6, 7, 9:
			if len(payload) > 0 {
				return nil, parsing.Malformed("PostgreSQL authentication message carries unexpected data")
			}
		case 5:
			if len(payload) != 4 {
				return nil, parsing.Malformed("PostgreSQL MD5 authentication requires a four-byte salt")
			}
		case 10:
			if len(payload) < 2 || !bytes.HasSuffix(payload, []byte{0, 0}) {
				return nil, parsing.Malformed("PostgreSQL SASL mechanism list must end with an empty string")
			}
			names := bytes.Split(payload[:len(payload)-1], []byte{0})
			bad := len(names) > 17 || len(names[len(names)-1]) != 0
			for _, n := range names[:len(names)-1] {
				if !pgSASLName.Match(n) {
					bad = true
				}
			}
			if bad {
				return nil, parsing.Malformed("PostgreSQL SASL mechanism list outside the profile")
			}
		}
		if (method == 8 || method == 11 || method == 12) && len(payload) == 0 {
			return nil, parsing.Malformed("PostgreSQL authentication continuation requires data")
		}
		r.Extra = []parsing.Row{row("postgresql_message", "authentication", "server", "structural"), row("postgresql_auth", label, "server", "asserted")}
		r.Reason = "PostgreSQL authentication request validated; method reported, salts and SASL data not emitted"
	case 0x45:
		if !bytes.HasSuffix(body, []byte{0, 0}) || len(body) < 3 {
			return nil, parsing.Malformed("PostgreSQL error response must end with an empty field")
		}
		fields := map[byte][]byte{}
		pos, count := 0, 0
		for body[pos] != 0 {
			count++
			if count > 32 {
				return nil, parsing.Budget("PostgreSQL error field count exceeds limit")
			}
			end := pos + bytes.IndexByte(body[pos:], 0)
			code, text := body[pos], body[pos+1:end]
			if _, dup := fields[code]; code < 0x41 || code > 0x7a || dup || len(text) == 0 {
				return nil, parsing.Malformed("PostgreSQL error field invalid or repeated")
			}
			fields[code] = text
			pos = end + 1
		}
		if pos != len(body)-1 {
			return nil, parsing.Malformed("Trailing bytes after PostgreSQL error fields")
		}
		severity := string(fields[0x53])
		if (severity != "ERROR" && severity != "FATAL" && severity != "PANIC") || !pgSQLState.Match(fields[0x43]) {
			return nil, parsing.Malformed("PostgreSQL error response requires severity and a five-character SQLSTATE")
		}
		r.Extra = []parsing.Row{row("postgresql_message", "error", "server", "structural"), row("postgresql_error_class", string(fields[0x43][:2]), "server", "asserted")}
		r.Reason = "PostgreSQL error response validated; SQLSTATE class reported, message text not emitted"
	default:
		if len(body) < 8 {
			return nil, parsing.Malformed("PostgreSQL NegotiateProtocolVersion shorter than its fixed fields")
		}
		count := be(body[4:8])
		if count > 64 {
			return nil, parsing.Budget("PostgreSQL unsupported option count exceeds limit")
		}
		options := body[8:]
		if (count > 0 && !bytes.HasSuffix(options, []byte{0})) || (count == 0 && len(options) > 0) || bytes.Count(options, []byte{0}) != count {
			return nil, parsing.Malformed("PostgreSQL unsupported option list disagrees with its count")
		}
		r.Extra = []parsing.Row{row("postgresql_message", "negotiate-version", "server", "structural")}
		r.Reason = "PostgreSQL protocol version negotiation validated; option names not emitted"
	}
	return r, nil
}

// --- RFB, BitTorrent -----------------------------------------------------------------------------

// NewRFB creates the parser (the 12-byte version banner).
func NewRFB(maxBytes int) *Parser {
	return newParser(maxBytes, spec{header: 12,
		size: func([]byte) (int, error) { return 12, nil },
		validate: func(d []byte) (*parsing.Result, error) {
			switch string(d) {
			case "RFB 003.003\n", "RFB 003.007\n", "RFB 003.008\n":
			default:
				return nil, parsing.Unsupported("Unsupported RFB version banner")
			}
			return &parsing.Result{ProtocolName: "rfb", Scope: "protocol_header", Reason: "RFB 3.3/3.7/3.8 version banner validated; VNC security exchange unverified"}, nil
		}})
}

// NewBitTorrent creates the parser (the 68-byte peer handshake).
func NewBitTorrent(maxBytes int) *Parser {
	return newParser(maxBytes, spec{header: 20,
		size: func(h []byte) (int, error) {
			if string(h) != "\x13BitTorrent protocol" {
				return 0, parsing.Malformed("Invalid BitTorrent protocol identifier")
			}
			return 68, nil
		},
		validate: func([]byte) (*parsing.Result, error) {
			return &parsing.Result{ProtocolName: "bittorrent", Reason: "BitTorrent peer handshake framing validated; info-hash and peer identity unverified"}, nil
		}})
}

// --- memcached binary ------------------------------------------------------------------------------

var memcachedStatus = map[int]string{0: "no-error", 1: "key-not-found", 2: "key-exists", 3: "value-too-large", 4: "invalid-arguments", 5: "item-not-stored",
	6: "non-numeric-value", 7: "vbucket-other-server", 8: "authentication-error", 9: "authentication-continue",
	0x20: "authentication-error", 0x21: "authentication-continue", 0x81: "unknown-command", 0x82: "out-of-memory",
	0x83: "not-supported", 0x84: "internal-error", 0x85: "busy", 0x86: "temporary-failure"}

// NewMemcached creates the parser (binary request or response header).
func NewMemcached(maxBytes int) *Parser {
	response := ""
	return newParser(maxBytes, spec{header: 24,
		size: func(h []byte) (int, error) {
			body := be(h[8:12])
			key, extras, command := be(h[2:4]), int(h[4]), int(h[1])
			if h[0] == 0x81 {
				if h[5] != 0 {
					return 0, parsing.Malformed("Memcached response data type must be raw bytes")
				}
				status := be(h[6:8])
				label, ok := memcachedStatus[status]
				if !ok {
					return 0, parsing.Unsupported("Memcached response status outside the known set")
				}
				if key > 250 || body < key+extras {
					return 0, parsing.Malformed("Invalid Memcached key/extras/body sizes")
				}
				value := body - key - extras
				var valid bool
				switch {
				case status != 0:
					valid = key == 0 && extras == 0 && command <= 0x1f
				case command == 0 || command == 9:
					valid = key == 0 && extras == 4
				case command == 12 || command == 13:
					valid = key > 0 && extras == 4
				case command == 1 || command == 2 || command == 3 || command == 4 || command == 7 || command == 8 || command == 10 || command == 14 || command == 15:
					valid = body == 0
				case command == 5 || command == 6:
					valid = key == 0 && extras == 0 && value == 8
				case command == 11:
					valid = key == 0 && extras == 0 && value > 0
				case command == 16:
					valid = extras == 0
				default:
					return 0, parsing.Unsupported("Unsupported Memcached binary command")
				}
				if !valid {
					return 0, parsing.Malformed("Memcached response contradicts field sizes")
				}
				response = label
				return 24 + body, nil
			}
			if h[0] != 0x80 || !allZero(h[5:8]) {
				return 0, parsing.Malformed("Invalid Memcached binary request header")
			}
			if key > 250 || body < key+extras {
				return 0, parsing.Malformed("Invalid Memcached key/extras/body sizes")
			}
			value := body - key - extras
			response = ""
			var valid bool
			switch command {
			case 0, 4, 9, 12, 13:
				valid = key > 0 && extras == 0 && value == 0
			case 1, 2, 3:
				valid = key > 0 && extras == 8
			case 5, 6:
				valid = key > 0 && extras == 20 && value == 0
			case 7, 10, 11:
				valid = body == 0
			case 8:
				valid = key == 0 && (extras == 0 || extras == 4) && value == 0
			case 14, 15:
				valid = key > 0 && extras == 0
			case 16:
				valid = extras == 0 && value == 0
			default:
				return 0, parsing.Unsupported("Unsupported Memcached binary command")
			}
			if !valid {
				return 0, parsing.Malformed("Memcached command contradicts field sizes")
			}
			return 24 + body, nil
		},
		validate: func([]byte) (*parsing.Result, error) {
			if response != "" {
				return &parsing.Result{ProtocolName: "memcached/binary", Scope: "response_header",
					Extra:  []parsing.Row{row("memcached_message", "response", "header", "structural"), row("memcached_status", response, "header", "asserted")},
					Reason: "Memcached binary response framing validated; keys and values not emitted, request unverified"}, nil
			}
			return &parsing.Result{ProtocolName: "memcached/binary", Extra: []parsing.Row{row("memcached_message", "request", "header", "structural")},
				Reason: "Memcached binary request framing validated; values and server reply unverified"}, nil
		}})
}

// --- Omron FINS/TCP (fins.py) -----------------------------------------------------------------------

// NewFINS creates the parser.
func NewFINS(maxBytes int) *Parser {
	command := 0
	return newParser(maxBytes, spec{header: 16,
		size: func(d []byte) (int, error) {
			if string(d[:4]) != "FINS" {
				return 0, parsing.Unsupported("FINS/TCP magic expected")
			}
			length, cmd, errorCode := be(d[4:8]), be(d[8:12]), be(d[12:16])
			if cmd != 0 && cmd != 1 && cmd != 2 {
				return 0, parsing.Unsupported("FINS/TCP command outside node address exchange and frame send")
			}
			if cmd == 0 && (length != 12 || errorCode != 0) {
				return 0, parsing.Malformed("FINS node address request must carry one node address without error")
			}
			if cmd == 1 && length != 16 {
				return 0, parsing.Malformed("FINS node address reply must carry two node addresses")
			}
			if cmd == 2 && (length < 20 || length > 2048) {
				return 0, parsing.Malformed("FINS frame length outside the profile")
			}
			if errorCode > 0x1f {
				return 0, parsing.Malformed("FINS/TCP error code outside the specification")
			}
			command = cmd
			return 8 + length, nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			body := d[16:]
			if command != 2 {
				for at := 0; at < len(body); at += 4 {
					end := at + 4
					if end > len(body) {
						end = len(body)
					}
					if be(body[at:end]) > 254 {
						return nil, parsing.Malformed("FINS node address outside 0..254")
					}
				}
				r := &parsing.Result{ProtocolName: "fins", Reason: "FINS/TCP node address exchange validated; node numbers not emitted"}
				if command == 1 {
					r.Scope = "negotiation_response"
					r.Extra = []parsing.Row{row("fins_message", "node-address-reply", "header", "structural")}
				} else {
					r.Extra = []parsing.Row{row("fins_message", "node-address-request", "header", "structural")}
				}
				return r, nil
			}
			icf := body[0]
			if icf&0x3f != 0 || body[1] != 0 || body[2] > 7 {
				return nil, parsing.Malformed("FINS frame ICF, reserved or gateway count outside the specification")
			}
			if body[3] > 127 || body[6] > 127 || body[5] > 15 || body[8] > 15 {
				return nil, parsing.Malformed("FINS frame network or unit address outside the specification")
			}
			response := icf&0x40 != 0
			if response && len(body) < 14 {
				return nil, parsing.Malformed("FINS response frame shorter than its command and end codes")
			}
			kind := "command"
			r := &parsing.Result{ProtocolName: "fins", Reason: "FINS/TCP frame header validated; command code, addresses and data not emitted"}
			if response {
				kind, r.Scope = "response", "response_header"
			}
			r.Extra = []parsing.Row{row("fins_message", "frame", "header", "structural"), row("fins_frame", kind, "fins_header", "structural")}
			return r, nil
		}})
}

// --- AFP over DSI (afp.py) ----------------------------------------------------------------------------

var dsiCommands = map[byte]string{3: "get-status", 4: "open-session"}

// NewAFP creates the DSI parser.
func NewAFP(maxBytes int) *Parser {
	var reply bool
	var command byte
	return newParser(maxBytes, spec{header: 16,
		size: func(d []byte) (int, error) {
			flags, cmd := d[0], d[1]
			if _, ok := dsiCommands[cmd]; flags > 1 || !ok {
				return 0, parsing.Unsupported("DSI profile covers GetStatus and OpenSession requests and replies")
			}
			if !allZero(d[12:16]) {
				return 0, parsing.Malformed("DSI reserved bytes must be zero")
			}
			reply = flags == 1
			if !reply && !allZero(d[4:8]) {
				return 0, parsing.Malformed("DSI request data offset must be zero")
			}
			if reply && d[4] != 0 && d[4] != 0xff {
				return 0, parsing.Malformed("DSI reply error code outside the AFP result range")
			}
			if reply && !allZero(d[4:8]) && d[4] == 0 && !allZero(d[5:8]) {
				return 0, parsing.Malformed("DSI reply error code outside the AFP result range")
			}
			length := be(d[8:12])
			limit := 64
			if cmd == 3 && reply {
				limit = 4096
			}
			if length > limit {
				return 0, parsing.Malformed("DSI payload length outside the profile")
			}
			if cmd == 3 && !reply && length > 0 {
				return 0, parsing.Malformed("DSIGetStatus request carries no data")
			}
			if cmd == 3 && reply && allZero(d[4:8]) && length == 0 {
				return 0, parsing.Malformed("DSIGetStatus reply without server information")
			}
			command = cmd
			return 16 + length, nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			payload := d[16:]
			if command == 4 {
				pos := 0
				for pos < len(payload) {
					if len(payload)-pos < 2 {
						return nil, parsing.Malformed("Truncated DSI option")
					}
					kind, length := payload[pos], int(payload[pos+1])
					if kind > 2 || length != 4 || pos+2+length > len(payload) {
						return nil, parsing.Malformed("DSI OpenSession option outside the profile")
					}
					pos += 2 + length
				}
			}
			r := &parsing.Result{ProtocolName: "afp", Reason: "DSI request validated; option values not emitted, AFP commands not inspected"}
			direction := "request"
			if reply {
				direction, r.Scope = "reply", "negotiation_response"
				r.Reason = "DSI reply validated; server information and option values not emitted"
			}
			r.Extra = []parsing.Row{row("dsi_message", direction, "dsi_header", "structural"), row("afp_command", dsiCommands[command], "dsi_header", "structural")}
			return r, nil
		}})
}

// --- ZMTP and Bolt (greetings.py) --------------------------------------------------------------------

var zmtpMechanisms = map[string]string{"NULL": "null", "PLAIN": "plain", "CURVE": "curve", "GSSAPI": "gssapi"}

func mechanismByte(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '-' || b == '_' || b == '.'
}

// NewZMTP creates the 64-byte greeting parser.
func NewZMTP(maxBytes int) *Parser {
	return newParser(maxBytes, spec{header: 64,
		size: func(d []byte) (int, error) {
			if d[0] != 0xff || d[9] != 0x7f {
				return 0, parsing.Unsupported("ZMTP signature expected")
			}
			if d[10] != 3 || d[11] > 1 {
				return 0, parsing.Unsupported("Only ZMTP 3.0 and 3.1 greetings are supported")
			}
			return 64, nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			mechanism := d[12:32]
			end := bytes.IndexByte(mechanism, 0)
			name := mechanism
			if end >= 0 {
				name = mechanism[:end]
			}
			bad := len(name) == 0 || (end >= 0 && !allZero(mechanism[end:]))
			for _, b := range name {
				if !mechanismByte(b) {
					bad = true
				}
			}
			if bad {
				return nil, parsing.Malformed("ZMTP mechanism must be an upper-case name padded with zero bytes")
			}
			if d[32] > 1 || !allZero(d[33:64]) {
				return nil, parsing.Malformed("ZMTP as-server flag or filler outside the specification")
			}
			label, ok := zmtpMechanisms[string(name)]
			if !ok {
				label = "other"
			}
			role := "client"
			if d[32] == 1 {
				role = "server"
			}
			return &parsing.Result{ProtocolName: "zmtp/3", Extra: []parsing.Row{row("zmtp_mechanism", label, "greeting", "structural"),
				row("zmtp_role", role, "greeting", "structural")}, Reason: "ZMTP 3.x greeting validated; handshake commands and frames not inspected"}, nil
		}})
}

var boltMaxMinor = map[int]int{1: 0, 2: 0, 3: 0, 4: 4, 5: 15}

func boltVersionOK(major, minor int) bool {
	max, ok := boltMaxMinor[major]
	return ok && minor <= max
}

// NewBolt creates the parser (client handshake; the four-byte version response only with the bolt hint).
func NewBolt(maxBytes int) *Parser {
	handshake := false
	return newParser(maxBytes, spec{header: 4,
		size: func(d []byte) (int, error) {
			if bytes.Equal(d[:4], []byte{0x60, 0x60, 0xb0, 0x17}) {
				handshake = true
				return 20, nil
			}
			if d[0] != 0 || d[1] != 0 {
				return 0, parsing.Unsupported("Bolt magic or version response expected")
			}
			handshake = false
			return 4, nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			if handshake {
				type version struct{ major, minor int }
				var versions []version
				ended := false
				for offset := 4; offset < 20; offset += 4 {
					reserved, span, minor, major := int(d[offset]), int(d[offset+1]), int(d[offset+2]), int(d[offset+3])
					if reserved != 0 || span > minor || (major != 0 && !boltVersionOK(major, minor)) {
						return nil, parsing.Malformed("Bolt version range outside the published versions")
					}
					if major == 0 {
						if minor != 0 || span != 0 {
							return nil, parsing.Malformed("Bolt version zero must be all zero")
						}
						ended = true
						continue
					}
					if ended {
						return nil, parsing.Malformed("Bolt version after an empty slot")
					}
					versions = append(versions, version{major, minor})
				}
				if len(versions) == 0 {
					return nil, parsing.Malformed("Bolt handshake without a version proposal")
				}
				v := versions[0]
				return &parsing.Result{ProtocolName: "bolt", Extra: []parsing.Row{row("bolt_message", "handshake", "handshake", "structural"),
					row("bolt_version", strconv.Itoa(v.major)+"."+strconv.Itoa(v.minor), "handshake", "offered")},
					Reason: "Bolt handshake magic and version proposals validated; messages not inspected"}, nil
			}
			minor, major := int(d[2]), int(d[3])
			if (major != 0 || minor != 0) && !boltVersionOK(major, minor) {
				return nil, parsing.Malformed("Bolt selected version outside the published versions")
			}
			selected := "none"
			if major != 0 {
				selected = strconv.Itoa(major) + "." + strconv.Itoa(minor)
			}
			return &parsing.Result{ProtocolName: "bolt", Scope: "negotiation_response", Extra: []parsing.Row{row("bolt_message", "version-response", "handshake", "structural"),
				row("bolt_version", selected, "handshake", "asserted")}, Reason: "Bolt version response validated with caller hint; four bytes alone never select this family"}, nil
		}})
}
