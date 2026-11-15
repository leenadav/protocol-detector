package framed

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"regexp"
	"strconv"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// find ports bytes.find(sub, start, end) for one byte: -1 when absent or when start is past the window.
func find(b []byte, c byte, start, end int) int {
	if end > len(b) {
		end = len(b)
	}
	if start < 0 || start > end {
		return -1
	}
	i := bytes.IndexByte(b[start:end], c)
	if i < 0 {
		return -1
	}
	return start + i
}

func le16(b []byte) int { return int(binary.LittleEndian.Uint16(b)) }

// --- MySQL (database.MySQLParser; selected by the mysql hint) ----------------------------------------

var mysqlPlugins = map[string]string{"mysql_native_password": "mysql_native_password", "caching_sha2_password": "caching_sha2_password",
	"sha256_password": "sha256_password", "mysql_clear_password": "cleartext", "authentication_ldap_sasl_client": "ldap-sasl",
	"authentication_kerberos_client": "kerberos"}

// NewMySQL creates the parser: server HandshakeV10, client SSLRequest or HandshakeResponse41.
func NewMySQL(maxBytes int) *Parser {
	return newParser(maxBytes, spec{header: 4,
		size: func(h []byte) (int, error) {
			size := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
			if h[3] == 1 {
				if size == 32 {
					return 36, nil
				}
				if size < 34 {
					return 0, parsing.Malformed("MySQL HandshakeResponse41 shorter than its fixed fields")
				}
				return size + 4, nil
			}
			if h[3] != 0 {
				return 0, parsing.Malformed("MySQL initial server handshake requires sequence zero")
			}
			if size < 32 {
				return 0, parsing.Malformed("MySQL packet shorter than modern handshake profile")
			}
			return size + 4, nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			if d[3] == 1 {
				if len(d) == 36 {
					return mysqlSSLRequest(d[4:])
				}
				return mysqlHandshakeResponse(d[4:])
			}
			return mysqlServer(d)
		}})
}

func mysqlServer(d []byte) (*parsing.Result, error) {
	if d[4] != 10 {
		return nil, parsing.Unsupported("Only MySQL server HandshakeV10 is supported")
	}
	limit := len(d)
	if limit > 134 {
		limit = 134
	}
	end := find(d, 0, 5, limit)
	bad := end <= 5
	if !bad {
		for _, b := range d[5:end] {
			if b < 33 || b > 126 {
				bad = true
			}
		}
	}
	if bad {
		return nil, parsing.Malformed("Invalid MySQL server version field")
	}
	pos := end + 1
	if pos+31 > len(d) {
		return nil, parsing.Malformed("Truncated MySQL handshake fields")
	}
	if d[pos+12] != 0 || d[pos+15] == 0 || !allZero(d[pos+21:pos+31]) {
		return nil, parsing.Malformed("Invalid MySQL filler, charset or reserved fields")
	}
	capabilities := le16(d[pos+13:pos+15]) | le16(d[pos+18:pos+20])<<16
	if capabilities&0x88200 != 0x88200 {
		return nil, parsing.Unsupported("MySQL profile requires protocol-4.1, secure-connection and plugin-auth capabilities")
	}
	if d[pos+20] != 21 {
		return nil, parsing.Unsupported("MySQL profile supports 21-byte authentication challenges only")
	}
	pos += 31
	if pos+13 >= len(d) || d[pos+12] != 0 {
		return nil, parsing.Malformed("Invalid MySQL second challenge length or terminator")
	}
	plugin := d[pos+13:]
	if plugin[len(plugin)-1] != 0 || bytes.IndexByte(plugin[:len(plugin)-1], 0) >= 0 {
		return nil, parsing.Malformed("Invalid MySQL authentication plugin framing")
	}
	switch string(plugin[:len(plugin)-1]) {
	case "mysql_native_password", "caching_sha2_password", "sha256_password":
	default:
		return nil, parsing.Unsupported("MySQL authentication plugin outside supported handshake profile")
	}
	return &parsing.Result{ProtocolName: "mysql", Scope: "protocol_header",
		Extra:  []parsing.Row{row("mysql_tls_supported", strconv.FormatBool(capabilities&0x800 != 0), "server_handshake", "offered")},
		Reason: "MySQL modern server handshake validated; advertised version/capabilities, authentication and commands unverified"}, nil
}

func mysqlHandshakeResponse(p []byte) (*parsing.Result, error) {
	capabilities := int(binary.LittleEndian.Uint32(p[:4]))
	if capabilities&0x200 != 0x200 {
		return nil, parsing.Unsupported("MySQL HandshakeResponse41 requires CLIENT_PROTOCOL_41")
	}
	if capabilities&0x800 != 0 {
		return nil, parsing.Malformed("MySQL HandshakeResponse41 with CLIENT_SSL must follow an SSLRequest")
	}
	if p[8] == 0 || !allZero(p[9:28]) {
		return nil, parsing.Malformed("MySQL HandshakeResponse41 character set or reserved bytes invalid")
	}
	end := find(p, 0, 32, len(p))
	if end < 32 || end-32 > 128 {
		return nil, parsing.Malformed("MySQL user name missing, unterminated or too long")
	}
	pos := end + 1
	switch {
	case capabilities&0x200000 != 0:
		if pos >= len(p) || p[pos] >= 0xfb {
			return nil, parsing.Malformed("MySQL authentication response length outside the one-byte profile")
		}
		pos += 1 + int(p[pos])
	case capabilities&0x8000 != 0:
		if pos >= len(p) {
			return nil, parsing.Malformed("MySQL authentication response length missing")
		}
		pos += 1 + int(p[pos])
	default:
		end := find(p, 0, pos, len(p))
		if end < 0 {
			return nil, parsing.Malformed("MySQL authentication response unterminated")
		}
		pos = end + 1
	}
	if pos > len(p) {
		return nil, parsing.Malformed("MySQL authentication response exceeds the packet")
	}
	if capabilities&0x8 != 0 {
		end := find(p, 0, pos, len(p))
		if end < pos || end-pos > 64 {
			return nil, parsing.Malformed("MySQL database name unterminated or too long")
		}
		pos = end + 1
	}
	plugin, hasPlugin := "", false
	if capabilities&0x80000 != 0 {
		end := find(p, 0, pos, len(p))
		if end < pos || end-pos > 64 {
			return nil, parsing.Malformed("MySQL plugin name unterminated or too long")
		}
		plugin, hasPlugin = string(p[pos:end]), true
		pos = end + 1
	}
	if capabilities&0x100000 != 0 {
		if pos >= len(p) || p[pos] >= 0xfb {
			return nil, parsing.Malformed("MySQL attribute block length outside the one-byte profile")
		}
		total := int(p[pos])
		pos++
		attrsEnd := pos + total
		if attrsEnd > len(p) {
			return nil, parsing.Malformed("MySQL attribute block exceeds the packet")
		}
		count := 0
		for pos < attrsEnd {
			count++
			if count > 32 {
				return nil, parsing.Budget("MySQL connection attribute count exceeds limit")
			}
			if p[pos] >= 0xfb {
				return nil, parsing.Malformed("MySQL attribute length outside the one-byte profile")
			}
			pos += 1 + int(p[pos])
		}
		if pos != attrsEnd {
			return nil, parsing.Malformed("MySQL attribute block length disagrees with its entries")
		}
	}
	if capabilities&0x4000000 != 0 && pos < len(p) {
		pos++
	}
	if pos != len(p) {
		return nil, parsing.Malformed("Trailing bytes after MySQL HandshakeResponse41")
	}
	label := "none"
	if hasPlugin {
		if label = mysqlPlugins[plugin]; label == "" {
			label = "other"
		}
	}
	return &parsing.Result{ProtocolName: "mysql", Scope: "authentication_request",
		Extra: []parsing.Row{row("mysql_auth_plugin", label, "handshake_response", "asserted"),
			row("mysql_client_ssl", "not-requested", "handshake_response", "structural")},
		Reason: "MySQL HandshakeResponse41 validated; user, database and authentication data not emitted"}, nil
}

func mysqlSSLRequest(p []byte) (*parsing.Result, error) {
	capabilities := int(binary.LittleEndian.Uint32(p[:4]))
	if capabilities&0xa00 != 0xa00 {
		return nil, parsing.Malformed("MySQL SSLRequest requires CLIENT_PROTOCOL_41 and CLIENT_SSL")
	}
	if p[8] == 0 {
		return nil, parsing.Malformed("MySQL SSLRequest character set must be nonzero")
	}
	if !allZero(p[9:28]) {
		return nil, parsing.Malformed("MySQL SSLRequest reserved bytes must be zero")
	}
	return &parsing.Result{ProtocolName: "mysql", Scope: "negotiation_request",
		Extra:  []parsing.Row{row("mysql_client_ssl", "requested", "ssl_request", "structural")},
		Reason: "MySQL client SSLRequest validated; TLS follows, authentication unverified",
		Shift:  &parsing.Shift{Boundary: "mysql-sslrequest", Expected: "tls"}}, nil
}

// --- MongoDB OP_MSG with bounded BSON (database.MongoDBParser, bson.py; selected by the mongodb hint) ------

var castagnoli = crc32.MakeTable(crc32.Castagnoli)
var mongoSequenceName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// NewMongoDB creates the parser; the CRC-32C budget is checked from the fixed header.
func NewMongoDB(cfg MongoConfig) *Parser {
	var flags uint32
	var response bool
	return newParser(cfg.MaxBytes, spec{header: 20,
		size: func(h []byte) (int, error) {
			size := int(int32(binary.LittleEndian.Uint32(h[0:4])))
			responseTo := int32(binary.LittleEndian.Uint32(h[8:12]))
			opcode := int32(binary.LittleEndian.Uint32(h[12:16]))
			f := binary.LittleEndian.Uint32(h[16:20])
			if opcode != 2013 {
				return 0, parsing.Unsupported("Only uncompressed MongoDB OP_MSG is supported")
			}
			if size < 26 {
				return 0, parsing.Malformed("MongoDB message shorter than OP_MSG body framing")
			}
			if f&0xfffc != 0 {
				return 0, parsing.Unsupported("Unknown required MongoDB OP_MSG flag")
			}
			if responseTo != 0 && f&0x10000 != 0 {
				return 0, parsing.Malformed("MongoDB reply cannot set exhaustAllowed")
			}
			if f&1 != 0 && size-4 > cfg.MaxCRC32CBytes {
				return 0, parsing.Budget("MongoDB CRC-32C input exceeds checksum budget")
			}
			flags, response = f, responseTo != 0
			return size, nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			limit := len(d)
			if flags&1 != 0 {
				limit -= 4
				if crc32.Checksum(d[:limit], castagnoli) != binary.LittleEndian.Uint32(d[limit:]) {
					return nil, parsing.Malformed("MongoDB CRC-32C mismatch")
				}
			}
			v := newBSON(d, cfg.MaxHeaders, cfg.MaxLine)
			sectionLimit := cfg.MaxHeaders
			if sectionLimit > 128 {
				sectionLimit = 128
			}
			pos, sections := 20, 0
			var body *bsonFields
			sequences := map[string]bool{}
			for pos < limit {
				kind := d[pos]
				pos++
				sections++
				if sections > sectionLimit {
					return nil, parsing.Budget("MongoDB section count exceeds budget")
				}
				switch kind {
				case 0:
					if body != nil {
						return nil, parsing.Malformed("MongoDB OP_MSG requires exactly one body")
					}
					end, fields, err := v.document(pos, limit, 1, false, true)
					if err != nil {
						return nil, err
					}
					pos, body = end, fields
				case 1:
					size, err := bsonI32(d, pos, limit)
					if err != nil {
						return nil, err
					}
					end := pos + size
					if size < 5 || end > limit {
						return nil, parsing.Malformed("Invalid MongoDB document-sequence length")
					}
					name, next, err := v.cstring(pos+4, end)
					if err != nil {
						return nil, err
					}
					if !mongoSequenceName.MatchString(name) {
						return nil, parsing.Unsupported("MongoDB sequence profile supports simple field identifiers only")
					}
					if sequences[name] {
						return nil, parsing.Malformed("Duplicate MongoDB sequence identifier")
					}
					sequences[name] = true
					pos = next
					for pos < end {
						if pos, _, err = v.document(pos, end, 1, false, false); err != nil {
							return nil, err
						}
					}
				default:
					return nil, parsing.Unsupported("MongoDB profile supports body and document-sequence sections only")
				}
			}
			if body == nil {
				return nil, parsing.Malformed("MongoDB OP_MSG has no body section")
			}
			for name := range sequences {
				if _, ok := body.values[name]; ok {
					return nil, parsing.Malformed("MongoDB sequence also exists in body")
				}
			}
			r := &parsing.Result{ProtocolName: "mongodb", Extra: []parsing.Row{row("mongodb_message", "request", "header", "structural")},
				Reason: "MongoDB OP_MSG framing and BSON validated; command semantics, authentication and subsequent messages unverified"}
			if response {
				r.Extra[0].Value = "reply"
				r.Scope = "response_header"
				return r, nil
			}
			first := ""
			if len(body.order) > 0 {
				first = body.order[0]
			}
			db, ok := body.values["$db"]
			if first == "" || first[0] == '$' || !ok {
				return nil, parsing.Malformed("MongoDB request requires a command first and a database field")
			}
			if db.kind != 2 || db.end-db.start <= 5 || bytes.IndexByte(d[db.start+4:db.end-1], 0) >= 0 {
				return nil, parsing.Malformed("MongoDB database must be a nonempty BSON string without NUL")
			}
			return r, nil
		}})
}

// MongoConfig is the subset of the inspection limits the MongoDB profile reads.
type MongoConfig struct{ MaxBytes, MaxHeaders, MaxLine, MaxCRC32CBytes int }

// --- TDS PRELOGIN (enterprise_db.TDSParser) -----------------------------------------------------------

var tdsOptions = map[byte]int{0x00: 6, 0x01: 1, 0x02: -1, 0x03: -1, 0x04: 1, 0x05: 36, 0x06: 1, 0x07: 32}
var tdsEncryption = map[byte]string{0x00: "off", 0x01: "on", 0x02: "not-supported", 0x03: "required"}
var tdsSessionEncryption = map[byte]string{0x00: "login-only", 0x01: "full", 0x02: "none", 0x03: "full"}

// NewTDS creates the PRELOGIN (client 0x12) / tabular response (server 0x04) parser.
func NewTDS(maxBytes int) *Parser {
	return newParser(maxBytes, spec{header: 8,
		size: func(h []byte) (int, error) {
			kind, status := h[0], h[1]
			if kind != 0x12 && kind != 0x04 {
				return 0, parsing.Unsupported("TDS profile covers PRELOGIN packets and their response")
			}
			if status&0x01 == 0 || status&^0x1b != 0 {
				return 0, parsing.Malformed("TDS PRELOGIN must be a single end-of-message packet with known status bits")
			}
			if h[7] != 0 {
				return 0, parsing.Malformed("TDS window byte must be zero")
			}
			if kind == 0x12 && (h[4] != 0 || h[5] != 0) {
				return 0, parsing.Malformed("TDS client packets carry SPID zero")
			}
			size := be(h[2:4])
			if size < 8+5+1+6+1+1 {
				return 0, parsing.Malformed("TDS PRELOGIN shorter than its mandatory options")
			}
			if size > 4096 {
				return 0, parsing.Budget("TDS PRELOGIN exceeds the profile size")
			}
			return size, nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			payload := d[8:]
			type option struct {
				token          byte
				offset, length int
			}
			var options []option
			seen := map[byte]option{}
			pos := 0
			for {
				if pos >= len(payload) {
					return nil, parsing.Malformed("TDS PRELOGIN option list lacks a terminator")
				}
				token := payload[pos]
				if token == 0xff {
					pos++
					break
				}
				if pos+5 > len(payload) {
					return nil, parsing.Malformed("Truncated TDS PRELOGIN option entry")
				}
				_, known := tdsOptions[token]
				if _, repeated := seen[token]; !known || repeated {
					return nil, parsing.Malformed("Unknown or repeated TDS PRELOGIN option")
				}
				o := option{token, be(payload[pos+1 : pos+3]), be(payload[pos+3 : pos+5])}
				seen[token] = o
				options = append(options, o)
				pos += 5
			}
			_, version := seen[0x00]
			encryptionOption, hasEncryption := seen[0x01]
			if !version || !hasEncryption {
				return nil, parsing.Malformed("TDS PRELOGIN requires VERSION and ENCRYPTION options")
			}
			last := 0
			for _, o := range options {
				if o.offset+o.length > last {
					last = o.offset + o.length
				}
			}
			if last != len(payload) {
				return nil, parsing.Malformed("TDS PRELOGIN carries bytes after its last option datum")
			}
			for _, o := range options {
				fixed := tdsOptions[o.token]
				if o.offset < pos || o.offset+o.length > len(payload) {
					return nil, parsing.Malformed("TDS PRELOGIN option data outside the packet")
				}
				if fixed >= 0 && o.length != fixed && !(d[0] == 0x04 && o.token == 0x05 && o.length == 0) {
					return nil, parsing.Malformed("TDS PRELOGIN option length outside its definition")
				}
				if o.token == 0x02 && (o.length < 1 || payload[o.offset+o.length-1] != 0) {
					return nil, parsing.Malformed("TDS INSTOPT must be a terminated string")
				}
				if o.token == 0x03 && o.length != 0 && o.length != 4 {
					return nil, parsing.Malformed("TDS THREADID is four bytes or absent")
				}
			}
			encryption := payload[encryptionOption.offset]
			label, ok := tdsEncryption[encryption]
			if !ok {
				return nil, parsing.Unsupported("TDS ENCRYPTION setting outside the 7.x profile")
			}
			evidence := []parsing.Row{row("tds_encryption", label, "prelogin", "offered")}
			if o, ok := seen[0x04]; ok {
				mars := payload[o.offset]
				if mars > 1 {
					return nil, parsing.Malformed("TDS MARS option must be 0 or 1")
				}
				evidence = append(evidence, row("tds_mars", map[bool]string{true: "on", false: "off"}[mars == 1], "prelogin", "offered"))
			}
			if o, ok := seen[0x06]; ok {
				fedauth := payload[o.offset]
				if fedauth > 1 {
					return nil, parsing.Malformed("TDS FEDAUTHREQUIRED option must be 0 or 1")
				}
				evidence = append(evidence, row("tds_federated_auth", map[bool]string{true: "yes", false: "no"}[fedauth == 1], "prelogin", "offered"))
			}
			r := &parsing.Result{ProtocolName: "tds", Scope: "negotiation_request", Extra: evidence,
				Reason: "TDS PRELOGIN validated; driver version, encryption and instance options are client assertions"}
			if d[0] == 0x04 {
				r.Extra = append(r.Extra, row("tds_session_encryption", tdsSessionEncryption[encryption], "prelogin_response", "asserted"))
				r.Scope = "negotiation_response"
				r.Reason = "TDS PRELOGIN response validated; server version and encryption choice unauthenticated"
			}
			return r, nil
		}})
}

// --- Oracle Net TNS (enterprise_db.TNSParser) ---------------------------------------------------------------

func tnsVersion(v int) bool { return v >= 0x0134 && v < 0x0140 }

func printableDescriptor(b []byte) bool { return len(b) > 0 && b[0] == 0x28 && printable(b) }

// NewTNS creates the CONNECT / ACCEPT / REFUSE / RESEND parser.
func NewTNS(maxBytes int) *Parser {
	minimum := map[byte]int{1: 34, 2: 24, 4: 12, 11: 8}
	return newParser(maxBytes, spec{header: 8,
		size: func(h []byte) (int, error) {
			if h[2] != 0 || h[3] != 0 || h[5] != 0 || h[6] != 0 || h[7] != 0 {
				return 0, parsing.Malformed("TNS header checksums and reserved byte must be zero")
			}
			least, ok := minimum[h[4]]
			if !ok {
				return 0, parsing.Unsupported("TNS profile covers CONNECT, ACCEPT, REFUSE and RESEND packets")
			}
			size := be(h[:2])
			if size < least {
				return 0, parsing.Malformed("TNS packet shorter than its fixed fields")
			}
			if h[4] == 11 && size != 8 {
				return 0, parsing.Malformed("TNS RESEND carries no body")
			}
			if size > 8192 {
				return 0, parsing.Budget("TNS packet exceeds the profile size")
			}
			return size, nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			r := &parsing.Result{ProtocolName: "tns", Scope: "negotiation_response"}
			switch d[4] {
			case 1:
				version := be(d[8:10])
				if !tnsVersion(version) {
					return nil, parsing.Unsupported("TNS CONNECT version outside the supported range")
				}
				if d[10] != 0x01 || d[11] != 0x2c {
					return nil, parsing.Malformed("TNS CONNECT version-compatible field must be 300")
				}
				if !byteOrderMarker(d[22:24]) {
					return nil, parsing.Malformed("TNS CONNECT byte-order marker invalid")
				}
				length, offset := be(d[24:26]), be(d[26:28])
				if offset < 34 || offset > 74 {
					return nil, parsing.Malformed("TNS connect data offset outside the header range")
				}
				if length < 1 {
					return nil, parsing.Malformed("TNS CONNECT requires a connect descriptor")
				}
				inline := "deferred"
				switch {
				case len(d) == offset:
				case len(d) == offset+length:
					inline = "inline"
					if !printableDescriptor(d[offset:]) {
						return nil, parsing.Malformed("TNS connect descriptor must be a printable parenthesised string")
					}
				default:
					return nil, parsing.Malformed("TNS connect data length disagrees with the packet")
				}
				r.Scope = "negotiation_request"
				r.Reason = "TNS CONNECT validated; descriptor contents (service, host, program) not emitted"
				r.Extra = []parsing.Row{row("tns_version", strconv.Itoa(version), "header", "asserted"), row("tns_connect_data", inline, "header", "structural")}
			case 11:
				r.Reason = "TNS RESEND validated; the client repeats its connect packet"
				r.Extra = []parsing.Row{row("tns_response", "resend", "header", "structural")}
			case 4:
				length := be(d[10:12])
				if 12+length != len(d) {
					return nil, parsing.Malformed("TNS REFUSE data length disagrees with the packet")
				}
				if length > 0 && !printableDescriptor(d[12:]) {
					return nil, parsing.Malformed("TNS REFUSE data is not a printable descriptor")
				}
				r.Reason = "TNS REFUSE validated; reason codes and descriptor not emitted"
				r.Extra = []parsing.Row{row("tns_response", "refuse", "header", "structural")}
			default:
				version := be(d[8:10])
				if !tnsVersion(version) {
					return nil, parsing.Unsupported("TNS ACCEPT version outside the supported range")
				}
				if !byteOrderMarker(d[16:18]) {
					return nil, parsing.Malformed("TNS ACCEPT byte-order marker invalid")
				}
				length, offset := be(d[18:20]), be(d[20:22])
				if length > 0 && (offset < 24 || offset+length != len(d)) {
					return nil, parsing.Malformed("TNS ACCEPT data region outside the packet")
				}
				r.Reason = "TNS ACCEPT validated; negotiated sizes and flags unauthenticated"
				r.Extra = []parsing.Row{row("tns_response", "accept", "header", "structural"), row("tns_version", strconv.Itoa(version), "header", "asserted")}
			}
			return r, nil
		}})
}

func byteOrderMarker(b []byte) bool { return (b[0] == 0 && b[1] == 1) || (b[0] == 1 && b[1] == 0) }

// --- Kafka request header and Cassandra CQL v4 (datainfra.py) -----------------------------------------------

var kafkaFirst = map[int]int{18: 4, 3: 12, 0: 10, 1: 16, 17: 1, 36: 2, 32: 4}

func s16(b []byte) int { return int(int16(binary.BigEndian.Uint16(b))) }

func kafkaProbe(p []byte) bool {
	if len(p) < 8 || p[0]&0x80 != 0 {
		return false
	}
	key, version := s16(p[4:6]), s16(p[6:8])
	highest, ok := kafkaFirst[key]
	return ok && version >= 0 && version <= highest && be(p[:4]) >= 10
}

// NewKafka creates the request-header parser.
func NewKafka(maxBytes int) *Parser {
	return newParser(maxBytes, spec{header: 10,
		size: func(h []byte) (int, error) {
			if !kafkaProbe(h) {
				return 0, parsing.Malformed("Kafka request header outside first-request profile")
			}
			size := be(h[:4])
			if size > 65536 {
				return 0, parsing.Budget("Kafka request exceeds profile size")
			}
			return 4 + size, nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			key, version := s16(d[4:6]), s16(d[6:8])
			clientLength := s16(d[12:14])
			pos := 14
			if clientLength < -1 || clientLength > 256 {
				return nil, parsing.Malformed("Kafka client id length outside profile")
			}
			if clientLength > 0 {
				if pos+clientLength > len(d) || !printableASCII(d[pos:pos+clientLength], 32) {
					return nil, parsing.Malformed("Kafka client id must be printable ASCII")
				}
				pos += clientLength
			}
			if key == 18 && version >= 3 {
				if pos >= len(d) || d[pos] != 0 {
					return nil, parsing.Malformed("Kafka ApiVersions v3 requires empty header tagged fields")
				}
				pos++
				nameLength := -1
				if pos < len(d) {
					nameLength = int(d[pos]) - 1
				}
				if nameLength < 1 || pos+1+nameLength > len(d) {
					return nil, parsing.Malformed("Kafka ApiVersions client software name invalid")
				}
			}
			return &parsing.Result{ProtocolName: "kafka", Scope: "request_header", Extra: []parsing.Row{row("kafka_api_key", strconv.Itoa(key), "request_header", "structural")},
				Reason: "Kafka request header validated; topics, records and authentication not decoded"}, nil
		}})
}

// printableASCII reports bytes within low..126.
func printableASCII(b []byte, low byte) bool {
	for _, c := range b {
		if c < low || c > 126 {
			return false
		}
	}
	return true
}

var cqlResponses = map[byte]string{0x00: "error", 0x02: "ready", 0x03: "authenticate", 0x06: "supported"}
var cqlResponseMinimum = map[byte]int{0x00: 6, 0x02: 0, 0x03: 2, 0x06: 2}

func cqlString(body []byte, pos int) (int, error) {
	if pos+2 > len(body) {
		return 0, parsing.Malformed("Truncated CQL string")
	}
	size := be(body[pos : pos+2])
	if pos+2+size > len(body) || !printableASCII(body[pos+2:pos+2+size], 32) {
		return 0, parsing.Malformed("CQL string outside printable ASCII or the frame")
	}
	return pos + 2 + size, nil
}

// NewCQL creates the Cassandra native protocol v4 parser (STARTUP/OPTIONS requests and four responses).
func NewCQL(maxBytes int) *Parser {
	return newParser(maxBytes, spec{header: 9,
		size: func(h []byte) (int, error) {
			if h[0] != 0x04 && h[0] != 0x84 {
				return 0, parsing.Unsupported("CQL profile covers protocol version 4 requests and responses")
			}
			if h[1]&0xf0 != 0 {
				return 0, parsing.Malformed("CQL flags reserved bits set")
			}
			size := be(h[5:9])
			if h[0] == 0x84 {
				minimum, ok := cqlResponseMinimum[h[4]]
				if !ok {
					return 0, parsing.Unsupported("CQL response profile covers ERROR, READY, AUTHENTICATE and SUPPORTED")
				}
				if size < minimum || size > 4096 || (h[4] == 0x02 && size != 0) {
					return 0, parsing.Malformed("CQL response body length outside profile")
				}
				return 9 + size, nil
			}
			if h[4] != 0x01 && h[4] != 0x05 {
				return 0, parsing.Unsupported("CQL profile covers STARTUP and OPTIONS requests")
			}
			if h[4] == 0x05 && size != 0 {
				return 0, parsing.Malformed("CQL OPTIONS carries no body")
			}
			if h[4] == 0x01 && (size < 2 || size > 4096) {
				return 0, parsing.Malformed("CQL STARTUP body length outside profile")
			}
			return 9 + size, nil
		},
		validate: func(d []byte) (*parsing.Result, error) {
			if d[0] == 0x84 {
				return cqlResponse(d)
			}
			if d[4] == 0x01 {
				count := be(d[9:11])
				if count < 1 || count > 16 {
					return nil, parsing.Malformed("CQL STARTUP string map count outside profile")
				}
				pos := 11
				keys := map[string]bool{}
				for i := 0; i < count; i++ {
					for j := 0; j < 2; j++ {
						if pos+2 > len(d) {
							return nil, parsing.Malformed("Truncated CQL string map")
						}
						size := be(d[pos : pos+2])
						if pos+2+size > len(d) || !printableASCII(d[pos+2:pos+2+size], 32) {
							return nil, parsing.Malformed("CQL string map entry outside printable ASCII")
						}
						if len(keys) < 32 {
							keys[string(bytes.ToUpper(d[pos+2:pos+2+size]))] = true
						}
						pos += 2 + size
					}
				}
				if pos != len(d) {
					return nil, parsing.Malformed("Trailing bytes after CQL STARTUP map")
				}
				if !keys["CQL_VERSION"] {
					return nil, parsing.Malformed("CQL STARTUP requires CQL_VERSION")
				}
			}
			return &parsing.Result{ProtocolName: "cql/4", Scope: "protocol_header",
				Reason: "Cassandra native protocol v4 request validated; authentication and queries unverified"}, nil
		}})
}

func cqlResponse(d []byte) (*parsing.Result, error) {
	opcode, body := d[4], d[9:]
	switch opcode {
	case 0x00:
		if _, err := cqlString(body, 4); err != nil {
			return nil, err
		}
	case 0x03:
		end, err := cqlString(body, 0)
		if err != nil {
			return nil, err
		}
		if end != len(body) {
			return nil, parsing.Malformed("CQL AUTHENTICATE carries one authenticator class string")
		}
	case 0x06:
		count := be(body[:2])
		if count < 1 || count > 16 {
			return nil, parsing.Malformed("CQL SUPPORTED multimap count outside profile")
		}
		pos := 2
		var err error
		for i := 0; i < count; i++ {
			if pos, err = cqlString(body, pos); err != nil {
				return nil, err
			}
			if pos+2 > len(body) {
				return nil, parsing.Malformed("Truncated CQL SUPPORTED multimap")
			}
			values := be(body[pos : pos+2])
			pos += 2
			if values > 64 {
				return nil, parsing.Budget("CQL SUPPORTED value count exceeds limit")
			}
			for k := 0; k < values; k++ {
				if pos, err = cqlString(body, pos); err != nil {
					return nil, err
				}
			}
		}
		if pos != len(body) {
			return nil, parsing.Malformed("Trailing bytes after CQL SUPPORTED multimap")
		}
	}
	return &parsing.Result{ProtocolName: "cql/4", Scope: "negotiation_response", Extra: []parsing.Row{row("cql_response", cqlResponses[opcode], "response", "structural")},
		Reason: "Cassandra native protocol v4 response validated; error text and option values not emitted"}, nil
}
