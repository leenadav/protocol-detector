package engine

import (
	"bytes"
	"encoding/binary"

	"github.com/leenadav/protocol-detector/go/internal/protocols/dnsx"
)

// Lookahead is the routing prefix length (dispatch.LOOKAHEAD).
const Lookahead = 24

// Decision of Select: a family name, Unknown, or Wait for more bytes.
const (
	Unknown = "unknown"
	Wait    = ""
)

var firstByte = func() [256]string {
	var table [256]string
	for i := range table {
		table[i] = Unknown
	}
	for _, b := range []byte("!#$%&'*+.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-") {
		table[b] = "text"
	}
	for b, family := range map[byte]string{64: "rsync", 3: "tpkt", 22: "tls", 5: "socks5", 16: "mqtt", 19: "bittorrent",
		0xc0: "tacacs-plus", 0xc1: "tacacs-plus", 0x12: "tds", 0x84: "cql", 58: "irc"} {
		table[b] = family
	}
	for _, b := range []byte{0, 1, 48, 82, 80, 65, 42, 67, 83, 255, 4, 0x63, 0x64, 0x65, 0x66, 0x6f, 0x70, 0x68, 69, 118, 0x81, 0x80, 0x60, 0x3c, 66, 108, 70} {
		table[b] = "ambiguous"
	}
	return table
}()

var (
	opcuaMagics  = [][]byte{[]byte("HELF"), []byte("ACKF"), []byte("ERRF"), []byte("RHEF")}
	stompStarts  = [][]byte{[]byte("CONNECT\n"), []byte("CONNECT\r\n"), []byte("CONNECTED\n"), []byte("CONNECTED\r\n"), []byte("STOMP\n"), []byte("STOMP\r\n")}
	h2Preface    = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	boltMagic    = []byte{0x60, 0x60, 0xb0, 0x17}
	kafkaFirst   = map[int16]int16{18: 4, 3: 12, 0: 10, 1: 16, 17: 1, 36: 2, 32: 4}
	opcuaMaxSize = 8 + 4 + 4096 + 4 + 4096
)

func isGitHex(b byte) bool { return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') }

func allGitHex(p []byte) bool {
	for _, b := range p {
		if !isGitHex(b) {
			return false
		}
	}
	return true
}

func opcuaProbe(p []byte) bool {
	if len(p) < 8 || p[6] != 0 || p[7] != 0 {
		return false
	}
	ok := false
	for _, m := range opcuaMagics {
		if bytes.Equal(p[:4], m) {
			ok = true
		}
	}
	size := int(binary.LittleEndian.Uint32(p[4:8]))
	return ok && size >= 8 && size <= opcuaMaxSize
}

func enipProbe(p []byte) bool {
	if len(p) < 8 || p[1] != 0 || p[3] != 0 {
		return false
	}
	switch p[0] {
	case 0x04, 0x63, 0x64, 0x65, 0x66, 0x6f, 0x70:
		return true
	}
	return false
}

func modbusProbe(p []byte) bool {
	if len(p) < 8 || p[2] != 0 || p[3] != 0 {
		return false
	}
	length := int(binary.BigEndian.Uint16(p[4:6]))
	code := p[7] & 0x7f
	return length >= 2 && length <= 254 && code >= 1 && code <= 127
}

func kafkaProbe(p []byte) bool {
	if len(p) < 8 || p[0]&0x80 != 0 {
		return false
	}
	key, version := int16(binary.BigEndian.Uint16(p[4:6])), int16(binary.BigEndian.Uint16(p[6:8]))
	max, ok := kafkaFirst[key]
	return ok && version >= 0 && version <= max && binary.BigEndian.Uint32(p[:4]) >= 10
}

func tnsProbe(p []byte) bool {
	if len(p) < 8 || p[2] != 0 || p[3] != 0 || p[5] != 0 || p[6] != 0 || p[7] != 0 {
		return false
	}
	kind := p[4]
	length := int(binary.BigEndian.Uint16(p[:2]))
	if kind == 11 { // RESEND
		return length == 8
	}
	if len(p) < 10 {
		return false
	}
	switch kind {
	case 1, 2: // CONNECT, ACCEPT
		min := 24
		if kind == 1 {
			min = 34
		}
		v := int(binary.BigEndian.Uint16(p[8:10]))
		return length >= min && v >= 0x0134 && v < 0x0140
	case 4: // REFUSE
		return length >= 12 && p[8] <= 0x7f && p[9] <= 0x7f
	}
	return false
}

func kerberosLength(p []byte) bool {
	size := int(binary.BigEndian.Uint32(p[:4]))
	first := int(p[5])
	if first < 128 {
		return size == 2+first
	}
	width := first & 127
	if width < 1 || width > 3 || 6+width > len(p) {
		return false
	}
	n := 0
	for _, b := range p[6 : 6+width] {
		n = n<<8 | int(b)
	}
	return size == 2+width+n
}

func startsWithAny(p []byte, starts [][]byte) (matched, waiting bool) {
	for _, s := range starts {
		if bytes.HasPrefix(p, s) {
			return true, false
		}
		if bytes.HasPrefix(s, p) {
			waiting = true
		}
	}
	return false, waiting
}

// Select returns a family, Unknown, or Wait; prefix holds 1..Lookahead bytes (dispatch.select).
func Select(prefix []byte) string {
	first := prefix[0]
	n := len(prefix)
	if first == 82 || first == 69 || first == 118 {
		if n < 3 {
			if n == 1 || prefix[1] == 0 {
				return Wait
			}
		} else if prefix[1] == 0 && prefix[2] == 0 {
			return "postgresql"
		}
	}
	if first == 72 || first == 65 || first == 69 || first == 82 {
		if n < 8 {
			head := prefix
			if len(head) > 4 {
				head = head[:4]
			}
			for _, m := range opcuaMagics {
				if bytes.HasPrefix(m, head) {
					return Wait
				}
			}
		} else if opcuaProbe(prefix) {
			return "opcua"
		}
	}
	if first == 71 {
		magic := []byte("GIOP")
		if n <= 4 && bytes.HasPrefix(magic, prefix) {
			return Wait
		}
		if n > 4 && bytes.Equal(prefix[:4], magic) && prefix[4] == 1 {
			return "giop"
		}
	}
	if isGitHex(first) && allGitHex(prefix[:minInt(4, n)]) {
		if n < 4 {
			return Wait
		}
		disc := prefix[4:minInt(8, n)]
		if bytes.HasPrefix([]byte("git-"), disc) {
			if len(disc) == 4 {
				return "git_text"
			}
			return Wait
		}
		if allGitHex(prefix[4:minInt(n, 24)]) {
			if n >= 24 {
				return "git"
			}
			return Wait
		}
		if bytes.HasPrefix([]byte("version 2\n"), prefix[4:minInt(14, n)]) {
			if n >= 14 {
				return "git"
			}
			return Wait
		}
	}
	if first == 5 {
		if n < 2 {
			return Wait
		}
		if prefix[1] == 0x64 {
			return "dnp3"
		}
		if prefix[1] == 0 {
			if n < 6 {
				return Wait
			}
			if prefix[2] == 5 && prefix[3] <= 8 && prefix[4] == 0 && (prefix[5] == 1 || prefix[5] == 3 || prefix[5] == 4) {
				return "socks5"
			}
			return "dcerpc"
		}
		return "socks5"
	}
	if first >= 0x31 && first <= 0x39 {
		digits := 0
		for digits < minInt(n, 5) && prefix[digits] >= 0x30 && prefix[digits] <= 0x39 {
			digits++
		}
		if digits == n || (digits < n && prefix[digits] == 0x20 && digits+1 == n) {
			return Wait
		}
		if digits < n-1 && prefix[digits] == 0x20 && prefix[digits+1] == 0x3c {
			return "syslog"
		}
	}
	family := firstByte[first]
	if family != "ambiguous" {
		return family
	}
	if first == 69 || first == 118 {
		return "text"
	}
	if first == 0x81 {
		if n < 4 {
			return Wait
		}
		if bytes.Equal(prefix[1:4], []byte{0, 0, 0x44}) {
			return "netbios-ss"
		}
		return "memcached"
	}
	if first == 255 {
		if n < 2 {
			return Wait
		}
		if prefix[1] == 255 {
			return "bgp"
		}
		if prefix[1] >= 0xf1 && prefix[1] <= 0xfe {
			return "telnet"
		}
		if prefix[1] != 0 {
			return Unknown
		}
		if n < 11 {
			return Wait
		}
		if prefix[9] == 0x7f && prefix[10] == 3 {
			return "zmtp"
		}
		return Unknown
	}
	if first == 0x80 {
		if n < 2 {
			return Wait
		}
		if prefix[1] != 0 {
			return "memcached"
		}
		if n < 16 {
			return Wait
		}
		if bytes.Equal(prefix[8:16], []byte{0, 0, 0, 0, 0, 0, 0, 2}) {
			return "onc-rpc"
		}
		if bytes.Equal(prefix[8:12], []byte{0, 0, 0, 1}) && (bytes.Equal(prefix[12:16], []byte{0, 0, 0, 0}) || bytes.Equal(prefix[12:16], []byte{0, 0, 0, 1})) && binary.BigEndian.Uint16(prefix[2:4]) >= 20 {
			return "onc-rpc"
		}
		return "memcached"
	}
	if first == 66 || first == 108 {
		if n < 2 {
			return Wait
		}
		if prefix[1] != 0 {
			return "text"
		}
		if n < 6 {
			return Wait
		}
		var want []byte
		if first == 66 {
			want = []byte{0, 0x0b}
		} else {
			want = []byte{0x0b, 0}
		}
		if bytes.Equal(prefix[2:4], want) && prefix[4] == 0 && prefix[5] == 0 {
			return "x11"
		}
		return Unknown
	}
	if first == 70 {
		fins := []byte("FINS\x00")
		if n < 5 {
			if bytes.HasPrefix(fins, prefix) {
				return Wait
			}
			return "text"
		}
		if bytes.Equal(prefix[:5], fins) {
			return "fins"
		}
		return "text"
	}
	if first == 0x3c {
		if n < 2 {
			return Wait
		}
		if prefix[1] >= 0x30 && prefix[1] <= 0x39 {
			return "syslog"
		}
		for _, start := range [][]byte{[]byte("<?xml"), []byte("<stream:stream")} {
			if bytes.HasPrefix(prefix, start) {
				return "xmpp"
			}
			if bytes.HasPrefix(start, prefix) {
				return Wait
			}
		}
		return Unknown
	}
	if first == 0x60 {
		if n < 4 {
			if bytes.HasPrefix(boltMagic, prefix) {
				return Wait
			}
			return "text"
		}
		if bytes.Equal(prefix[:4], boltMagic) {
			return "bolt"
		}
		return "text"
	}
	if first == 4 {
		if n < 5 {
			return Wait
		}
		if prefix[1] == 0 && prefix[4] == 0 {
			return "ethernet-ip"
		}
		if prefix[1]&1 != 0 {
			if n < 9 {
				return Wait
			}
			if prefix[7] == 0 && prefix[8] == 0 {
				return "tds"
			}
		}
		return "cql"
	}
	switch first {
	case 0x63, 0x64, 0x65, 0x66, 0x6f, 0x70:
		if n < 2 {
			return Wait
		}
		if prefix[1] != 0 {
			return "text"
		}
		if n < 8 {
			return Wait
		}
		if enipProbe(prefix) {
			return "ethernet-ip"
		}
		return Unknown
	}
	if first == 0x68 {
		if n < 2 {
			return Wait
		}
		if prefix[1] != 4 {
			return "text"
		}
		if n >= 6 && prefix[2]&3 == 3 && prefix[3] == 0 && prefix[4] == 0 && prefix[5] == 0 {
			return "iec-104"
		}
		if n >= 6 {
			return "text"
		}
		return Wait
	}
	if first == 67 || first == 83 {
		second := byte(79)
		if first == 83 {
			second = 84
		}
		if n > 1 && prefix[1] != second {
			return "text"
		}
		matched, waiting := startsWithAny(prefix, stompStarts)
		if matched {
			return "stomp"
		}
		if waiting {
			return Wait
		}
		return "text"
	}
	if first == 0 || first == 1 {
		if n < 8 {
			return Wait
		}
		if first == 1 && prefix[4]&0x0f == 0 && bytes.Equal(prefix[5:8], []byte{0, 1, 1}) {
			if n < 12 {
				return Wait
			}
			if bytes.Equal(prefix[8:12], []byte{0, 0, 0, 0}) {
				return "diameter"
			}
		}
		if first == 1 && prefix[1] == 1 && !(prefix[2] == 0 && prefix[3] == 0) && prefix[4] == 0 && prefix[5] == 8 && prefix[7] == 0 {
			return "fastcgi"
		}
		if first == 1 && (prefix[1] == 3 || prefix[1] == 6 || prefix[1] == 7) && !(prefix[2] == 0 && prefix[3] == 0) && prefix[7] == 0 && (prefix[1] != 3 || (prefix[4] == 0 && prefix[5] == 8)) {
			return "fastcgi"
		}
		if first == 1 && prefix[1] == 0 && prefix[2] == 0 {
			if n < 11 {
				return Wait
			}
			if bytes.Equal(prefix[7:11], []byte{0, 0x0a, 0, 0x0a}) {
				return "amqp"
			}
		}
		if first == 0 && bytes.Equal(prefix[4:8], []byte("\xfeSMB")) {
			return "smb2"
		}
		if first == 0 && bytes.Equal(prefix[4:8], []byte("\xffSMB")) {
			return "smb1"
		}
		if first == 0 && bytes.Equal(prefix[4:8], []byte{0x1a, 0x2b, 0x3c, 0x4d}) {
			return "pptp"
		}
		if bytes.Equal(prefix[4:8], []byte{0x21, 0x12, 0xa4, 0x42}) {
			return "stun"
		}
		if first == 0 && (prefix[4] == 0x6a || prefix[4] == 0x6b || prefix[4] == 0x6c || prefix[4] == 0x6d || prefix[4] == 0x7e) && kerberosLength(prefix) {
			return "kerberos"
		}
		if prefix[2] == 0 && prefix[3] == 0 && (prefix[4] == 1 || prefix[4] == 2 || prefix[4] == 4 || prefix[4] == 11) && prefix[5] == 0 && prefix[6] == 0 && prefix[7] == 0 {
			if prefix[4] != 11 && n < 10 {
				return Wait
			}
			if tnsProbe(prefix) {
				return "tns"
			}
		}
		if modbusProbe(prefix) {
			return "modbus"
		}
		code := binary.BigEndian.Uint32(prefix[4:8])
		if first == 0 && (code == 80877103 || code == 80877104 || (code>>16 == 3 && code&65535 <= 2)) {
			return "postgresql"
		}
		if (prefix[1] == 3 || prefix[1] == 4) && (bytes.Equal(prefix[4:8], []byte{0, 0, 0, 0}) || (first == 1 && prefix[4] == 0xff)) {
			if n < 16 {
				return Wait
			}
			if bytes.Equal(prefix[12:16], []byte{0, 0, 0, 0}) && binary.BigEndian.Uint32(prefix[8:12]) <= 4096 {
				return "afp"
			}
		}
		if first == 0 && kafkaProbe(prefix) {
			return "kafka"
		}
		if binary.BigEndian.Uint16(prefix[:2]) < 12 {
			return Unknown
		}
		if n < 14 {
			return Wait
		}
		if dnsx.Probe(prefix[2:14]) {
			return "dns"
		}
		length := int(binary.BigEndian.Uint16(prefix[:2]))
		if (prefix[2] == 0x38 || prefix[2] == 0x40 || prefix[2] == 0x50) && length >= 14 && length <= 1500 && !bytes.Equal(prefix[3:11], make([]byte, 8)) {
			return "openvpn"
		}
		return Unknown
	}
	if first == 48 {
		if n < 2 {
			return Wait
		}
		width := 0
		if prefix[1] >= 128 {
			width = int(prefix[1] & 127)
		}
		if width > 4 || prefix[1] == 128 {
			return "text"
		}
		offset := 2 + width
		if n <= offset {
			return Wait
		}
		if prefix[offset] == 2 {
			return "ldap"
		}
	}
	if first == 82 {
		if bytes.HasPrefix(prefix, []byte("REDQ")) {
			return "spice"
		}
		if n < 4 && bytes.HasPrefix([]byte("REDQ"), prefix) {
			return Wait
		}
		for _, v := range [][]byte{[]byte("RFB 003.003\n"), []byte("RFB 003.007\n"), []byte("RFB 003.008\n")} {
			if bytes.HasPrefix(prefix, v) {
				return "rfb"
			}
			if bytes.HasPrefix(v, prefix) {
				return Wait
			}
		}
	}
	if first == 80 {
		if bytes.HasPrefix(h2Preface, prefix) {
			if n == len(h2Preface) {
				return "http2"
			}
			return Wait
		}
	} else if first == 65 {
		magic := []byte("AMQP\x00")
		if bytes.HasPrefix(prefix, magic) {
			return "amqp"
		}
		if bytes.HasPrefix(magic, prefix) {
			return Wait
		}
	} else if first == 42 {
		end := bytes.Index(prefix, []byte("\r\n"))
		if end >= 0 && isDigits(prefix[1:end]) {
			return "resp"
		}
		digits := prefix[1:]
		if bytes.HasSuffix(digits, []byte("\r")) {
			digits = digits[:len(digits)-1]
		}
		if (len(digits) == 0 || isDigits(digits)) && n < Lookahead {
			return Wait
		}
	}
	return "text"
}

// isDigits mirrors bytes.isdigit(): non-empty and all ASCII digits.
func isDigits(p []byte) bool {
	if len(p) == 0 {
		return false
	}
	for _, b := range p {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
