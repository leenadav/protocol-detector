package framed

import (
	"bytes"
	"hash/crc32"
	"strconv"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

func init() {
	for name, v := range map[string]DatagramValidator{"netflow": netflowDatagram, "sflow": sflowDatagram, "stun": stunDatagram,
		"dhcp": dhcpDatagram, "radius": radiusDatagram} {
		DatagramValidators[name] = v
	}
}

func min128(n int) int {
	if n > 128 {
		return 128
	}
	return n
}

// --- NetFlow v5/v9 and IPFIX, sFlow v5 (telemetry.py) -------------------------------------------------------

func netflowDatagram(data []byte, limits Limits) (*Datagram, error) {
	if len(data) < 16 {
		return nil, parsing.Malformed("Flow export header too short")
	}
	budget := min128(limits.MaxHeaders)
	switch version := be(data[:2]); version {
	case 5:
		count := be(data[2:4])
		if count < 1 || count > 30 {
			return nil, parsing.Malformed("NetFlow v5 count outside 1..30")
		}
		if len(data) != 24+48*count {
			return nil, parsing.Malformed("NetFlow v5 datagram length disagrees with record count")
		}
		for i := 0; i < count; i++ {
			record := data[24+48*i : 72+48*i]
			if be(record[16:20]) == 0 || be(record[20:24]) == 0 {
				return nil, parsing.Malformed("NetFlow v5 record requires nonzero packet and byte counters")
			}
			if record[36] != 0 || record[46] != 0 || record[47] != 0 {
				return nil, parsing.Malformed("NetFlow v5 record padding must be zero")
			}
		}
		return &Datagram{Protocol: "netflow/5", Simple: true,
			Reason: "NetFlow v5 header and " + strconv.Itoa(count) + " records framed; counters and addresses are not emitted"}, nil
	case 9:
		count := be(data[2:4])
		if count < 1 || count > budget {
			return nil, parsing.Budget("NetFlow v9 record count outside budget")
		}
		if len(data) < 20 {
			return nil, parsing.Malformed("NetFlow v9 header too short")
		}
		pos, flowsets := 20, 0
		for pos < len(data) {
			flowsets++
			if flowsets > budget {
				return nil, parsing.Budget("NetFlow v9 flowset count exceeds budget")
			}
			if pos+4 > len(data) {
				return nil, parsing.Malformed("Truncated NetFlow v9 flowset header")
			}
			identifier, length := be(data[pos:pos+2]), be(data[pos+2:pos+4])
			if length < 4 || pos+length > len(data) || length%4 != 0 {
				return nil, parsing.Malformed("NetFlow v9 flowset length invalid")
			}
			if identifier > 1 && identifier < 256 {
				return nil, parsing.Malformed("NetFlow v9 flowset id reserved")
			}
			if identifier == 0 && length < 8 {
				return nil, parsing.Malformed("NetFlow v9 template flowset too short")
			}
			pos += length
		}
		if flowsets == 0 {
			return nil, parsing.Malformed("NetFlow v9 header without flowsets")
		}
		return &Datagram{Protocol: "netflow/9", Simple: true,
			Reason: "NetFlow v9 header and " + strconv.Itoa(flowsets) + " flowsets framed; templates and records are not decoded"}, nil
	case 10:
		length := be(data[2:4])
		if length != len(data) || length < 20 {
			return nil, parsing.Malformed("IPFIX message length disagrees with datagram")
		}
		pos, sets := 16, 0
		for pos < length {
			sets++
			if sets > budget {
				return nil, parsing.Budget("IPFIX set count exceeds budget")
			}
			if pos+4 > length {
				return nil, parsing.Malformed("Truncated IPFIX set header")
			}
			identifier, size := be(data[pos:pos+2]), be(data[pos+2:pos+4])
			if size < 4 || pos+size > length || identifier == 0 || identifier == 1 || (identifier > 3 && identifier < 256) {
				return nil, parsing.Malformed("IPFIX set id or length invalid")
			}
			pos += size
		}
		if sets == 0 {
			return nil, parsing.Malformed("IPFIX message without sets")
		}
		return &Datagram{Protocol: "ipfix", Simple: true,
			Reason: "IPFIX message header and " + strconv.Itoa(sets) + " sets framed; templates and records are not decoded"}, nil
	}
	return nil, parsing.Unsupported("Flow export version outside NetFlow v5/v9 and IPFIX")
}

func sflowDatagram(data []byte, limits Limits) (*Datagram, error) {
	if len(data) < 28 || !bytes.Equal(data[:4], []byte{0, 0, 0, 5}) {
		return nil, parsing.Unsupported("Outside sFlow v5 datagram header")
	}
	if be(data[4:8]) != 1 {
		return nil, parsing.Unsupported("sFlow profile covers IPv4 agent addresses")
	}
	budget := limits.MaxHeaders
	if budget > 64 {
		budget = 64
	}
	samples := be(data[24:28])
	if samples < 1 || samples > budget {
		return nil, parsing.Budget("sFlow sample count outside budget")
	}
	pos := 28
	for i := 0; i < samples; i++ {
		if pos+8 > len(data) {
			return nil, parsing.Malformed("Truncated sFlow sample header")
		}
		kind, length := be(data[pos:pos+4]), be(data[pos+4:pos+8])
		if length < 8 || pos+8+length > len(data) || length%4 != 0 {
			return nil, parsing.Malformed("sFlow sample length invalid")
		}
		if t := kind & 0xfff; t < 1 || t > 4 {
			return nil, parsing.Unsupported("sFlow sample type outside flow/counter samples")
		}
		pos += 8 + length
	}
	if pos != len(data) {
		return nil, parsing.Malformed("Trailing bytes after sFlow samples")
	}
	return &Datagram{Protocol: "sflow/5", Simple: true,
		Reason: "sFlow v5 datagram and " + strconv.Itoa(samples) + " sample headers framed; sample contents are not decoded"}, nil
}

// --- STUN/TURN (wire.stun) ----------------------------------------------------------------------------------------

var stunMethods = map[int]string{1: "binding", 3: "allocate", 4: "refresh", 6: "send", 7: "data", 8: "create-permission", 9: "channel-bind",
	10: "connect", 11: "connection-bind", 12: "connection-attempt"}
var stunClasses = []string{"request", "indication", "success-response", "error-response"}
var stunAddress = map[int]bool{0x0001: true, 0x0020: true, 0x0012: true, 0x0016: true, 0x8020: true}
var stunFixed = map[int]int{0x0019: 4, 0x000d: 4, 0x000c: 4, 0x0018: 1, 0x0022: 8}
var stunText = map[int]int{0x0006: 513, 0x0014: 763, 0x0015: 763, 0x8022: 763}

func stunDatagram(data []byte, _ Limits) (*Datagram, error) {
	if len(data) < 20 || data[0]&0xc0 != 0 || !bytes.Equal(data[4:8], []byte{0x21, 0x12, 0xa4, 0x42}) {
		return nil, parsing.Malformed("Invalid STUN header")
	}
	length, kind := be(data[2:4]), be(data[:2])
	method := kind&15 | (kind>>1)&0x70 | (kind>>2)&0xf80
	class := (kind>>7)&2 | (kind>>4)&1
	name, ok := stunMethods[method]
	if !ok {
		return nil, parsing.Unsupported("STUN method outside Binding and the TURN methods")
	}
	indicationOnly := method == 6 || method == 7 || method == 12
	if indicationOnly != (class == 1) && method != 1 {
		return nil, parsing.Malformed("STUN class inconsistent with its method (Send/Data/ConnectionAttempt are indications only)")
	}
	if length%4 != 0 || length+20 != len(data) {
		return nil, parsing.Malformed("Invalid STUN message length")
	}
	pos, count := 20, 0
	for pos < len(data) {
		count++
		if count > 128 {
			return nil, parsing.Budget("STUN attribute count exceeds inspection limit")
		}
		if pos+4 > len(data) {
			return nil, parsing.Malformed("Truncated STUN attribute")
		}
		tag, size := be(data[pos:pos+2]), be(data[pos+2:pos+4])
		end := pos + 4 + size
		padded := pos + 4 + (size+3)&^3
		if padded > len(data) {
			return nil, parsing.Malformed("STUN attribute exceeds message")
		}
		value := data[pos+4 : end]
		switch {
		case stunAddress[tag]:
			if (size != 8 && size != 20) || value[0] != 0 || !((value[1] == 1 && size == 8) || (value[1] == 2 && size == 20)) {
				return nil, parsing.Malformed("Invalid STUN address attribute")
			}
		case stunFixed[tag] != 0:
			if size != stunFixed[tag] {
				return nil, parsing.Malformed("TURN attribute size outside the specification")
			}
			if tag == 0x0019 && ((value[0] != 6 && value[0] != 17) || !allZero(value[1:])) {
				return nil, parsing.Malformed("TURN REQUESTED-TRANSPORT must name UDP or TCP with zero reserved bytes")
			}
			if tag == 0x000c && (value[0]&0xc0 != 0x40 || !allZero(value[2:])) {
				return nil, parsing.Malformed("TURN CHANNEL-NUMBER outside 0x4000..0x7FFF")
			}
			if tag == 0x0018 && value[0]&0x7f != 0 {
				return nil, parsing.Malformed("TURN EVEN-PORT reserved bits set")
			}
		case stunText[tag] != 0:
			if size > stunText[tag] {
				return nil, parsing.Malformed("STUN text attribute exceeds its specified length")
			}
		case tag == 0x0009:
			if size < 4 || size > 4+763 || value[0] != 0 || value[1] != 0 || value[2] < 3 || value[2] > 6 || value[3] > 99 {
				return nil, parsing.Malformed("Invalid STUN ERROR-CODE attribute")
			}
		}
		if tag == 0x0008 && size != 20 {
			return nil, parsing.Malformed("Invalid STUN MESSAGE-INTEGRITY size")
		}
		if tag == 0x001c && (size < 16 || size > 32 || size%4 != 0) {
			return nil, parsing.Malformed("Invalid STUN SHA256 integrity size")
		}
		if tag == 0x8028 {
			if size != 4 || padded != len(data) {
				return nil, parsing.Malformed("STUN FINGERPRINT must be the last four-byte attribute")
			}
			if uint32(be(value)) != crc32.ChecksumIEEE(data[:pos])^0x5354554e {
				return nil, parsing.Malformed("STUN FINGERPRINT mismatch")
			}
		}
		pos = padded
	}
	reason := "TURN " + name + " framing validated; relayed addresses, credentials, realm and nonce not emitted, HMAC unverified"
	if method == 1 {
		reason = "STUN Binding framing validated; optional fingerprint checked, HMAC and peer identity unverified"
	}
	return &Datagram{Protocol: "stun", Reason: reason, Evidence: []parsing.Row{row("application_protocol", "stun", "wire", "structural"),
		row("stun_method", name, "wire", "structural"), row("stun_class", stunClasses[class], "wire", "structural")}}, nil
}

// --- DHCPv4 (wire.dhcp) -------------------------------------------------------------------------------------------

var dhcpMessages = map[byte]string{1: "discover", 2: "offer", 3: "request", 4: "decline", 5: "ack", 6: "nak", 7: "release", 8: "inform"}

func dhcpDatagram(data []byte, _ Limits) (*Datagram, error) {
	if len(data) < 241 || !bytes.Equal(data[236:240], []byte{0x63, 0x82, 0x53, 0x63}) {
		return nil, parsing.Malformed("Invalid DHCPv4 fixed header/cookie")
	}
	if (data[0] != 1 && data[0] != 2) || data[2] < 1 || data[2] > 16 || data[1] == 0 {
		return nil, parsing.Malformed("Invalid DHCPv4 operation or hardware address length")
	}
	if be(data[10:12])&0x7fff != 0 {
		return nil, parsing.Malformed("Reserved DHCPv4 flags set")
	}
	pos, count := 240, 0
	var messageType byte
	for pos < len(data) {
		code := data[pos]
		pos++
		if code == 0 {
			continue
		}
		if code == 255 {
			if messageType == 0 || !allZero(data[pos:]) {
				return nil, parsing.Malformed("Missing DHCP message type or non-padding after END")
			}
			expected := byte(2)
			switch messageType {
			case 1, 3, 4, 7, 8:
				expected = 1
			}
			if data[0] != expected {
				return nil, parsing.Malformed("DHCP message type conflicts with operation")
			}
			operation := "reply"
			if expected == 1 {
				operation = "request"
			}
			return &Datagram{Protocol: "dhcp/4", Reason: "DHCPv4 header and option framing validated; lease state and option semantics unverified",
				Evidence: []parsing.Row{row("application_protocol", "dhcp/4", "wire", "structural"), row("dhcp_operation", operation, "wire", "structural"),
					row("dhcp_message", dhcpMessages[messageType], "wire", "structural")}}, nil
		}
		count++
		if count > 128 {
			return nil, parsing.Budget("DHCP option count exceeds inspection limit")
		}
		if pos >= len(data) || pos+1+int(data[pos]) > len(data) {
			return nil, parsing.Malformed("Truncated DHCP option")
		}
		size := int(data[pos])
		value := data[pos+1 : pos+1+size]
		pos += 1 + size
		if code == 52 {
			return nil, parsing.Unsupported("DHCP overloaded option fields are outside this profile")
		}
		if code == 53 {
			if size != 1 || messageType != 0 || value[0] < 1 || value[0] > 8 {
				return nil, parsing.Malformed("Invalid or duplicate DHCP message type")
			}
			messageType = value[0]
		}
	}
	return nil, parsing.Malformed("DHCP options require END")
}

// --- RADIUS (radius.py; hint only) -------------------------------------------------------------------------------

func byteSet(values ...int) map[int]bool {
	out := map[int]bool{}
	for _, v := range values {
		out[v] = true
	}
	return out
}

var (
	radiusFixedFour       = byteSet(4, 5, 6, 7, 8, 9, 12, 13, 14, 61, 62)
	radiusStrings         = byteSet(1, 19, 24, 30, 31, 32, 33, 60)
	radiusRepeatable      = byteSet(13, 14, 26, 33)
	radiusSupported       = byteSet(4, 5, 6, 7, 8, 9, 12, 13, 14, 61, 62, 1, 19, 24, 30, 31, 32, 33, 60, 2, 3, 26, 80)
	radiusResponseFour    = byteSet(6, 7, 8, 9, 12, 13, 14, 27, 28, 29, 85)
	radiusResponseStrings = byteSet(11, 18, 24, 25, 79, 87)
	radiusAcceptAllowed   = byteSet(6, 7, 8, 9, 12, 13, 14, 27, 28, 29, 85, 11, 18, 24, 25, 79, 87, 26, 33, 80)
	radiusRejectAllowed   = byteSet(18, 26, 33, 79, 80)
	radiusChallenge       = byteSet(18, 24, 26, 27, 28, 33, 79, 80)
	radiusCodes           = map[byte]string{1: "access-request", 2: "access-accept", 3: "access-reject", 11: "access-challenge"}
)

func radiusMatch(code, reason string) *Datagram {
	return wireMatch("radius", reason, "radius_code", code)
}

func radiusDatagram(data []byte, limits Limits) (*Datagram, error) {
	if len(data) < 20 {
		return nil, parsing.Malformed("Truncated RADIUS header")
	}
	codeName, ok := radiusCodes[data[0]]
	if !ok {
		return nil, parsing.Unsupported("RADIUS profile supports Access-Request, Accept, Reject and Challenge")
	}
	length := be(data[2:4])
	if length < 20 || length > 4096 || length > len(data) {
		return nil, parsing.Malformed("Invalid RADIUS packet length")
	}
	if length != len(data) {
		return nil, parsing.Unsupported("RADIUS trailing datagram padding outside conservative profile")
	}
	budget := min128(limits.MaxHeaders)
	request := data[0] == 1
	allowed := radiusSupported
	switch data[0] {
	case 2:
		allowed = radiusAcceptAllowed
	case 3:
		allowed = radiusRejectAllowed
	case 11:
		allowed = radiusChallenge
	}
	pos, count := 20, 0
	seen := map[int]bool{}
	for pos < length {
		count++
		if count > budget {
			return nil, parsing.Budget("RADIUS attribute count exceeds budget")
		}
		if pos+2 > length {
			return nil, parsing.Malformed("Truncated RADIUS attribute header")
		}
		kind, size := int(data[pos]), int(data[pos+1])
		if size < 2 || pos+size > length {
			return nil, parsing.Malformed("Invalid RADIUS attribute boundary")
		}
		if !allowed[kind] {
			if request {
				return nil, parsing.Unsupported("RADIUS attribute outside supported Access-Request profile")
			}
			return nil, parsing.Unsupported("RADIUS attribute outside the response profile for this code")
		}
		repeatable := radiusRepeatable[kind] || (!request && (kind == 18 || kind == 79 || kind == 25))
		if seen[kind] && !repeatable {
			return nil, parsing.Malformed("Duplicate singleton RADIUS attribute")
		}
		seen[kind] = true
		valueSize := size - 2
		four, strings := radiusFixedFour, radiusStrings
		if !request {
			four, strings = radiusResponseFour, radiusResponseStrings
		}
		if four[kind] && valueSize != 4 {
			return nil, parsing.Malformed("RADIUS address/integer attribute must contain four bytes")
		}
		if strings[kind] && valueSize == 0 {
			return nil, parsing.Malformed("RADIUS string attribute cannot be empty")
		}
		if request && kind == 2 && (valueSize < 16 || valueSize > 128 || valueSize%16 != 0) {
			return nil, parsing.Malformed("Invalid RADIUS User-Password ciphertext length")
		}
		if request && kind == 3 && valueSize != 17 {
			return nil, parsing.Malformed("RADIUS CHAP-Password must contain identifier and sixteen-byte response")
		}
		if kind == 26 && (valueSize < 5 || data[pos+2] != 0) {
			return nil, parsing.Malformed("Invalid RADIUS vendor identifier or empty vendor payload")
		}
		if kind == 80 && valueSize != 16 {
			return nil, parsing.Malformed("RADIUS Message-Authenticator must contain sixteen bytes")
		}
		pos += size
	}
	if !request {
		if data[0] == 11 && !seen[24] {
			return nil, parsing.Malformed("RADIUS Access-Challenge requires a State attribute")
		}
		return radiusMatch(codeName, "RADIUS "+codeName+" attribute framing validated; authenticator, values and authorization unverified"), nil
	}
	if !seen[4] && !seen[32] {
		return nil, parsing.Malformed("RADIUS Access-Request requires NAS address or identifier")
	}
	if !seen[2] && !seen[3] && !seen[24] {
		return nil, parsing.Unsupported("RADIUS profile requires PAP, CHAP or State authentication fields")
	}
	if seen[2] && seen[3] {
		return nil, parsing.Malformed("RADIUS Access-Request cannot combine User-Password and CHAP-Password")
	}
	return radiusMatch("access-request", "RADIUS Access-Request and supported attributes structurally validated; "+
		"authenticators, password values, vendor contents and authorization unverified"), nil
}
