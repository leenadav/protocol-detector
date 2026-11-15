package framed

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"strconv"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// headerMatch ports the rip.py/smarthome.py _match helper: rows carry "wire:header" provenance.
func headerMatch(protocol, reason string, rows ...[2]string) *Datagram {
	evidence := []parsing.Row{row("application_protocol", protocol, "wire", "structural")}
	for _, r := range rows {
		evidence = append(evidence, row(r[0], r[1], "wire:header", "structural"))
	}
	return &Datagram{Protocol: protocol, Reason: reason, Evidence: evidence}
}

func wireMatch(protocol, reason, field, value string) *Datagram {
	return &Datagram{Protocol: protocol, Reason: reason, Evidence: []parsing.Row{row("application_protocol", protocol, "wire", "structural"),
		row(field, value, "wire", "structural")}}
}

func init() {
	for name, v := range map[string]DatagramValidator{"tftp": tftpDatagram, "ntp": ntpDatagram, "l2tp": l2tpDatagram, "coap": coapDatagram,
		"rip": ripDatagram, "rtcp": rtcpDatagram, "lifx-lan": lifxDatagram, "tuya-lan": tuyaDatagram, "ethernet-ip": enipDatagram} {
		DatagramValidators[name] = v
	}
}

// --- TFTP (network.tftp) ------------------------------------------------------------------------------------

func asciiLower(b []byte) string { return string(bytes.ToLower(b)) }

func tftpDatagram(data []byte, _ Limits) (*Datagram, error) {
	if len(data) >= 2 && data[0] == 0 && (data[1] == 5 || data[1] == 6) {
		return tftpServer(data)
	}
	if len(data) < 2 || data[0] != 0 || (data[1] != 1 && data[1] != 2) {
		return nil, parsing.Unsupported("Only TFTP RRQ/WRQ/OACK/ERROR supported")
	}
	if len(data) > 512 || data[len(data)-1] != 0 {
		return nil, parsing.Malformed("Invalid TFTP request length or terminator")
	}
	parts := bytes.Split(data[2:len(data)-1], []byte{0})
	if len(parts) < 2 || len(parts)%2 != 0 || len(parts[0]) == 0 {
		return nil, parsing.Malformed("Invalid TFTP filename/mode/options")
	}
	for _, p := range parts {
		if !printableASCII(p, 32) {
			return nil, parsing.Malformed("TFTP request fields must be printable ASCII in this profile")
		}
	}
	switch asciiLower(parts[1]) {
	case "octet", "netascii", "mail":
	default:
		return nil, parsing.Unsupported("Unsupported TFTP transfer mode")
	}
	if len(parts) > 34 {
		return nil, parsing.Budget("TFTP option count exceeds limit")
	}
	seen := map[string]bool{}
	for i := 2; i < len(parts); i += 2 {
		name, value := asciiLower(parts[i]), parts[i+1]
		if name == "" || len(value) == 0 || seen[name] {
			return nil, parsing.Malformed("Empty or duplicate TFTP option")
		}
		seen[name] = true
		switch name {
		case "blksize", "timeout", "tsize", "windowsize":
			if !gitDigits(value) || len(value) > 20 {
				return nil, parsing.Malformed("Invalid numeric TFTP option")
			}
			n, err := strconv.ParseUint(string(value), 10, 64)
			if err != nil {
				n = ^uint64(0) // 20 digits beyond uint64: every range check below rejects it, as in Python
			}
			if (name == "blksize" && (n < 8 || n > 65464)) || (name == "timeout" && (n < 1 || n > 255)) ||
				(name == "windowsize" && (n < 1 || n > 65535)) || (name == "tsize" && data[1] == 1 && n != 0) {
				return nil, parsing.Malformed("TFTP option outside permitted range")
			}
		}
	}
	return wireMatch("tftp", "TFTP initial read/write request and option framing validated; transfer unverified", "tftp_packet", "request"), nil
}

func tftpServer(data []byte) (*Datagram, error) {
	if len(data) > 512 || data[len(data)-1] != 0 {
		return nil, parsing.Malformed("Invalid TFTP packet length or terminator")
	}
	if data[1] == 5 {
		if len(data) < 6 || be(data[2:4]) > 8 {
			return nil, parsing.Malformed("TFTP error code outside RFC 1350/2347 or empty message")
		}
		message := data[4 : len(data)-1]
		if bytes.IndexByte(message, 0) >= 0 || !printableASCII(message, 32) {
			return nil, parsing.Malformed("TFTP error message must be one printable string")
		}
		return wireMatch("tftp", "TFTP error packet validated; code and message not emitted", "tftp_packet", "error"), nil
	}
	end := len(data) - 1
	if end < 2 {
		end = 2 // data[2:-1] of a two-byte OACK clamps to empty in Python
	}
	parts := bytes.Split(data[2:end], []byte{0})
	if len(parts) < 2 || len(parts)%2 != 0 || len(parts) > 32 {
		return nil, parsing.Malformed("TFTP OACK requires 1..16 option/value pairs")
	}
	seen := map[string]bool{}
	for i := 0; i < len(parts); i += 2 {
		name, value := asciiLower(parts[i]), parts[i+1]
		switch name {
		case "blksize", "timeout", "tsize", "windowsize":
		default:
			name = ""
		}
		if name == "" || seen[name] {
			return nil, parsing.Unsupported("TFTP OACK option outside the RFC 2348/2349/7440 set or repeated")
		}
		if !gitDigits(value) || len(value) == 0 || len(value) > 20 {
			return nil, parsing.Malformed("Invalid numeric TFTP option")
		}
		seen[name] = true
	}
	return wireMatch("tftp", "TFTP option acknowledgement validated; option values not emitted, transfer unverified", "tftp_packet", "oack"), nil
}

// --- NTP base header (network.ntp; hint only) ---------------------------------------------------------------

func ntpDatagram(data []byte, _ Limits) (*Datagram, error) {
	if len(data) != 48 {
		return nil, parsing.Unsupported("Only 48-byte unauthenticated NTP messages supported")
	}
	version, mode := (data[0]>>3)&7, data[0]&7
	if (version != 3 && version != 4) || (mode != 3 && mode != 4) {
		return nil, parsing.Unsupported("Only NTPv3/v4 client/server modes supported")
	}
	if data[1] > 16 {
		return nil, parsing.Malformed("Invalid NTP stratum")
	}
	if mode == 4 && allZero(data[40:48]) {
		return nil, parsing.Malformed("NTP server transmit timestamp is zero")
	}
	protocol := "ntp/" + strconv.Itoa(int(version))
	role := "server"
	if mode == 3 {
		role = "client"
	}
	return wireMatch(protocol, "NTP base header validated with caller hint; timestamps, peer, extensions and authentication unverified", "ntp_mode", role), nil
}

// --- L2TPv2 SCCRQ/SCCRP (vpn.l2tp) ---------------------------------------------------------------------------

func l2tpDatagram(data []byte, limits Limits) (*Datagram, error) {
	budget := limits.MaxHeaders
	if budget > 64 {
		budget = 64
	}
	return l2tpWith(data, budget)
}

func l2tpWith(data []byte, budget int) (*Datagram, error) {
	if len(data) < 20 {
		return nil, parsing.Malformed("L2TP control message too short")
	}
	flags := be(data[:2])
	if flags&0x8000 == 0 || flags&0x000f != 2 {
		return nil, parsing.Unsupported("L2TP profile covers version 2 control messages")
	}
	if flags&0x4000 == 0 || flags&0x0800 == 0 || flags&0x3030 != 0 {
		return nil, parsing.Malformed("L2TP control messages require L and S bits and zero reserved bits")
	}
	length := be(data[2:4])
	if length != len(data) {
		return nil, parsing.Malformed("L2TP length disagrees with datagram")
	}
	tunnel, session := be(data[4:6]), be(data[6:8])
	pos := 12
	if flags&0x0200 != 0 {
		pos += 2
	}
	count, first := 0, -1
	for pos < length {
		count++
		if count > budget {
			return nil, parsing.Budget("L2TP AVP count exceeds budget")
		}
		if pos+6 > length {
			return nil, parsing.Malformed("Truncated L2TP AVP")
		}
		flagsLength := be(data[pos : pos+2])
		avpLength := flagsLength & 0x3ff
		if flagsLength&0x3c00 != 0 || avpLength < 6 || pos+avpLength > length {
			return nil, parsing.Malformed("L2TP AVP reserved bits or length invalid")
		}
		vendor, attribute := be(data[pos+2:pos+4]), be(data[pos+4:pos+6])
		if first < 0 {
			if vendor != 0 || attribute != 0 || avpLength != 8 || flagsLength&0x8000 == 0 {
				return nil, parsing.Malformed("L2TP first AVP must be the mandatory Message Type")
			}
			first = be(data[pos+6 : pos+8])
			if first != 1 && first != 2 {
				return nil, parsing.Unsupported("L2TP profile covers SCCRQ and SCCRP as the first control messages")
			}
			if session != 0 || (first == 1 && tunnel != 0) || (first == 2 && tunnel == 0) {
				return nil, parsing.Malformed("L2TP SCCRQ requires zero identifiers; SCCRP carries the peer's assigned tunnel id")
			}
		}
		pos += avpLength
	}
	if first < 0 {
		return nil, parsing.Malformed("L2TP control message without AVPs")
	}
	name, upper := "sccrq", "SCCRQ"
	if first == 2 {
		name, upper = "sccrp", "SCCRP"
	}
	return wireMatch("l2tp/2", "L2TPv2 "+upper+" control framing and AVP boundaries validated; tunnel establishment unverified", "l2tp_message", name), nil
}

// --- CoAP (wire.coap) ------------------------------------------------------------------------------------------

func coapDatagram(data []byte, _ Limits) (*Datagram, error) {
	if len(data) < 4 || data[0]>>6 != 1 || data[0]&15 > 8 {
		return nil, parsing.Malformed("Invalid CoAP v1 header/token length")
	}
	token := int(data[0] & 15)
	kind, code := (data[0]>>4)&3, data[1]
	if code == 0 {
		if token != 0 || len(data) != 4 || kind == 1 {
			return nil, parsing.Malformed("Invalid CoAP empty message")
		}
		return &Datagram{Protocol: "coap", Reason: "CoAP empty-message framing only; no peer authentication", Simple: true}, nil
	}
	class := code >> 5
	if (class != 0 && class != 2 && class != 4 && class != 5) || (class == 0 && (code < 1 || code > 4)) {
		return nil, parsing.Unsupported("Unsupported CoAP code profile")
	}
	if kind == 3 || (code < 32 && kind != 0 && kind != 1) {
		return nil, parsing.Malformed("CoAP code conflicts with message type")
	}
	pos := 4 + token
	if pos > len(data) {
		return nil, parsing.Malformed("Truncated CoAP token")
	}
	extended := func(value, offset int) (int, int, error) {
		if value < 13 {
			return value, offset, nil
		}
		if value == 15 {
			return 0, 0, parsing.Malformed("Reserved CoAP option nibble")
		}
		width, base := 1, 13
		if value == 14 {
			width, base = 2, 269
		}
		if offset+width > len(data) {
			return 0, 0, parsing.Malformed("Truncated CoAP extended option")
		}
		return be(data[offset:offset+width]) + base, offset + width, nil
	}
	option, count := 0, 0
	for pos < len(data) {
		if data[pos] == 255 {
			if pos+1 == len(data) {
				return nil, parsing.Malformed("CoAP payload marker without payload")
			}
			break
		}
		count++
		if count > 128 {
			return nil, parsing.Budget("CoAP option count exceeds inspection limit")
		}
		b := int(data[pos])
		delta, next, err := extended(b>>4, pos+1)
		if err != nil {
			return nil, err
		}
		size, next, err := extended(b&15, next)
		if err != nil {
			return nil, err
		}
		option += delta
		if option > 65535 || next+size > len(data) {
			return nil, parsing.Malformed("CoAP option outside message or number range")
		}
		pos = next + size
	}
	return &Datagram{Protocol: "coap", Reason: "CoAP v1 token/options framing validated; option semantics and payload unverified", Simple: true}, nil
}

// --- RIP v1/v2 and hinted RTCP (rip.py) -------------------------------------------------------------------------

var ripCommands = map[byte]string{1: "request", 2: "response"}

func ripDatagram(data []byte, _ Limits) (*Datagram, error) {
	if len(data) < 24 || (len(data)-4)%20 != 0 {
		return nil, parsing.Malformed("RIP datagram is a header plus 20-byte entries")
	}
	command, version := data[0], data[1]
	name, ok := ripCommands[command]
	if !ok || (version != 1 && version != 2) {
		return nil, parsing.Unsupported("RIP profile covers request/response of versions 1 and 2")
	}
	if data[2] != 0 || data[3] != 0 {
		return nil, parsing.Malformed("RIP header zero field must be zero")
	}
	count := (len(data) - 4) / 20
	if count > 25 {
		return nil, parsing.Malformed("RIP datagram exceeds 25 entries")
	}
	authentication, pos, end := "none", 4, len(data)
	if version == 2 && data[4] == 0xff && data[5] == 0xff {
		switch be(data[6:8]) {
		case 2:
			authentication = "simple-password"
		case 3:
			authentication = "md5"
			if count < 2 || !bytes.Equal(data[end-20:end-16], []byte{0xff, 0xff, 0, 1}) {
				return nil, parsing.Malformed("RIP MD5 authentication requires a trailer entry")
			}
			if be(data[8:10]) != len(data)-20 || data[11] != 16 {
				return nil, parsing.Malformed("RIP MD5 authentication header fields outside the specification")
			}
			end -= 20
		default:
			return nil, parsing.Malformed("RIP authentication type outside the specification")
		}
		pos += 20
		if pos >= end {
			return nil, parsing.Malformed("RIP authentication without routing entries")
		}
	}
	wholeTable := command == 1 && end-pos == 20 && data[pos] == 0 && data[pos+1] == 0
	for ; pos < end; pos += 20 {
		family, metric := be(data[pos:pos+2]), be(data[pos+16:pos+20])
		if wholeTable {
			if !allZero(data[pos+2:pos+16]) || metric != 16 {
				return nil, parsing.Malformed("RIP whole-table request must be family zero, address zero, metric 16")
			}
			continue
		}
		if family != 2 {
			return nil, parsing.Malformed("RIP entry address family must be IP")
		}
		if metric < 1 || metric > 16 {
			return nil, parsing.Malformed("RIP metric outside 1..16")
		}
		if version == 1 && (!allZero(data[pos+2:pos+4]) || !allZero(data[pos+8:pos+16])) {
			return nil, parsing.Malformed("RIP v1 entries must zero the route tag, mask and next hop")
		}
	}
	return headerMatch("rip/"+strconv.Itoa(int(version)), "RIP "+name+" validated; routes and password not emitted",
		[2]string{"rip_command", name}, [2]string{"rip_authentication", authentication}), nil
}

var rtcpTypes = map[byte]string{200: "sr", 201: "rr", 202: "sdes", 203: "bye", 204: "app", 205: "rtpfb", 206: "psfb", 207: "xr"}

func rtcpDatagram(data []byte, _ Limits) (*Datagram, error) {
	if len(data) < 8 {
		return nil, parsing.Malformed("RTCP packet shorter than its header")
	}
	pos, packets := 0, 0
	var first byte
	for pos < len(data) {
		if len(data)-pos < 4 {
			return nil, parsing.Malformed("Truncated RTCP packet header")
		}
		if data[pos]>>6 != 2 {
			return nil, parsing.Unsupported("RTCP profile requires version 2")
		}
		kind := data[pos+1]
		if _, ok := rtcpTypes[kind]; !ok {
			return nil, parsing.Unsupported("RTCP packet type outside the specification")
		}
		if first == 0 {
			if kind != 200 && kind != 201 {
				return nil, parsing.Malformed("RTCP compound packet must begin with SR or RR")
			}
			first = kind
		}
		length := 4 * (be(data[pos+2:pos+4]) + 1)
		count := int(data[pos] & 0x1f)
		switch {
		case kind == 200 && length < 28+24*count:
			return nil, parsing.Malformed("RTCP SR shorter than its sender info and report blocks")
		case kind == 201 && length < 8+24*count:
			return nil, parsing.Malformed("RTCP RR shorter than its report blocks")
		case kind == 203 && length < 4+4*count:
			return nil, parsing.Malformed("RTCP BYE shorter than its source list")
		}
		if pos+length > len(data) {
			return nil, parsing.Malformed("RTCP packet length exceeds the datagram")
		}
		packets++
		if packets > 8 {
			return nil, parsing.Malformed("RTCP compound packet exceeds the packet budget")
		}
		pos += length
	}
	return headerMatch("rtcp", "RTCP compound packet framing validated with a candidate hint; reports not decoded",
		[2]string{"rtcp_packet", rtcpTypes[first]}, [2]string{"rtcp_packets", strconv.Itoa(packets)}), nil
}

// --- LIFX LAN and Tuya LAN (smarthome.py) -------------------------------------------------------------------------

var lifxTypes = map[int]struct {
	name string
	size int
}{2: {"getservice", 0}, 3: {"stateservice", 5}, 14: {"gethostfirmware", 0}, 15: {"statehostfirmware", 20},
	16: {"getwifiinfo", 0}, 17: {"statewifiinfo", 14}, 18: {"getwififirmware", 0}, 19: {"statewififirmware", 20},
	20: {"getpower", 0}, 21: {"setpower", 2}, 22: {"statepower", 2}, 23: {"getlabel", 0}, 25: {"statelabel", 32},
	32: {"getversion", 0}, 33: {"stateversion", 12}, 34: {"getinfo", 0}, 35: {"stateinfo", 24},
	45: {"acknowledgement", 0}, 48: {"getlocation", 0}, 50: {"statelocation", 56}, 51: {"getgroup", 0},
	53: {"stategroup", 56}, 58: {"echorequest", 64}, 59: {"echoresponse", 64},
	101: {"get", 0}, 102: {"setcolor", 13}, 107: {"lightstate", 52}, 116: {"lightgetpower", 0},
	117: {"lightsetpower", 6}, 118: {"lightstatepower", 2}}

func lifxDatagram(data []byte, _ Limits) (*Datagram, error) {
	if len(data) < 36 {
		return nil, parsing.Malformed("LIFX LAN header requires 36 bytes")
	}
	if le16(data[:2]) != len(data) {
		return nil, parsing.Malformed("LIFX LAN size field must equal the datagram length")
	}
	word := le16(data[2:4])
	if word&0xfff != 1024 || word&0x1000 == 0 || word&0xc000 != 0 {
		return nil, parsing.Unsupported("LIFX LAN requires protocol 1024, addressable 1 and origin 0")
	}
	tagged := word&0x2000 != 0
	if data[14] != 0 || data[15] != 0 || (tagged && !allZero(data[8:14])) {
		return nil, parsing.Malformed("LIFX LAN target must end in two zero bytes and be zero when tagged")
	}
	if data[22]&0xfc != 0 || data[34] != 0 || data[35] != 0 {
		return nil, parsing.Malformed("LIFX LAN reserved flag bits and the reserved word after the type must be zero")
	}
	kind := le16(data[32:34])
	if kind == 0 {
		return nil, parsing.Malformed("LIFX LAN message type zero is undefined")
	}
	known, ok := lifxTypes[kind]
	if ok && len(data)-36 != known.size {
		return nil, parsing.Malformed("LIFX LAN payload size disagrees with its message type")
	}
	name := "other"
	if ok {
		name = known.name
	}
	taggedLabel := "no"
	if tagged {
		taggedLabel = "yes"
	}
	return headerMatch("lifx-lan", "LIFX LAN header (size, protocol 1024, addressable, origin, target, message payload size) validated; "+
		"target, source and payload never emitted", [2]string{"lifx_message", name}, [2]string{"lifx_tagged", taggedLabel}), nil
}

var tuyaCommands = map[int]string{0x00: "udp", 0x07: "control", 0x08: "status", 0x09: "heartbeat", 0x0a: "dp-query",
	0x0d: "control-new", 0x10: "dp-query-new", 0x12: "ap-config", 0x13: "udp-new", 0x14: "ap-config-new", 0x23: "broadcast-lpv34"}

func tuyaDatagram(data []byte, _ Limits) (*Datagram, error) {
	if len(data) < 24 || !bytes.Equal(data[:4], []byte{0, 0, 0x55, 0xaa}) || !bytes.Equal(data[len(data)-4:], []byte{0, 0, 0xaa, 0x55}) {
		return nil, parsing.Unsupported("Tuya LAN 3.3 framing requires the 0x000055AA prefix and 0x0000AA55 suffix")
	}
	if 16+be(data[12:16]) != len(data) {
		return nil, parsing.Malformed("Tuya LAN length field must count the rest of the datagram")
	}
	if crc32.ChecksumIEEE(data[:len(data)-8]) != binary.BigEndian.Uint32(data[len(data)-8:len(data)-4]) {
		return nil, parsing.Malformed("Tuya LAN CRC32 does not match (3.4 HMAC framing is outside the profile)")
	}
	command, ok := tuyaCommands[be(data[8:12])]
	if !ok {
		command = "other"
	}
	return headerMatch("tuya-lan", "Tuya LAN 3.3 frame (prefix, length, CRC32, suffix) validated; payload not decrypted or emitted",
		[2]string{"tuya_command", command}), nil
}

// --- EtherNet/IP over UDP (datagram.enip_datagram) ---------------------------------------------------------------

func enipDatagram(data []byte, limits Limits) (*Datagram, error) {
	p := NewENIP(limits.MaxBytes)
	consumed, err := p.Feed(data)
	if err != nil {
		return nil, err
	}
	if !p.Done() || consumed != len(data) {
		return nil, parsing.Malformed("EtherNet/IP datagram must contain exactly one encapsulation message")
	}
	r := p.Result()
	return &Datagram{Protocol: r.ProtocolName, Reason: r.Reason, Simple: true}, nil
}
