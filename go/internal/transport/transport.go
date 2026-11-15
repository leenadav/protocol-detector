// Package transport decodes captured frames into IPv4 TCP segments and UDP datagrams, mirroring
// protocol_adapters/link_packets.py: Ethernet (up to two VLAN tags), BSD/OpenBSD loopback, Linux cooked
// v1/v2 and raw IPv4 link types; IPv6, IPv4 fragments and every other transport are rejected with a typed
// reason and, where the headers were readable, the flow's endpoints so the owner can mark it (D06).
//
// Checksums follow the three policies of the Python adapter: ignore (default; host captures predate
// offload), audit (computed, reported, packet still decoded) and verify (a failure rejects the packet).
// Every length is checked before it is used for slicing; payloads returned here are sub-slices of the
// caller's frame and must be copied by anyone who retains them (ADR 0001).
package transport

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

// Reject kinds (PacketError.KINDS in Python).
const (
	KindLink      = "link"
	KindNetwork   = "network"
	KindFragment  = "fragment"
	KindLength    = "length"
	KindTransport = "transport"
	KindTruncated = "truncated"
	KindChecksum  = "checksum"
	KindMalformed = "malformed"
)

// Checksum policies.
const (
	Ignore = "ignore"
	Audit  = "audit"
	Verify = "verify"
)

// Endpoint is an IPv4 address in dotted form and a port; the dotted string keeps the Python ordering
// of flow keys (string comparison of addresses, then the port).
type Endpoint struct {
	Addr string
	Port uint16
}

func (e Endpoint) String() string { return e.Addr + ":" + strconv.Itoa(int(e.Port)) }

// Less orders endpoints exactly like Python's tuple comparison of (address string, port).
func (e Endpoint) Less(o Endpoint) bool {
	if e.Addr != o.Addr {
		return e.Addr < o.Addr
	}
	return e.Port < o.Port
}

// Reject is the typed decode failure.
type Reject struct {
	Kind      string
	Message   string
	Endpoints *[2]Endpoint // source, destination when the transport header was readable
}

func (r *Reject) Error() string { return r.Kind + ": " + r.Message }

// TCP is one decoded segment. Payload aliases the input frame.
type TCP struct {
	Source, Destination Endpoint
	Sequence, Ack       uint32
	Flags               byte
	Payload             []byte
	ChecksumFailures    []string
}

// UDP is one decoded datagram. Payload aliases the input frame.
type UDP struct {
	Source, Destination Endpoint
	Payload             []byte
	ChecksumFailures    []string
}

// TCP flag bits.
const (
	FIN byte = 1
	SYN byte = 2
	RST byte = 4
	ACK byte = 16
	URG byte = 32
)

func reject(kind, message string) *Reject { return &Reject{Kind: kind, Message: message} }

func be16(b []byte) int { return int(binary.BigEndian.Uint16(b)) }

// networkPayload strips the link header and returns the IPv4 packet (unchecked length).
func networkPayload(frame []byte, linktype int) ([]byte, error) {
	var offset int
	ipv4 := false
	switch linktype {
	case 1: // Ethernet
		if len(frame) < 14 {
			return nil, reject(KindLink, "Truncated Ethernet header")
		}
		kind, tags := be16(frame[12:14]), 0
		offset = 14
		for kind == 0x8100 || kind == 0x88a8 {
			if tags == 2 || len(frame) < offset+4 {
				return nil, reject(KindLink, "Unsupported or truncated VLAN tags")
			}
			kind = be16(frame[offset+2 : offset+4])
			offset += 4
			tags++
		}
		ipv4 = kind == 0x0800
	case 0, 108: // BSD / OpenBSD loopback
		if len(frame) < 4 {
			return nil, reject(KindLink, "Truncated loopback header")
		}
		family := binary.BigEndian.Uint32(frame[:4])
		if linktype == 0 && family != 2 {
			family = binary.LittleEndian.Uint32(frame[:4])
		}
		ipv4, offset = family == 2, 4
	case 113, 276: // Linux cooked v1 / v2
		offset = 16
		if linktype == 276 {
			offset = 20
		}
		if len(frame) < offset {
			return nil, reject(KindLink, "Truncated Linux cooked header")
		}
		if linktype == 113 {
			ipv4 = be16(frame[14:16]) == 0x0800
		} else {
			ipv4 = be16(frame[:2]) == 0x0800
		}
	case 101, 228: // raw IPv4
		offset, ipv4 = 0, true
	default:
		return nil, reject(KindLink, "Unsupported capture link type (IPv4 only)")
	}
	ip := frame[offset:]
	if !ipv4 || len(ip) == 0 || ip[0]>>4 != 4 {
		return nil, reject(KindNetwork, "Unsupported or inconsistent network protocol (IPv4 only)")
	}
	return ip, nil
}

func onesComplement(parts ...[]byte) uint16 {
	var total uint32
	odd := false
	var carry byte
	for _, data := range parts {
		for _, b := range data {
			if odd {
				total += uint32(carry)<<8 | uint32(b)
			} else {
				carry = b
			}
			odd = !odd
		}
	}
	if odd {
		total += uint32(carry) << 8
	}
	for total>>16 != 0 {
		total = (total & 0xffff) + (total >> 16)
	}
	return ^uint16(total)
}

func checksumFailures(ip []byte, start, total int, protocol byte, data []byte) []string {
	var failures []string
	if onesComplement(ip[:start]) != 0 {
		failures = append(failures, "ip")
	}
	length := total - start
	pseudo := append(append([]byte{}, ip[12:20]...), 0, protocol, byte(length>>8), byte(length))
	if protocol == 6 && len(data) >= 20 && onesComplement(pseudo, data) != 0 {
		failures = append(failures, "tcp")
	}
	if protocol == 17 && len(data) >= 8 && (data[6] != 0 || data[7] != 0) && onesComplement(pseudo, data) != 0 {
		failures = append(failures, "udp")
	}
	return failures
}

func dotted(b []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

// Decode decodes one frame. The result is *TCP or *UDP; the error is always a *Reject.
func Decode(frame []byte, linktype int, checksums string) (interface{}, error) {
	if checksums != Ignore && checksums != Audit && checksums != Verify {
		return nil, reject(KindMalformed, "unknown checksum policy")
	}
	ip, err := networkPayload(frame, linktype)
	if err != nil {
		return nil, err
	}
	if len(ip) < 20 {
		return nil, reject(KindLength, "Truncated IPv4 header")
	}
	start, total := int(ip[0]&15)*4, be16(ip[2:4])
	if start < 20 || total < start || total > len(ip) {
		return nil, reject(KindLength, "Invalid or truncated IPv4 length")
	}
	protocol := ip[9]
	source, destination := dotted(ip[12:16]), dotted(ip[16:20])
	data := ip[start:total]
	flagsOffset := be16(ip[6:8])
	if flagsOffset&0xbfff != 0 {
		r := reject(KindFragment, "IPv4 fragments/reserved flag unsupported")
		if flagsOffset&0x1fff == 0 && (protocol == 6 || protocol == 17) && len(data) >= 4 {
			r.Endpoints = &[2]Endpoint{{source, uint16(be16(data[0:2]))}, {destination, uint16(be16(data[2:4]))}}
		}
		return nil, r
	}
	var failures []string
	if checksums != Ignore && (protocol == 6 || protocol == 17) {
		failures = checksumFailures(ip, start, total, protocol, data)
	}
	switch protocol {
	case 6:
		if len(data) < 20 {
			return nil, reject(KindLength, "Truncated TCP header")
		}
		size := int(data[12]>>4) * 4
		ends := &[2]Endpoint{{source, uint16(be16(data[0:2]))}, {destination, uint16(be16(data[2:4]))}}
		if size < 20 || size > len(data) {
			r := reject(KindLength, "Invalid TCP header length")
			r.Endpoints = ends
			return nil, r
		}
		if len(failures) > 0 && checksums == Verify {
			r := reject(KindChecksum, "Checksum failure: "+join(failures))
			r.Endpoints = ends
			return nil, r
		}
		return &TCP{Source: ends[0], Destination: ends[1], Sequence: binary.BigEndian.Uint32(data[4:8]),
			Ack: binary.BigEndian.Uint32(data[8:12]), Flags: data[13], Payload: data[size:], ChecksumFailures: failures}, nil
	case 17:
		if len(data) < 8 {
			return nil, reject(KindLength, "Truncated UDP header")
		}
		ends := &[2]Endpoint{{source, uint16(be16(data[0:2]))}, {destination, uint16(be16(data[2:4]))}}
		size := be16(data[4:6])
		if size < 8 || size != len(data) {
			r := reject(KindLength, "UDP length disagrees with IP payload")
			r.Endpoints = ends
			return nil, r
		}
		if len(failures) > 0 && checksums == Verify {
			r := reject(KindChecksum, "Checksum failure: "+join(failures))
			r.Endpoints = ends
			return nil, r
		}
		return &UDP{Source: ends[0], Destination: ends[1], Payload: data[8:], ChecksumFailures: failures}, nil
	}
	return nil, reject(KindTransport, "Unsupported IP transport")
}

func join(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ","
		}
		out += p
	}
	return out
}
