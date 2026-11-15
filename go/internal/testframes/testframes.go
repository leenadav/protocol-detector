// Package testframes builds synthetic Ethernet/IPv4 TCP and UDP frames for tests, byte-compatible with
// protocol_adapters/make_sample_pcap.py (valid checksums, 60-byte minimum). Never transmitted.
package testframes

import (
	"encoding/binary"
	"net"
)

func checksum(parts ...[]byte) uint16 {
	var total uint32
	var buf []byte
	for _, p := range parts {
		buf = append(buf, p...)
	}
	if len(buf)%2 == 1 {
		buf = append(buf, 0)
	}
	for i := 0; i < len(buf); i += 2 {
		total += uint32(binary.BigEndian.Uint16(buf[i:]))
	}
	for total>>16 != 0 {
		total = (total & 0xffff) + (total >> 16)
	}
	return ^uint16(total)
}

func ip4(addr string) []byte { return net.ParseIP(addr).To4() }

func ethernet() []byte {
	return []byte{2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x08, 0x00}
}

func ipHeader(src, dst []byte, protocol byte, payloadLen int) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+payloadLen))
	binary.BigEndian.PutUint16(ip[4:], 1)
	binary.BigEndian.PutUint16(ip[6:], 0x4000)
	ip[8], ip[9] = 64, protocol
	copy(ip[12:], src)
	copy(ip[16:], dst)
	binary.BigEndian.PutUint16(ip[10:], checksum(ip))
	return ip
}

func pad(frame []byte) []byte {
	for len(frame) < 60 {
		frame = append(frame, 0)
	}
	return frame
}

// TCP builds one segment with a 20-byte TCP header, window 65535 and correct checksums.
func TCP(srcAddr string, srcPort uint16, dstAddr string, dstPort uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	src, dst := ip4(srcAddr), ip4(dstAddr)
	tcp := make([]byte, 20, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:], srcPort)
	binary.BigEndian.PutUint16(tcp[2:], dstPort)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	binary.BigEndian.PutUint32(tcp[8:], ack)
	tcp[12], tcp[13] = 5<<4, flags
	binary.BigEndian.PutUint16(tcp[14:], 65535)
	tcp = append(tcp, payload...)
	pseudo := append(append(append([]byte{}, src...), dst...), 0, 6, byte(len(tcp)>>8), byte(len(tcp)))
	binary.BigEndian.PutUint16(tcp[16:], checksum(pseudo, tcp))
	return pad(append(append(ethernet(), ipHeader(src, dst, 6, len(tcp))...), tcp...))
}

// UDP builds one datagram with correct checksums.
func UDP(srcAddr string, srcPort uint16, dstAddr string, dstPort uint16, payload []byte) []byte {
	src, dst := ip4(srcAddr), ip4(dstAddr)
	udp := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:], srcPort)
	binary.BigEndian.PutUint16(udp[2:], dstPort)
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(payload)))
	udp = append(udp, payload...)
	pseudo := append(append(append([]byte{}, src...), dst...), 0, 17, byte(len(udp)>>8), byte(len(udp)))
	sum := checksum(pseudo, udp)
	if sum == 0 {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:], sum)
	return pad(append(append(ethernet(), ipHeader(src, dst, 17, len(udp))...), udp...))
}
