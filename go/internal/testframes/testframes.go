// Package testframes builds synthetic Ethernet/IPv4 TCP and UDP frames for tests, byte-compatible with
// protocol_adapters/make_sample_pcap.py (valid checksums, 60-byte minimum). Never transmitted.
package testframes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
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

// QUICInitial seals a client Initial (RFC 9001 section 5) around a plaintext frame payload, padded to padTo bytes,
// with a 4-byte packet number. It derives the Initial keys independently of the engine (test helper).
func QUICInitial(version uint32, dcid, scid, frames []byte, packetNumber uint32, token []byte, padTo int) []byte {
	salt := map[uint32]string{1: "38762cf7f55934b34d179ae6a4c80cadccbb7f0a", 0x6b3343cf: "0dede3def700a6db819381be6e269dcbf9bd2ed9"}[version]
	saltBytes, _ := hex.DecodeString(salt)
	prefix := map[uint32]string{1: "quic ", 0x6b3343cf: "quicv2 "}[version]
	expand := func(secret []byte, label string, n int) []byte {
		full := "tls13 " + label
		info := append([]byte{byte(n >> 8), byte(n), byte(len(full))}, full...)
		out, _ := hkdf.Expand(sha256.New, secret, string(append(info, 0)), n)
		return out
	}
	prk, _ := hkdf.Extract(sha256.New, dcid, saltBytes)
	secret := expand(prk, "client in", 32)
	key, iv, hp := expand(secret, prefix+"key", 16), expand(secret, prefix+"iv", 12), expand(secret, prefix+"hp", 16)
	varint := func(v int) []byte {
		switch {
		case v < 1<<6:
			return []byte{byte(v)}
		case v < 1<<14:
			return []byte{0x40 | byte(v>>8), byte(v)}
		default:
			return []byte{0x80 | byte(v>>24), byte(v >> 16), byte(v >> 8), byte(v)}
		}
	}
	pad := padTo - (7 + len(dcid) + len(scid) + 1 + len(token) + 2 + 4 + len(frames) + 16)
	payload := append([]byte{}, frames...)
	if pad > 0 {
		payload = append(payload, make([]byte, pad)...)
	}
	first := byte(0xc3)
	if version != 1 {
		first = 0xd3
	}
	header := []byte{first, byte(version >> 24), byte(version >> 16), byte(version >> 8), byte(version), byte(len(dcid))}
	header = append(append(header, dcid...), byte(len(scid)))
	header = append(append(append(header, scid...), varint(len(token))...), token...)
	length := 4 + len(payload) + 16
	header = append(header, 0x40|byte(length>>8), byte(length))
	header = append(header, byte(packetNumber>>24), byte(packetNumber>>16), byte(packetNumber>>8), byte(packetNumber))
	nonce := append([]byte{}, iv...)
	for i := 0; i < 4; i++ {
		nonce[11-i] ^= byte(packetNumber >> (8 * i))
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	sealed := gcm.Seal(nil, nonce, payload, header)
	hpBlock, _ := aes.NewCipher(hp)
	mask := make([]byte, 16)
	hpBlock.Encrypt(mask, sealed[:16])
	out := append(append([]byte{}, header...), sealed...)
	pnOffset := len(header) - 4
	out[0] ^= mask[0] & 0x0f
	for i := 0; i < 4; i++ {
		out[pnOffset+i] ^= mask[1+i]
	}
	return out
}

// CryptoFrames splits handshake bytes into CRYPTO frames at the cut offsets (each under 16384 bytes).
func CryptoFrames(data []byte, cuts ...int) [][]byte {
	bounds := append(append([]int{0}, cuts...), len(data))
	var out [][]byte
	for i := 0; i+1 < len(bounds); i++ {
		start, end := bounds[i], bounds[i+1]
		frame := []byte{6, 0x40 | byte(start>>8), byte(start), 0x40 | byte((end-start)>>8), byte(end - start)}
		out = append(out, append(frame, data[start:end]...))
	}
	return out
}
