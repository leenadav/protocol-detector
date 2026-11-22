// Package sessionid is protocol_adapters/events.py session_identity: a deterministic session id from the
// transport and both endpoints, independent of direction. The id is a hash (BLAKE2s with an 8-byte digest,
// RFC 7693), so no address or port leaves through it.
package sessionid

import (
	"encoding/binary"
	"encoding/hex"
	"math/bits"
	"strconv"

	"github.com/leenadav/protocol-detector/go/internal/transport"
)

var iv = [8]uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}

var sigma = [10][16]byte{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
}

func compress(h *[8]uint32, block *[64]byte, counter uint64, last bool) {
	var m [16]uint32
	for i := range m {
		m[i] = binary.LittleEndian.Uint32(block[4*i:])
	}
	v := [16]uint32{h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], iv[0], iv[1], iv[2], iv[3],
		iv[4] ^ uint32(counter), iv[5] ^ uint32(counter>>32), iv[6], iv[7]}
	if last {
		v[14] = ^v[14]
	}
	g := func(a, b, c, d int, x, y uint32) {
		v[a] += v[b] + x
		v[d] = bits.RotateLeft32(v[d]^v[a], -16)
		v[c] += v[d]
		v[b] = bits.RotateLeft32(v[b]^v[c], -12)
		v[a] += v[b] + y
		v[d] = bits.RotateLeft32(v[d]^v[a], -8)
		v[c] += v[d]
		v[b] = bits.RotateLeft32(v[b]^v[c], -7)
	}
	for _, s := range sigma {
		g(0, 4, 8, 12, m[s[0]], m[s[1]])
		g(1, 5, 9, 13, m[s[2]], m[s[3]])
		g(2, 6, 10, 14, m[s[4]], m[s[5]])
		g(3, 7, 11, 15, m[s[6]], m[s[7]])
		g(0, 5, 10, 15, m[s[8]], m[s[9]])
		g(1, 6, 11, 12, m[s[10]], m[s[11]])
		g(2, 7, 8, 13, m[s[12]], m[s[13]])
		g(3, 4, 9, 14, m[s[14]], m[s[15]])
	}
	for i := range h {
		h[i] ^= v[i] ^ v[i+8]
	}
}

// Blake2s8 is hashlib.blake2s(data, digest_size=8).hexdigest().
func Blake2s8(data []byte) string {
	h := iv
	h[0] ^= 0x01010000 ^ 8
	var block [64]byte
	counter := uint64(0)
	for len(data) > 64 {
		copy(block[:], data[:64])
		counter += 64
		compress(&h, &block, counter, false)
		data = data[64:]
	}
	block = [64]byte{}
	copy(block[:], data)
	counter += uint64(len(data))
	compress(&h, &block, counter, true)
	var out [8]byte
	binary.LittleEndian.PutUint32(out[0:], h[0])
	binary.LittleEndian.PutUint32(out[4:], h[1])
	return hex.EncodeToString(out[:])
}

// Identity is session_identity(transport, client, server).
func Identity(transportName string, client, server transport.Endpoint) string {
	a, b := client, server
	if b.Less(a) {
		a, b = b, a
	}
	text := []byte(transportName + "|" + a.Addr + ":" + strconv.Itoa(int(a.Port)) + "|" + b.Addr + ":" + strconv.Itoa(int(b.Port)))
	for i, c := range text {
		if c > 0x7f {
			text[i] = '?' // encode("ascii", "replace"); addresses are ASCII
		}
	}
	return Blake2s8(text)
}
