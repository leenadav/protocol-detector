"""Pure-Python AES-128 (encryption direction only), AES-GCM open and HKDF-SHA256.

Used solely to remove QUIC Initial packet protection, whose keys are derived
from public values (version salt and Destination Connection ID). Nothing here
is secret material and no constant-time guarantee is offered or needed: the
inputs are attacker-visible and the output is a plaintext the attacker already
chose. The implementation is table-driven and bounded by the datagram size.
"""
import hashlib
import hmac
import struct

# ---- AES-128 ---------------------------------------------------------------
_SBOX = bytes((
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16))


def _xtime(value):
    value <<= 1
    return (value ^ 0x1b) & 0xff if value & 0x100 else value


# T-tables: Te0[x] = (S[x]*2, S[x], S[x], S[x]*3) packed big-endian; rotations give Te1..Te3.
_TE0 = []
for _x in range(256):
    _s = _SBOX[_x]
    _s2 = _xtime(_s)
    _TE0.append((_s2 << 24) | (_s << 16) | (_s << 8) | (_s2 ^ _s))
_TE0 = tuple(_TE0)
_TE1 = tuple(((v >> 8) | ((v & 0xff) << 24)) for v in _TE0)
_TE2 = tuple(((v >> 16) | ((v & 0xffff) << 16)) for v in _TE0)
_TE3 = tuple(((v >> 24) | ((v & 0xffffff) << 8)) for v in _TE0)
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)


def expand_key(key):
    """AES-128 round keys as 44 big-endian words."""
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    words = list(struct.unpack(">4I", key))
    for index in range(4, 44):
        temp = words[index - 1]
        if index % 4 == 0:
            temp = ((temp << 8) & 0xffffffff) | (temp >> 24)
            temp = ((_SBOX[temp >> 24] << 24) | (_SBOX[(temp >> 16) & 0xff] << 16)
                    | (_SBOX[(temp >> 8) & 0xff] << 8) | _SBOX[temp & 0xff]) ^ (_RCON[index // 4 - 1] << 24)
        words.append(words[index - 4] ^ temp)
    return tuple(words)


def encrypt_block(round_keys, block):
    """Encrypt one 16-byte block with expanded AES-128 round keys."""
    s0, s1, s2, s3 = struct.unpack(">4I", block)
    s0 ^= round_keys[0]; s1 ^= round_keys[1]; s2 ^= round_keys[2]; s3 ^= round_keys[3]
    te0, te1, te2, te3 = _TE0, _TE1, _TE2, _TE3
    for r in range(1, 10):
        k = 4 * r
        t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xff] ^ te2[(s2 >> 8) & 0xff] ^ te3[s3 & 0xff] ^ round_keys[k]
        t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xff] ^ te2[(s3 >> 8) & 0xff] ^ te3[s0 & 0xff] ^ round_keys[k + 1]
        t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xff] ^ te2[(s0 >> 8) & 0xff] ^ te3[s1 & 0xff] ^ round_keys[k + 2]
        t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xff] ^ te2[(s1 >> 8) & 0xff] ^ te3[s2 & 0xff] ^ round_keys[k + 3]
        s0, s1, s2, s3 = t0, t1, t2, t3
    sb = _SBOX
    o0 = ((sb[s0 >> 24] << 24) | (sb[(s1 >> 16) & 0xff] << 16) | (sb[(s2 >> 8) & 0xff] << 8) | sb[s3 & 0xff]) ^ round_keys[40]
    o1 = ((sb[s1 >> 24] << 24) | (sb[(s2 >> 16) & 0xff] << 16) | (sb[(s3 >> 8) & 0xff] << 8) | sb[s0 & 0xff]) ^ round_keys[41]
    o2 = ((sb[s2 >> 24] << 24) | (sb[(s3 >> 16) & 0xff] << 16) | (sb[(s0 >> 8) & 0xff] << 8) | sb[s1 & 0xff]) ^ round_keys[42]
    o3 = ((sb[s3 >> 24] << 24) | (sb[(s0 >> 16) & 0xff] << 16) | (sb[(s1 >> 8) & 0xff] << 8) | sb[s2 & 0xff]) ^ round_keys[43]
    return struct.pack(">4I", o0, o1, o2, o3)


# ---- GCM -------------------------------------------------------------------
_R = 0xe1 << 120


def _gf_mult(x, y):
    """GF(2^128) multiplication per NIST SP 800-38D (bit-reflected convention)."""
    z = 0
    v = x
    for bit in range(127, -1, -1):
        if (y >> bit) & 1:
            z ^= v
        v = (v >> 1) ^ _R if v & 1 else v >> 1
    return z


def _ghash_table(h):
    """Byte-windowed multiplication tables: table[position][byte] = H * (byte << 8*position).

    Built from the 128 products H * x^i (one shift-and-reduce step each) and
    combined by XOR, so construction costs about 128 shifts plus 4096 XORs
    instead of 4096 full field multiplications.
    """
    bit_products = [0] * 128  # bit_products[i] = H * (1 << i) in the GCM field
    value = h
    for i in range(127, -1, -1):
        # Going from bit 127 (identity, H * x^0 in the reflected convention) downwards
        # multiplies by x each step: v = (v >> 1) ^ R if the low bit is set.
        bit_products[i] = value
        value = (value >> 1) ^ _R if value & 1 else value >> 1
    table = []
    for position in range(16):
        base = position * 8
        row = [0] * 256
        for byte in range(1, 256):
            low = byte & -byte
            row[byte] = row[byte ^ low] ^ bit_products[base + low.bit_length() - 1]
        table.append(row)
    return table


def _ghash(table, data):
    """GHASH over data (padded to 16-byte blocks) with 16 table lookups per block."""
    y = 0
    t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15 = table
    for pos in range(0, len(data), 16):
        x = y ^ int.from_bytes(data[pos:pos + 16], "big")
        y = (t0[x & 255] ^ t1[(x >> 8) & 255] ^ t2[(x >> 16) & 255] ^ t3[(x >> 24) & 255]
             ^ t4[(x >> 32) & 255] ^ t5[(x >> 40) & 255] ^ t6[(x >> 48) & 255] ^ t7[(x >> 56) & 255]
             ^ t8[(x >> 64) & 255] ^ t9[(x >> 72) & 255] ^ t10[(x >> 80) & 255] ^ t11[(x >> 88) & 255]
             ^ t12[(x >> 96) & 255] ^ t13[(x >> 104) & 255] ^ t14[(x >> 112) & 255] ^ t15[x >> 120])
    return y


def gcm_open(key, nonce, aad, ciphertext_and_tag):
    """AES-128-GCM decrypt-and-verify; returns plaintext or None on tag mismatch.

    Deliberately non-constant-time: the inputs are public network bytes and a
    forged tag only means the packet is not a decodable Initial.
    """
    if len(nonce) != 12 or len(ciphertext_and_tag) < 16:
        return None
    round_keys = expand_key(key)
    ciphertext, tag = ciphertext_and_tag[:-16], ciphertext_and_tag[-16:]
    h = int.from_bytes(encrypt_block(round_keys, bytes(16)), "big")
    table = _ghash_table(h)
    lengths = struct.pack(">QQ", len(aad) * 8, len(ciphertext) * 8)
    padded_aad = aad + bytes((-len(aad)) % 16)
    padded_cipher = ciphertext + bytes((-len(ciphertext)) % 16)
    digest = _ghash(table, padded_aad + padded_cipher + lengths)
    j0 = nonce + b"\0\0\0\1"
    expected = (digest ^ int.from_bytes(encrypt_block(round_keys, j0), "big")).to_bytes(16, "big")
    if expected != tag:
        return None
    counter = int.from_bytes(j0, "big")
    output = bytearray()
    for pos in range(0, len(ciphertext), 16):
        counter += 1
        block = encrypt_block(round_keys, counter.to_bytes(16, "big"))
        chunk = ciphertext[pos:pos + 16]
        output.extend(a ^ b for a, b in zip(chunk, block))
    return bytes(output)


def gcm_seal(key, nonce, aad, plaintext):
    """AES-128-GCM encrypt (used only by tests to build fixtures)."""
    round_keys = expand_key(key)
    j0 = nonce + b"\0\0\0\1"
    counter = int.from_bytes(j0, "big")
    output = bytearray()
    for pos in range(0, len(plaintext), 16):
        counter += 1
        block = encrypt_block(round_keys, counter.to_bytes(16, "big"))
        output.extend(a ^ b for a, b in zip(plaintext[pos:pos + 16], block))
    ciphertext = bytes(output)
    h = int.from_bytes(encrypt_block(round_keys, bytes(16)), "big")
    table = _ghash_table(h)
    lengths = struct.pack(">QQ", len(aad) * 8, len(ciphertext) * 8)
    digest = _ghash(table, aad + bytes((-len(aad)) % 16) + ciphertext + bytes((-len(ciphertext)) % 16) + lengths)
    tag = (digest ^ int.from_bytes(encrypt_block(round_keys, j0), "big")).to_bytes(16, "big")
    return ciphertext + tag


# ---- HKDF-SHA256 (RFC 5869) and TLS 1.3 HKDF-Expand-Label (RFC 8446 7.1) ----
def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, length):
    output, block, counter = b"", b"", 1
    while len(output) < length:
        block = hmac.new(prk, block + info + bytes((counter,)), hashlib.sha256).digest()
        output += block
        counter += 1
    return output[:length]


def hkdf_expand_label(secret, label, context, length):
    info = struct.pack(">H", length) + bytes((6 + len(label),)) + b"tls13 " + label + bytes((len(context),)) + context
    return hkdf_expand(secret, info, length)
