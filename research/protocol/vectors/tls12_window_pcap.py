"""Synthetic IPv4 loopback TLS 1.2 session pcap: handshake, ClientHello (SNI), ServerHello with a chosen cipher,
then optional client application data. usage: tls_syn.py OUT.pcap CIPHER_HEX EXTRA_CLIENT_BYTES"""
import struct, sys, os
out, cipher, extra = sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3])
def csum(b):
    if len(b) % 2: b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b)//2), b)); s = (s >> 16) + (s & 0xffff); s += s >> 16
    return (~s) & 0xffff
C, Sv = bytes([127,0,0,1]), bytes([127,0,0,2]); CP, SP = 50000, 443
def pkt(src, dst, sp, dp, seq, ack, flags, data=b""):
    tcp = struct.pack("!HHIIBBHHH", sp, dp, seq, ack, 5 << 4, flags, 65535, 0, 0) + data
    ph = src + dst + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", csum(ph + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + ip + tcp
def ext(t, body): return struct.pack("!HH", t, len(body)) + body
name = b"example.com"
sni = ext(0, struct.pack("!H", len(name) + 3) + b"\0" + struct.pack("!H", len(name)) + name)
exts = sni + ext(10, b"\x00\x04\x00\x17\x00\x18") + ext(11, b"\x01\x00") + ext(13, b"\x00\x04\x04\x01\x04\x03") + ext(0xff01, b"\x00")
suites = [0xc02f, 0xc030, 0x009c, 0x002f]
ch = b"\x03\x03" + bytes(range(32)) + b"\x00" + struct.pack("!H", 2 * len(suites)) + b"".join(struct.pack("!H", s) for s in suites) + b"\x01\x00" + struct.pack("!H", len(exts)) + exts
ch = b"\x01" + struct.pack("!I", len(ch))[1:] + ch
chrec = b"\x16\x03\x01" + struct.pack("!H", len(ch)) + ch
sexts = ext(0xff01, b"\x00") + ext(11, b"\x01\x00")
sh = b"\x03\x03" + bytes(range(32, 64)) + b"\x00" + struct.pack("!H", cipher) + b"\x00" + struct.pack("!H", len(sexts)) + sexts
sh = b"\x02" + struct.pack("!I", len(sh))[1:] + sh
shrec = b"\x16\x03\x03" + struct.pack("!H", len(sh)) + sh
frames, t = [], [1_700_000_000, 0]
cs, ss = 1000, 5000
frames.append(pkt(C, Sv, CP, SP, cs, 0, 0x02)); frames.append(pkt(Sv, C, SP, CP, ss, cs + 1, 0x12)); cs += 1; ss += 1
frames.append(pkt(C, Sv, CP, SP, cs, ss, 0x10))
frames.append(pkt(C, Sv, CP, SP, cs, ss, 0x18, chrec)); cs += len(chrec)
frames.append(pkt(Sv, C, SP, CP, ss, cs, 0x18, shrec)); ss += len(shrec)
sent = 0
while sent < extra:
    n = min(1400, extra - sent); data = b"\x17\x03\x03" + struct.pack("!H", n - 5) + os.urandom(n - 5) if n > 5 else os.urandom(n)
    frames.append(pkt(C, Sv, CP, SP, cs, ss, 0x18, data)); cs += n; sent += n
frames.append(pkt(C, Sv, CP, SP, cs, ss, 0x11)); frames.append(pkt(Sv, C, SP, CP, ss, cs + 1, 0x11)); frames.append(pkt(C, Sv, CP, SP, cs + 1, ss + 1, 0x10))
with open(out, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for i, fr in enumerate(frames):
        f.write(struct.pack("<IIII", 1_700_000_000, i * 1000, len(fr), len(fr)) + fr)
print(out, len(frames), "frames")
