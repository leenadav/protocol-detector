"""Generate synthetic Ethernet/IPv4 TCP/UDP packets on disk; never transmit."""
import argparse
import socket
import struct
from pathlib import Path

A, B = ("192.0.2.10", 52000), ("192.0.2.20", 8080)
C, D = ("192.0.2.10", 52001), ("192.0.2.30", 443)
REQUEST = b"DELETE / HTTP/1.1\r\nHost: example.com\r\n\r\n"


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!{}H".format(len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def frame(source, destination, sequence, ack, flags, payload=b""):
    src, dst = socket.inet_aton(source[0]), socket.inet_aton(destination[0])
    tcp = struct.pack("!HHIIBBHHH", source[1], destination[1], sequence, ack,
                      5 << 4, flags, 65535, 0, 0) + payload
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0x4000,
                     64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    ethernet = bytes.fromhex("0200000000020200000000010800")
    return (ethernet + ip + tcp).ljust(60, b"\x00")


def sample_frames():
    return [
        frame(A, B, 999, 0, 2),
        frame(B, A, 8999, 1000, 18),
        frame(A, B, 1000, 9000, 16),
        frame(A, B, 1011, 9000, 24, REQUEST[11:]),
        frame(C, D, 1999, 0, 2),
        frame(D, C, 7999, 2000, 18),
        frame(C, D, 2000, 8000, 24, b"SSH-2.0-Demo_1.0\r\n"),
        frame(A, B, 1000, 9000, 24, REQUEST[:11]),
        frame(A, B, 1000, 9000, 24, REQUEST[:11]),
        frame(B, A, 9000, 1040, 24, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
        frame(A, B, 1040, 9038, 17),
        frame(B, A, 9038, 1041, 17),
    ]


def udp_frame(source, destination, payload):
    src, dst = socket.inet_aton(source[0]), socket.inet_aton(destination[0])
    size = 8 + len(payload)
    udp = struct.pack("!4H", source[1], destination[1], size, 0) + payload
    pseudo = src + dst + struct.pack("!BBH", 0, 17, size)
    udp = udp[:6] + struct.pack("!H", checksum(pseudo + udp) or 65535) + udp[8:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + size, 1, 0x4000, 64, 17, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return (bytes.fromhex("0200000000020200000000010800") + ip + udp).ljust(60, b"\x00")


def expanded_frames():
    from protocol_fixtures import STREAM_CASES, DATAGRAM_CASES
    frames = []
    for index, (payload, _) in enumerate(STREAM_CASES):
        source, destination = ("192.0.2.10", 50000 + index), ("192.0.2.20", 40000 + index)
        split = len(payload) // 2
        frames.extend((frame(source, destination, 999, 0, 2),
                       frame(destination, source, 8999, 1000, 18),
                       frame(source, destination, 1000 + split, 9000, 24, payload[split:]),
                       frame(source, destination, 1000, 9000, 24, payload[:split])))
    for index, (payload, _) in enumerate(DATAGRAM_CASES):
        frames.append(udp_frame(("192.0.2.10", 55000), ("192.0.2.20", 45000 + index), payload))
    return frames


def database_frames(hint):
    from protocol_fixtures import HINTED_STREAM_CASES
    payload = next(data for data, _, candidate in HINTED_STREAM_CASES if candidate == hint)
    # MySQL starts from server; MongoDB OP_MSG fixture is a client request.
    source, destination, sequence, acknowledgement = (B, A, 9000, 1000) if hint == 'mysql' else (A, B, 1000, 9000)
    cut = len(payload) // 2
    return [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18),
            frame(source, destination, sequence + cut, acknowledgement, 24, payload[cut:]),
            frame(source, destination, sequence, acknowledgement, 24, payload[:cut])]


def pcap_bytes(frames, endian="<", nano=False):
    magic = 0xa1b23c4d if nano else 0xa1b2c3d4
    data = struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, 1)
    for index, packet in enumerate(frames):
        data += struct.pack(endian + "IIII", 1700000000 + index, 0, len(packet), len(packet)) + packet
    return data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", nargs="?", default="sample.pcap")
    profile = parser.add_mutually_exclusive_group()
    profile.add_argument("--expanded", action="store_true", help="Include all current automatic TCP/UDP fixture profiles")
    profile.add_argument('--database', choices=('mysql', 'mongodb'), help='Synthetic explicit-candidate TCP fixture')
    profile.add_argument('--radius', action='store_true', help='Synthetic explicit-candidate RADIUS UDP fixture')
    args = parser.parse_args()
    from protocol_fixtures import RADIUS
    # Do not silently replace a user's recording.
    with Path(args.output).open("xb") as output:
        output.write(pcap_bytes([udp_frame(A, B, RADIUS)] if args.radius else database_frames(args.database) if args.database else expanded_frames() if args.expanded else sample_frames()))
    print("Created synthetic capture: " + args.output)


def _block(endian, kind, body):
    total = 12 + ((len(body) + 3) & ~3)
    return struct.pack(endian + "II", kind, total) + body + bytes(total - 12 - len(body)) + struct.pack(endian + "I", total)


def pcapng_option(endian, code, value):
    return struct.pack(endian + "HH", code, len(value)) + value + bytes((-len(value)) % 4)


def pcapng_bytes(frames, endian="<", tsresol=None, linktype=1, snaplen=65535, simple=False, extra_blocks=(), interfaces=1):
    """pcapng capture: one SHB, `interfaces` IDBs, then EPBs (or SPBs) for each frame.

    tsresol is the raw if_tsresol byte (None omits the option: microseconds).
    extra_blocks are inserted after the interface descriptions as (kind, body).
    """
    bom = 0x1A2B3C4D
    section = struct.pack(endian + "IHHq", bom, 1, 0, -1) + pcapng_option(endian, 0, b"")
    data = _block(endian, 0x0A0D0D0A, section)
    options = (pcapng_option(endian, 9, bytes([tsresol])) if tsresol is not None else b"") + pcapng_option(endian, 0, b"")
    for _ in range(interfaces):
        data += _block(endian, 1, struct.pack(endian + "HHI", linktype, 0, snaplen) + options)
    for kind, body in extra_blocks:
        data += _block(endian, kind, body)
    resolution = 1000000 if tsresol is None else ((1 << (tsresol & 0x7f)) if tsresol & 0x80 else 10 ** tsresol)
    for index, packet in enumerate(frames):
        if simple:
            data += _block(endian, 3, struct.pack(endian + "I", len(packet)) + (packet[:snaplen] if snaplen else packet))
        else:
            stamp = (1700000000 + index) * resolution
            data += _block(endian, 6, struct.pack(endian + "IIIII", index % interfaces, stamp >> 32, stamp & 0xffffffff, len(packet), len(packet)) + packet)
    return data
