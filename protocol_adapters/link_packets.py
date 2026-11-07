"""Capture link framing plus bounded IPv4-only transport decoding.

Checksums are not verified (host captures may precede checksum offload).
IPv6 and fragmented IPv4 packets are unsupported.
"""
import socket
import struct
from .packets import PacketError, TCPPacket, UDPPacket


def network_payload(frame, linktype):
    expected = None
    if linktype == 1:
        if len(frame) < 14:
            raise PacketError("Truncated Ethernet header", "link")
        kind, offset, tags = int.from_bytes(frame[12:14], "big"), 14, 0
        while kind in (0x8100, 0x88a8):
            if tags == 2 or len(frame) < offset + 4:
                raise PacketError("Unsupported or truncated VLAN tags", "link")
            kind = int.from_bytes(frame[offset + 2:offset + 4], "big")
            offset += 4
            tags += 1
        expected = 4 if kind == 0x0800 else None
    elif linktype in (0, 108):
        if len(frame) < 4:
            raise PacketError("Truncated loopback header", "link")
        family = int.from_bytes(frame[:4], "big")
        if linktype == 0 and family != 2:
            family = int.from_bytes(frame[:4], "little")
        expected, offset = (4 if family == 2 else None), 4
    elif linktype in (113, 276):
        offset = 16 if linktype == 113 else 20
        if len(frame) < offset:
            raise PacketError("Truncated Linux cooked header", "link")
        kind = int.from_bytes(frame[14:16] if linktype == 113 else frame[:2], "big")
        expected = 4 if kind == 0x0800 else None
    elif linktype in (101, 228):
        offset = 0
        expected = 4
    else:
        raise PacketError("Unsupported capture link type (IPv4 only)", "link")
    ip = frame[offset:]
    if expected != 4 or not ip or ip[0] >> 4 != 4:
        raise PacketError("Unsupported or inconsistent network protocol (IPv4 only)", "network")
    return ip


CHECKSUM_POLICIES = ("ignore", "audit", "verify")


def _ones_complement(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def checksum_failures(ip, start, total, protocol, data):
    """Names of the checksums that do not verify on one IPv4 packet: 'ip', 'tcp', 'udp' (an all-zero UDP
    checksum is "not present", not a failure). Used only under the audit and verify policies: host captures
    taken before checksum offload show failures on every transmitted packet, which is why the default is
    ignore (D06)."""
    failures = []
    if _ones_complement(bytes(ip[:start])) != 0:
        failures.append("ip")
    pseudo = bytes(ip[12:20]) + bytes((0, protocol)) + (total - start).to_bytes(2, "big")
    if protocol == 6 and len(data) >= 20 and _ones_complement(pseudo + bytes(data)) != 0:
        failures.append("tcp")
    if protocol == 17 and len(data) >= 8 and data[6:8] != b"\x00\x00" and _ones_complement(pseudo + bytes(data)) != 0:
        failures.append("udp")
    return failures


def decode_frame(frame, linktype=1, checksums="ignore"):
    """Decode one captured frame into a TCPPacket or UDPPacket, or raise a typed PacketError.

    checksums: "ignore" (default: never computed; offload makes them meaningless on host captures), "audit"
    (computed, reported on the returned packet's `checksum_failures`, packet still decoded) or "verify"
    (a failure raises PacketError kind "checksum" with the endpoints).
    """
    if checksums not in CHECKSUM_POLICIES:
        raise ValueError("checksums must be one of " + ", ".join(CHECKSUM_POLICIES))
    ip = network_payload(frame, linktype)
    if len(ip) < 20:
        raise PacketError("Truncated IPv4 header", "length")
    start, total = (ip[0] & 15) * 4, int.from_bytes(ip[2:4], "big")
    if start < 20 or total < start or total > len(ip):
        raise PacketError("Invalid or truncated IPv4 length", "length")
    protocol, source, destination = ip[9], socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
    data = ip[start:total]
    flags_offset = int.from_bytes(ip[6:8], "big")
    if flags_offset & 0xbfff:
        # IPv4 fragmentation is outside this adapter (D06): the first fragment still carries the transport
        # header, so the affected flow can be named and marked as not fully inspected.
        endpoints = None
        if flags_offset & 0x1fff == 0 and protocol in (6, 17) and len(data) >= 4:
            sport, dport = struct.unpack("!HH", data[:4])
            endpoints = ((source, sport), (destination, dport))
        raise PacketError("IPv4 fragments/reserved flag unsupported", "fragment", endpoints)
    failures = checksum_failures(ip, start, total, protocol, data) if checksums != "ignore" and protocol in (6, 17) else []
    if protocol == 6:
        if len(data) < 20:
            raise PacketError("Truncated TCP header", "length")
        size = (data[12] >> 4) * 4
        sport, dport, sequence, ack = struct.unpack("!HHII", data[:12])
        if size < 20 or size > len(data):
            raise PacketError("Invalid TCP header length", "length", ((source, sport), (destination, dport)))
        if failures and checksums == "verify":
            raise PacketError("Checksum failure: " + ",".join(failures), "checksum", ((source, sport), (destination, dport)))
        return TCPPacket((source, sport), (destination, dport), sequence, ack, data[13], data[size:], tuple(failures))
    if protocol == 17:
        if len(data) < 8:
            raise PacketError("Truncated UDP header", "length")
        sport, dport, size = struct.unpack("!HHH", data[:6])
        if size < 8 or size != len(data):
            raise PacketError("UDP length disagrees with IP payload", "length", ((source, sport), (destination, dport)))
        if failures and checksums == "verify":
            raise PacketError("Checksum failure: " + ",".join(failures), "checksum", ((source, sport), (destination, dport)))
        return UDPPacket((source, sport), (destination, dport), data[8:], tuple(failures))
    raise PacketError("Unsupported IP transport", "transport")
