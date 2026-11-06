"""Capture link framing plus bounded IPv4-only transport decoding.

Checksums are not verified (host captures may precede checksum offload).
IPv6 and fragmented IPv4 packets are unsupported.
"""
import socket
import struct
from packets import PacketError, TCPPacket, UDPPacket


def network_payload(frame, linktype):
    expected = None
    if linktype == 1:
        if len(frame) < 14:
            raise PacketError("Truncated Ethernet header")
        kind, offset, tags = int.from_bytes(frame[12:14], "big"), 14, 0
        while kind in (0x8100, 0x88a8):
            if tags == 2 or len(frame) < offset + 4:
                raise PacketError("Unsupported or truncated VLAN tags")
            kind = int.from_bytes(frame[offset + 2:offset + 4], "big")
            offset += 4
            tags += 1
        expected = 4 if kind == 0x0800 else None
    elif linktype in (0, 108):
        if len(frame) < 4:
            raise PacketError("Truncated loopback header")
        family = int.from_bytes(frame[:4], "big")
        if linktype == 0 and family != 2:
            family = int.from_bytes(frame[:4], "little")
        expected, offset = (4 if family == 2 else None), 4
    elif linktype in (113, 276):
        offset = 16 if linktype == 113 else 20
        if len(frame) < offset:
            raise PacketError("Truncated Linux cooked header")
        kind = int.from_bytes(frame[14:16] if linktype == 113 else frame[:2], "big")
        expected = 4 if kind == 0x0800 else None
    elif linktype in (101, 228):
        offset = 0
        expected = 4
    else:
        raise PacketError("Unsupported capture link type (IPv4 only)")
    ip = frame[offset:]
    if expected != 4 or not ip or ip[0] >> 4 != 4:
        raise PacketError("Unsupported or inconsistent network protocol (IPv4 only)")
    return ip


def decode_frame(frame, linktype=1):
    ip = network_payload(frame, linktype)
    if len(ip) < 20:
        raise PacketError("Truncated IPv4 header")
    start, total = (ip[0] & 15) * 4, int.from_bytes(ip[2:4], "big")
    if start < 20 or total < start or total > len(ip):
        raise PacketError("Invalid or truncated IPv4 length")
    if int.from_bytes(ip[6:8], "big") & 0xbfff:
        raise PacketError("IPv4 fragments/reserved flag unsupported")
    protocol, source, destination = ip[9], socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
    data = ip[start:total]
    if protocol == 6:
        if len(data) < 20:
            raise PacketError("Truncated TCP header")
        size = (data[12] >> 4) * 4
        if size < 20 or size > len(data):
            raise PacketError("Invalid TCP header length")
        sport, dport, sequence, ack = struct.unpack("!HHII", data[:12])
        return TCPPacket((source, sport), (destination, dport), sequence, ack, data[13], data[size:])
    if protocol == 17:
        if len(data) < 8:
            raise PacketError("Truncated UDP header")
        sport, dport, size = struct.unpack("!HHH", data[:6])
        if size < 8 or size != len(data):
            raise PacketError("UDP length disagrees with IP payload")
        return UDPPacket((source, sport), (destination, dport), data[8:])
    raise PacketError("Unsupported IP transport")
