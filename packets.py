"""Read classic Ethernet PCAP files and decode unfragmented IPv4 TCP/UDP."""
import socket
import struct
from dataclasses import dataclass


class CaptureError(ValueError):
    pass


class PacketError(ValueError):
    pass


@dataclass(frozen=True)
class TCPPacket:
    source: tuple
    destination: tuple
    sequence: int
    acknowledgement: int
    flags: int
    payload: bytes


@dataclass(frozen=True)
class UDPPacket:
    source: tuple
    destination: tuple
    payload: bytes


@dataclass(frozen=True)
class CaptureRecord:
    timestamp: float
    data: bytes
    original_length: int
    linktype: int

    @property
    def truncated(self):
        return len(self.data) < self.original_length


def read_pcap(path):
    """Legacy (timestamp, frame) API; reject records that would hide truncation.

    Use read_pcap_records to handle captured/original lengths explicitly.
    """
    for record in read_pcap_records(path):
        if record.truncated:
            raise CaptureError("Capture truncation; use read_pcap_records for metadata")
        yield record.timestamp, record.data


def read_pcap_records(path):
    """Yield Ethernet CaptureRecord objects, retaining original wire length."""
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1000000),
        b"\xa1\xb2\xc3\xd4": (">", 1000000),
        b"\x4d\x3c\xb2\xa1": ("<", 1000000000),
        b"\xa1\xb2\x3c\x4d": (">", 1000000000),
    }
    with open(path, "rb") as capture:
        header = capture.read(24)
        if header[:4] == b"\x0a\x0d\x0d\x0a":
            raise CaptureError("PCAPNG unsupported; export as classic PCAP")
        if len(header) != 24 or header[:4] not in formats:
            raise CaptureError("Missing or invalid classic PCAP header")
        endian, resolution = formats[header[:4]]
        major, minor, _, _, snaplen, linktype = struct.unpack(endian + "HHIIII", header[4:])
        if (major, minor) != (2, 4) or not 1 <= snaplen <= 1048576:
            raise CaptureError("Unsupported PCAP version or snapshot length")
        if linktype != 1:
            raise CaptureError("Only plain Ethernet link type 1 is supported")
        while True:
            record = capture.read(16)
            if not record:
                return
            if len(record) != 16:
                raise CaptureError("Truncated PCAP record header")
            seconds, fraction, included, original = struct.unpack(endian + "IIII", record)
            if included > snaplen or included > original or fraction >= resolution:
                raise CaptureError("Invalid PCAP record lengths or timestamp")
            frame = capture.read(included)
            if len(frame) != included:
                raise CaptureError("Truncated PCAP record data")
            # A captured frame may be shorter than its original wire length.
            yield CaptureRecord(seconds + fraction / resolution, frame, original, linktype)


def _ipv4(frame):
    if len(frame) < 14:
        raise PacketError("Truncated Ethernet header")
    offset = 14
    ethertype = int.from_bytes(frame[12:14], "big")
    tags = 0
    while ethertype in (0x8100, 0x88a8):
        if tags == 2 or len(frame) < offset + 4:
            raise PacketError("Unsupported or truncated VLAN tags")
        ethertype = int.from_bytes(frame[offset + 2:offset + 4], "big")
        offset += 4
        tags += 1
    if ethertype != 0x0800:
        raise PacketError("Unsupported network protocol (only IPv4)")
    ip = frame[offset:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        raise PacketError("Invalid IPv4 header")
    ip_length = (ip[0] & 15) * 4
    total = int.from_bytes(ip[2:4], "big")
    if ip_length < 20 or total < ip_length or total > len(ip):
        raise PacketError("Invalid or truncated IPv4 length")
    if int.from_bytes(ip[6:8], "big") & 0xbfff:
        raise PacketError("IPv4 fragments/reserved flag unsupported")
    return ip[:total]


def _tcp(ip):
    ip_length = (ip[0] & 15) * 4
    if ip[9] != 6:
        raise PacketError("Unsupported transport (expected TCP)")
    total = len(ip)
    tcp = ip[ip_length:total]
    if len(tcp) < 20:
        raise PacketError("Truncated TCP header")
    tcp_length = (tcp[12] >> 4) * 4
    if tcp_length < 20 or tcp_length > len(tcp):
        raise PacketError("Invalid TCP header length")
    source_port, destination_port, sequence, ack = struct.unpack("!HHII", tcp[:12])
    return TCPPacket(
        (socket.inet_ntoa(ip[12:16]), source_port),
        (socket.inet_ntoa(ip[16:20]), destination_port),
        sequence, ack, tcp[13], tcp[tcp_length:],
    )


def decode_tcp(frame):
    """Compatibility API: reject transports other than TCP."""
    return _tcp(_ipv4(frame))


def decode_packet(frame):
    ip = _ipv4(frame)
    if ip[9] == 6:
        return _tcp(ip)
    if ip[9] != 17:
        raise PacketError("Unsupported transport (only TCP and UDP)")
    udp = ip[(ip[0] & 15) * 4:]
    if len(udp) < 8:
        raise PacketError("Truncated UDP header")
    source, destination, size = struct.unpack("!HHH", udp[:6])
    if size < 8 or size != len(udp):
        raise PacketError("UDP length disagrees with IPv4 payload")
    return UDPPacket((socket.inet_ntoa(ip[12:16]), source),
                     (socket.inet_ntoa(ip[16:20]), destination), udp[8:])
