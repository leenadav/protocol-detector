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
    """Yield CaptureRecord objects (classic PCAP or pcapng), retaining original wire length.

    Frames keep their link type; supported types are those of capture_stream.LINK_TYPES.
    """
    from capture_stream import PcapStreamDecoder
    decoder = PcapStreamDecoder()
    with open(path, "rb") as capture:
        while True:
            chunk = capture.read(65536)
            if not chunk:
                break
            for record in decoder.feed(chunk):
                yield record
    decoder.end()


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
