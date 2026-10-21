"""RIP v1/v2 datagrams (RFC 1058, RFC 2453) and, with a hint, RTCP compound packets (RFC 3550).

RIP: command, version, zero field and 1..25 twenty-byte entries; v2 may open
with an authentication entry (simple password or MD5 with its trailer). The
password is read for framing only and never emitted. RTCP: the fixed header is
too weak to select itself, so the profile applies with the `rtcp` hint only;
the compound packet must start with SR or RR and every packet length must fit.
"""
from .datagram_result import DatagramMatch
from .extended import UnsupportedPrefix
from .model import Evidence
from .parsers import ParseError

RIP_ENTRY = 20
MAX_RIP_ENTRIES = 25
_RIP_COMMANDS = {1: "request", 2: "response"}
RTCP_TYPES = {200: "sr", 201: "rr", 202: "sdes", 203: "bye", 204: "app", 205: "rtpfb", 206: "psfb", 207: "xr"}
MAX_RTCP_PACKETS = 8


def rip(data, config):
    if len(data) < 4 + RIP_ENTRY or (len(data) - 4) % RIP_ENTRY:
        raise ParseError("RIP datagram is a header plus 20-byte entries")
    command, version = data[0], data[1]
    if command not in _RIP_COMMANDS or version not in (1, 2):
        raise UnsupportedPrefix("RIP profile covers request/response of versions 1 and 2")
    if data[2:4] != b"\x00\x00":
        raise ParseError("RIP header zero field must be zero")
    count = (len(data) - 4) // RIP_ENTRY
    if count > MAX_RIP_ENTRIES:
        raise ParseError("RIP datagram exceeds 25 entries")
    authentication = "none"
    pos = 4
    end = len(data)
    if version == 2 and data[4:6] == b"\xff\xff":
        kind = int.from_bytes(data[6:8], "big")
        if kind == 2:
            authentication = "simple-password"
        elif kind == 3:
            authentication = "md5"
            if count < 2 or data[end - RIP_ENTRY:end - RIP_ENTRY + 4] != b"\xff\xff\x00\x01":
                raise ParseError("RIP MD5 authentication requires a trailer entry")
            if data[8:10] != (len(data) - RIP_ENTRY).to_bytes(2, "big") or data[11] != 16:
                raise ParseError("RIP MD5 authentication header fields outside the specification")
            end -= RIP_ENTRY
        else:
            raise ParseError("RIP authentication type outside the specification")
        pos += RIP_ENTRY
        if pos >= end:
            raise ParseError("RIP authentication without routing entries")
    whole_table = command == 1 and end - pos == RIP_ENTRY and data[pos:pos + 2] == b"\x00\x00"
    while pos < end:
        family = int.from_bytes(data[pos:pos + 2], "big")
        metric = int.from_bytes(data[pos + 16:pos + 20], "big")
        if whole_table:
            if any(data[pos + 2:pos + 16]) or metric != 16:
                raise ParseError("RIP whole-table request must be family zero, address zero, metric 16")
        else:
            if family != 2:
                raise ParseError("RIP entry address family must be IP")
            if not 1 <= metric <= 16:
                raise ParseError("RIP metric outside 1..16")
            if version == 1 and (any(data[pos + 2:pos + 4]) or any(data[pos + 8:pos + 16])):
                raise ParseError("RIP v1 entries must zero the route tag, mask and next hop")
        pos += RIP_ENTRY
    protocol = "rip/" + str(version)
    return _match(protocol, "RIP {} validated; routes and password not emitted".format(_RIP_COMMANDS[command]),
                  (("rip_command", _RIP_COMMANDS[command]), ("rip_authentication", authentication)))


def rtcp(data, config):
    if len(data) < 8:
        raise ParseError("RTCP packet shorter than its header")
    pos, packets, first = 0, 0, None
    while pos < len(data):
        if len(data) - pos < 4:
            raise ParseError("Truncated RTCP packet header")
        if data[pos] >> 6 != 2:
            raise UnsupportedPrefix("RTCP profile requires version 2")
        kind = data[pos + 1]
        if kind not in RTCP_TYPES:
            raise UnsupportedPrefix("RTCP packet type outside the specification")
        if first is None:
            if kind not in (200, 201):
                raise ParseError("RTCP compound packet must begin with SR or RR")
            first = kind
        length = 4 * (int.from_bytes(data[pos + 2:pos + 4], "big") + 1)
        count = data[pos] & 0x1f
        if kind == 200 and length < 28 + 24 * count:
            raise ParseError("RTCP SR shorter than its sender info and report blocks")
        if kind == 201 and length < 8 + 24 * count:
            raise ParseError("RTCP RR shorter than its report blocks")
        if kind == 203 and length < 4 + 4 * count:
            raise ParseError("RTCP BYE shorter than its source list")
        if pos + length > len(data):
            raise ParseError("RTCP packet length exceeds the datagram")
        packets += 1
        if packets > MAX_RTCP_PACKETS:
            raise ParseError("RTCP compound packet exceeds the packet budget")
        pos += length
    return _match("rtcp", "RTCP compound packet framing validated with a candidate hint; reports not decoded",
                  (("rtcp_packet", RTCP_TYPES[first]), ("rtcp_packets", str(packets))))


def _match(protocol, reason, rows):
    return DatagramMatch(reason, application_protocol=protocol,
                         evidence=(Evidence("application_protocol", protocol, "wire", "structural"),)
                         + tuple(Evidence(field, value, "wire:header", "structural") for field, value in rows))
