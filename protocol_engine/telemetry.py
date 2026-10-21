"""Discovery and export datagrams: SSDP, NetFlow v5/v9, IPFIX, sFlow v5."""
import struct
from .parsers import BudgetError, LineParser, ParseError
from .extended import UnsupportedPrefix


def ssdp_probe(data):
    return data[:9] == b"M-SEARCH " or data[:7] == b"NOTIFY " or data[:15] == b"HTTP/1.1 200 OK"


def ssdp(data, config):
    """HTTPU request/response with SSDP-specific headers (MAN/NTS/ST/USN)."""
    if not ssdp_probe(data):
        raise UnsupportedPrefix("Outside SSDP M-SEARCH/NOTIFY/response start lines")
    parser = LineParser(config, "http")
    consumed = parser.feed(data)
    if not parser.done or consumed != len(data):
        raise ParseError("SSDP message must be exactly one complete HTTP header block")
    head = data.lower()
    if data[:9] == b"M-SEARCH ":
        if b"\r\nman: \"ssdp:discover\"\r\n" not in head or b"\r\nst:" not in head:
            raise ParseError("SSDP M-SEARCH requires MAN ssdp:discover and ST headers")
        kind = "search"
    elif data[:7] == b"NOTIFY ":
        if b"\r\nnts: ssdp:" not in head or b"\r\nnt:" not in head:
            raise ParseError("SSDP NOTIFY requires NTS and NT headers")
        kind = "notify"
    else:
        if b"\r\nst:" not in head or b"\r\nusn:" not in head:
            raise ParseError("SSDP response requires ST and USN headers")
        kind = "response"
    return "ssdp", "SSDP {} header framing validated; device descriptions and locations are not emitted".format(kind)


def netflow(data, config):
    """NetFlow v5 fixed records, NetFlow v9 flowsets or IPFIX sets, bounded by count/length."""
    if len(data) < 16:
        raise ParseError("Flow export header too short")
    version = int.from_bytes(data[:2], "big")
    if version == 5:
        count = int.from_bytes(data[2:4], "big")
        if not 1 <= count <= 30:
            raise ParseError("NetFlow v5 count outside 1..30")
        if len(data) != 24 + 48 * count:
            raise ParseError("NetFlow v5 datagram length disagrees with record count")
        for index in range(count):
            record = data[24 + 48 * index:72 + 48 * index]
            if int.from_bytes(record[16:20], "big") == 0 or int.from_bytes(record[20:24], "big") == 0:
                raise ParseError("NetFlow v5 record requires nonzero packet and byte counters")
            if record[36] or record[46:48] != b"\x00\x00":
                raise ParseError("NetFlow v5 record padding must be zero")
        return "netflow/5", "NetFlow v5 header and {} records framed; counters and addresses are not emitted".format(count)
    if version == 9:
        count = int.from_bytes(data[2:4], "big")
        if not 1 <= count <= min(config.max_headers, 128):
            raise BudgetError("NetFlow v9 record count outside budget")
        if len(data) < 20:
            raise ParseError("NetFlow v9 header too short")
        pos, flowsets = 20, 0
        while pos < len(data):
            flowsets += 1
            if flowsets > min(config.max_headers, 128):
                raise BudgetError("NetFlow v9 flowset count exceeds budget")
            if pos + 4 > len(data):
                raise ParseError("Truncated NetFlow v9 flowset header")
            identifier, length = struct.unpack("!HH", data[pos:pos + 4])
            if length < 4 or pos + length > len(data) or length % 4:
                raise ParseError("NetFlow v9 flowset length invalid")
            if 1 < identifier < 256:
                raise ParseError("NetFlow v9 flowset id reserved")
            if identifier == 0 and length < 8:
                raise ParseError("NetFlow v9 template flowset too short")
            pos += length
        if not flowsets:
            raise ParseError("NetFlow v9 header without flowsets")
        return "netflow/9", "NetFlow v9 header and {} flowsets framed; templates and records are not decoded".format(flowsets)
    if version == 10:
        length = int.from_bytes(data[2:4], "big")
        if length != len(data) or length < 20:
            raise ParseError("IPFIX message length disagrees with datagram")
        pos, sets = 16, 0
        while pos < length:
            sets += 1
            if sets > min(config.max_headers, 128):
                raise BudgetError("IPFIX set count exceeds budget")
            if pos + 4 > length:
                raise ParseError("Truncated IPFIX set header")
            identifier, size = struct.unpack("!HH", data[pos:pos + 4])
            if size < 4 or pos + size > length or identifier in (0, 1) or 3 < identifier < 256:
                raise ParseError("IPFIX set id or length invalid")
            pos += size
        if not sets:
            raise ParseError("IPFIX message without sets")
        return "ipfix", "IPFIX message header and {} sets framed; templates and records are not decoded".format(sets)
    raise UnsupportedPrefix("Flow export version outside NetFlow v5/v9 and IPFIX")


def netflow_probe(data):
    return len(data) >= 16 and data[0] == 0 and data[1] in (5, 9, 10)


def sflow(data, config):
    """sFlow v5 datagram (sflow.org specification): agent address, sequence, uptime, samples."""
    if len(data) < 28 or data[:4] != b"\0\0\0\x05":
        raise UnsupportedPrefix("Outside sFlow v5 datagram header")
    address_type = int.from_bytes(data[4:8], "big")
    if address_type != 1:
        raise UnsupportedPrefix("sFlow profile covers IPv4 agent addresses")
    pos = 12  # version, address type, IPv4 agent address
    sub_agent, sequence, uptime, samples = struct.unpack("!IIII", data[pos:pos + 16])
    pos += 16
    if not 1 <= samples <= min(config.max_headers, 64):
        raise BudgetError("sFlow sample count outside budget")
    for _ in range(samples):
        if pos + 8 > len(data):
            raise ParseError("Truncated sFlow sample header")
        kind, length = struct.unpack("!II", data[pos:pos + 8])
        if length < 8 or pos + 8 + length > len(data) or length % 4:
            raise ParseError("sFlow sample length invalid")
        if kind & 0xfff not in (1, 2, 3, 4):
            raise UnsupportedPrefix("sFlow sample type outside flow/counter samples")
        pos += 8 + length
    if pos != len(data):
        raise ParseError("Trailing bytes after sFlow samples")
    return "sflow/5", "sFlow v5 datagram and {} sample headers framed; sample contents are not decoded".format(samples)
