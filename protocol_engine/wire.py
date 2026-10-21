"""Complete-message validators shared by stream framing and datagram inspection.

No ports, I/O, application attribution or payload values in diagnostic messages.
"""
import struct
import zlib
from .datagram_result import DatagramMatch
from .model import Evidence
from .parsers import BudgetError, ParseError
from .extended import UnsupportedPrefix


def dns_probe(data):
    return (len(data) >= 12 and data[2] & 0x78 == 0 and not data[3] & 0x40
            and data[4:6] == b"\x00\x01")


_DNS_RCODES = ("noerror", "formerr", "servfail", "nxdomain", "notimp", "refused", "yxdomain", "yxrrset", "nxrrset", "notauth", "notzone")
# Evidence rows are immutable; the sixteen possible header outcomes are built once (hot UDP path).
_DNS_QUERY_EVIDENCE = (Evidence("dns_message", "query", "wire", "structural"),)
_DNS_RESPONSE_EVIDENCE = tuple((Evidence("dns_message", "response", "wire", "structural"),
                                Evidence("dns_rcode", _DNS_RCODES[code] if code < len(_DNS_RCODES) else "other", "wire", "structural"))
                               for code in range(16))
_DNS_PROTOCOL_EVIDENCE = (Evidence("application_protocol", "dns", "wire", "structural"),)


def dns_message_evidence(header):
    """(dns_message, dns_rcode) evidence rows for a validated header; query or response, no names."""
    if not header[2] & 0x80:
        return _DNS_QUERY_EVIDENCE
    return _DNS_RESPONSE_EVIDENCE[header[3] & 0x0f]


def dns(data, config):
    protocol, reason, _, _ = dns_details(data, config)
    return DatagramMatch(reason, application_protocol=protocol, evidence=_DNS_PROTOCOL_EVIDENCE + dns_message_evidence(data))


def dns_details(data, config):
    """Validate; return (protocol, reason, qname bytes, qtype) for signature contexts."""
    if not dns_probe(data):
        raise UnsupportedPrefix("DNS profile requires QUERY opcode and one question")
    if data[2] & 2:
        raise UnsupportedPrefix("Truncated DNS messages require transport retry")
    counts = struct.unpack("!4H", data[4:12])
    if sum(counts) > 128:
        raise BudgetError("DNS record count exceeds inspection limit")
    if not data[2] & 0x80 and (data[2] & 0x04 or data[3] & 0x0f or counts[1] or counts[2]):
        raise ParseError("DNS query must not carry the AA bit, answers, authority records or a response code")
    steps = 0
    boundaries = set()

    def name(start):
        nonlocal steps
        pos, end, size = start, None, 1
        visited = set()
        while True:
            steps += 1
            if steps > config.max_bytes:
                raise BudgetError("DNS name work budget exhausted")
            if pos >= len(data) or pos in visited:
                raise ParseError("Truncated or cyclic DNS name")
            visited.add(pos)
            length = data[pos]
            if length & 0xc0 == 0xc0:
                if pos + 1 >= len(data):
                    raise ParseError("Truncated DNS compression pointer")
                target = ((length & 63) << 8) | data[pos + 1]
                if target >= pos or target not in boundaries:
                    raise ParseError("DNS pointer must reference an earlier parsed name boundary")
                if end is None:
                    end = pos + 2
                pos = target
                continue
            if length & 0xc0 or pos + 1 + length > len(data):
                raise ParseError("Invalid DNS label length")
            boundaries.add(pos)
            pos += 1
            if not length:
                return end if end is not None else pos
            size += 1 + length
            if size > 255:
                raise ParseError("DNS expanded name exceeds 255 bytes")
            pos += length

    pos = name(12)
    if pos + 4 > len(data):
        raise ParseError("Truncated DNS question")
    qname = _expand_name(data, 12, pos)
    qtype, qclass = struct.unpack("!HH", data[pos:pos + 4])
    if not qtype or qclass & 0x7fff not in (1, 255):
        raise UnsupportedPrefix("Unsupported DNS question type/class profile")
    pos += 4
    for _ in range(sum(counts[1:])):
        pos = name(pos)
        if pos + 10 > len(data):
            raise ParseError("Truncated DNS resource record")
        kind, _, _, size = struct.unpack("!HHIH", data[pos:pos + 10])
        pos += 10
        end = pos + size
        if end > len(data):
            raise ParseError("DNS RDATA exceeds message")
        if kind in (1, 28) and size != (4 if kind == 1 else 16):
            raise ParseError("Invalid DNS address record size")
        if kind in (2, 5, 12) and name(pos) != end:
            raise ParseError("Invalid DNS name RDATA length")
        if kind == 15 and (size < 3 or name(pos + 2) != end):
            raise ParseError("Invalid DNS MX RDATA")
        if kind == 6 and name(name(pos)) + 20 != end:
            raise ParseError("Invalid DNS SOA RDATA")
        if kind == 16:
            cursor = pos
            while cursor < end:
                cursor += 1 + data[cursor]
            if cursor != end:
                raise ParseError("Invalid DNS TXT RDATA")
        if kind == 41:
            cursor = pos
            while cursor < end:
                if cursor + 4 > end:
                    raise ParseError("Truncated EDNS option")
                cursor += 4 + int.from_bytes(data[cursor + 2:cursor + 4], "big")
            if cursor != end:
                raise ParseError("Invalid EDNS option length")
        pos = end
    if pos != len(data):
        raise ParseError("Trailing bytes after DNS sections")
    return "dns", "DNS question and record framing validated; unknown RDATA semantics and DNSSEC unverified", qname, qtype


def _expand_name(data, start, end):
    """Lowercase dotted question name from already validated labels (no pointers in a question start)."""
    labels, pos = [], start
    while pos < end:
        length = data[pos]
        if length & 0xc0:
            break  # compressed question names are validated but not expanded for contexts
        pos += 1
        if not length:
            break
        labels.append(data[pos:pos + length].lower())
        pos += length
    return b".".join(labels)


def stun(data, config):
    if len(data) < 20 or data[0] & 0xc0 or data[4:8] != b"\x21\x12\xa4\x42":
        raise ParseError("Invalid STUN header")
    length = int.from_bytes(data[2:4], "big")
    kind = int.from_bytes(data[:2], "big")
    method = (kind & 15) | ((kind >> 1) & 0x70) | ((kind >> 2) & 0xf80)
    if method != 1:
        raise UnsupportedPrefix("Only STUN Binding method is supported; TURN methods need separate validation")
    if length % 4 or length + 20 != len(data):
        raise ParseError("Invalid STUN message length")
    pos, count = 20, 0
    while pos < len(data):
        count += 1
        if count > 128:
            raise BudgetError("STUN attribute count exceeds inspection limit")
        if pos + 4 > len(data):
            raise ParseError("Truncated STUN attribute")
        tag, size = struct.unpack("!HH", data[pos:pos + 4])
        end = pos + 4 + size
        padded = pos + 4 + ((size + 3) & ~3)
        if padded > len(data):
            raise ParseError("STUN attribute exceeds message")
        if tag in (0x0001, 0x0020):
            value = data[pos + 4:end]
            if size not in (8, 20) or value[0] != 0 or (value[1], size) not in ((1, 8), (2, 20)):
                raise ParseError("Invalid STUN address attribute")
        if tag == 0x0008 and size != 20:
            raise ParseError("Invalid STUN MESSAGE-INTEGRITY size")
        if tag == 0x001c and (size < 16 or size > 32 or size % 4):
            raise ParseError("Invalid STUN SHA256 integrity size")
        if tag == 0x8028:
            if size != 4 or padded != len(data):
                raise ParseError("STUN FINGERPRINT must be the last four-byte attribute")
            expected = (zlib.crc32(data[:pos]) & 0xffffffff) ^ 0x5354554e
            if int.from_bytes(data[pos + 4:end], "big") != expected:
                raise ParseError("STUN FINGERPRINT mismatch")
        pos = padded
    return "stun", "STUN Binding framing validated; optional fingerprint checked, HMAC and peer identity unverified"


def dhcp(data, config):
    if len(data) < 241 or data[236:240] != b"\x63\x82\x53\x63":
        raise ParseError("Invalid DHCPv4 fixed header/cookie")
    if data[0] not in (1, 2) or not 1 <= data[2] <= 16 or data[1] == 0:
        raise ParseError("Invalid DHCPv4 operation or hardware address length")
    if int.from_bytes(data[10:12], "big") & 0x7fff:
        raise ParseError("Reserved DHCPv4 flags set")
    pos, message_type, count = 240, None, 0
    while pos < len(data):
        code = data[pos]
        pos += 1
        if code == 0:
            continue
        if code == 255:
            if message_type is None or any(data[pos:]):
                raise ParseError("Missing DHCP message type or non-padding after END")
            expected = 1 if message_type in (1, 3, 4, 7, 8) else 2
            if data[0] != expected:
                raise ParseError("DHCP message type conflicts with operation")
            return "dhcp/4", "DHCPv4 header and option framing validated; lease state and option semantics unverified"
        count += 1
        if count > 128:
            raise BudgetError("DHCP option count exceeds inspection limit")
        if pos >= len(data) or pos + 1 + data[pos] > len(data):
            raise ParseError("Truncated DHCP option")
        size = data[pos]
        value = data[pos + 1:pos + 1 + size]
        pos += 1 + size
        if code == 52:
            raise UnsupportedPrefix("DHCP overloaded option fields are outside this profile")
        if code == 53:
            if size != 1 or message_type is not None or not 1 <= value[0] <= 8:
                raise ParseError("Invalid or duplicate DHCP message type")
            message_type = value[0]
    raise ParseError("DHCP options require END")


def coap(data, config):
    if len(data) < 4 or data[0] >> 6 != 1 or (data[0] & 15) > 8:
        raise ParseError("Invalid CoAP v1 header/token length")
    token = data[0] & 15
    kind, code = (data[0] >> 4) & 3, data[1]
    if not code:
        if token or len(data) != 4 or kind == 1:
            raise ParseError("Invalid CoAP empty message")
        return "coap", "CoAP empty-message framing only; no peer authentication"
    if code >> 5 not in (0, 2, 4, 5) or (code >> 5 == 0 and not 1 <= code <= 4):
        raise UnsupportedPrefix("Unsupported CoAP code profile")
    if kind == 3 or (code < 32 and kind not in (0, 1)):
        raise ParseError("CoAP code conflicts with message type")
    pos = 4 + token
    if pos > len(data):
        raise ParseError("Truncated CoAP token")
    option, count = 0, 0

    def extended(value, offset):
        if value < 13:
            return value, offset
        if value == 15:
            raise ParseError("Reserved CoAP option nibble")
        width = 1 if value == 13 else 2
        if offset + width > len(data):
            raise ParseError("Truncated CoAP extended option")
        return int.from_bytes(data[offset:offset + width], "big") + (13 if width == 1 else 269), offset + width

    while pos < len(data):
        if data[pos] == 255:
            if pos + 1 == len(data):
                raise ParseError("CoAP payload marker without payload")
            break
        count += 1
        if count > 128:
            raise BudgetError("CoAP option count exceeds inspection limit")
        byte = data[pos]
        delta, pos = extended(byte >> 4, pos + 1)
        size, pos = extended(byte & 15, pos)
        option += delta
        if option > 65535 or pos + size > len(data):
            raise ParseError("CoAP option outside message or number range")
        pos += size
    return "coap", "CoAP v1 token/options framing validated; option semantics and payload unverified"
