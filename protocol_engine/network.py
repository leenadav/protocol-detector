"""Bounded management/routing protocol profiles; no peer authentication."""
from .datagram_result import DatagramMatch
from .framing import FrameParser, ber_field
from .model import Evidence
from .parsers import BudgetError, ParseError
from .extended import UnsupportedPrefix


class BGPParser(FrameParser):
    header_size = 19
    protocol_name = "bgp/4"
    scope = "negotiation_request"

    def frame_size(self, header):
        if header[:16] != b"\xff" * 16:
            raise ParseError("Invalid BGP marker")
        size = int.from_bytes(header[16:18], "big")
        if header[18] != 1:
            raise UnsupportedPrefix("Only BGP OPEN is supported")
        if not 29 <= size <= 4096:
            raise ParseError("Invalid BGP OPEN length")
        return size

    def validate(self, data):
        if data[19] != 4:
            raise UnsupportedPrefix("Only BGP version 4 is supported")
        hold = int.from_bytes(data[22:24], "big")
        if hold in (1, 2):
            raise ParseError("Invalid BGP hold time")
        if data[28] == 255:
            raise UnsupportedPrefix("Extended BGP OPEN parameter lengths unsupported")
        if len(data) != 29 + data[28]:
            raise ParseError("BGP optional parameter length mismatch")
        pos, count = 29, 0
        while pos < len(data):
            if pos + 2 > len(data):
                raise ParseError("Truncated BGP optional parameter")
            kind, size = data[pos:pos + 2]
            pos += 2
            end = pos + size
            if end > len(data):
                raise ParseError("BGP parameter exceeds message")
            if kind != 2:
                raise UnsupportedPrefix("Only BGP capability parameters supported")
            if not size:
                raise ParseError("Empty BGP capability parameter")
            while pos < end:
                count += 1
                if count > 128:
                    raise BudgetError("BGP capability count exceeds limit")
                if pos + 2 > end:
                    raise ParseError("Truncated BGP capability")
                code, length = data[pos:pos + 2]
                pos += 2
                if pos + length > end:
                    raise ParseError("BGP capability exceeds parameter")
                if (code in (1, 65) and length != 4) or (code in (2, 6) and length != 0):
                    raise ParseError("Invalid known BGP capability size")
                if code == 1 and data[pos + 2] != 0:
                    raise ParseError("Invalid multiprotocol BGP reserved field")
                pos += length
        self.reason = "BGPv4 OPEN and capability framing validated; peer identity and session unverified"


class SMB2Parser(FrameParser):
    header_size = 8
    protocol_name = "smb2"
    scope = "negotiation_request"

    def frame_size(self, header):
        if header[0] != 0 or header[4:8] != b"\xfeSMB":
            raise ParseError("Invalid direct TCP SMB2 header")
        size = int.from_bytes(header[1:4], "big")
        if size < 102:
            raise ParseError("SMB2 NEGOTIATE frame too short")
        return 4 + size

    def validate(self, framed):
        data = framed[4:]
        u16 = lambda at: int.from_bytes(data[at:at + 2], "little")
        u32 = lambda at: int.from_bytes(data[at:at + 4], "little")
        if u16(4) != 64 or u16(12) != 0:
            raise UnsupportedPrefix("Only SMB2 NEGOTIATE requests supported")
        # This initial synchronous request is unsigned and not compounded.
        if u32(16) != 0 or u32(20) != 0 or any(data[8:12] + data[36:64]):
            raise ParseError("Invalid initial SMB2 request flags, IDs or signature")
        if u16(64) != 36 or u16(68) not in (1, 2, 3) or u16(70) != 0:
            raise ParseError("Invalid SMB2 negotiate fixed fields")
        count = u16(66)
        if not count:
            raise ParseError("SMB2 requires at least one dialect")
        if count > 128:
            raise BudgetError("SMB2 dialect count exceeds limit")
        end = 100 + count * 2
        if end > len(data):
            raise ParseError("Truncated SMB2 dialect array")
        dialects = {u16(at) for at in range(100, end, 2)}
        if not dialects.intersection((0x202, 0x210, 0x300, 0x302, 0x311)):
            raise UnsupportedPrefix("No supported SMB2 dialect offered")
        if 0x311 not in dialects:
            if any(data[92:100]) or len(data) != end:
                raise ParseError("Unexpected SMB2 negotiate extension")
        else:
            pos, contexts = u32(92), u16(96)
            if not contexts or contexts > 128:
                raise BudgetError("SMB3 negotiate context count outside inspection limit")
            if u16(98) or pos < end or pos % 8 or pos > len(data):
                raise ParseError("Invalid SMB3 context offset")
            seen = set()
            for index in range(contexts):
                if pos + 8 > len(data):
                    raise ParseError("Truncated SMB3 context header")
                kind, size = u16(pos), u16(pos + 2)
                if kind in seen or u32(pos + 4):
                    raise ParseError("Duplicate SMB3 context or nonzero reserved field")
                seen.add(kind)
                start, end = pos + 8, pos + 8 + size
                if end > len(data):
                    raise ParseError("SMB3 context exceeds frame")
                if kind == 1:
                    if size < 6:
                        raise ParseError("Truncated SMB3 preauthentication context")
                    hashes, salt = u16(start), u16(start + 2)
                    if not hashes or 4 + 2 * hashes + salt != size:
                        raise ParseError("Invalid SMB3 preauthentication lengths")
                    if 1 not in {u16(at) for at in range(start + 4, start + 4 + 2 * hashes, 2)}:
                        raise UnsupportedPrefix("SMB3 preauthentication lacks supported SHA-512 offer")
                elif kind == 2:
                    if size < 4 or not u16(start) or 2 + 2 * u16(start) != size:
                        raise ParseError("Invalid SMB3 encryption capability lengths")
                pos = (end + 7) & ~7 if index + 1 < contexts else end
            if 1 not in seen or pos != len(data):
                raise ParseError("Missing SMB3 preauthentication context or trailing data")
        self.reason = "SMB2/3 direct TCP NEGOTIATE request validated; dialects are offers, signing/encryption unverified"


def tftp(data, config):
    if data[:2] not in (b"\x00\x01", b"\x00\x02"):
        raise UnsupportedPrefix("Only TFTP RRQ/WRQ supported")
    if len(data) > 512 or not data.endswith(b"\x00"):
        raise ParseError("Invalid TFTP request length or terminator")
    parts = data[2:-1].split(b"\x00")
    if len(parts) < 2 or len(parts) % 2 or not parts[0]:
        raise ParseError("Invalid TFTP filename/mode/options")
    if any(any(c < 32 or c > 126 for c in value) for value in parts):
        raise ParseError("TFTP request fields must be printable ASCII in this profile")
    if parts[1].lower() not in (b"octet", b"netascii", b"mail"):
        raise UnsupportedPrefix("Unsupported TFTP transfer mode")
    seen = set()
    if len(parts) > 34:
        raise BudgetError("TFTP option count exceeds limit")
    for index in range(2, len(parts), 2):
        name, value = parts[index].lower(), parts[index + 1]
        if not name or not value or name in seen:
            raise ParseError("Empty or duplicate TFTP option")
        seen.add(name)
        if name in (b"blksize", b"timeout", b"tsize", b"windowsize"):
            if not value.isdigit() or len(value) > 20:
                raise ParseError("Invalid numeric TFTP option")
            number = int(value)
            if ((name == b"blksize" and not 8 <= number <= 65464)
                    or (name == b"timeout" and not 1 <= number <= 255)
                    or (name == b"windowsize" and not 1 <= number <= 65535)
                    or (name == b"tsize" and data[1] == 1 and number != 0)):
                raise ParseError("TFTP option outside permitted range")
    return "tftp", "TFTP initial read/write request and option framing validated; transfer unverified"


def _integer(data, pos):
    value, end = ber_field(data, pos, len(data), 2)
    if not 1 <= len(value) <= 4:
        raise ParseError("SNMP integer outside signed 32-bit profile")
    return int.from_bytes(value, "big", signed=True), end


def _oid(value):
    if not value:
        raise ParseError("Empty SNMP object identifier")
    number, count, beginning = 0, 0, True
    for byte in value:
        if beginning and byte == 128:
            raise ParseError("Nonminimal SNMP OID subidentifier")
        number = (number << 7) | (byte & 127)
        if number > 0xffffffff + (80 if count == 0 else 0):
            raise ParseError("SNMP OID subidentifier too large")
        beginning = not bool(byte & 128)
        if beginning:
            count += 1
            number = 0
            if count > 127:
                raise BudgetError("SNMP OID exceeds 128 arcs")
    if not beginning:
        raise ParseError("Truncated SNMP OID subidentifier")


def _snmp_pdu(pdu, kind):
    """Request-id, error/bulk integers and variable bindings of a Get/GetNext/GetBulk/Report PDU."""
    _, pos = _integer(pdu, 0)
    first, pos = _integer(pdu, pos)
    second, pos = _integer(pdu, pos)
    if first < 0 or second < 0 or (kind in (0xa0, 0xa1) and (first or second)):
        raise ParseError("Invalid SNMP request status/index or bulk counts")
    bindings, pos = ber_field(pdu, pos, len(pdu), 0x30)
    if pos != len(pdu):
        raise ParseError("Trailing SNMP request fields")
    pos, count = 0, 0
    while pos < len(bindings):
        count += 1
        if count > 128:
            raise BudgetError("SNMP variable binding count exceeds limit")
        binding, pos = ber_field(bindings, pos, len(bindings), 0x30)
        oid, cursor = ber_field(binding, 0, len(binding), 6)
        _oid(oid)
        if kind == 0xa8:
            if cursor >= len(binding):
                raise ParseError("SNMP report binding without a value")
            _, cursor = ber_field(binding, cursor, len(binding), binding[cursor])  # counter or exception value, not emitted
        else:
            null, cursor = ber_field(binding, cursor, len(binding), 5)
            if null:
                raise ParseError("SNMP read binding must contain NULL value")
        if cursor != len(binding):
            raise ParseError("SNMP read binding must contain NULL value")


def _snmpv3(message, pos):
    """SNMPv3 message (RFC 3412 6): global header, security parameters and a scoped PDU, plaintext or encrypted."""
    header, pos = ber_field(message, pos, len(message), 0x30)
    message_id, cursor = _integer(header, 0)
    max_size, cursor = _integer(header, cursor)
    flags, cursor = ber_field(header, cursor, len(header), 4)
    model, cursor = _integer(header, cursor)
    if cursor != len(header):
        raise ParseError("Trailing SNMPv3 header data")
    if message_id < 0 or max_size < 484 or model < 1:
        raise ParseError("SNMPv3 header values outside RFC 3412 ranges")
    if len(flags) != 1 or flags[0] & 0xf8:
        raise ParseError("SNMPv3 msgFlags must be one byte with reserved bits clear")
    auth, priv, reportable = flags[0] & 1, flags[0] & 2, flags[0] & 4
    if priv and not auth:
        raise ParseError("SNMPv3 privacy without authentication is invalid")
    params, pos = ber_field(message, pos, len(message), 4)
    if model == 3:
        usm, end = ber_field(params, 0, len(params), 0x30)
        if end != len(params):
            raise ParseError("Trailing USM security parameter data")
        engine_id, cursor = ber_field(usm, 0, len(usm), 4)
        boots, cursor = _integer(usm, cursor)
        clock, cursor = _integer(usm, cursor)
        user, cursor = ber_field(usm, cursor, len(usm), 4)
        auth_params, cursor = ber_field(usm, cursor, len(usm), 4)
        priv_params, cursor = ber_field(usm, cursor, len(usm), 4)
        if cursor != len(usm) or len(engine_id) > 32 or len(user) > 32 or len(auth_params) > 64 or len(priv_params) > 32 or boots < 0 or clock < 0:
            raise ParseError("USM security parameters outside profile")
        if auth and not auth_params:
            raise ParseError("SNMPv3 authentication flag without authentication parameters")
        if priv and not priv_params:
            raise ParseError("SNMPv3 privacy flag without privacy parameters")
        security = "usm"
    else:
        if len(params) > 256:
            raise ParseError("SNMPv3 security parameters exceed profile")
        security = "model-{}".format(model)
    if pos >= len(message):
        raise ParseError("SNMPv3 message without scoped PDU")
    if priv:
        encrypted, pos = ber_field(message, pos, len(message), 4)
        if not encrypted or pos != len(message):
            raise ParseError("SNMPv3 encrypted scoped PDU framing invalid")
        scope = "encrypted"
    else:
        scoped, pos = ber_field(message, pos, len(message), 0x30)
        if pos != len(message):
            raise ParseError("Trailing SNMPv3 message data")
        context_engine, cursor = ber_field(scoped, 0, len(scoped), 4)
        context_name, cursor = ber_field(scoped, cursor, len(scoped), 4)
        if len(context_engine) > 32 or len(context_name) > 32 or cursor >= len(scoped):
            raise ParseError("SNMPv3 scoped PDU context outside profile")
        kind = scoped[cursor]
        if kind not in (0xa0, 0xa1, 0xa5, 0xa8):
            raise UnsupportedPrefix("SNMPv3 profile covers Get/GetNext/GetBulk requests and Report PDUs")
        pdu, cursor = ber_field(scoped, cursor, len(scoped), kind)
        if cursor != len(scoped):
            raise ParseError("Trailing SNMPv3 scoped PDU data")
        _snmp_pdu(pdu, kind)
        scope = "plaintext"
    evidence = (Evidence("application_protocol", "snmp/3", "wire", "structural"),
                Evidence("snmp_security", security, "wire", "structural"),
                Evidence("snmp_scoped_pdu", scope, "wire", "structural"),
                Evidence("snmp_flags", "".join(name for bit, name in ((auth, "auth"), (priv, "priv"), (reportable, "reportable")) if bit) or "none", "wire", "structural"))
    return DatagramMatch("SNMPv3 header, security parameter and {} scoped PDU framing validated; user, engine, keys and values unverified and never emitted".format(scope),
                         application_protocol="snmp/3", evidence=evidence)


def snmp(data, config):
    message, end = ber_field(data, 0, len(data), 0x30)
    if end != len(data):
        raise ParseError("Trailing SNMP datagram data")
    version, pos = _integer(message, 0)
    if version == 3:
        return _snmpv3(message, pos)
    if version not in (0, 1):
        raise UnsupportedPrefix("Only SNMPv1/v2c read requests and SNMPv3 messages supported")
    _, pos = ber_field(message, pos, len(message), 4)  # never expose community
    if pos >= len(message) or message[pos] not in ((0xa0, 0xa1) if version == 0 else (0xa0, 0xa1, 0xa5)):
        raise UnsupportedPrefix("Only SNMP Get/GetNext/GetBulk supported")
    kind = message[pos]
    pdu, pos = ber_field(message, pos, len(message), kind)
    if pos != len(message):
        raise ParseError("Trailing SNMP PDU data")
    _snmp_pdu(pdu, kind)
    return "snmp/" + ("1" if version == 0 else "2c"), "SNMP read request BER/PDU/OID framing validated; community and response unverified"


def ntp(data, config):
    # Hint-only: the base header has no strong discriminator from random bytes.
    if len(data) != 48:
        raise UnsupportedPrefix("Only 48-byte unauthenticated NTP messages supported")
    version, mode = (data[0] >> 3) & 7, data[0] & 7
    if version not in (3, 4) or mode not in (3, 4):
        raise UnsupportedPrefix("Only NTPv3/v4 client/server modes supported")
    if data[1] > 16:
        raise ParseError("Invalid NTP stratum")
    if mode == 4 and not any(data[40:48]):
        raise ParseError("NTP server transmit timestamp is zero")
    return "ntp/" + str(version), "NTP base header validated with caller hint; timestamps, peer, extensions and authentication unverified"
