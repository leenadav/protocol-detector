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


_SMB_DIALECTS = {0x202: "2.0.2", 0x210: "2.1", 0x2ff: "wildcard", 0x300: "3.0", 0x302: "3.0.2", 0x311: "3.1.1"}


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
            raise UnsupportedPrefix("Only SMB2 NEGOTIATE requests and responses supported")
        flags = u32(16)
        if flags == 1:
            return self._response(data, u16, u32)
        # This initial synchronous request is unsigned and not compounded.
        if flags != 0 or u32(20) != 0 or any(data[8:12] + data[36:64]):
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
            self._contexts(data, u16, u32, u32(92), u16(96), end, u16(98))
        self.reason = "SMB2/3 direct TCP NEGOTIATE request validated; dialects are offers, signing/encryption unverified"

    def _contexts(self, data, u16, u32, pos, contexts, end, reserved, response=False):
        """SMB 3.1.1 negotiate contexts: 8-byte aligned, unique kinds, preauth (kind 1) required."""
        if not contexts or contexts > 128:
            raise BudgetError("SMB3 negotiate context count outside inspection limit")
        if reserved or pos < end or pos % 8 or pos > len(data):
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
                if not hashes or 4 + 2 * hashes + salt != size or (response and hashes != 1):
                    raise ParseError("Invalid SMB3 preauthentication lengths")
                if 1 not in {u16(at) for at in range(start + 4, start + 4 + 2 * hashes, 2)}:
                    raise UnsupportedPrefix("SMB3 preauthentication lacks supported SHA-512 offer")
            elif kind == 2:
                if size < 4 or not u16(start) or 2 + 2 * u16(start) != size or (response and u16(start) != 1):
                    raise ParseError("Invalid SMB3 encryption capability lengths")
            pos = (end + 7) & ~7 if index + 1 < contexts else end
        if 1 not in seen or pos != len(data):
            raise ParseError("Missing SMB3 preauthentication context or trailing data")

    def _response(self, data, u16, u32):
        """MS-SMB2 2.2.4 NEGOTIATE response: fixed 64-byte body, security buffer, 3.1.1 contexts."""
        if u32(8) != 0 or u32(20) != 0:
            raise UnsupportedPrefix("SMB2 NEGOTIATE response profile covers STATUS_SUCCESS without next-command chaining")
        if len(data) < 128 or u16(64) != 65:
            raise ParseError("SMB2 NEGOTIATE response body shorter than its fixed fields")
        security_mode, dialect, contexts = u16(66), u16(68), u16(70)
        if security_mode not in (1, 2, 3):
            raise ParseError("SMB2 response security mode must enable signing")
        if dialect not in _SMB_DIALECTS:
            raise UnsupportedPrefix("SMB2 response dialect outside the profile")
        if not u32(92) or not u32(96) or not u32(100):
            raise ParseError("SMB2 response transfer sizes must be nonzero")
        offset, length = u16(120), u16(122)
        if length and (offset != 128 or offset + length > len(data)):
            raise ParseError("SMB2 response security buffer outside the frame")
        end = 128 + length
        if dialect == 0x311:
            self._contexts(data, u16, u32, u32(124), contexts, end, 0, response=True)
        elif contexts or u32(124) or len(data) != end:
            raise ParseError("Negotiate contexts require dialect 3.1.1")
        self.scope = "negotiation_response"
        self.reason = "SMB2/3 NEGOTIATE response validated; selected dialect and signing mode unauthenticated, security token not emitted"
        self.extra_evidence = (("smb_dialect", _SMB_DIALECTS[dialect], "negotiate_response", "asserted"),
                               ("smb_signing", "required" if security_mode & 2 else "enabled", "negotiate_response", "asserted"))


def tftp(data, config):
    if data[:2] in (b"\x00\x05", b"\x00\x06"):
        return _tftp_server(data, config)
    if data[:2] not in (b"\x00\x01", b"\x00\x02"):
        raise UnsupportedPrefix("Only TFTP RRQ/WRQ/OACK/ERROR supported")
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
    return DatagramMatch("TFTP initial read/write request and option framing validated; transfer unverified", application_protocol="tftp",
                         evidence=(Evidence("application_protocol", "tftp", "wire", "structural"), Evidence("tftp_packet", "request", "wire", "structural")))


def _tftp_server(data, config):
    """OACK (RFC 2347) option pairs or ERROR (RFC 1350) code and message; DATA/ACK are too weak to identify (v0.49)."""
    if len(data) > 512 or not data.endswith(b"\x00"):
        raise ParseError("Invalid TFTP packet length or terminator")
    if data[1] == 5:
        if len(data) < 6 or int.from_bytes(data[2:4], "big") > 8:
            raise ParseError("TFTP error code outside RFC 1350/2347 or empty message")
        message = data[4:-1]
        if b"\x00" in message or any(c < 32 or c > 126 for c in message):
            raise ParseError("TFTP error message must be one printable string")
        return DatagramMatch("TFTP error packet validated; code and message not emitted", application_protocol="tftp",
                             evidence=(Evidence("application_protocol", "tftp", "wire", "structural"), Evidence("tftp_packet", "error", "wire", "structural")))
    parts = data[2:-1].split(b"\x00")
    if len(parts) < 2 or len(parts) % 2 or len(parts) > 32:
        raise ParseError("TFTP OACK requires 1..16 option/value pairs")
    seen = set()
    for index in range(0, len(parts), 2):
        name, value = parts[index].lower(), parts[index + 1]
        if name not in (b"blksize", b"timeout", b"tsize", b"windowsize") or name in seen:
            raise UnsupportedPrefix("TFTP OACK option outside the RFC 2348/2349/7440 set or repeated")
        if not value.isdigit() or len(value) > 20:
            raise ParseError("Invalid numeric TFTP option")
        seen.add(name)
    return DatagramMatch("TFTP option acknowledgement validated; option values not emitted, transfer unverified", application_protocol="tftp",
                         evidence=(Evidence("application_protocol", "tftp", "wire", "structural"), Evidence("tftp_packet", "oack", "wire", "structural")))


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


_SNMP_PDU_NAMES = {0xa0: "get", 0xa1: "get-next", 0xa2: "response", 0xa3: "set", 0xa4: "trap", 0xa5: "get-bulk",
                   0xa6: "inform", 0xa7: "trap", 0xa8: "report"}
_SNMP_V1_KINDS = (0xa0, 0xa1, 0xa2, 0xa3, 0xa4)
_SNMP_V2_KINDS = (0xa0, 0xa1, 0xa2, 0xa3, 0xa5, 0xa6, 0xa7, 0xa8)
# Value tags a binding may carry outside read requests: ASN.1 INTEGER, OCTET STRING, NULL, OID,
# SMI IpAddress, Counter32, Gauge32, TimeTicks, Opaque, Counter64 and the three v2 exceptions.
_SNMP_VALUE_TAGS = frozenset((0x02, 0x04, 0x05, 0x06, 0x40, 0x41, 0x42, 0x43, 0x44, 0x46, 0x80, 0x81, 0x82))


def _snmp_bindings(bindings, read_only):
    """Variable bindings: OID plus NULL (read requests) or one value TLV; values are never emitted."""
    pos, count = 0, 0
    while pos < len(bindings):
        count += 1
        if count > 128:
            raise BudgetError("SNMP variable binding count exceeds limit")
        binding, pos = ber_field(bindings, pos, len(bindings), 0x30)
        oid, cursor = ber_field(binding, 0, len(binding), 6)
        _oid(oid)
        if cursor >= len(binding):
            raise ParseError("SNMP binding without a value")
        tag = binding[cursor]
        if read_only:
            null, cursor = ber_field(binding, cursor, len(binding), 5)
            if null:
                raise ParseError("SNMP read binding must contain NULL value")
        else:
            if tag not in _SNMP_VALUE_TAGS:
                raise ParseError("SNMP binding value tag outside the SMI profile")
            value, cursor = ber_field(binding, cursor, len(binding), tag)
            if (tag == 0x40 and len(value) != 4) or (tag in (0x80, 0x81, 0x82) and value) or (tag == 0x05 and value) \
                    or (tag in (0x02, 0x41, 0x42, 0x43) and not 1 <= len(value) <= 5) or (tag == 0x46 and not 1 <= len(value) <= 9):
                raise ParseError("SNMP binding value length outside its type")
        if cursor != len(binding):
            raise ParseError("Trailing SNMP binding data")


def _snmp_pdu(pdu, kind):
    """Validate one PDU body by kind and return its name for evidence."""
    if kind == 0xa4:
        # SNMPv1 Trap-PDU: enterprise, agent address, generic and specific trap, time stamp, bindings.
        enterprise, pos = ber_field(pdu, 0, len(pdu), 6)
        _oid(enterprise)
        agent, pos = ber_field(pdu, pos, len(pdu), 0x40)
        if len(agent) != 4:
            raise ParseError("SNMPv1 trap agent address must be four bytes")
        generic, pos = _integer(pdu, pos)
        specific, pos = _integer(pdu, pos)
        if not 0 <= generic <= 6 or specific < 0:
            raise ParseError("SNMPv1 trap codes outside their ranges")
        ticks, pos = ber_field(pdu, pos, len(pdu), 0x43)
        if not 1 <= len(ticks) <= 5:
            raise ParseError("SNMPv1 trap time stamp length invalid")
        bindings, pos = ber_field(pdu, pos, len(pdu), 0x30)
        if pos != len(pdu):
            raise ParseError("Trailing SNMPv1 trap fields")
        _snmp_bindings(bindings, False)
        return "trap"
    _, pos = _integer(pdu, 0)
    first, pos = _integer(pdu, pos)
    second, pos = _integer(pdu, pos)
    if first < 0 or second < 0:
        raise ParseError("Invalid SNMP request status/index or bulk counts")
    if kind in (0xa0, 0xa1, 0xa3, 0xa6, 0xa7) and (first or second):
        raise ParseError("SNMP request error-status and error-index must be zero")
    if kind == 0xa2 and first > 18:
        raise ParseError("SNMP response error-status outside RFC 3416")
    bindings, pos = ber_field(pdu, pos, len(pdu), 0x30)
    if pos != len(pdu):
        raise ParseError("Trailing SNMP request fields")
    _snmp_bindings(bindings, kind in (0xa0, 0xa1, 0xa5))
    return _SNMP_PDU_NAMES[kind]


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
        if kind not in _SNMP_V2_KINDS:
            raise UnsupportedPrefix("SNMPv3 scoped PDU kind outside the SNMPv2 PDU set")
        pdu, cursor = ber_field(scoped, cursor, len(scoped), kind)
        if cursor != len(scoped):
            raise ParseError("Trailing SNMPv3 scoped PDU data")
        name = _snmp_pdu(pdu, kind)
        scope = "plaintext"
    evidence = (Evidence("application_protocol", "snmp/3", "wire", "structural"),
                Evidence("snmp_pdu", "encrypted" if priv else name, "wire", "structural"),
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
        raise UnsupportedPrefix("Only SNMPv1, v2c and v3 messages are supported")
    _, pos = ber_field(message, pos, len(message), 4)  # never expose community
    if pos >= len(message) or message[pos] not in (_SNMP_V1_KINDS if version == 0 else _SNMP_V2_KINDS):
        raise UnsupportedPrefix("SNMP PDU kind outside the version's PDU set")
    kind = message[pos]
    pdu, pos = ber_field(message, pos, len(message), kind)
    if pos != len(message):
        raise ParseError("Trailing SNMP PDU data")
    name = _snmp_pdu(pdu, kind)
    protocol = "snmp/" + ("1" if version == 0 else "2c")
    return DatagramMatch("SNMP {} BER/PDU/OID framing validated; community and values unverified and never emitted".format(name),
                         application_protocol=protocol,
                         evidence=(Evidence("application_protocol", protocol, "wire", "structural"), Evidence("snmp_pdu", name, "wire", "structural")))


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
    protocol = "ntp/" + str(version)
    return DatagramMatch("NTP base header validated with caller hint; timestamps, peer, extensions and authentication unverified",
                         application_protocol=protocol,
                         evidence=(Evidence("application_protocol", protocol, "wire", "structural"),
                                   Evidence("ntp_mode", "client" if mode == 3 else "server", "wire", "structural")))
