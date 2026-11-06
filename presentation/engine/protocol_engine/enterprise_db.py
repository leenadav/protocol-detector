"""Enterprise database wire protocols: MSSQL TDS PRELOGIN and Oracle Net (TNS) connect.

Both profiles cover the first packet of each direction only. Instance names,
connect descriptors (service names, hosts, programs), thread identifiers,
trace identifiers and nonces are read for their framing and never emitted.
"""
from .framing import FrameParser
from .parsers import ParseError, BudgetError
from .extended import UnsupportedPrefix

# MS-TDS 2.2.6.5 PRELOGIN option tokens and their fixed data lengths (None: variable).
_TDS_OPTIONS = {0x00: 6, 0x01: 1, 0x02: None, 0x03: None, 0x04: 1, 0x05: 36, 0x06: 1, 0x07: 32}
_TDS_ENCRYPTION = {0x00: "off", 0x01: "on", 0x02: "not-supported", 0x03: "required"}
TDS_MAX_PRELOGIN = 4096


class TDSParser(FrameParser):
    """TDS 7.x PRELOGIN (client, type 0x12) or its tabular response (server, type 0x04)."""
    header_size = 8
    protocol_name = "tds"
    scope = "negotiation_request"

    def frame_size(self, header):
        kind, status = header[0], header[1]
        if kind not in (0x12, 0x04):
            raise UnsupportedPrefix("TDS profile covers PRELOGIN packets and their response")
        if status & 0x01 == 0 or status & ~0x1b:
            raise ParseError("TDS PRELOGIN must be a single end-of-message packet with known status bits")
        if header[7] != 0:
            raise ParseError("TDS window byte must be zero")
        if kind == 0x12 and header[4:6] != b"\x00\x00":
            raise ParseError("TDS client packets carry SPID zero")
        size = int.from_bytes(header[2:4], "big")
        if size < 8 + 5 + 1 + 6 + 1 + 1:   # header, VERSION and ENCRYPTION entries, terminator, their data
            raise ParseError("TDS PRELOGIN shorter than its mandatory options")
        if size > TDS_MAX_PRELOGIN:
            raise BudgetError("TDS PRELOGIN exceeds the profile size")
        return size

    def validate(self, data):
        payload = memoryview(data)[8:]
        pos, seen = 0, {}
        while True:
            if pos >= len(payload):
                raise ParseError("TDS PRELOGIN option list lacks a terminator")
            token = payload[pos]
            if token == 0xff:
                pos += 1
                break
            if pos + 5 > len(payload):
                raise ParseError("Truncated TDS PRELOGIN option entry")
            if token not in _TDS_OPTIONS or token in seen:
                raise ParseError("Unknown or repeated TDS PRELOGIN option")
            offset = int.from_bytes(payload[pos + 1:pos + 3], "big")
            length = int.from_bytes(payload[pos + 3:pos + 5], "big")
            seen[token] = (offset, length)
            pos += 5
        if 0x00 not in seen or 0x01 not in seen:
            raise ParseError("TDS PRELOGIN requires VERSION and ENCRYPTION options")
        if max(offset + length for offset, length in seen.values()) != len(payload):
            raise ParseError("TDS PRELOGIN carries bytes after its last option datum")
        for token, (offset, length) in seen.items():
            fixed = _TDS_OPTIONS[token]
            if offset < pos or offset + length > len(payload):
                raise ParseError("TDS PRELOGIN option data outside the packet")
            if fixed is not None and length != fixed and not (data[0] == 0x04 and token == 0x05 and length == 0):
                raise ParseError("TDS PRELOGIN option length outside its definition")
            if token == 0x02 and (length < 1 or payload[offset + length - 1] != 0):
                raise ParseError("TDS INSTOPT must be a terminated string")
            if token == 0x03 and length not in (0, 4):
                raise ParseError("TDS THREADID is four bytes or absent")
        encryption = payload[seen[0x01][0]]
        if encryption not in _TDS_ENCRYPTION:
            raise UnsupportedPrefix("TDS ENCRYPTION setting outside the 7.x profile")
        evidence = [("tds_encryption", _TDS_ENCRYPTION[encryption], "prelogin", "offered")]
        if 0x04 in seen:
            mars = payload[seen[0x04][0]]
            if mars > 1:
                raise ParseError("TDS MARS option must be 0 or 1")
            evidence.append(("tds_mars", "on" if mars else "off", "prelogin", "offered"))
        if 0x06 in seen:
            fedauth = payload[seen[0x06][0]]
            if fedauth > 1:
                raise ParseError("TDS FEDAUTHREQUIRED option must be 0 or 1")
            evidence.append(("tds_federated_auth", "yes" if fedauth else "no", "prelogin", "offered"))
        if data[0] == 0x04:
            self.scope = "negotiation_response"
            self.reason = "TDS PRELOGIN response validated; server version and encryption choice unauthenticated"
        else:
            self.reason = "TDS PRELOGIN validated; driver version, encryption and instance options are client assertions"
        self.extra_evidence = tuple(evidence)


# Oracle Net packet types.
_TNS_CONNECT, _TNS_ACCEPT, _TNS_REFUSE, _TNS_RESEND = 1, 2, 4, 11
TNS_VERSIONS = range(0x0134, 0x0140)   # 308 (8i) .. 319 (23c)
TNS_MAX_PACKET = 8192


def tns_probe(prefix):
    """Header 8 bytes: length, checksum 0, type, reserved 0, header checksum 0; 10 bytes except RESEND."""
    if len(prefix) < 8 or prefix[2:4] != b"\x00\x00" or prefix[5] != 0 or prefix[6:8] != b"\x00\x00":
        return False
    kind = prefix[4]
    length = int.from_bytes(prefix[:2], "big")
    if kind == _TNS_RESEND:
        return length == 8
    if len(prefix) < 10:
        return False
    if kind in (_TNS_CONNECT, _TNS_ACCEPT):
        return length >= (34 if kind == _TNS_CONNECT else 24) and int.from_bytes(prefix[8:10], "big") in TNS_VERSIONS
    if kind == _TNS_REFUSE:
        return length >= 12 and prefix[8] <= 0x7f and prefix[9] <= 0x7f
    return False


class TNSParser(FrameParser):
    """Oracle Net CONNECT (client) or ACCEPT/REFUSE/RESEND (server) packet framing."""
    header_size = 8
    protocol_name = "tns"
    scope = "negotiation_request"

    def frame_size(self, header):
        if header[2:4] != b"\x00\x00" or header[5] != 0 or header[6:8] != b"\x00\x00":
            raise ParseError("TNS header checksums and reserved byte must be zero")
        kind = header[4]
        if kind not in (_TNS_CONNECT, _TNS_ACCEPT, _TNS_REFUSE, _TNS_RESEND):
            raise UnsupportedPrefix("TNS profile covers CONNECT, ACCEPT, REFUSE and RESEND packets")
        size = int.from_bytes(header[:2], "big")
        minimum = {_TNS_CONNECT: 34, _TNS_ACCEPT: 24, _TNS_REFUSE: 12, _TNS_RESEND: 8}[kind]
        if size < minimum:
            raise ParseError("TNS packet shorter than its fixed fields")
        if kind == _TNS_RESEND and size != 8:
            raise ParseError("TNS RESEND carries no body")
        if size > TNS_MAX_PACKET:
            raise BudgetError("TNS packet exceeds the profile size")
        return size

    def validate(self, data):
        kind = data[4]
        if kind == _TNS_CONNECT:
            self._connect(data)
            return
        self.scope = "negotiation_response"
        if kind == _TNS_RESEND:
            self.reason = "TNS RESEND validated; the client repeats its connect packet"
            self.extra_evidence = (("tns_response", "resend", "header", "structural"),)
            return
        if kind == _TNS_REFUSE:
            length = int.from_bytes(data[10:12], "big")
            if 12 + length != len(data):
                raise ParseError("TNS REFUSE data length disagrees with the packet")
            if length and (data[12] != 0x28 or not all(0x20 <= byte < 0x7f for byte in data[12:])):
                raise ParseError("TNS REFUSE data is not a printable descriptor")
            self.reason = "TNS REFUSE validated; reason codes and descriptor not emitted"
            self.extra_evidence = (("tns_response", "refuse", "header", "structural"),)
            return
        version = int.from_bytes(data[8:10], "big")
        if version not in TNS_VERSIONS:
            raise UnsupportedPrefix("TNS ACCEPT version outside the supported range")
        if data[16:18] not in (b"\x00\x01", b"\x01\x00"):
            raise ParseError("TNS ACCEPT byte-order marker invalid")
        length = int.from_bytes(data[18:20], "big")
        offset = int.from_bytes(data[20:22], "big")
        if length and (offset < 24 or offset + length != len(data)):
            raise ParseError("TNS ACCEPT data region outside the packet")
        self.reason = "TNS ACCEPT validated; negotiated sizes and flags unauthenticated"
        self.extra_evidence = (("tns_response", "accept", "header", "structural"),
                               ("tns_version", str(version), "header", "asserted"))

    def _connect(self, data):
        version = int.from_bytes(data[8:10], "big")
        if version not in TNS_VERSIONS:
            raise UnsupportedPrefix("TNS CONNECT version outside the supported range")
        if data[10:12] != b"\x01\x2c":
            raise ParseError("TNS CONNECT version-compatible field must be 300")
        if data[22:24] not in (b"\x00\x01", b"\x01\x00"):
            raise ParseError("TNS CONNECT byte-order marker invalid")
        length = int.from_bytes(data[24:26], "big")
        offset = int.from_bytes(data[26:28], "big")
        if not 34 <= offset <= 74:
            raise ParseError("TNS connect data offset outside the header range")
        if length < 1:
            raise ParseError("TNS CONNECT requires a connect descriptor")
        if len(data) == offset:
            inline = "deferred"   # descriptor follows in a DATA packet
        elif len(data) == offset + length:
            inline = "inline"
            descriptor = data[offset:]
            if descriptor[0] != 0x28 or not all(0x20 <= byte < 0x7f for byte in descriptor):
                raise ParseError("TNS connect descriptor must be a printable parenthesised string")
        else:
            raise ParseError("TNS connect data length disagrees with the packet")
        self.reason = "TNS CONNECT validated; descriptor contents (service, host, program) not emitted"
        self.extra_evidence = (("tns_version", str(version), "header", "asserted"),
                               ("tns_connect_data", inline, "header", "structural"))
