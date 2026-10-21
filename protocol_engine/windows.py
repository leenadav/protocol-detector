"""SMB1 negotiate, NetBIOS session request, Kerberos AS/TGS requests and TACACS+ headers."""
from .framing import FrameParser, ber_field, ber_length
from .parsers import BudgetError, ParseError
from .extended import UnsupportedPrefix


class SMB1Parser(FrameParser):
    """NetBIOS session header plus SMB_COM_NEGOTIATE request with NUL-terminated dialect strings."""
    header_size = 8
    protocol_name = "smb1"
    scope = "negotiation_request"

    def frame_size(self, header):
        if header[0] != 0 or header[4:8] != b"\xffSMB":
            raise ParseError("Invalid NetBIOS/SMB1 header")
        size = int.from_bytes(header[1:4], "big")
        if size < 35:
            raise ParseError("SMB1 negotiate frame too short")
        return 4 + size

    def validate(self, framed):
        data = framed[4:]
        if data[4] != 0x72:
            raise UnsupportedPrefix("Only SMB1 NEGOTIATE requests are supported")
        if data[5:9] != bytes(4) or data[9] & 0x80:
            raise ParseError("SMB1 negotiate request must carry zero status and the request direction flag")
        if data[32] != 0:
            raise ParseError("SMB1 negotiate word count must be zero")
        count = int.from_bytes(data[33:35], "little")
        body = data[35:]
        if len(body) != count or not body:
            raise ParseError("SMB1 byte count disagrees with frame")
        pos, dialects = 0, 0
        while pos < len(body):
            if body[pos] != 2:
                raise ParseError("SMB1 dialect must use the string buffer format")
            end = body.find(b"\0", pos + 1)
            if end < 0 or end == pos + 1:
                raise ParseError("SMB1 dialect string unterminated or empty")
            if any(byte < 32 or byte > 126 for byte in body[pos + 1:end]):
                raise ParseError("SMB1 dialect outside printable ASCII")
            dialects += 1
            if dialects > min(self.config.max_headers, 32):
                raise BudgetError("SMB1 dialect count exceeds budget")
            pos = end + 1
        self.reason = "SMB1 negotiate request framing and dialect strings validated; dialect selection and session unverified"


class NetBIOSSessionParser(FrameParser):
    """NetBIOS Session Service request (RFC 1002 4.3.2) with two first-level encoded names."""
    header_size = 4
    protocol_name = "netbios-ss"
    scope = "negotiation_request"

    def frame_size(self, header):
        if header[0] != 0x81 or header[1] & 0xfe:
            raise ParseError("Invalid NetBIOS session request header")
        size = ((header[1] & 1) << 16) | int.from_bytes(header[2:4], "big")
        if size != 68:
            raise ParseError("NetBIOS session request requires two 34-byte encoded names")
        return 4 + size

    def validate(self, data):
        for offset in (4, 38):
            if data[offset] != 32 or data[offset + 33] != 0:
                raise ParseError("NetBIOS name label framing invalid")
            if any(byte < 0x41 or byte > 0x50 for byte in data[offset + 1:offset + 33]):
                raise ParseError("NetBIOS first-level encoding requires letters A-P")
        self.reason = "NetBIOS session request names validated (first-level encoding); names are not emitted"


def _kerberos_body(data, limit, config):
    """Validate KDC-REQ: [APPLICATION 10|12] SEQUENCE { [1] pvno 5, [2] msg-type, [3] padata?, [4] req-body }."""
    tag = data[0]
    if tag not in (0x6a, 0x6c):
        raise UnsupportedPrefix("Kerberos profile supports AS-REQ and TGS-REQ only")
    outer, end = ber_field(data, 0, limit, tag)
    if end != limit:
        raise ParseError("Trailing bytes after Kerberos request")
    sequence, end = ber_field(outer, 0, len(outer), 0x30)
    if end != len(outer):
        raise ParseError("Kerberos request wrapper must contain one SEQUENCE")
    pos, seen = 0, []
    while pos < len(sequence):
        if len(seen) > 4:
            raise BudgetError("Kerberos request field count exceeds profile")
        field_tag = sequence[pos]
        if field_tag & 0xe0 != 0xa0:
            raise ParseError("Kerberos request fields must be context-specific constructed")
        value, pos = ber_field(sequence, pos, len(sequence), field_tag)
        number = field_tag & 0x1f
        if seen and number <= seen[-1]:
            raise ParseError("Kerberos request fields out of order")
        seen.append(number)
        if number == 1:
            integer, _ = ber_field(value, 0, len(value), 2)
            if integer != b"\x05":
                raise UnsupportedPrefix("Kerberos pvno outside version 5")
        elif number == 2:
            integer, _ = ber_field(value, 0, len(value), 2)
            if integer != (b"\x0a" if tag == 0x6a else b"\x0c"):
                raise ParseError("Kerberos msg-type disagrees with application tag")
        elif number == 3:
            padata, inner_end = ber_field(value, 0, len(value), 0x30)
            if inner_end != len(value):
                raise ParseError("Kerberos padata framing invalid")
            count, inner = 0, 0
            while inner < len(padata):
                count += 1
                if count > min(config.max_headers, 32):
                    raise BudgetError("Kerberos padata count exceeds budget")
                _, inner = ber_field(padata, inner, len(padata), 0x30)
        elif number == 4:
            body, inner_end = ber_field(value, 0, len(value), 0x30)
            if inner_end != len(value) or not body:
                raise ParseError("Kerberos req-body framing invalid")
        else:
            raise ParseError("Unexpected Kerberos request field")
    if 1 not in seen or 2 not in seen or 4 not in seen:
        raise ParseError("Kerberos request requires pvno, msg-type and req-body")
    return "kerberos", "Kerberos KDC request ASN.1 framing validated; principals, pre-authentication and tickets unverified"


class KerberosParser(FrameParser):
    """Kerberos over TCP: 4-byte length then one KDC-REQ."""
    header_size = 5
    protocol_name = "kerberos"

    def frame_size(self, header):
        size = int.from_bytes(header[:4], "big")
        if header[0] & 0x80:
            raise UnsupportedPrefix("Kerberos TCP extension bit outside profile")
        if size < 40:
            raise ParseError("Kerberos TCP length too short for a KDC request")
        return 4 + size

    def validate(self, data):
        self.protocol_name, self.reason = _kerberos_body(data[4:], len(data) - 4, self.config)


def kerberos(data, config):
    if len(data) < 40:
        raise ParseError("Kerberos datagram too short for a KDC request")
    return _kerberos_body(data, len(data), config)


def kerberos_probe(data):
    """Application tag 10/12 with a definite length that exactly fits the message."""
    if len(data) < 40 or data[0] not in (0x6a, 0x6c):
        return False
    try:
        size, start = ber_length(data, 1, len(data))
    except ParseError:
        return False
    return start + size == len(data)


class TACACSParser(FrameParser):
    """TACACS+ (RFC 8907) packet header: version 0xc0/0xc1, type, seq_no, flags, session, length."""
    header_size = 12
    protocol_name = "tacacs-plus"
    scope = "protocol_header"

    def frame_size(self, header):
        if header[0] not in (0xc0, 0xc1):
            raise ParseError("TACACS+ major version must be 0xc")
        if header[1] not in (1, 2, 3):
            raise UnsupportedPrefix("TACACS+ type outside authentication/authorization/accounting")
        if header[2] != 1:
            raise UnsupportedPrefix("TACACS+ profile covers the first packet of a session (seq_no 1)")
        if header[3] & 0xfa:
            raise ParseError("TACACS+ reserved flag bits set")
        size = int.from_bytes(header[8:12], "big")
        if not 1 <= size <= 65535:
            raise ParseError("TACACS+ body length outside profile")
        return 12 + size

    def validate(self, data):
        if data[3] & 1 and data[1] == 1:
            body = data[12:]
            if len(body) < 8:
                raise ParseError("TACACS+ authentication START body too short")
            if body[0] not in (1, 2, 3, 4) or not 1 <= body[2] <= 9:
                raise ParseError("TACACS+ START action or authen_type invalid")
            if 8 + body[4] + body[5] + body[6] + body[7] != len(body):
                raise ParseError("TACACS+ START field lengths disagree with body")
        self.reason = "TACACS+ header validated; body is encrypted or opaque, no authentication claim"
