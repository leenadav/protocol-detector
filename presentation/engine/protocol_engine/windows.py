"""SMB1 negotiate, NetBIOS session request, Kerberos AS/TGS requests and TACACS+ headers."""
from .datagram_result import DatagramMatch
from .model import Evidence
from .framing import FrameParser, ber_field, ber_length
from .parsers import BudgetError, ParseError
from .extended import UnsupportedPrefix


class SMB1Parser(FrameParser):
    """NetBIOS session header plus SMB_COM_NEGOTIATE (either direction), then one SESSION_SETUP_ANDX frame (v0.56)."""
    header_size = 8
    protocol_name = "smb1"
    scope = "negotiation_request"

    def __init__(self, config):
        super().__init__(config)
        self.continues = False
        self.refined = False
        self.extra_evidence = ()
        self.frame = bytearray()
        self.frame_needed = 8

    def feed(self, data):
        if not self.done:
            consumed = FrameParser.feed(self, data)
            if self.done:
                self.continues = True
            return consumed
        return self._next_frame(data)

    def _next_frame(self, data):
        pos = 0
        while pos < len(data) and self.continues:
            start = pos
            amount = min(self.frame_needed - len(self.frame), len(data) - pos)
            self.frame.extend(data[pos:pos + amount])
            pos += amount
            if len(self.frame) < self.frame_needed:
                break
            if self.frame_needed == 8:
                if self.frame[0] != 0 or self.frame[4:8] != b"\xffSMB":
                    self.continues = False      # not an SMB1 frame: the identification stands, these bytes are not inspected
                    return start
                size = int.from_bytes(self.frame[1:4], "big")
                if size < 35:
                    raise ParseError("SMB1 frame shorter than a header with word and byte counts")
                if 4 + size > self.config.max_bytes:
                    raise BudgetError("SMB1 SESSION_SETUP frame exceeds byte budget")
                self.frame_needed = 4 + size
                if len(self.frame) < self.frame_needed:
                    continue
            self._session_setup(bytes(self.frame[4:]))
            self.continues = False
        return pos

    def _session_setup(self, data):
        """SMB_COM_SESSION_SETUP_ANDX (0x73): extended security blob, LM/NTLM response lengths or the response action."""
        if data[4] != 0x73:
            raise UnsupportedPrefix("Only SESSION_SETUP_ANDX is read after NEGOTIATE")
        words = data[32]
        count = int.from_bytes(data[33 + 2 * words:35 + 2 * words], "little") if len(data) >= 35 + 2 * words else None
        if count is None or 35 + 2 * words + count != len(data):
            raise ParseError("SMB1 SESSION_SETUP_ANDX word or byte count disagrees with the frame")
        body = data[35 + 2 * words:]
        rows = []
        if data[9] & 0x80:
            status = int.from_bytes(data[5:9], "little")
            if status not in (0, 0xC0000016):
                raise UnsupportedPrefix("SESSION_SETUP_ANDX response status outside success and more-processing")
            if words not in (3, 4):
                raise ParseError("SESSION_SETUP_ANDX response word count must be 3 or 4")
            action = int.from_bytes(data[37:39], "little")
            if action & ~3:
                raise ParseError("SESSION_SETUP_ANDX response action outside the defined bits")
            rows.append(("smb1_message", "session-setup-response", "header", "structural"))
            session = "continuing" if status else ("guest" if action & 1 else "authenticated")
            rows.append(("smb_session", session, "session_setup", "asserted"))
            if words == 4:
                length = int.from_bytes(data[39:41], "little")
                if length > count:
                    raise ParseError("SESSION_SETUP_ANDX response security blob exceeds the byte count")
                if length:
                    rows += self._token(body[:length])
        else:
            if data[5:9] != bytes(4):
                raise ParseError("SESSION_SETUP_ANDX request must carry zero status")
            rows.append(("smb1_message", "session-setup-request", "header", "structural"))
            if words == 12:
                length = int.from_bytes(data[47:49], "little")
                if not length or length > count:
                    raise ParseError("SESSION_SETUP_ANDX extended security blob outside the byte count")
                rows += self._token(body[:length])
            elif words == 13:
                insensitive, sensitive = int.from_bytes(data[47:49], "little"), int.from_bytes(data[49:51], "little")
                if insensitive + sensitive > count or insensitive > 24 or sensitive > 1024:
                    raise ParseError("SESSION_SETUP_ANDX password response lengths outside the byte count or NTLM sizes")
                rows.append(("gss_mechanism", "ntlm-response" if insensitive or sensitive else "none", "session_setup", "asserted"))
            elif words == 10:
                length = int.from_bytes(data[47:49], "little")
                if length > count or length > 24:
                    raise ParseError("SESSION_SETUP_ANDX LAN Manager password length outside the byte count")
                rows.append(("gss_mechanism", "lm-response" if length else "none", "session_setup", "asserted"))
            else:
                raise UnsupportedPrefix("SESSION_SETUP_ANDX word count outside the 10/12/13 layouts")
        self.extra_evidence += tuple(rows)
        self.refined = True
        self.reason += "; SESSION_SETUP_ANDX read for the authentication mechanism, names and responses not emitted"

    @staticmethod
    def _token(blob):
        from .gss import classify_token
        token = classify_token(blob)
        rows = [("gss_mechanism", token.mechanism, "session_setup", "asserted")]
        if token.ntlm_message:
            rows.append(("ntlm_message", token.ntlm_message, "session_setup", "asserted"))
        return rows

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
            raise UnsupportedPrefix("Only SMB1 NEGOTIATE requests and responses are supported")
        if data[9] & 0x80:
            return self._response(data)
        if data[5:9] != bytes(4):
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
        self.extra_evidence = (("smb1_message", "negotiate-request", "header", "structural"),)
        self.reason = "SMB1 negotiate request framing and dialect strings validated; dialect selection and session unverified"

    def _response(self, data):
        """SMB_COM_NEGOTIATE response: NT LM 0.12 (17 words), LAN Manager (13) or core (1) layouts (v0.47)."""
        if data[5:9] != bytes(4):
            raise UnsupportedPrefix("SMB1 negotiate response profile covers STATUS_SUCCESS")
        words = data[32]
        if words not in (1, 13, 17):
            raise UnsupportedPrefix("SMB1 negotiate response word count outside the known dialect layouts")
        if len(data) < 33 + 2 * words + 2:
            raise ParseError("SMB1 negotiate response shorter than its parameter words")
        dialect_index = int.from_bytes(data[33:35], "little")
        if dialect_index > 32 and dialect_index != 0xffff:
            raise ParseError("SMB1 dialect index outside the request's possible range")
        byte_count = int.from_bytes(data[33 + 2 * words:35 + 2 * words], "little")
        body = data[35 + 2 * words:]
        if len(body) != byte_count:
            raise ParseError("SMB1 byte count disagrees with frame")
        if words == 17:
            if data[35] & ~0x0f:
                raise ParseError("SMB1 security mode reserved bits set")
            challenge = data[66]   # EncryptionKeyLength: the last of the 34 parameter bytes
            if challenge > byte_count or challenge not in (0, 8):
                raise ParseError("SMB1 encryption key length must be 0 or 8 within the byte count")
            label = "nt-lm-0.12"
        elif words == 13:
            label = "lan-manager"
        else:
            label = "core"
        self.scope = "negotiation_response"
        self.extra_evidence = (("smb1_message", "negotiate-response", "header", "structural"), ("smb1_dialect_layout", label, "header", "asserted"))
        self.reason = "SMB1 negotiate response framing validated; challenge and domain not emitted, dialect selection unverified"


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


_KRB_TAGS = {0x6a: ("as-req", b"\x0a"), 0x6c: ("tgs-req", b"\x0c"), 0x6b: ("as-rep", b"\x0b"), 0x6d: ("tgs-rep", b"\x0d"), 0x7e: ("error", b"\x1e")}
KRB_ERR_PREAUTH_REQUIRED = 25


def _kerberos_fields(sequence, config, allowed, budget):
    """Yield (field number, value) of a KDC message SEQUENCE: context-specific, strictly increasing."""
    pos, last, count = 0, -1, 0
    while pos < len(sequence):
        count += 1
        if count > budget:
            raise BudgetError("Kerberos field count exceeds profile")
        field_tag = sequence[pos]
        if field_tag & 0xe0 != 0xa0:
            raise ParseError("Kerberos fields must be context-specific constructed")
        value, pos = ber_field(sequence, pos, len(sequence), field_tag)
        number = field_tag & 0x1f
        if number <= last or number not in allowed:
            raise ParseError("Kerberos fields out of order or outside the message definition")
        last = number
        yield number, value


def _krb_inner(value, tag, what):
    inner, end = ber_field(value, 0, len(value), tag)
    if end != len(value):
        raise ParseError("Kerberos " + what + " framing invalid")
    return inner


def _kerberos_body(data, limit, config):
    """Validate one KDC message: AS/TGS-REQ, AS/TGS-REP or KRB-ERROR; return (reason, evidence rows)."""
    tag = data[0]
    if tag not in _KRB_TAGS:
        raise UnsupportedPrefix("Kerberos profile covers KDC requests, replies and KRB-ERROR")
    name, msg_type = _KRB_TAGS[tag]
    outer, end = ber_field(data, 0, limit, tag)
    if end != limit:
        raise ParseError("Trailing bytes after Kerberos message")
    sequence, end = ber_field(outer, 0, len(outer), 0x30)
    if end != len(outer):
        raise ParseError("Kerberos wrapper must contain one SEQUENCE")
    evidence = [("kerberos_message", name, "message", "structural")]
    if name.endswith("req"):
        seen = set()
        for number, value in _kerberos_fields(sequence, config, (1, 2, 3, 4), 5):
            seen.add(number)
            if number == 1 and _krb_inner(value, 2, "pvno") != b"\x05":
                raise UnsupportedPrefix("Kerberos pvno outside version 5")
            elif number == 2 and _krb_inner(value, 2, "msg-type") != msg_type:
                raise ParseError("Kerberos msg-type disagrees with application tag")
            elif number == 3:
                padata = _krb_inner(value, 0x30, "padata")
                count, inner = 0, 0
                while inner < len(padata):
                    count += 1
                    if count > min(config.max_headers, 32):
                        raise BudgetError("Kerberos padata count exceeds budget")
                    _, inner = ber_field(padata, inner, len(padata), 0x30)
            elif number == 4 and not _krb_inner(value, 0x30, "req-body"):
                raise ParseError("Kerberos req-body framing invalid")
        if not {1, 2, 4} <= seen:
            raise ParseError("Kerberos request requires pvno, msg-type and req-body")
        return "Kerberos KDC request ASN.1 framing validated; principals, pre-authentication and tickets unverified", tuple(evidence)
    if name.endswith("rep"):
        seen = set()
        for number, value in _kerberos_fields(sequence, config, (0, 1, 2, 3, 4, 5, 6), 8):
            seen.add(number)
            if number == 0 and _krb_inner(value, 2, "pvno") != b"\x05":
                raise UnsupportedPrefix("Kerberos pvno outside version 5")
            elif number == 1 and _krb_inner(value, 2, "msg-type") != msg_type:
                raise ParseError("Kerberos msg-type disagrees with application tag")
            elif number == 2:
                padata = _krb_inner(value, 0x30, "padata")
                count, inner = 0, 0
                while inner < len(padata):
                    count += 1
                    if count > min(config.max_headers, 32):
                        raise BudgetError("Kerberos padata count exceeds budget")
                    _, inner = ber_field(padata, inner, len(padata), 0x30)
            elif number == 3 and not _krb_inner(value, 0x1b, "crealm"):
                raise ParseError("Kerberos crealm must be a non-empty GeneralString")
            elif number == 4 and not _krb_inner(value, 0x30, "cname"):
                raise ParseError("Kerberos cname framing invalid")
            elif number == 5 and not _krb_inner(value, 0x61, "ticket"):
                raise ParseError("Kerberos ticket framing invalid")
            elif number == 6 and not _krb_inner(value, 0x30, "enc-part"):
                raise ParseError("Kerberos enc-part framing invalid")
        if not {0, 1, 3, 4, 5, 6} <= seen:
            raise ParseError("Kerberos reply requires pvno, msg-type, crealm, cname, ticket and enc-part")
        return "Kerberos KDC reply ASN.1 framing validated; ticket and encrypted part opaque, principals not emitted", tuple(evidence)
    seen, code = set(), None
    for number, value in _kerberos_fields(sequence, config, tuple(range(13)), 14):
        seen.add(number)
        if number == 0 and _krb_inner(value, 2, "pvno") != b"\x05":
            raise UnsupportedPrefix("Kerberos pvno outside version 5")
        elif number == 1 and _krb_inner(value, 2, "msg-type") != msg_type:
            raise ParseError("Kerberos msg-type disagrees with application tag")
        elif number in (2, 4):
            stamp = _krb_inner(value, 0x18, "time")
            if len(stamp) != 15 or not stamp[:14].isdigit() or stamp[14:] != b"Z":
                raise ParseError("Kerberos time must be a GeneralizedTime in UTC")
        elif number in (3, 5):
            usec = _krb_inner(value, 2, "microseconds")
            # RFC 4120 Microseconds ::= INTEGER (0..999999); three octets alone would allow 8,388,607 (review round 3).
            if not 1 <= len(usec) <= 3 or not 0 <= int.from_bytes(usec, "big", signed=True) <= 999999:
                raise ParseError("Kerberos microseconds outside range")
        elif number == 6:
            raw = _krb_inner(value, 2, "error-code")
            code = int.from_bytes(raw, "big", signed=True)
            if not 1 <= len(raw) <= 2 or not 0 <= code <= 127:
                raise ParseError("Kerberos error-code outside RFC 4120 range")
        elif number in (7, 9) and not _krb_inner(value, 0x1b, "realm"):
            raise ParseError("Kerberos realm must be a non-empty GeneralString")
        elif number in (8, 10) and not _krb_inner(value, 0x30, "principal"):
            raise ParseError("Kerberos principal framing invalid")
        elif number == 11:
            _krb_inner(value, 0x1b, "e-text")
        elif number == 12:
            _krb_inner(value, 4, "e-data")
    if not {0, 1, 4, 5, 6, 9, 10} <= seen:
        raise ParseError("KRB-ERROR requires pvno, msg-type, stime, susec, error-code, realm and sname")
    evidence.append(("kerberos_error", str(code), "message", "structural"))
    return "KRB-ERROR ASN.1 framing validated; error code reported, principals and text not emitted", tuple(evidence)


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
        self.reason, self.extra_evidence = _kerberos_body(data[4:], len(data) - 4, self.config)
        if self.extra_evidence[0][1].endswith(("rep", "error")):
            self.scope = "negotiation_response"


def kerberos(data, config):
    if len(data) < 40:
        raise ParseError("Kerberos datagram too short for a KDC message")
    reason, rows = _kerberos_body(data, len(data), config)
    return DatagramMatch(reason, application_protocol="kerberos",
                         evidence=(Evidence("application_protocol", "kerberos", "wire", "structural"),)
                         + tuple(Evidence(field, value, "wire:" + source, strength) for field, value, source, strength in rows))


def kerberos_probe(data):
    """Application tag 10/11/12/13/30 with a definite length that exactly fits the message."""
    if len(data) < 40 or data[0] not in _KRB_TAGS:
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
        if header[2] not in (1, 2):
            raise UnsupportedPrefix("TACACS+ profile covers the first two packets of a session (seq_no 1 and 2)")
        if header[3] & 0xfa:
            raise ParseError("TACACS+ reserved flag bits set")
        size = int.from_bytes(header[8:12], "big")
        if not 1 <= size <= 65535:
            raise ParseError("TACACS+ body length outside profile")
        return 12 + size

    def validate(self, data):
        kind = {1: "authentication", 2: "authorization", 3: "accounting"}[data[1]]
        if data[2] == 2:
            return self._reply(data, kind)
        if data[3] & 1 and data[1] == 1:
            body = data[12:]
            if len(body) < 8:
                raise ParseError("TACACS+ authentication START body too short")
            if body[0] not in (1, 2, 3, 4) or not 1 <= body[2] <= 9:
                raise ParseError("TACACS+ START action or authen_type invalid")
            if 8 + body[4] + body[5] + body[6] + body[7] != len(body):
                raise ParseError("TACACS+ START field lengths disagree with body")
        self.extra_evidence = (("tacacs_packet", "start", "header", "structural"), ("tacacs_type", kind, "header", "structural"))
        self.reason = "TACACS+ header validated; body is encrypted or opaque, no authentication claim"

    def _reply(self, data, kind):
        """Server packet seq_no 2 (RFC 8907 4.1): unencrypted REPLY bodies checked by type (v0.47)."""
        body = data[12:]
        if data[3] & 1:
            if kind == "authentication":
                if len(body) < 6 or body[0] not in (1, 2, 3, 4, 5, 6, 7, 0x21) or 6 + int.from_bytes(body[2:4], "big") + int.from_bytes(body[4:6], "big") != len(body):
                    raise ParseError("TACACS+ authentication REPLY status or lengths invalid")
            elif kind == "authorization":
                if len(body) < 6 or body[0] not in (1, 2, 16, 17, 33) or 6 + body[1] + int.from_bytes(body[2:4], "big") + int.from_bytes(body[4:6], "big") + sum(body[6:6 + body[1]]) != len(body) or len(body) < 6 + body[1]:
                    raise ParseError("TACACS+ authorization REPLY status or lengths invalid")
            else:
                if len(body) < 5 or body[4] not in (1, 2, 3) or 5 + int.from_bytes(body[0:2], "big") + int.from_bytes(body[2:4], "big") != len(body):
                    raise ParseError("TACACS+ accounting REPLY status or lengths invalid")
        self.scope = "negotiation_response"
        self.extra_evidence = (("tacacs_packet", "reply", "header", "structural"), ("tacacs_type", kind, "header", "structural"))
        self.reason = "TACACS+ reply header validated; body is encrypted or opaque, status and messages not emitted"
