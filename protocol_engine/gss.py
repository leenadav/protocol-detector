"""Bounded classification of GSS-API, SPNEGO and NTLMSSP tokens (RFC 2743 3.1, RFC 4178, MS-NLMP).

Authentication blobs carried by SMB session setup, LDAP SASL binds and similar
first messages name their mechanism in a few DER fields. Only the closed
mechanism and message labels leave this module; principal names, domains,
workstation names, challenges, MICs and ticket bytes are never decoded.
"""
from collections import namedtuple

from .framing import ber_field, ber_length
from .parsers import BudgetError, ParseError

OID_SPNEGO = b"\x2b\x06\x01\x05\x05\x02"
OID_KRB5 = b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"
OID_MS_KRB5 = b"\x2a\x86\x48\x82\xf7\x12\x01\x02\x02"
OID_KRB5_USER_TO_USER = b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x03"
OID_NTLMSSP = b"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
OID_NEGOEX = b"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x1e"
_MECHANISMS = {OID_KRB5: "kerberos", OID_MS_KRB5: "kerberos", OID_KRB5_USER_TO_USER: "kerberos", OID_NTLMSSP: "ntlm", OID_NEGOEX: "negoex"}
NTLMSSP_SIGNATURE = b"NTLMSSP\x00"
_NTLM_MESSAGES = {1: "negotiate", 2: "challenge", 3: "authenticate"}
_NEG_STATES = ("accept-completed", "accept-incomplete", "reject", "request-mic")
# RFC 4121 4.1 / RFC 1964 1.1 TOK_ID and the Kerberos message each one frames: AP-REQ [APPLICATION 14],
# AP-REP [APPLICATION 15], KRB-ERROR [APPLICATION 30]; user-to-user TGT-REQ is a SEQUENCE.
_KERBEROS_TOKENS = {b"\x01\x00": 0x6e, b"\x02\x00": 0x6f, b"\x03\x00": 0x7e, b"\x04\x00": 0x30}
MAX_TOKEN = 4096
MAX_MECHANISMS = 8

GssToken = namedtuple("GssToken", "kind mechanism ntlm_message state")
# kind: ntlmssp | kerberos | spnego-init | spnego-response | gss-other
# mechanism: kerberos | ntlm | negoex | spnego-other | other
# ntlm_message: negotiate | challenge | authenticate | None
# state: accept-completed | accept-incomplete | reject | request-mic | None


def _ntlm_message(blob):
    if len(blob) < 12:
        raise ParseError("NTLMSSP message shorter than its signature and type")
    kind = int.from_bytes(blob[8:12], "little")
    if kind not in _NTLM_MESSAGES:
        raise ParseError("NTLMSSP message type outside NEGOTIATE, CHALLENGE and AUTHENTICATE")
    return _NTLM_MESSAGES[kind]


MAX_PRINCIPAL_PARTS = 8


def _fields(sequence, allowed, required, what):
    """Context-tagged fields [n] of a Kerberos SEQUENCE, strictly increasing (so at most len(allowed))."""
    pos, last, found = 0, -1, {}
    while pos < len(sequence):
        tag = sequence[pos]
        number = tag & 0x1f
        if tag & 0xe0 != 0xa0 or number <= last or number not in allowed:
            raise ParseError(what + " fields out of order or outside the message definition")
        found[number], pos = ber_field(sequence, pos, len(sequence), tag)
        last = number
    if not required <= found.keys():
        raise ParseError(what + " lacks a required field")
    return found


def _only(value, tag, what):
    """The single element of an explicitly tagged field, which must fill it."""
    inner, end = ber_field(value, 0, len(value), tag)
    if end != len(value):
        raise ParseError(what + " framing invalid")
    return inner


def _small_integer(value, what, expected=None, width=4):
    number = _only(value, 0x02, what)
    if not 1 <= len(number) <= width or (expected is not None and number != bytes((expected,))):
        raise ParseError(what + " outside the Kerberos profile")


def _encrypted_data(value, what):
    """EncryptedData ::= SEQUENCE { etype [0] Int32, kvno [1] UInt32 OPTIONAL, cipher [2] OCTET STRING }."""
    found = _fields(_only(value, 0x30, what), (0, 1, 2), {0, 2}, what)
    _small_integer(found[0], what + " etype")
    if 1 in found:
        _small_integer(found[1], what + " kvno", width=5)
    if not _only(found[2], 0x04, what + " cipher"):
        raise ParseError(what + " cipher must not be empty")


def _principal(value, what):
    """PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1] SEQUENCE OF KerberosString }; framing only."""
    found = _fields(_only(value, 0x30, what), (0, 1), {0, 1}, what)
    _small_integer(found[0], what + " name-type")
    names, pos, count = _only(found[1], 0x30, what), 0, 0
    while pos < len(names):
        count += 1
        if count > MAX_PRINCIPAL_PARTS:
            raise ParseError(what + " exceeds the name component budget")
        _, pos = ber_field(names, pos, len(names), 0x1b)
    if not count:
        raise ParseError(what + " has no name component")


def _realm(value, what):
    if not _only(value, 0x1b, what):
        raise ParseError(what + " must be a non-empty GeneralString")


def _ticket(value):
    """Ticket ::= [APPLICATION 1] SEQUENCE { tkt-vno [0] 5, realm [1], sname [2], enc-part [3] EncryptedData }."""
    found = _fields(_only(_only(value, 0x61, "Ticket"), 0x30, "Ticket"), (0, 1, 2, 3), {0, 1, 2, 3}, "Ticket")
    _small_integer(found[0], "Ticket tkt-vno", 5)
    _realm(found[1], "Ticket realm")
    _principal(found[2], "Ticket sname")
    _encrypted_data(found[3], "Ticket enc-part")


def _kerberos_flags(bits, what):
    """KerberosFlags ::= BIT STRING (SIZE (32..MAX)) under DER (review round 3): at least 32 significant
    bits, an unused-bit count of 0..7 (0 when there are no data octets), and zero padding bits."""
    unused = bits[0] if bits else 8
    if unused > 7 or (len(bits) - 1) * 8 - unused < 32 or (unused and bits[-1] & ((1 << unused) - 1)):
        raise ParseError(what + " must be a DER KerberosFlags BIT STRING of at least 32 bits")


def _kerberos_message(message, tag):
    """RFC 4120 5.5.1 AP-REQ, 5.5.2 AP-REP, 5.9.1 KRB-ERROR, user-to-user TGT-REQ: bounded envelopes, nothing kept."""
    if tag == 0x7e:
        from .windows import _kerberos_body
        _kerberos_body(message, len(message), None)        # the Kerberos family's KRB-ERROR profile
        return
    body = _only(message, tag, "Kerberos message")
    if tag == 0x30:                                        # KERB-TGT-REQUEST: pvno, msg-type 16, optional server-name and realm
        found = _fields(body, (0, 1, 2, 3), {0, 1}, "TGT-REQ")
        _small_integer(found[0], "TGT-REQ pvno", 5)
        _small_integer(found[1], "TGT-REQ msg-type", 16)
        if 2 in found:
            _principal(found[2], "TGT-REQ server-name")
        if 3 in found:
            _realm(found[3], "TGT-REQ realm")
        return
    sequence = _only(body, 0x30, "Kerberos message")
    if tag == 0x6e:
        found = _fields(sequence, (0, 1, 2, 3, 4), {0, 1, 2, 3, 4}, "AP-REQ")
        _small_integer(found[0], "AP-REQ pvno", 5)
        _small_integer(found[1], "AP-REQ msg-type", 14)
        _kerberos_flags(_only(found[2], 0x03, "AP-REQ ap-options"), "AP-REQ ap-options")
        _ticket(found[3])
        _encrypted_data(found[4], "AP-REQ authenticator")
    else:
        found = _fields(sequence, (0, 1, 2), {0, 1, 2}, "AP-REP")
        _small_integer(found[0], "AP-REP pvno", 5)
        _small_integer(found[1], "AP-REP msg-type", 15)
        _encrypted_data(found[2], "AP-REP enc-part")


def _kerberos_token(blob, pos, limit):
    """After a Kerberos mechanism OID: a known TOK_ID, then exactly the Kerberos message it names (review rounds 1 and 2)."""
    expected = _KERBEROS_TOKENS.get(bytes(blob[pos:pos + 2]))
    if expected is None:
        raise ParseError("Kerberos GSS token needs a known TOK_ID")
    _, end = ber_field(blob, pos + 2, limit, expected)
    if end != limit:
        raise ParseError("Kerberos GSS token has bytes after its message")
    _kerberos_message(bytes(blob[pos + 2:limit]), expected)


def _inner(blob, limit):
    """Mechanism of a mechToken/responseToken: NTLMSSP, a Kerberos GSS token, or other.

    A token that names a Kerberos OID must pass the same validator as a direct
    Kerberos token (review round 1); otherwise the blob is malformed.
    """
    if blob.startswith(NTLMSSP_SIGNATURE):
        return "ntlm", _ntlm_message(blob)
    if blob[:1] == b"\x60":
        size, start = ber_length(blob, 1, limit)
        if start + size == limit and blob[start:start + 1] == b"\x06":
            oid, pos = ber_field(blob, start, limit, 0x06)
            if _MECHANISMS.get(oid) == "kerberos":
                _kerberos_token(blob, pos, limit)
                return "kerberos", None
    return "other", None


def classify_token(blob):
    """Return a GssToken for an authentication blob; ParseError when it is none of the known layouts."""
    limit = len(blob)
    if limit > MAX_TOKEN:
        raise BudgetError("Authentication token exceeds the inspection limit")
    if not limit:
        raise ParseError("Empty authentication token")
    if blob.startswith(NTLMSSP_SIGNATURE):
        return GssToken("ntlmssp", "ntlm", _ntlm_message(blob), None)
    tag = blob[0]
    if tag == 0x60:
        size, start = ber_length(blob, 1, limit)
        if start + size != limit:
            raise ParseError("GSS-API token length disagrees with the blob")
        oid, pos = ber_field(blob, start, limit, 0x06)
        if oid == OID_SPNEGO:
            if pos >= limit or blob[pos] != 0xa0:
                raise ParseError("SPNEGO initial token requires NegTokenInit")
            return _neg_token_init(blob, pos, limit)
        if _MECHANISMS.get(oid) == "kerberos":
            _kerberos_token(blob, pos, limit)
            return GssToken("kerberos", "kerberos", None, None)
        return GssToken("gss-other", "other", None, None)
    if tag == 0xa1:
        return _neg_token_resp(blob, 0, limit)
    raise ParseError("Authentication token is neither GSS-API, SPNEGO nor NTLMSSP")


def _neg_token_init(blob, pos, limit):
    wrapper, pos = ber_field(blob, pos, limit, 0xa0)
    if pos != limit:
        raise ParseError("Trailing bytes after NegTokenInit")
    body, end = ber_field(wrapper, 0, len(wrapper), 0x30)
    if end != len(wrapper):
        raise ParseError("Trailing bytes after the NegTokenInit sequence")
    cursor, preferred, mechanism, ntlm = 0, None, "spnego-other", None
    if cursor < len(body) and body[cursor] == 0xa0:
        mechs, cursor = ber_field(body, cursor, len(body), 0xa0)
        listed, inner = ber_field(mechs, 0, len(mechs), 0x30)
        if inner != len(mechs):
            raise ParseError("Trailing bytes after the mechType list")
        offset, count = 0, 0
        while offset < len(listed):
            oid, offset = ber_field(listed, offset, len(listed), 0x06)
            count += 1
            if count > MAX_MECHANISMS:
                raise BudgetError("SPNEGO mechType list exceeds the inspection limit")
            if preferred is None:
                preferred = oid
        if not count:
            raise ParseError("Empty SPNEGO mechType list")
        mechanism = _MECHANISMS.get(preferred, "spnego-other")
    if cursor < len(body) and body[cursor] == 0xa1:
        _, cursor = ber_field(body, cursor, len(body), 0xa1)
    if cursor < len(body) and body[cursor] == 0xa2:
        holder, cursor = ber_field(body, cursor, len(body), 0xa2)
        token, inner = ber_field(holder, 0, len(holder), 0x04)
        if inner != len(holder):
            raise ParseError("Trailing bytes after the SPNEGO mechToken")
        if token:
            carried, ntlm = _inner(token, len(token))
            if carried != "other":
                mechanism = carried
    if cursor < len(body) and body[cursor] == 0xa3:
        _, cursor = ber_field(body, cursor, len(body), 0xa3)
    if cursor != len(body):
        raise ParseError("Unexpected NegTokenInit field order")
    return GssToken("spnego-init", mechanism, ntlm, None)


def _neg_token_resp(blob, pos, limit):
    wrapper, pos = ber_field(blob, pos, limit, 0xa1)
    if pos != limit:
        raise ParseError("Trailing bytes after NegTokenResp")
    body, end = ber_field(wrapper, 0, len(wrapper), 0x30)
    if end != len(wrapper):
        raise ParseError("Trailing bytes after the NegTokenResp sequence")
    cursor, state, mechanism, ntlm = 0, None, "spnego-other", None
    if cursor < len(body) and body[cursor] == 0xa0:
        holder, cursor = ber_field(body, cursor, len(body), 0xa0)
        value, inner = ber_field(holder, 0, len(holder), 0x0a)
        if inner != len(holder) or len(value) != 1 or value[0] > 3:
            raise ParseError("Invalid SPNEGO negState")
        state = _NEG_STATES[value[0]]
    if cursor < len(body) and body[cursor] == 0xa1:
        holder, cursor = ber_field(body, cursor, len(body), 0xa1)
        oid, inner = ber_field(holder, 0, len(holder), 0x06)
        if inner != len(holder):
            raise ParseError("Trailing bytes after the supportedMech")
        mechanism = _MECHANISMS.get(oid, "spnego-other")
    if cursor < len(body) and body[cursor] == 0xa2:
        holder, cursor = ber_field(body, cursor, len(body), 0xa2)
        token, inner = ber_field(holder, 0, len(holder), 0x04)
        if inner != len(holder):
            raise ParseError("Trailing bytes after the SPNEGO responseToken")
        if token:
            carried, ntlm = _inner(token, len(token))
            if carried != "other":
                mechanism = carried
    if cursor < len(body) and body[cursor] == 0xa3:
        _, cursor = ber_field(body, cursor, len(body), 0xa3)
    if cursor != len(body):
        raise ParseError("Unexpected NegTokenResp field order")
    if state is None and mechanism == "spnego-other" and ntlm is None:
        raise ParseError("Empty NegTokenResp")
    return GssToken("spnego-response", mechanism, ntlm, state)
