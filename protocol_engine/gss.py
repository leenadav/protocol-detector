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


def _inner(blob, limit):
    """Mechanism of a mechToken/responseToken: NTLMSSP, a Kerberos GSS token, or other."""
    if blob.startswith(NTLMSSP_SIGNATURE):
        return "ntlm", _ntlm_message(blob)
    if blob[:1] == b"\x60":
        size, start = ber_length(blob, 1, limit)
        if start + size == limit and blob[start:start + 1] == b"\x06":
            oid, _ = ber_field(blob, start, limit, 0x06)
            if oid in _MECHANISMS and _MECHANISMS[oid] == "kerberos":
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
        if oid in _MECHANISMS and _MECHANISMS[oid] == "kerberos":
            if limit - pos < 2 or blob[pos:pos + 2] not in (b"\x01\x00", b"\x02\x00", b"\x03\x00", b"\x04\x00"):
                raise ParseError("Kerberos GSS token needs a known TOK_ID")
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
