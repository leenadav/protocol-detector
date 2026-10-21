"""Bounded structural walk of the leaf X.509 certificate from a TLS 1.2 Certificate message.

The walk reports what the structure says about itself (version, whether the
issuer equals the subject, public key family and size, signature algorithm
family, validity lifetime) and nothing that names or identifies the server:
issuer, subject, serial number, alternative names, key bytes and signature
bytes are read for their framing only and are never returned. Nothing is
verified: no signature check, chain building, name matching or revocation.
Every DER length is checked against its container before the bytes are read
and element counts are bounded, so a hostile certificate costs at most one
linear pass over at most ``MAX_LEAF`` bytes.
"""
from datetime import datetime

from .parsers import ParseError

MAX_LEAF = 16384         # largest leaf certificate inspected; bigger ones end the continuation quietly
MAX_NAME_PARTS = 32      # relative distinguished names per Name and attributes per RDN
MAX_EXTENSIONS = 64
MAX_SERIAL = 32          # RFC 5280 asks for <= 20 octets; a few CAs exceed it, nobody needs more than 32

# Object identifiers as encoded DER contents. Tables, not parsing, decide the label.
_RSA = bytes.fromhex("2a864886f70d010101")        # 1.2.840.113549.1.1.1 rsaEncryption
_EC = bytes.fromhex("2a8648ce3d0201")             # 1.2.840.10045.2.1 id-ecPublicKey
_ED25519 = bytes.fromhex("2b6570")                # 1.3.101.112
_ED448 = bytes.fromhex("2b6571")                  # 1.3.101.113
_CURVES = {bytes.fromhex("2a8648ce3d030107"): 256,   # P-256
           bytes.fromhex("2b81040022"): 384,         # P-384
           bytes.fromhex("2b81040023"): 521}         # P-521
_SIGNATURES = {bytes.fromhex("2a864886f70d010104"): "md5-rsa",
               bytes.fromhex("2a864886f70d010105"): "sha1-rsa",
               bytes.fromhex("2a864886f70d01010b"): "sha256-rsa",
               bytes.fromhex("2a864886f70d01010c"): "sha384-rsa",
               bytes.fromhex("2a864886f70d01010d"): "sha512-rsa",
               bytes.fromhex("2a864886f70d01010a"): "rsa-pss",
               bytes.fromhex("2a8648ce3d0401"): "ecdsa-sha1",
               bytes.fromhex("2a8648ce3d040302"): "ecdsa-sha256",
               bytes.fromhex("2a8648ce3d040303"): "ecdsa-sha384",
               bytes.fromhex("2a8648ce3d040304"): "ecdsa-sha512",
               _ED25519: "ed25519", _ED448: "ed448"}
WEAK_SIGNATURES = frozenset(("md5-rsa", "sha1-rsa", "ecdsa-sha1"))
MIN_RSA_BITS = 2048
MIN_EC_BITS = 256

_SEQUENCE, _SET, _INTEGER, _BIT_STRING, _OCTET_STRING, _NULL, _OID, _BOOLEAN = 0x30, 0x31, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01
_UTC_TIME, _GENERALIZED_TIME = 0x17, 0x18


def _element(data, pos, limit):
    """Return (tag, content_start, content_end) of the DER element at pos, bounded by limit."""
    if pos + 2 > limit:
        raise ParseError("DER element truncated")
    tag = data[pos]
    if tag & 0x1f == 0x1f:
        raise ParseError("Multi-byte DER tag outside the certificate profile")
    first = data[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise ParseError("Indefinite DER length is not valid in a certificate")
    else:
        count = first & 0x7f
        if count > 4 or pos + count > limit:
            raise ParseError("DER length encoding invalid")
        length = int.from_bytes(data[pos:pos + count], "big")
        if length < 0x80 or data[pos] == 0:
            raise ParseError("DER length is not minimally encoded")
        pos += count
    if pos + length > limit:
        raise ParseError("DER element exceeds its container")
    return tag, pos, pos + length


def _expect(data, pos, limit, tag, what):
    found, start, end = _element(data, pos, limit)
    if found != tag:
        raise ParseError(what + " has an unexpected DER tag")
    return start, end


def _oid(data, pos, limit, what):
    start, end = _expect(data, pos, limit, _OID, what)
    if start == end or end - start > 32 or data[end - 1] & 0x80:
        raise ParseError(what + " object identifier is malformed")
    return bytes(data[start:end]), end


def _algorithm(data, pos, limit, what):
    """AlgorithmIdentifier: return (oid, parameters bytes or None, end)."""
    start, end = _expect(data, pos, limit, _SEQUENCE, what)
    oid, cursor = _oid(data, start, end, what)
    params = None
    if cursor < end:
        _, _, after = _element(data, cursor, end)
        params = bytes(data[cursor:after])
        if after != end:
            raise ParseError(what + " algorithm identifier has trailing bytes")
    return oid, params, end


def _name(data, pos, limit, what):
    """Name ::= SEQUENCE OF SET OF SEQUENCE { OID, ANY }; framing only, no values kept."""
    start, end = _expect(data, pos, limit, _SEQUENCE, what)
    cursor, parts = start, 0
    while cursor < end:
        parts += 1
        if parts > MAX_NAME_PARTS:
            raise ParseError(what + " exceeds the name component budget")
        rdn_start, rdn_end = _expect(data, cursor, end, _SET, what)
        if rdn_start == rdn_end:
            raise ParseError(what + " contains an empty relative distinguished name")
        inner, attributes = rdn_start, 0
        while inner < rdn_end:
            attributes += 1
            if attributes > MAX_NAME_PARTS:
                raise ParseError(what + " exceeds the name component budget")
            attr_start, attr_end = _expect(data, inner, rdn_end, _SEQUENCE, what)
            _, value_pos = _oid(data, attr_start, attr_end, what)
            _, _, value_end = _element(data, value_pos, attr_end)
            if value_end != attr_end:
                raise ParseError(what + " attribute has trailing bytes")
            inner = value_end
        cursor = rdn_end
    return bytes(data[start:end]), end


def _time(data, pos, limit):
    tag, start, end = _element(data, pos, limit)
    text = bytes(data[start:end])
    if tag == _UTC_TIME and len(text) == 13:
        digits, year = text[:12], None
    elif tag == _GENERALIZED_TIME and len(text) == 15:
        digits, year = text[:14], None
    else:
        raise ParseError("Certificate validity time is not a UTCTime or GeneralizedTime with seconds in UTC")
    if text[-1:] != b"Z" or not digits.isdigit():
        raise ParseError("Certificate validity time is not in UTC")
    if tag == _UTC_TIME:
        two = int(digits[:2])
        year, rest = (1900 + two if two >= 50 else 2000 + two), digits[2:]
    else:
        year, rest = int(digits[:4]), digits[4:]
    try:
        moment = datetime(year, int(rest[0:2]), int(rest[2:4]), int(rest[4:6]), int(rest[6:8]), int(rest[8:10]))
    except ValueError:
        raise ParseError("Certificate validity time is not a calendar date") from None
    return moment, end


def _bit_string(data, pos, limit, what):
    start, end = _expect(data, pos, limit, _BIT_STRING, what)
    if start == end or data[start] != 0:
        raise ParseError(what + " bit string must be non-empty with no unused bits")
    return start + 1, end


def _public_key(data, pos, limit):
    """SubjectPublicKeyInfo: return (label, end). Key bytes are checked for framing only."""
    start, end = _expect(data, pos, limit, _SEQUENCE, "Subject public key info")
    oid, params, cursor = _algorithm(data, start, end, "Public key")
    key_start, key_end = _bit_string(data, cursor, end, "Subject public key")
    if key_end != end:
        raise ParseError("Subject public key info has trailing bytes")
    size = key_end - key_start
    if oid == _RSA:
        if params != b"\x05\x00":
            raise ParseError("RSA public key parameters must be NULL")
        seq_start, seq_end = _expect(data, key_start, key_end, _SEQUENCE, "RSA public key")
        mod_start, mod_end = _expect(data, seq_start, seq_end, _INTEGER, "RSA modulus")
        exp_start, exp_end = _expect(data, mod_end, seq_end, _INTEGER, "RSA exponent")
        if exp_end != seq_end or exp_end - exp_start > 8 or mod_start == mod_end:
            raise ParseError("RSA public key encoding invalid")
        if data[mod_start] & 0x80 or data[exp_start] & 0x80 or (data[exp_start] == 0 and exp_end - exp_start > 1):
            raise ParseError("RSA public key integers must be positive and minimally encoded")
        if data[mod_start] == 0:
            if mod_end - mod_start == 1 or not data[mod_start + 1] & 0x80:
                raise ParseError("RSA modulus is not minimally encoded")
            mod_start += 1
        bits = (mod_end - mod_start - 1) * 8 + data[mod_start].bit_length()
        return "rsa-%d" % bits, end
    if oid == _EC:
        if params is None or params[0] != _OID:
            return "ec-other", end       # explicit or implicit curve parameters: not a named curve
        curve = _CURVES.get(params[2:])
        if curve is None:
            return "ec-other", end
        coordinate = (curve + 7) // 8
        form = data[key_start]
        if not ((form == 4 and size == 1 + 2 * coordinate) or (form in (2, 3) and size == 1 + coordinate)):
            raise ParseError("EC public key point encoding does not match the named curve")
        return "ec-%d" % curve, end
    if oid in (_ED25519, _ED448):
        if params is not None or size != (32 if oid == _ED25519 else 57):
            raise ParseError("Edwards public key encoding invalid")
        return "ed25519" if oid == _ED25519 else "ed448", end
    return "other", end


def _extensions(data, pos, limit):
    start, end = _expect(data, pos, limit, _SEQUENCE, "Extensions")
    if start == end:
        raise ParseError("Extensions sequence must not be empty")
    cursor, count = start, 0
    while cursor < end:
        count += 1
        if count > MAX_EXTENSIONS:
            raise ParseError("Certificate exceeds the extension count budget")
        ext_start, ext_end = _expect(data, cursor, end, _SEQUENCE, "Extension")
        _, inner = _oid(data, ext_start, ext_end, "Extension")
        tag, flag_start, flag_end = _element(data, inner, ext_end)
        if tag == _BOOLEAN:
            if flag_end - flag_start != 1 or data[flag_start] not in (0x00, 0xff):
                raise ParseError("Extension critical flag is not a DER boolean")
            inner = flag_end
        value_start, value_end = _expect(data, inner, ext_end, _OCTET_STRING, "Extension value")
        if value_end != ext_end:
            raise ParseError("Extension has trailing bytes")
        cursor = ext_end
    return end


def leaf_profile(der):
    """Walk one DER certificate and return ((field, value), ...) structural evidence.

    Raises ParseError for anything that disagrees with RFC 5280 section 4.1
    framing. Returned values come from closed sets or are small integers.
    """
    limit = len(der)
    if limit > MAX_LEAF:
        raise ParseError("Leaf certificate exceeds the inspection budget")
    outer_start, outer_end = _expect(der, 0, limit, _SEQUENCE, "Certificate")
    if outer_end != limit:
        raise ParseError("Certificate has trailing bytes")
    tbs_start, tbs_end = _expect(der, outer_start, outer_end, _SEQUENCE, "TBSCertificate")
    cursor, version = tbs_start, 1
    tag, start, end = _element(der, cursor, tbs_end)
    if tag == 0xa0:
        value_start, value_end = _expect(der, start, end, _INTEGER, "Version")
        if value_end != end or value_end - value_start != 1 or der[value_start] not in (1, 2):
            raise ParseError("Certificate version must be an explicit v2 or v3")
        version, cursor = der[value_start] + 1, end
    serial_start, serial_end = _expect(der, cursor, tbs_end, _INTEGER, "Serial number")
    if not 1 <= serial_end - serial_start <= MAX_SERIAL:
        raise ParseError("Serial number length outside the profile")
    signature_oid, _, cursor = _algorithm(der, serial_end, tbs_end, "Certificate signature")
    inner_algorithm = bytes(der[serial_end:cursor])
    issuer, cursor = _name(der, cursor, tbs_end, "Issuer")
    validity_start, validity_end = _expect(der, cursor, tbs_end, _SEQUENCE, "Validity")
    not_before, cursor = _time(der, validity_start, validity_end)
    not_after, cursor = _time(der, cursor, validity_end)
    if cursor != validity_end:
        raise ParseError("Validity has trailing bytes")
    if not_after < not_before:
        raise ParseError("Certificate validity ends before it starts")
    subject, cursor = _name(der, validity_end, tbs_end, "Subject")
    key, cursor = _public_key(der, cursor, tbs_end)
    while cursor < tbs_end:
        tag, start, end = _element(der, cursor, tbs_end)
        if tag in (0x81, 0x82):
            if version < 2 or start == end:
                raise ParseError("Unique identifiers require a v2 or v3 certificate")
        elif tag == 0xa3:
            if version != 3:
                raise ParseError("Extensions require a v3 certificate")
            if _extensions(der, start, end) != end or end != tbs_end:
                raise ParseError("Extensions must be the last TBSCertificate field")
        else:
            raise ParseError("Unexpected field after the subject public key")
        cursor = end
    outer_oid, _, cursor = _algorithm(der, tbs_end, outer_end, "Outer signature")
    if bytes(der[tbs_end:cursor]) != inner_algorithm:
        raise ParseError("Certificate signature algorithms disagree")
    _, signature_end = _bit_string(der, cursor, outer_end, "Signature value")
    if signature_end != outer_end:
        raise ParseError("Certificate has bytes after the signature")
    return (("tls_certificate_version", str(version)),
            ("tls_certificate_self_issued", "yes" if issuer == subject else "no"),
            ("tls_certificate_key", key),
            ("tls_certificate_signature", _SIGNATURES.get(signature_oid, "other")),
            ("tls_certificate_lifetime_days", str((not_after - not_before).days)))


def weak_key(label):
    """True for a key label below the documented minimum (RSA < 2048, named curve < 256 bits)."""
    family, _, bits = label.partition("-")
    if not bits.isdigit():
        return False
    return (family == "rsa" and int(bits) < MIN_RSA_BITS) or (family == "ec" and int(bits) < MIN_EC_BITS)
