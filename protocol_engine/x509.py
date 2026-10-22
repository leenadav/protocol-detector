"""Bounded structural walk of the leaf X.509 certificate from a TLS 1.2 Certificate message.

The walk reports what the structure says about itself (version, whether the
issuer equals the subject, public key family and size, signature algorithm
family, validity lifetime and, since v0.57, the CA flag, the extended key usage
class, whether alternative names are present and the validity window in
calendar days) and nothing that names or identifies the server:
issuer, subject, serial number, alternative names, key bytes and signature
bytes are read for their framing only and are never returned. Nothing is
verified: no signature check, chain building, name matching or revocation.
Every DER length is checked against its container before the bytes are read
and element counts are bounded, so a hostile certificate costs at most one
linear pass over at most ``MAX_LEAF`` bytes.
"""
from datetime import datetime, timedelta

from .parsers import ParseError

MAX_LEAF = 16384         # largest leaf certificate inspected; bigger ones end the continuation quietly
MAX_NAME_PARTS = 32      # relative distinguished names per Name and attributes per RDN
MAX_EXTENSIONS = 64
MAX_SERIAL = 32          # RFC 5280 asks for <= 20 octets; a few CAs exceed it, nobody needs more than 32
MAX_EKU = 16             # key purposes per extendedKeyUsage (v0.57)
MAX_GENERAL_NAMES = 256  # subjectAltName entries (v0.57 review round 1); multi-domain leaves stay well below it
MAX_PATH_LENGTH_OCTETS = 4

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
# v0.57: the three extensions whose contents are interpreted; every other extension is framing only.
_BASIC_CONSTRAINTS = bytes.fromhex("551d13")      # 2.5.29.19
_SUBJECT_ALT_NAME = bytes.fromhex("551d11")       # 2.5.29.17
_EXTENDED_KEY_USAGE = bytes.fromhex("551d25")     # 2.5.29.37
_SERVER_AUTH = bytes.fromhex("2b06010505070301")  # 1.3.6.1.5.5.7.3.1 id-kp-serverAuth
_ANY_KEY_USAGE = bytes.fromhex("551d2500")        # 2.5.29.37.0 anyExtendedKeyUsage
_EPOCH = datetime(1970, 1, 1)
MIN_CAPTURE_TIME = 946684800      # 2000-01-01T00:00:00Z: earlier capture clocks are treated as unset
MAX_CAPTURE_TIME = 253402300800   # 10000-01-01T00:00:00Z: beyond the calendar a certificate can express


def _day(moment):
    """Fixed-width YYYY-MM-DD (strftime does not zero-pad years below 1000 on every libc)."""
    return "%04d-%02d-%02d" % (moment.year, moment.month, moment.day)


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


def _oid_contents(data, start, end, what):
    """DER OBJECT IDENTIFIER contents: 1..32 octets, every arc minimal (no leading 0x80), the last arc complete."""
    if start == end or end - start > 32 or data[end - 1] & 0x80:
        raise ParseError(what + " object identifier is malformed")
    # An arc is non-minimal when it starts with 0x80: the first octet, or a 0x80 after an arc's last octet.
    # bytes.find keeps this at C speed; 0x80 octets are rare in real identifiers.
    position = data.find(b"\x80", start, end)
    while position != -1:
        if position == start or not data[position - 1] & 0x80:
            raise ParseError(what + " object identifier arc is not minimally encoded")
        position = data.find(b"\x80", position + 1, end)


def _oid(data, pos, limit, what):
    start, end = _expect(data, pos, limit, _OID, what)
    _oid_contents(data, start, end, what)
    return bytes(data[start:end]), end


def _single(data, start, end, what):
    """The contents of an EXPLICIT tag: exactly one complete element filling it."""
    if start == end:
        raise ParseError(what + " is empty")
    _, _, inner_end = _element(data, start, end)
    if inner_end != end:
        raise ParseError(what + " must hold exactly one element")


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
        # The named curve is an interpreted OID, so it passes the same DER rule as every other one
        # (v0.57 round-3 finding): exactly one OID filling the parameters, minimal arcs, complete last arc.
        named, after = _oid(params, 0, len(params), "EC named curve")
        if after != len(params):
            raise ParseError("EC named curve parameters have trailing bytes")
        curve = _CURVES.get(named)
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


def _basic_constraints(data, start, end):
    """BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER (0..MAX) OPTIONAL }."""
    seq_start, seq_end = _expect(data, start, end, _SEQUENCE, "Basic constraints")
    if seq_end != end:
        raise ParseError("Basic constraints has trailing bytes")
    ca, cursor = False, seq_start
    if cursor < seq_end and data[cursor] == _BOOLEAN:
        flag_start, flag_end = _expect(data, cursor, seq_end, _BOOLEAN, "Basic constraints cA")
        if flag_end - flag_start != 1 or data[flag_start] != 0xff:
            raise ParseError("Basic constraints cA must be absent or a DER TRUE")   # DER omits the FALSE default
        ca, cursor = True, flag_end
    if cursor < seq_end and data[cursor] == _INTEGER:
        if not ca:
            raise ParseError("Path length constraint requires cA TRUE")      # RFC 5280 4.2.1.9
        value_start, value_end = _expect(data, cursor, seq_end, _INTEGER, "Path length constraint")
        size = value_end - value_start
        if not 1 <= size <= MAX_PATH_LENGTH_OCTETS or data[value_start] & 0x80 or \
                (data[value_start] == 0 and size > 1 and not data[value_start + 1] & 0x80):
            raise ParseError("Path length constraint must be a small non-negative minimally encoded INTEGER")
        cursor = value_end
    if cursor != seq_end:
        raise ParseError("Basic constraints has unexpected fields")
    return "yes" if ca else "no"


def _key_usage_purposes(data, start, end):
    """ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId; returns a closed label."""
    seq_start, seq_end = _expect(data, start, end, _SEQUENCE, "Extended key usage")
    if seq_end != end or seq_start == seq_end:
        raise ParseError("Extended key usage must be one non-empty sequence")
    cursor, count, purposes = seq_start, 0, set()
    while cursor < seq_end:
        count += 1
        if count > MAX_EKU:
            raise ParseError("Extended key usage exceeds the purpose budget")
        purpose, cursor = _oid(data, cursor, seq_end, "Key purpose")
        if purpose in (_SERVER_AUTH, _ANY_KEY_USAGE):
            purposes.add(purpose)
    if _SERVER_AUTH in purposes:
        return "server-auth"
    return "any" if purposes else "other"


# GeneralName CHOICE (RFC 5280 4.2.1.6) with the encoding form each alternative must use under DER:
# otherName [0], x400Address [3], directoryName [4] (explicit: Name is a CHOICE) and ediPartyName [5] are
# constructed; rfc822Name [1], dNSName [2], URI [6], iPAddress [7] and registeredID [8] are primitive.
_GENERAL_NAME_TAGS = frozenset((0xa0, 0x81, 0x82, 0xa3, 0xa4, 0xa5, 0x86, 0x87, 0x88))


def _general_names(data, start, end):
    """GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName; framing only, no name is read or kept.

    Review rounds 1 and 2 (v0.57): at most MAX_GENERAL_NAMES entries, each in the DER form of its
    alternative with its inner framing: non-empty IA5 text names, a 4- or 16-octet address, a DER
    registeredID, an otherName OID plus exactly one [0] value, 1..MAX_NAME_PARTS complete elements in an
    x400Address, one Name in a directoryName, an ediPartyName of optional [0] and required [1] each
    holding exactly one element. Bytes are checked, never kept.
    """
    seq_start, seq_end = _expect(data, start, end, _SEQUENCE, "Subject alternative name")
    if seq_end != end or seq_start == seq_end:
        raise ParseError("Subject alternative name must be one non-empty sequence")
    cursor, count = seq_start, 0
    while cursor < seq_end:
        count += 1
        if count > MAX_GENERAL_NAMES:
            raise ParseError("Subject alternative name exceeds the entry budget")
        tag, value_start, value_end = _element(data, cursor, seq_end)
        if tag not in _GENERAL_NAME_TAGS:
            raise ParseError("Subject alternative name entry is not a GeneralName choice in its DER form")
        size = value_end - value_start
        if tag in (0x81, 0x82, 0x86):
            # IA5String (implicitly tagged): non-empty, seven-bit octets only (review round 2).
            if not size or max(data[value_start:value_end]) & 0x80:
                raise ParseError("Subject alternative name text entry must be a non-empty IA5String")
        elif tag == 0x87:
            if size not in (4, 16):
                raise ParseError("Subject alternative name iPAddress must be 4 or 16 octets")
        elif tag == 0x88:
            _oid_contents(data, value_start, value_end, "Subject alternative name registeredID")
        elif tag == 0xa0:
            # otherName ::= SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY } (implicitly tagged [0]).
            _, after = _oid(data, value_start, value_end, "Subject alternative name otherName")
            tag_value, inner_start, inner_end = _element(data, after, value_end) if after < value_end else (None, 0, 0)
            if tag_value != 0xa0 or inner_end != value_end:
                raise ParseError("Subject alternative name otherName needs exactly its [0] value")
            _single(data, inner_start, inner_end, "Subject alternative name otherName value")
        elif tag == 0xa3:
            # x400Address: ORAddress SEQUENCE contents, framed as 1..MAX_NAME_PARTS complete elements.
            inner, parts = value_start, 0
            while inner < value_end:
                parts += 1
                if parts > MAX_NAME_PARTS:
                    raise ParseError("Subject alternative name x400Address exceeds the component budget")
                _, _, inner = _element(data, inner, value_end)
            if not parts:
                raise ParseError("Subject alternative name x400Address is empty")
        elif tag == 0xa4:
            _, name_end = _name(data, value_start, value_end, "Subject alternative name directoryName")
            if name_end != value_end:
                raise ParseError("Subject alternative name directoryName has trailing bytes")
        else:
            # ediPartyName ::= SEQUENCE { nameAssigner [0] DirectoryString OPTIONAL, partyName [1] DirectoryString };
            # DirectoryString is a CHOICE, so both tags are explicit and hold exactly one element.
            inner = value_start
            if inner < value_end and data[inner] == 0xa0:
                _, assigner_start, inner = _element(data, inner, value_end)
                _single(data, assigner_start, inner, "Subject alternative name ediPartyName nameAssigner")
            if inner >= value_end or data[inner] != 0xa1:
                raise ParseError("Subject alternative name ediPartyName needs its partyName")
            _, party_start, party_end = _element(data, inner, value_end)
            if party_end != value_end:
                raise ParseError("Subject alternative name ediPartyName has trailing bytes")
            _single(data, party_start, party_end, "Subject alternative name ediPartyName partyName")
        cursor = value_end


def _extensions(data, pos, limit):
    """Walk Extensions; return (end, ca, eku, san) for the three interpreted extensions."""
    start, end = _expect(data, pos, limit, _SEQUENCE, "Extensions")
    if start == end:
        raise ParseError("Extensions sequence must not be empty")
    cursor, seen = start, set()
    ca, eku, san = "no", "absent", "absent"
    while cursor < end:
        if len(seen) >= MAX_EXTENSIONS:
            raise ParseError("Certificate exceeds the extension count budget")
        ext_start, ext_end = _expect(data, cursor, end, _SEQUENCE, "Extension")
        oid, inner = _oid(data, ext_start, ext_end, "Extension")
        if oid in seen:
            raise ParseError("Certificate repeats an extension")             # RFC 5280 4.2
        seen.add(oid)
        tag, flag_start, flag_end = _element(data, inner, ext_end)
        if tag == _BOOLEAN:
            # critical is BOOLEAN DEFAULT FALSE: DER omits FALSE, so only an encoded TRUE (0xff) is valid
            # (v0.57 review round 1; the same rule as basicConstraints cA).
            if flag_end - flag_start != 1 or data[flag_start] != 0xff:
                raise ParseError("Extension critical flag must be absent or a DER TRUE")
            inner = flag_end
        value_start, value_end = _expect(data, inner, ext_end, _OCTET_STRING, "Extension value")
        if value_end != ext_end:
            raise ParseError("Extension has trailing bytes")
        if oid == _BASIC_CONSTRAINTS:
            ca = _basic_constraints(data, value_start, value_end)
        elif oid == _EXTENDED_KEY_USAGE:
            eku = _key_usage_purposes(data, value_start, value_end)
        elif oid == _SUBJECT_ALT_NAME:
            _general_names(data, value_start, value_end)
            san = "present"
        cursor = ext_end
    return end, ca, eku, san


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
    posture = ("no", "absent", "absent")      # a v3 certificate without extensions: not a CA, no EKU, no SAN
    while cursor < tbs_end:
        tag, start, end = _element(der, cursor, tbs_end)
        if tag in (0x81, 0x82):
            if version < 2 or start == end:
                raise ParseError("Unique identifiers require a v2 or v3 certificate")
        elif tag == 0xa3:
            if version != 3:
                raise ParseError("Extensions require a v3 certificate")
            walked, *posture = _extensions(der, start, end)
            if walked != end or end != tbs_end:
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
    fields = (("tls_certificate_version", str(version)),
              ("tls_certificate_self_issued", "yes" if issuer == subject else "no"),
              ("tls_certificate_key", key),
              ("tls_certificate_signature", _SIGNATURES.get(signature_oid, "other")),
              ("tls_certificate_lifetime_days", str((not_after - not_before).days)),
              # v0.57: calendar days only (no time of day), so the window is a coarse posture fact, not a fingerprint.
              ("tls_certificate_not_before", _day(not_before)),
              ("tls_certificate_not_after", _day(not_after)))
    if version == 3:
        fields += (("tls_certificate_ca", posture[0]), ("tls_certificate_eku", posture[1]), ("tls_certificate_san", posture[2]))
    return fields


def validity(not_before, not_after, at):
    """Validity of a leaf at capture time `at` (POSIX seconds) from its day-granular window.

    Returns current / expired / not-yet-valid, or None when either date is
    missing or the capture clock is unset (before MIN_CAPTURE_TIME: synthetic
    and anonymised captures often start at zero). Boundary days count as
    inside the window, so a day-granular comparison never flags a valid leaf.
    Nothing here reads the wall clock of the analysis run.
    """
    if not not_before or not not_after or at is None or not MIN_CAPTURE_TIME <= at < MAX_CAPTURE_TIME:
        return None
    day = _day(_EPOCH + timedelta(seconds=int(at)))
    if day < not_before:
        return "not-yet-valid"
    return "expired" if day > not_after else "current"


def weak_key(label):
    """True for a key label below the documented minimum (RSA < 2048, named curve < 256 bits)."""
    family, _, bits = label.partition("-")
    if not bits.isdigit():
        return False
    return (family == "rsa" and int(bits) < MIN_RSA_BITS) or (family == "ec" and int(bits) < MIN_EC_BITS)
