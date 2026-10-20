"""Derived handshake fingerprints: JA3/JA4 (TLS client), JA3S/JA4S (TLS server),
HASSH (SSH), HTTP/2 SETTINGS.

A fingerprint is a deterministic digest of structural handshake fields. It is
derived evidence: it identifies a client/server implementation family at best,
never a user, a product version or an authenticated identity. No key material,
random bytes or session identifiers enter any digest.

JA4 follows the FoxIO specification (JA4 TLS client fingerprint, BSD-licensed
algorithm description); JA3/JA3S follow the Salesforce definition; HASSH
follows the Salesforce definition over SSH_MSG_KEXINIT name-lists.
"""
import hashlib

# draft-ietf-tls-grease: 0x0a0a, 0x1a1a, ..., 0xfafa
GREASE = frozenset(0x0a0a + 0x1010 * index for index in range(16))
_VERSIONS = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2",
             0xfeff: "d1", 0xfefd: "d2", 0xfefc: "d3"}


def _sha12(text):
    return hashlib.sha256(text.encode("ascii")).hexdigest()[:12]


def _alpn_code(alpn):
    """JA4 two-character ALPN code from the first offered/selected value."""
    if not alpn:
        return "00"
    value = alpn[0]
    raw = bytes.fromhex(value[4:]) if value.startswith("hex:") else value.encode("latin-1", "replace")
    if not raw:
        return "00"
    first, last = raw[0], raw[-1]
    alnum = lambda byte: 0x30 <= byte <= 0x39 or 0x41 <= byte <= 0x5a or 0x61 <= byte <= 0x7a
    if alnum(first) and alnum(last):
        return chr(first) + chr(last)
    text = raw.hex()
    return text[0] + text[-1]


def _version_code(version, supported_versions):
    candidates = [value for value in supported_versions if value not in GREASE]
    chosen = max(candidates) if candidates else version
    return _VERSIONS.get(chosen, "00")


def ja4(info, protocol="t"):
    """JA4 client fingerprint from a ClientHelloInfo; protocol t (TCP), q (QUIC) or d (DTLS)."""
    ciphers = [value for value in info.ciphers if value not in GREASE]
    extensions = [value for value in info.extensions if value not in GREASE]
    sni = "d" if 0 in info.extensions else "i"
    part_a = "{}{}{}{:02d}{:02d}{}".format(protocol, _version_code(info.version, info.supported_versions), sni,
                                           min(len(ciphers), 99), min(len(extensions), 99), _alpn_code(info.alpn))
    part_b = _sha12(",".join("%04x" % value for value in sorted(ciphers))) if ciphers else "000000000000"
    filtered = sorted(value for value in extensions if value not in (0, 16))
    algorithms = [value for value in info.signature_algorithms if value not in GREASE]
    text = ",".join("%04x" % value for value in filtered)
    if algorithms:
        text += "_" + ",".join("%04x" % value for value in algorithms)
    part_c = _sha12(text) if filtered or algorithms else "000000000000"
    return "_".join((part_a, part_b, part_c))


def ja4_raw(info, protocol="t"):
    """JA4_r: the unhashed form, useful for debugging a fingerprint."""
    ciphers = sorted(value for value in info.ciphers if value not in GREASE)
    extensions = sorted(value for value in info.extensions if value not in GREASE and value not in (0, 16))
    algorithms = [value for value in info.signature_algorithms if value not in GREASE]
    sni = "d" if 0 in info.extensions else "i"
    part_a = "{}{}{}{:02d}{:02d}{}".format(protocol, _version_code(info.version, info.supported_versions), sni,
                                           min(len(ciphers), 99), min(len([v for v in info.extensions if v not in GREASE]), 99),
                                           _alpn_code(info.alpn))
    text_c = ",".join("%04x" % value for value in extensions)
    if algorithms:
        text_c += "_" + ",".join("%04x" % value for value in algorithms)
    return "_".join((part_a, ",".join("%04x" % value for value in ciphers), text_c))


def ja3(info):
    """JA3 (md5) over version, ciphers, extensions, groups and point formats, GREASE removed."""
    fields = (str(info.version),
              "-".join(str(value) for value in info.ciphers if value not in GREASE),
              "-".join(str(value) for value in info.extensions if value not in GREASE),
              "-".join(str(value) for value in info.groups if value not in GREASE),
              "-".join(str(value) for value in info.point_formats))
    return hashlib.md5(",".join(fields).encode("ascii"), usedforsecurity=False).hexdigest()  # noqa: S324 - fingerprint, not security


def ja3s(version, cipher, extensions):
    """JA3S (md5) over the server's version, selected cipher and extension order."""
    text = "{},{},{}".format(version, cipher, "-".join(str(value) for value in extensions))
    return hashlib.md5(text.encode("ascii"), usedforsecurity=False).hexdigest()  # noqa: S324


def ja4s(version, cipher, extensions, alpn, protocol="t"):
    """JA4S server fingerprint: protocol, version, extension count, ALPN code, cipher, extension hash."""
    count = min(len(extensions), 99)
    part_a = "{}{}{:02d}{}".format(protocol, _VERSIONS.get(version, "00"), count, _alpn_code(alpn))
    part_b = "%04x" % cipher
    part_c = _sha12(",".join("%04x" % value for value in extensions)) if extensions else "000000000000"
    return "_".join((part_a, part_b, part_c))


def hassh(kex, encryption, mac, compression):
    """HASSH (md5) over the client's KEXINIT algorithm name-lists."""
    text = ";".join(part.decode("ascii", "replace") if isinstance(part, bytes) else part for part in (kex, encryption, mac, compression))
    return hashlib.md5(text.encode("ascii", "replace"), usedforsecurity=False).hexdigest()  # noqa: S324


def h2_settings_fingerprint(settings):
    """Akamai-style HTTP/2 SETTINGS portion: 'id:value;id:value' in frame order."""
    return ";".join("{}:{}".format(identifier, value) for identifier, value in settings)
