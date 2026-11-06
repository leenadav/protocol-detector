"""QUIC v1/v2 Initial and Version Negotiation packets (RFC 9000, 9001, 9369).

Structural recognition of the long header is always attempted. When
Config.quic_decrypt is set, client Initial packet protection is removed with
keys derived from public values (version salt, Destination Connection ID), the
frames are validated (PADDING, PING, ACK, CRYPTO, CONNECTION_CLOSE only) and
the CRYPTO stream is assembled into a TLS ClientHello for SNI, ALPN and JA4
(protocol code q). This recovers data the client sent in the clear by design;
it decrypts nothing that a passive observer could not. Server Initials, later
packets and 0-RTT remain opaque. No connection state beyond the bounded CRYPTO
assembler is kept.
"""
from collections import OrderedDict
from .aes import encrypt_block, expand_key, gcm_open, hkdf_expand_label, hkdf_extract
from .datagram_result import DatagramMatch
from .extended import UnsupportedPrefix
from .model import Evidence
from .parsers import BudgetError, ClientHelloInfo, ParseError, parse_hello

V1, V2 = 0x00000001, 0x6b3343cf
_SALTS = {V1: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
          V2: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")}
_LABELS = {V1: (b"quic key", b"quic iv", b"quic hp"), V2: (b"quicv2 key", b"quicv2 iv", b"quicv2 hp")}
_INITIAL_TYPE = {V1: 0, V2: 1}
_VERSION_NAME = {V1: "1", V2: "2"}
MAX_CRYPTO = 16384       # assembled ClientHello bytes per connection
MAX_FRAGMENTS = 8        # CRYPTO fragments kept per connection


def quic_probe(data):
    """Long header with a supported version and Initial type, or Version Negotiation."""
    if len(data) < 7 or data[0] & 0xc0 != 0xc0:
        return False
    version = int.from_bytes(data[1:5], "big")
    if version == 0:
        return len(data) >= 7
    return version in _SALTS and (data[0] >> 4) & 3 == _INITIAL_TYPE[version] and data[0] & 0x40 != 0 or False


def varint(data, pos, limit):
    if pos >= limit:
        raise ParseError("Truncated QUIC variable-length integer")
    prefix = data[pos] >> 6
    size = 1 << prefix
    if pos + size > limit:
        raise ParseError("Truncated QUIC variable-length integer")
    value = int.from_bytes(data[pos:pos + size], "big") & ((1 << (8 * size - 2)) - 1)
    return value, pos + size


class QuicAssembler:
    """Bounded CRYPTO fragment store keyed by Destination Connection ID (LRU eviction)."""

    def __init__(self, max_connections=64):
        self.max_connections = max_connections
        self.entries = OrderedDict()

    def clear(self):
        self.entries.clear()

    def add(self, dcid, fragments):
        """Merge fragments; return the complete ClientHello bytes when available, else None."""
        entry = self.entries.pop(dcid, None)
        if entry is None:
            if len(self.entries) >= self.max_connections:
                self.entries.popitem(last=False)
            entry = []
        entry.extend(fragments)
        entry.sort(key=lambda item: item[0])
        if len(entry) > MAX_FRAGMENTS or sum(len(item[1]) for item in entry) > MAX_CRYPTO:
            return None  # over budget: forget this connection
        self.entries[dcid] = entry
        return assemble(entry)


def assemble(fragments):
    """Contiguous CRYPTO bytes from offset zero; a complete handshake message or None."""
    data = bytearray()
    for offset, chunk in sorted(fragments, key=lambda item: item[0]):
        if offset > len(data):
            return None
        if offset + len(chunk) > len(data):
            data.extend(chunk[len(data) - offset:])
    if len(data) < 4 or data[0] != 1:
        return None
    size = int.from_bytes(data[1:4], "big")
    return bytes(data[:4 + size]) if len(data) >= 4 + size else None


def _initial_keys(version, dcid):
    secret = hkdf_expand_label(hkdf_extract(_SALTS[version], dcid), b"client in", b"", 32)
    key_label, iv_label, hp_label = _LABELS[version]
    return (hkdf_expand_label(secret, key_label, b"", 16), hkdf_expand_label(secret, iv_label, b"", 12),
            hkdf_expand_label(secret, hp_label, b"", 16))


def unprotect(data, pn_offset, length, version, dcid):
    """Remove header protection and AEAD on one Initial packet; return (plaintext, header, packet_number) or None."""
    key, iv, hp = _initial_keys(version, dcid)
    sample = data[pn_offset + 4:pn_offset + 20]
    mask = encrypt_block(expand_key(hp), sample)
    first = data[0] ^ (mask[0] & 0x0f)
    pn_length = (first & 3) + 1
    if first & 0x0c:
        return None  # reserved bits must be zero once unprotected
    header = bytearray(data[:pn_offset + pn_length])
    header[0] = first
    for index in range(pn_length):
        header[pn_offset + index] ^= mask[1 + index]
    packet_number = int.from_bytes(header[pn_offset:pn_offset + pn_length], "big")
    nonce = bytes(a ^ b for a, b in zip(iv, packet_number.to_bytes(12, "big")))
    payload = data[pn_offset + pn_length:pn_offset + length]
    if len(payload) < 16:
        return None
    plaintext = gcm_open(key, nonce, bytes(header), payload)
    if plaintext is None:
        return None
    return plaintext, bytes(header), packet_number


def frames(plaintext, config):
    """Validate Initial-permitted frames; return CRYPTO fragments [(offset, bytes)]."""
    pos, limit, fragments, count = 0, len(plaintext), [], 0
    budget = min(config.max_headers, 128)
    while pos < limit:
        kind = plaintext[pos]
        if kind == 0:  # PADDING runs are cheap to skip
            pos += 1
            continue
        count += 1
        if count > budget:
            raise BudgetError("QUIC Initial frame count exceeds budget")
        pos += 1
        if kind == 1:  # PING
            continue
        if kind in (2, 3):  # ACK
            _, pos = varint(plaintext, pos, limit)
            _, pos = varint(plaintext, pos, limit)
            ranges, pos = varint(plaintext, pos, limit)
            _, pos = varint(plaintext, pos, limit)
            if ranges > budget:
                raise BudgetError("QUIC ACK range count exceeds budget")
            for _ in range(ranges):
                _, pos = varint(plaintext, pos, limit)
                _, pos = varint(plaintext, pos, limit)
            if kind == 3:
                for _ in range(3):
                    _, pos = varint(plaintext, pos, limit)
            continue
        if kind == 6:  # CRYPTO
            offset, pos = varint(plaintext, pos, limit)
            size, pos = varint(plaintext, pos, limit)
            if offset + size > MAX_CRYPTO:
                raise BudgetError("QUIC CRYPTO offset exceeds assembly budget")
            if pos + size > limit:
                raise ParseError("QUIC CRYPTO frame exceeds packet")
            fragments.append((offset, plaintext[pos:pos + size]))
            pos += size
            continue
        if kind in (0x1c, 0x1d):  # CONNECTION_CLOSE
            _, pos = varint(plaintext, pos, limit)
            if kind == 0x1c:
                _, pos = varint(plaintext, pos, limit)
            size, pos = varint(plaintext, pos, limit)
            if pos + size > limit:
                raise ParseError("QUIC CONNECTION_CLOSE reason exceeds packet")
            pos += size
            continue
        raise ParseError("Frame type not permitted in a QUIC Initial packet")
    return fragments


def quic(data, config, assembler=None):
    if not quic_probe(data):
        raise UnsupportedPrefix("Outside QUIC long-header Initial/Version Negotiation profile")
    version = int.from_bytes(data[1:5], "big")
    pos = 5
    dcil = data[pos]
    pos += 1
    if dcil > 20 or pos + dcil > len(data):
        raise ParseError("Invalid QUIC Destination Connection ID length")
    dcid = data[pos:pos + dcil]
    pos += dcil
    if pos >= len(data):
        raise ParseError("Truncated QUIC Source Connection ID length")
    scil = data[pos]
    pos += 1
    if scil > 20 or pos + scil > len(data):
        raise ParseError("Invalid QUIC Source Connection ID length")
    pos += scil
    evidence = [Evidence("encryption", "quic", "wire", "structural")]
    if version == 0:
        rest = len(data) - pos
        if rest < 4 or rest % 4:
            raise ParseError("QUIC Version Negotiation requires a list of 32-bit versions")
        if rest // 4 > min(config.max_headers, 128):
            raise BudgetError("QUIC Version Negotiation list exceeds budget")
        evidence.append(Evidence("packet_type", "version_negotiation", "wire", "structural"))
        return DatagramMatch(encryption="quic", evidence=tuple(evidence),
                             reason="QUIC Version Negotiation framing validated; offered versions are server assertions")
    token_length, pos = varint(data, pos, len(data))
    if token_length > len(data) - pos:
        raise ParseError("QUIC Initial token exceeds datagram")
    pos += token_length
    length, pos = varint(data, pos, len(data))
    pn_offset = pos
    # Packet number (1..4 bytes) plus a 16-byte AEAD tag are the minimum payload.
    if length < 17 or pn_offset + length > len(data) or pn_offset + 20 > len(data):
        raise ParseError("QUIC Initial length field disagrees with datagram")
    evidence.extend((Evidence("quic_version", _VERSION_NAME[version], "wire", "structural"),
                     Evidence("packet_type", "initial", "wire", "structural")))
    if token_length:
        evidence.append(Evidence("initial_token", "present", "wire", "structural"))
    if not config.quic_decrypt:
        evidence.append(Evidence("initial_protection", "skipped", "wire", "context"))
        return DatagramMatch(encryption="quic", evidence=tuple(evidence),
                             reason="QUIC Initial framing validated; protection removal disabled by configuration")
    if len(data) > config.max_bytes:
        raise BudgetError("QUIC Initial exceeds byte budget")
    opened = unprotect(data, pn_offset, length, version, dcid)
    if opened is None:
        evidence.append(Evidence("initial_protection", "unverified", "wire", "context"))
        return DatagramMatch(encryption="quic", evidence=tuple(evidence),
                             reason="QUIC Initial framing validated; client Initial keys did not open the payload (server packet, retry token flow or damaged datagram)")
    plaintext = opened[0]
    try:
        fragments = frames(plaintext, config)
    except BudgetError:
        raise  # budgets are reported as budget_exhausted, never hidden as unverified protection
    except ParseError as error:
        evidence.append(Evidence("initial_protection", "unverified", "wire", "context"))
        return DatagramMatch(encryption="quic", evidence=tuple(evidence),
                             reason="QUIC Initial opened but frames outside the Initial profile: " + str(error))
    evidence.append(Evidence("initial_protection", "removed", "wire", "structural"))
    hello = assemble(fragments)
    if hello is None and assembler is not None and fragments:
        hello = assembler.add(bytes(dcid), fragments)
    if hello is None:
        evidence.append(Evidence("crypto_assembly", "partial", "wire", "structural"))
        return DatagramMatch(encryption="quic", evidence=tuple(evidence),
                             reason="QUIC Initial protection removed; ClientHello incomplete in this datagram")
    info = ClientHelloInfo() if (config.retain_contexts or config.fingerprints) else None
    offered = []
    try:
        hostname, alpn = parse_hello(hello[4:], info, offered)
    except ParseError:
        evidence.append(Evidence("crypto_assembly", "invalid", "wire", "structural"))
        return DatagramMatch(encryption="quic", evidence=tuple(evidence),
                             reason="QUIC Initial protection removed; CRYPTO stream is not a supported ClientHello")
    evidence.append(Evidence("crypto_assembly", "complete", "wire", "structural"))
    if hostname:
        evidence.append(Evidence("hostname", hostname, "quic_sni", "asserted"))
    if alpn:
        evidence.append(Evidence("offered_alpn", ",".join(alpn), "quic_alpn", "asserted"))
    if offered[2] is not None:
        evidence.append(Evidence("tls_ech", offered[2], "quic_client_hello", "offered"))
    contexts = None
    if info is not None:
        info.version = 0x0304  # QUIC requires TLS 1.3; supported_versions carries it
        if config.fingerprints:
            from .fingerprints import ja4
            evidence.append(Evidence("ja4", ja4(info, "q"), "wire:quic_client_hello", "derived"))
        if config.retain_contexts:
            contexts = {"ssl-req-client-hello": hello[4:], "ssl-req-version": info.version,
                        "ssl-req-cipher-suite": frozenset(info.ciphers),
                        "ssl-req-client-hello-ext-type": frozenset(info.extensions)}
            if hostname:
                contexts["ssl-req-chello-sni"] = hostname.encode("ascii")
            if alpn:
                contexts["ssl-req-alpn"] = ",".join(alpn).encode("latin-1", "replace")
    return DatagramMatch(encryption="quic", hostname=hostname, offered_alpn=alpn, evidence=tuple(evidence),
                         reason="QUIC Initial protection removed and ClientHello validated; SNI/ALPN are client offers, handshake not completed",
                         contexts=contexts, signature_family="tls")
