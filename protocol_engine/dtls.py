"""RFC6347: one epoch-zero record containing one complete DTLS ClientHello.

No fragment/replay/association state. Cookie, random and session ID stay opaque.
The TLS-shaped ClientHello tail shares SNI/ALPN syntax validation, not TLS state.
"""
from .datagram_result import DatagramMatch
from .extended import UnsupportedPrefix
from .model import Evidence
from .parsers import BudgetError, ClientHelloInfo, ParseError, Reader, parse_hello


def dtls(data, config):
    if len(data) < 25:
        raise ParseError("Incomplete DTLS record/handshake headers")
    if data[0] != 22 or data[1:3] not in (b'\xfe\xff', b'\xfe\xfd'):
        raise UnsupportedPrefix("Outside supported DTLS plaintext handshake record versions")
    if data[3:5] != b'\0\0':
        raise UnsupportedPrefix("DTLS encrypted epochs are outside the ClientHello profile")
    record_size = int.from_bytes(data[11:13], 'big')
    if not 12 <= record_size <= 16384 or len(data) < 13 + record_size:
        raise ParseError("Invalid or truncated DTLS plaintext record length")
    if len(data) != 13 + record_size:
        raise UnsupportedPrefix("DTLS profile requires exactly one record per datagram")
    if data[13] != 1:
        raise UnsupportedPrefix("DTLS profile supports ClientHello only")
    length = int.from_bytes(data[14:17], 'big')
    offset = int.from_bytes(data[19:22], 'big')
    fragment = int.from_bytes(data[22:25], 'big')
    if length < 42 or offset + fragment > length or fragment > record_size - 12:
        raise ParseError("Invalid DTLS handshake or fragment length")
    if length + 25 > config.max_bytes:
        raise BudgetError("DTLS declared ClientHello exceeds byte budget")
    if offset or fragment != length:
        raise UnsupportedPrefix("Fragmented DTLS ClientHello is unsupported; datagrams are not joined")
    if fragment != record_size - 12:
        raise UnsupportedPrefix("DTLS profile requires exactly one handshake per record")
    body = data[25:]
    reader = Reader(body)
    if reader.take(2) != b'\xfe\xfd':
        raise UnsupportedPrefix("DTLS ClientHello legacy version outside the 1.2 profile")
    reader.take(32)
    if len(reader.vector(1)) > 32:
        raise ParseError("DTLS session ID exceeds maximum")
    cookie_start = reader.pos
    reader.vector(1)
    cookie_end = reader.pos
    ciphers = reader.vector(2)
    if len(ciphers) < 2 or len(ciphers) % 2:
        raise ParseError("Invalid DTLS cipher vector")
    compression = reader.vector(1)
    if not compression or 0 not in compression:
        raise ParseError("Invalid DTLS compression vector")
    if compression != b'\0':
        raise UnsupportedPrefix("DTLS profile requires a sole null-compression offer")
    # Count before shared TLS decoding, bounding its extension set and metadata.
    if reader.pos < len(body):
        extensions = Reader(reader.vector(2))
        reader.end()
        count = 0
        while extensions.pos < len(extensions.data):
            count += 1
            if count > min(config.max_headers, 128):
                raise BudgetError("DTLS extension count exceeds budget")
            kind = int.from_bytes(extensions.take(2), 'big')
            extensions.vector(2)
            if kind == 43:
                raise UnsupportedPrefix("DTLS supported_versions negotiation is outside this 1.2 profile")
    # Translate only the wire layout for the existing structural decoder. This
    # does not make DTLS a TLS stream, select a version or authenticate metadata.
    info = ClientHelloInfo() if config.fingerprints else None
    host, alpn = parse_hello(b'\x03\x03' + body[2:cookie_start] + body[cookie_end:], info)
    evidence = [Evidence('encryption', 'dtls', 'wire', 'structural'),
                Evidence('handshake', 'client_hello', 'wire', 'structural'),
                Evidence('offered_dtls_version', '1.2', 'dtls_client_hello', 'asserted')]
    if host:
        evidence.append(Evidence('hostname', host, 'dtls_sni', 'asserted'))
    if alpn:
        evidence.append(Evidence('offered_alpn', ','.join(alpn), 'dtls_alpn', 'asserted'))
    if info is not None:
        from .fingerprints import ja4
        info.version = 0xfefd  # the DTLS 1.2 legacy version, not the translated TLS wire layout
        evidence.append(Evidence('ja4', ja4(info, 'd'), 'wire:dtls_client_hello', 'derived'))
    return DatagramMatch(encryption='dtls', hostname=host, offered_alpn=alpn,
                         evidence=tuple(evidence), reason='DTLS ClientHello structure validated; client offers and cookie unverified; no inner application identification')
