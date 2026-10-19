"""Bounded ServerHello/HelloRetryRequest profiles; no handshake authentication."""
from .parsers import Reader, ParseError, BudgetError
from .extended import UnsupportedPrefix

HRR_RANDOM = bytes.fromhex('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c')
_TLS12_ECC_CIPHERS = frozenset(range(0xc023, 0xc033))
_TLS12_CIPHERS = frozenset((0x002f,)) | _TLS12_ECC_CIPHERS
_KEY_SIZES = {23:65, 24:97, 25:133, 29:32, 30:56,
              256:256, 257:384, 258:512, 259:768, 260:1024}


def parse_server_hello(body, config, record_versions, record_remaining):
    reader = Reader(body)
    if reader.take(2) != b'\x03\x03':
        raise UnsupportedPrefix('ServerHello profile requires TLS 1.2 or 1.3 legacy version')
    retry = reader.take(32) == HRR_RANDOM
    if len(reader.vector(1)) > 32:
        raise ParseError('ServerHello session ID exceeds maximum')
    cipher = int.from_bytes(reader.take(2), 'big')
    if reader.take(1) != b'\0':
        raise UnsupportedPrefix('ServerHello compression outside null-compression profile')
    extensions = {}
    if reader.pos < len(body):
        block = Reader(reader.vector(2))
        reader.end()
        while block.pos < len(block.data):
            if len(extensions) >= min(config.max_headers, 128):
                raise BudgetError('ServerHello extension count exceeds budget')
            kind = int.from_bytes(block.take(2), 'big')
            if kind in extensions:
                raise ParseError('Duplicate ServerHello extension')
            extensions[kind] = block.vector(2)
    tls13 = 43 in extensions
    source = 'hello_retry_request' if retry else 'server_hello'
    evidence = [('tls_handshake', source, source, 'structural')]
    if tls13:
        if extensions[43] != b'\x03\x04':
            raise UnsupportedPrefix('ServerHello selected version outside TLS 1.3 profile')
        if cipher not in range(0x1301, 0x1306):
            raise UnsupportedPrefix('TLS 1.3 cipher outside RFC8446 profile')
        if record_versions != 1 << 3 or record_remaining:
            raise ParseError('TLS 1.3 server hello requires 0303 records and a record boundary')
        allowed = {43, 44, 51} if retry else {43, 41, 51}
        if not set(extensions) <= allowed:
            raise UnsupportedPrefix('Extension outside supported TLS 1.3 server hello context')
        if retry:
            if not ({44, 51} & extensions.keys()):
                raise ParseError('HelloRetryRequest must request a change')
            if 44 in extensions:
                cookie = Reader(extensions[44])
                if not cookie.vector(2):
                    raise ParseError('Empty retry cookie')
                cookie.end()
            if 51 in extensions:
                value = extensions[51]
                if len(value) != 2:
                    raise ParseError('Retry key_share must contain one selected group')
                group = int.from_bytes(value, 'big')
                if group not in _KEY_SIZES:
                    raise UnsupportedPrefix('Retry group outside supported named groups')
                evidence.append(('requested_group', str(group), source, 'asserted'))
        else:
            if not ({41, 51} & extensions.keys()):
                raise ParseError('TLS 1.3 ServerHello requires PSK or key share')
            if 41 in extensions and len(extensions[41]) != 2:
                raise ParseError('Server PSK selection requires a two-byte index')
            if 51 in extensions:
                value = Reader(extensions[51])
                group = int.from_bytes(value.take(2), 'big')
                key = value.vector(2)
                value.end()
                if group not in _KEY_SIZES:
                    raise UnsupportedPrefix('Server key share group outside supported profile')
                if len(key) != _KEY_SIZES[group] or (group in (23,24,25) and key[0] != 4):
                    raise ParseError('Server key share encoding length or point format invalid')
                # Key validity / curve membership and DH checks require the TLS stack.
                evidence.append(('selected_group', str(group), source, 'asserted'))
        version = '1.3'
    else:
        if retry:
            raise ParseError('HelloRetryRequest requires TLS 1.3 supported_versions')
        if cipher not in _TLS12_CIPHERS:
            raise UnsupportedPrefix('TLS 1.2 cipher outside supported ServerHello profile')
        for kind, value in extensions.items():
            if kind in (0, 5, 23, 35):  # SNI/status/EMS/session-ticket acknowledgements
                if value:
                    raise ParseError('ServerHello acknowledgement extension must be empty')
            elif kind == 65281:
                if value != b'\0':
                    raise UnsupportedPrefix('Only initial-handshake renegotiation_info supported')
            elif kind == 11:
                if cipher not in _TLS12_ECC_CIPHERS:
                    raise ParseError('EC point formats require an ECC cipher suite')
                formats = Reader(value)
                values = formats.vector(1)
                formats.end()
                if not values or 0 not in values or any(x > 2 for x in values):
                    raise ParseError('Invalid server EC point formats')
            elif kind == 16:
                alpn = Reader(value)
                names = Reader(alpn.vector(2))
                alpn.end()
                name = names.vector(1)
                names.end()
                if not name:
                    raise ParseError('Empty server ALPN selection')
                text = name.decode('ascii') if all(32 <= c < 127 for c in name) else 'hex:' + name.hex()
                evidence.append(('selected_alpn', text, source, 'asserted'))
            else:
                raise UnsupportedPrefix('TLS 1.2 ServerHello extension outside supported profile')
        version = '1.2'
    evidence.extend((('selected_tls_version', version, source, 'asserted'),
                     ('selected_cipher', '0x%04x' % cipher, source, 'asserted')))
    reason = ('HelloRetryRequest structure validated; requested changes unverified' if retry else
              'ServerHello structure validated; server selections unauthenticated, handshake completion unverified')
    return tuple(evidence), source, reason
