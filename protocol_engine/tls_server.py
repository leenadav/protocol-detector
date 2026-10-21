"""Bounded ServerHello/HelloRetryRequest profiles; no handshake authentication."""
from .parsers import Reader, ParseError, BudgetError
from .extended import UnsupportedPrefix
from .x509 import MAX_LEAF, leaf_profile

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
    if config.fingerprints and not retry:
        from .fingerprints import ja3s, ja4s
        selected = tuple(value for field, value, _, _ in evidence if field == 'selected_alpn')
        negotiated = 0x0304 if tls13 else 0x0303
        evidence.extend((('ja4s', ja4s(negotiated, cipher, tuple(extensions), selected), source, 'derived'),
                         ('ja3s', ja3s(negotiated, cipher, tuple(extensions)), source, 'derived')))
    reason = ('HelloRetryRequest structure validated; requested changes unverified' if retry else
              'ServerHello structure validated; server selections unauthenticated, handshake completion unverified')
    return tuple(evidence), source, reason


class CertificateWatch:
    """Read the records after a TLS 1.2 ServerHello until the leaf certificate is complete.

    Only the Certificate handshake message (type 11) may follow; a
    ChangeCipherSpec record (abbreviated handshake), an alert or any other
    message ends the watch without evidence. The leaf is the first list entry;
    later chain entries are never read. Any error keeps the ServerHello
    identification (SR-21): the Inspector treats a ParseError in a continuation
    as the end of optional evidence.
    """
    def __init__(self, config, record_remaining, budget):
        self.config = config
        self.budget = budget                         # bytes this watch may consume (shared max_bytes budget)
        self.consumed = 0
        self.record_header = bytearray()
        self.record_remaining = record_remaining     # bytes left in the record that carried the ServerHello
        self.handshake = bytearray()
        self.needed = 4                              # handshake header first
        self.message_length = None
        self.chain = None
        self.done = False
        self.evidence = ()

    def feed(self, data):
        pos = 0
        while pos < len(data) and not self.done:
            if self.consumed + pos >= self.budget:
                raise BudgetError('Certificate inspection exceeds the configured byte budget')
            if self.record_remaining == 0:
                amount = min(5 - len(self.record_header), len(data) - pos, self.budget - self.consumed - pos)
                self.record_header.extend(data[pos:pos + amount])
                pos += amount
                if len(self.record_header) < 5:
                    break
                header = self.record_header
                if header[0] != 22:
                    raise ParseError('Certificate message must follow the ServerHello in a handshake record')
                if header[1] != 3 or header[2] not in (1, 2, 3):
                    raise ParseError('Expected plaintext TLS handshake record')
                self.record_remaining = int.from_bytes(header[3:5], 'big')
                self.record_header.clear()
                if not 1 <= self.record_remaining <= 16384:
                    raise ParseError('Invalid TLS record length')
            amount = min(self.needed - len(self.handshake), self.record_remaining, len(data) - pos, self.budget - self.consumed - pos)
            self.handshake.extend(data[pos:pos + amount])
            pos += amount
            self.record_remaining -= amount
            if len(self.handshake) < self.needed:
                continue
            if self.needed == 4:
                if self.handshake[0] != 11:
                    raise ParseError('Handshake message after the ServerHello is not Certificate')
                self.message_length = int.from_bytes(self.handshake[1:4], 'big')
                if self.message_length < 6:
                    raise ParseError('Certificate message too short for one certificate')
                self.needed = 10
            elif self.needed == 10:
                list_length = int.from_bytes(self.handshake[4:7], 'big')
                leaf_length = int.from_bytes(self.handshake[7:10], 'big')
                if list_length != self.message_length - 3 or leaf_length == 0 or leaf_length + 3 > list_length:
                    raise ParseError('Certificate list lengths disagree with the message')
                if leaf_length > min(MAX_LEAF, self.budget - self.consumed - pos):
                    raise BudgetError('Leaf certificate exceeds the inspection budget')
                self.chain = 'single' if list_length == leaf_length + 3 else 'chain'
                self.needed = 10 + leaf_length
            else:
                profile = leaf_profile(bytes(self.handshake[10:]))
                self.evidence = (('tls_certificate_chain', self.chain, 'certificate', 'structural'),) + tuple(
                    (field, value, 'certificate', 'asserted') for field, value in profile)
                self.handshake.clear()
                self.done = True
        self.consumed += pos
        return pos
