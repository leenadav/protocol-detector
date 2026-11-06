"""Offline, bounded TLS 1.3 key-log decryption. Not a TLS endpoint or trust validator."""
import hashlib
import hmac
import struct

MAX_STREAM = 262144
SUITES = {0x1301: ('sha256', 16), 0x1302: ('sha384', 32), 0x1303: ('sha256', 32)}
LABELS = {'CLIENT_HANDSHAKE_TRAFFIC_SECRET', 'SERVER_HANDSHAKE_TRAFFIC_SECRET',
          'CLIENT_TRAFFIC_SECRET_0', 'SERVER_TRAFFIC_SECRET_0', 'CLIENT_RANDOM'}


class DecryptionError(ValueError):
    pass


def read_keys(text):
    if not isinstance(text, str) or len(text) > 262144:
        raise DecryptionError('Key log exceeds 256 KiB.')
    keys = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        if len(parts) != 3:
            raise DecryptionError('Invalid key-log line (secret values are not displayed).')
        label, random, secret = parts
        if label not in LABELS:
            continue
        try:
            random, secret = bytes.fromhex(random), bytes.fromhex(secret)
        except ValueError:
            raise DecryptionError('Invalid key-log hexadecimal encoding.') from None
        if len(random) != 32 or len(secret) not in (32, 48):
            raise DecryptionError('Invalid TLS 1.3 secret length.')
        if label == 'CLIENT_RANDOM' and len(secret) != 48:
            raise DecryptionError('TLS 1.2 master secret must contain 48 bytes.')
        key = (label, random)
        if key in keys and keys[key] != secret:
            raise DecryptionError('Conflicting secrets for the same connection.')
        keys[key] = secret
        if len(keys) > 1024:
            raise DecryptionError('Too many key-log entries.')
    return keys


def expand(secret, label, length, digest):
    label = b'tls13 ' + label
    info = struct.pack('!H', length) + bytes([len(label)]) + label + b'\x00'
    out, block = b'', b''
    for counter in range(1, (length + hashlib.new(digest).digest_size - 1) // hashlib.new(digest).digest_size + 1):
        block = hmac.new(secret, block + info + bytes([counter]), digest).digest()
        out += block
    return out[:length]


def records(data):
    if len(data) > MAX_STREAM:
        raise DecryptionError('TLS stream exceeds 256 KiB profile.')
    pos = 0
    while pos < len(data):
        if len(data) - pos < 5:
            raise DecryptionError('Incomplete TLS record header.')
        header = data[pos:pos + 5]
        size = int.from_bytes(header[3:5], 'big')
        if header[0] not in (20, 21, 22, 23) or header[1:3] not in (b'\x03\x01', b'\x03\x03') or size > 16640:
            raise DecryptionError('Unsupported TLS record framing.')
        if pos + 5 + size > len(data):
            raise DecryptionError('Incomplete TLS record body.')
        yield header, data[pos + 5:pos + 5 + size]
        pos += 5 + size


def hello(record_list, expected, allow_trailing=False):
    data = b''
    consumed = 0
    for header, body in record_list:
        if header[0] != 22:
            break
        data += body
        consumed += 1
        if len(data) >= 4 and len(data) >= 4 + int.from_bytes(data[1:4], 'big'):
            end = 4 + int.from_bytes(data[1:4], 'big')
            if data[0] != expected or (not allow_trailing and len(data) != end):
                raise DecryptionError('Unsupported initial TLS handshake layout.')
            return data[4:end], consumed
    raise DecryptionError('Capture must include complete ClientHello and ServerHello.')


def decrypt_streams(client, server, keys):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.exceptions import InvalidTag
    cr, sr = list(records(client)), list(records(server))
    ch, cn = hello(cr, 1)
    sh, sn = hello(sr, 2, allow_trailing=True)
    if len(ch) < 35 or len(sh) < 40 or ch[:2] != b'\x03\x03' or sh[:2] != b'\x03\x03':
        raise DecryptionError('Unsupported TLS hello.')
    random = ch[2:34]
    sid = sh[34]
    offset = 35 + sid
    if sid > 32 or offset + 5 > len(sh):
        raise DecryptionError('Malformed ServerHello.')
    suite = int.from_bytes(sh[offset:offset + 2], 'big')
    from .tls12 import SUITES12, decrypt12
    if suite in SUITES12:
        if sh[offset+2] != 0:
            raise DecryptionError('TLS compression is unsupported.')
        ext = sh[offset+5:]
        if int.from_bytes(sh[offset+3:offset+5],'big') != len(ext):
            raise DecryptionError('Malformed TLS 1.2 ServerHello extensions.')
        seen12 = set()
        while ext:
            if len(ext)<4:
                raise DecryptionError('Truncated TLS 1.2 extension.')
            kind, length = struct.unpack('!HH',ext[:4])
            if kind in seen12 or length>len(ext)-4 or kind==43:
                raise DecryptionError('Invalid TLS 1.2 extension.')
            seen12.add(kind)
            ext=ext[4+length:]
        return decrypt12(cr, sr, ch, sh, suite, keys)
    if suite not in SUITES:
        raise DecryptionError('Unsupported TLS cipher suite; supported: TLS 1.3 AEAD and TLS 1.2 ECDHE-RSA AES-GCM.')
    sh, sn = hello(sr, 2)
    if sh[2:34].hex() == 'cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c':
        raise DecryptionError('HelloRetryRequest is outside the POC profile.')
    extensions = sh[offset + 5:]
    if sh[offset + 2] != 0 or int.from_bytes(sh[offset + 3:offset + 5], 'big') != len(extensions):
        raise DecryptionError('Malformed ServerHello extensions.')
    selected, seen = False, set()
    while extensions:
        if len(extensions) < 4:
            raise DecryptionError('Truncated ServerHello extension.')
        kind, size = struct.unpack('!HH', extensions[:4])
        if size > len(extensions) - 4 or kind in seen:
            raise DecryptionError('Invalid ServerHello extension.')
        seen.add(kind)
        if kind == 43:
            selected = extensions[4:4 + size] == b'\x03\x04'
        extensions = extensions[4 + size:]
    if not selected:
        raise DecryptionError('TLS 1.3 was not selected.')
    digest, key_size = SUITES[suite]

    def direction(items, sender):
        phase, sequence, pending, plain, count = 'HANDSHAKE_TRAFFIC_SECRET', 0, b'', bytearray(), 0
        ciphers = {}
        secrets = {}
        updates = 0
        for phase_name in ('HANDSHAKE_TRAFFIC_SECRET', 'TRAFFIC_SECRET_0'):
            secret = keys.get((sender + '_' + phase_name, random))
            if secret is None:
                raise DecryptionError('Matching handshake and application secrets are required for both directions.')
            if len(secret) != hashlib.new(digest).digest_size:
                raise DecryptionError('Secret length does not match cipher suite.')
            cipher = ChaCha20Poly1305 if suite == 0x1303 else AESGCM
            ciphers[phase_name] = (cipher(expand(secret, b'key', key_size, digest)), expand(secret, b'iv', 12, digest))
            secrets[phase_name] = secret
        for header, body in items:
            if header[0] == 20 and body == b'\x01':
                continue
            if header[0] != 23 or header[1:3] != b'\x03\x03':
                raise DecryptionError('Unexpected record after hello; early data and renegotiation are unsupported.')
            cipher, iv = ciphers[phase]
            nonce = bytes(a ^ b for a, b in zip(iv, sequence.to_bytes(12, 'big')))
            try:
                decoded = cipher.decrypt(nonce, body, header)
            except InvalidTag:
                raise DecryptionError('TLS authentication failed: wrong keys, missing records or modified ciphertext. No plaintext classification published.') from None
            sequence += 1
            count += 1
            content = decoded.rstrip(b'\x00')
            if not content:
                raise DecryptionError('TLS inner content type is missing.')
            kind, content = content[-1], content[:-1]
            if len(content) > 16384:
                raise DecryptionError('TLS inner plaintext exceeds record limit.')
            if kind == 22:
                pending += content
                if len(pending) > MAX_STREAM:
                    raise DecryptionError('Handshake exceeds profile limit.')
                while len(pending) >= 4:
                    size = int.from_bytes(pending[1:4], 'big')
                    if len(pending) < 4 + size:
                        break
                    message, pending = pending[:4 + size], pending[4 + size:]
                    if message[0] == 24:
                        if phase != 'TRAFFIC_SECRET_0' or size != 1 or message[4] not in (0,1) or pending or updates>=32:
                            raise DecryptionError('Invalid TLS KeyUpdate boundary or update budget exceeded.')
                        secret = expand(secrets[phase], b'traffic upd', hashlib.new(digest).digest_size, digest)
                        secrets[phase] = secret
                        constructor = ChaCha20Poly1305 if suite == 0x1303 else AESGCM
                        ciphers[phase] = (constructor(expand(secret,b'key',key_size,digest)),expand(secret,b'iv',12,digest))
                        sequence = 0
                        updates += 1
                    if message[0] == 20:
                        if phase != 'HANDSHAKE_TRAFFIC_SECRET' or size != hashlib.new(digest).digest_size or pending:
                            raise DecryptionError('Unexpected Finished message.')
                        phase, sequence = 'TRAFFIC_SECRET_0', 0
            elif kind == 23:
                if phase != 'TRAFFIC_SECRET_0' or pending:
                    raise DecryptionError('Application data before handshake completion.')
                plain.extend(content)
                if len(plain) > MAX_STREAM:
                    raise DecryptionError('Decrypted payload exceeds 256 KiB profile.')
            elif kind != 21 or len(content) != 2:
                raise DecryptionError('Unsupported TLS inner content.')
        if pending or phase != 'TRAFFIC_SECRET_0':
            raise DecryptionError('Incomplete encrypted handshake.')
        return bytes(plain), count

    cp, cc = direction(cr[cn:], 'CLIENT')
    sp, sc = direction(sr[sn:], 'SERVER')
    return cp, sp, {'version': 'TLS 1.3', 'cipher_suite': hex(suite), 'authenticated_records': cc + sc,
                    'client_plaintext_bytes': len(cp), 'server_plaintext_bytes': len(sp)}
