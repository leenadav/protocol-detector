"""TLS 1.2 ECDHE-RSA AES-GCM records using NSS CLIENT_RANDOM secrets."""
import hashlib
import hmac
from . import DecryptionError, MAX_STREAM

SUITES12 = {0xc02f: ('sha256', 16), 0xc030: ('sha384', 32)}


def prf(secret, seed, length, digest):
    output, a = b'', seed
    while len(output) < length:
        a = hmac.new(secret, a, digest).digest()
        output += hmac.new(secret, a + seed, digest).digest()
    return output[:length]


def decrypt12(cr, sr, ch, sh, suite, keys):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    digest, size = SUITES12[suite]
    master = keys.get(('CLIENT_RANDOM', ch[2:34]))
    if master is None or len(master) != 48:
        raise DecryptionError('TLS 1.2 requires a matching CLIENT_RANDOM master secret.')
    block = prf(master, b'key expansion' + sh[2:34] + ch[2:34], 2*size + 8, digest)

    def direction(items, key, iv):
        cipher = AESGCM(key)
        active, finished, seq = False, False, 0
        pending, plain, count = b'', bytearray(), 0
        for header, body in items:
            kind = header[0]
            if not active:
                if kind == 20:
                    if body != b'\x01' or pending:
                        raise DecryptionError('Invalid TLS 1.2 ChangeCipherSpec boundary.')
                    active = True
                    continue
                if kind != 22:
                    raise DecryptionError('Unexpected plaintext TLS 1.2 record.')
                pending += body
                while len(pending) >= 4:
                    length = int.from_bytes(pending[1:4], 'big')
                    if length > MAX_STREAM:
                        raise DecryptionError('TLS 1.2 handshake exceeds profile.')
                    if len(pending) < length + 4:
                        break
                    pending = pending[length+4:]
                continue
            if header[1:3] != b'\x03\x03' or kind not in (21,22,23) or len(body) < 24:
                raise DecryptionError('Unsupported protected TLS 1.2 record.')
            length = len(body)-24
            if length > 16384:
                raise DecryptionError('TLS 1.2 plaintext exceeds record limit.')
            aad = seq.to_bytes(8,'big') + header[:3] + length.to_bytes(2,'big')
            try:
                content = cipher.decrypt(iv+body[:8], body[8:], aad)
            except InvalidTag:
                raise DecryptionError('TLS authentication failed: wrong keys, missing records or modified ciphertext.') from None
            seq += 1
            count += 1
            if kind == 22:
                if finished:
                    raise DecryptionError('TLS 1.2 renegotiation is outside the profile.')
                pending += content
                if len(pending) >= 4:
                    if pending[:4] != b'\x14\x00\x00\x0c' or len(pending)>16:
                        raise DecryptionError('Unexpected TLS 1.2 encrypted handshake.')
                    if len(pending)==16:
                        finished, pending = True, b''
            elif kind == 23:
                if not finished or pending:
                    raise DecryptionError('TLS 1.2 application data before Finished.')
                plain.extend(content)
            elif len(content)!=2 or pending:
                raise DecryptionError('Invalid TLS 1.2 alert.')
        if not finished or pending:
            raise DecryptionError('Incomplete TLS 1.2 handshake.')
        return bytes(plain), count

    cp, cc = direction(cr, block[:size], block[2*size:2*size+4])
    sp, sc = direction(sr, block[size:2*size], block[2*size+4:])
    return cp, sp, {'version':'TLS 1.2','cipher_suite':hex(suite),'authenticated_records':cc+sc,
                    'client_plaintext_bytes':len(cp),'server_plaintext_bytes':len(sp)}
