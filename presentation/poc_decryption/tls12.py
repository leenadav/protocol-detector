"""TLS 1.2 ECDHE-RSA AES-GCM parameters: the PRF and the two supported suites (engine.Tls12Direction decodes)."""
import hmac

SUITES12 = {0xc02f: ('sha256', 16), 0xc030: ('sha384', 32)}


def prf(secret, seed, length, digest):
    output, a = b'', seed
    while len(output) < length:
        a = hmac.new(secret, a, digest).digest()
        output += hmac.new(secret, a + seed, digest).digest()
    return output[:length]
