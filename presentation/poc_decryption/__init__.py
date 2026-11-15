"""Offline, bounded TLS key-log decryption. Not a TLS endpoint or trust validator.

Stage 4 (A02, A09): the record engine is incremental (engine.TlsConnection), the key store is append-oriented
(KeyProvider) and every failure carries a typed reason code. decrypt_streams() stays as the whole-stream
convenience used by tests and by nothing on the live path.
"""
import hashlib
import hmac
import struct

MAX_STREAM = 262144
MAX_KEYLOG = 262144
MAX_ENTRIES = 1024
SUITES = {0x1301: ('sha256', 16), 0x1302: ('sha384', 32), 0x1303: ('sha256', 32)}
LABELS = {'CLIENT_HANDSHAKE_TRAFFIC_SECRET', 'SERVER_HANDSHAKE_TRAFFIC_SECRET',
          'CLIENT_TRAFFIC_SECRET_0', 'SERVER_TRAFFIC_SECRET_0', 'CLIENT_RANDOM'}
REASON_CODES = ('awaiting_hello', 'awaiting_keys', 'awaiting_bytes', 'unsupported_profile', 'authentication_failed',
                'gap', 'budget_exhausted', 'incomplete', 'complete')


class DecryptionError(ValueError):
    """A typed decryption failure; `code` is one of REASON_CODES and never carries key or payload bytes."""
    def __init__(self, message, code='unsupported_profile'):
        super().__init__(message)
        if code not in REASON_CODES:
            raise ValueError('unknown reason code')
        self.code = code


class KeyProvider:
    """Append-oriented NSS key-log store: each line is parsed once, lookups are by (label, client random).

    `version` increases whenever a new secret is indexed, so a connection waiting for keys asks again only
    when something changed (A02). Bounds: 256 KiB of appended text and 1024 indexed entries in total.
    """
    def __init__(self, max_age=None, clock=None):
        self.keys = {}
        self.randoms = set()
        self.version = 0
        self.consumed = 0
        self.released = False
        self.max_age = max_age            # seconds a secret stays usable after it was indexed (None: the run)
        self.clock = clock
        self._indexed_at = {}

    def __repr__(self):
        # Secrets never appear in reprs, logs, exceptions or crash artifacts; only counts do.
        return '<KeyProvider entries=%d randoms=%d version=%d released=%s>' % (len(self.keys), len(self.randoms), self.version, self.released)

    def release(self):
        """Drop every reference to secret material (stage 8, A10). Idempotent; the provider is unusable after.

        Python cannot promise memory zeroization; this releases references so the interpreter can reclaim
        them and makes later use an explicit error instead of a stale success.
        """
        self.keys.clear()
        self.randoms.clear()
        self._indexed_at.clear()
        self.released = True

    def expire(self, now=None):
        """Forget secrets older than max_age (no-op without max_age); returns how many were dropped."""
        if self.max_age is None:
            return 0
        now = self.clock() if now is None and self.clock is not None else now
        if now is None:
            return 0
        stale = [key for key, at in self._indexed_at.items() if now - at > self.max_age]
        for key in stale:
            self.keys.pop(key, None)
            self._indexed_at.pop(key, None)
        self.randoms = {random for (_, random) in self.keys}
        if stale:
            self.version += 1
        return len(stale)

    def append(self, text):
        if self.released:
            raise DecryptionError('Key provider was released.', 'budget_exhausted')
        if not isinstance(text, str):
            raise DecryptionError('Key log must be text.', 'unsupported_profile')
        self.consumed += len(text)
        if self.consumed > MAX_KEYLOG:
            raise DecryptionError('Key log exceeds 256 KiB.', 'budget_exhausted')
        added = 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) != 3:
                raise DecryptionError('Invalid key-log line (secret values are not displayed).', 'unsupported_profile')
            label, random, secret = parts
            if label not in LABELS:
                continue
            try:
                random, secret = bytes.fromhex(random), bytes.fromhex(secret)
            except ValueError:
                raise DecryptionError('Invalid key-log hexadecimal encoding.', 'unsupported_profile') from None
            if len(random) != 32 or len(secret) not in (32, 48):
                raise DecryptionError('Invalid TLS 1.3 secret length.', 'unsupported_profile')
            if label == 'CLIENT_RANDOM' and len(secret) != 48:
                raise DecryptionError('TLS 1.2 master secret must contain 48 bytes.', 'unsupported_profile')
            key = (label, random)
            previous = self.keys.get(key)
            if previous is not None:
                if previous != secret:
                    raise DecryptionError('Conflicting secrets for the same connection.', 'unsupported_profile')
                continue
            if len(self.keys) >= MAX_ENTRIES:
                raise DecryptionError('Too many key-log entries.', 'budget_exhausted')
            self.keys[key] = secret
            self.randoms.add(random)
            if self.clock is not None:
                self._indexed_at[key] = self.clock()
            added += 1
        if added:
            self.version += 1
        return added

    def get(self, key, default=None):
        if self.released:
            raise DecryptionError('Key provider was released.', 'budget_exhausted')
        return self.keys.get(key, default)

    def has(self, random):
        return random in self.randoms

    def __len__(self):
        return len(self.keys)


def read_keys(text):
    """Whole-text convenience: the same validation as KeyProvider.append, returning the plain index."""
    provider = KeyProvider()
    provider.append(text)
    return provider.keys


def expand(secret, label, length, digest):
    label = b'tls13 ' + label
    info = struct.pack('!H', length) + bytes([len(label)]) + label + b'\x00'
    out, block = b'', b''
    for counter in range(1, (length + hashlib.new(digest).digest_size - 1) // hashlib.new(digest).digest_size + 1):
        block = hmac.new(secret, block + info + bytes([counter]), digest).digest()
        out += block
    return out[:length]


def records(data):
    """Whole-stream record split through the incremental framer (same errors, one implementation)."""
    from .engine import RecordFramer
    framer = RecordFramer()
    framer.feed(data)
    for item in framer.records():
        yield item
    framer.finish()


def decrypt_streams(client, server, keys):
    """Decode two complete directions with an index of secrets; raises DecryptionError with a reason code."""
    from .engine import TlsConnection
    connection = TlsConnection(keys, 'client', 'server')
    plain = {'client': bytearray(), 'server': bytearray()}
    connection.feed('client', client)
    connection.feed('server', server)
    while connection.has_work() and not connection.terminal:
        for delta in connection.advance(4096):
            plain[delta.endpoint].extend(delta.data)
        if connection.state == 'awaiting_keys':
            break
    connection.finish()
    if connection.state != 'complete':
        raise DecryptionError(connection.reason or 'Decryption did not complete.', connection.reason_code or 'incomplete')
    metadata = connection.metadata()
    metadata.pop('state', None)
    return bytes(plain['client']), bytes(plain['server']), metadata
