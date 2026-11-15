"""Incremental TLS record decoding with typed states (stage 4: A02, A09).

One TlsConnection per TCP connection. Bytes arrive as deltas (from the coordinator's retained tier, or from a
whole captured stream in the offline adapter); records are framed once, decrypted once, and released as
authenticated PlaintextDelta values with provenance (endpoint, epoch). Nothing here reads a clock, a file or a
socket; the key provider is injected and consulted again only when its version changed.

States (TlsConnection.state) and terminal reason codes (TlsConnection.reason_code):

    awaiting_hello   both hellos not yet complete
    awaiting_keys    hellos parsed, secrets for this client random not available yet
    decrypting       keys derived; records are authenticated as they complete
    complete         finish() ran with both handshakes complete (terminal)
    failed           terminal; reason_code is one of
                     unsupported_profile   framing, suite, HRR, compression, extension or layout outside the profile
                     authentication_failed AEAD tag rejected: wrong keys, missing records or modified ciphertext
                     gap                   bytes missing in the reassembled stream (reported by the owner)
                     budget_exhausted      a per-connection or aggregate budget was hit
                     incomplete            the stream ended inside a record or before the handshake completed
                     awaiting_keys         the stream ended and no matching secrets ever arrived

A failed or complete connection never publishes further plaintext. This remains record authentication with
supplied secrets: Finished transcripts and certificate trust are not verified and never claimed.
"""
import hashlib
import struct
from collections import deque
from dataclasses import dataclass

from . import DecryptionError, MAX_STREAM, SUITES, expand
from .tls12 import SUITES12, prf

HRR_RANDOM = bytes.fromhex('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c')
MAX_RECORDS_PER_CONNECTION = 65536


@dataclass(frozen=True)
class PlaintextDelta:
    """Authenticated application plaintext released by one direction, in order, exactly once."""
    endpoint: tuple
    epoch: str
    data: bytes


class RecordFramer:
    """Splits one direction's bytes into TLS records once; retains only an incomplete tail."""
    def __init__(self, limit=MAX_STREAM):
        self.pending = bytearray()
        self.total = 0
        self.limit = limit
        self.count = 0

    def feed(self, data):
        self.total += len(data)
        if self.total > self.limit:
            raise DecryptionError('TLS stream exceeds 256 KiB profile.', 'budget_exhausted')
        self.pending.extend(data)

    def ready(self):
        """True when at least one complete record is buffered (an incomplete tail is not work)."""
        return len(self.pending) >= 5 and len(self.pending) >= 5 + int.from_bytes(self.pending[3:5], 'big')

    def records(self):
        while len(self.pending) >= 5:
            header = bytes(self.pending[:5])
            size = int.from_bytes(header[3:5], 'big')
            if header[0] not in (20, 21, 22, 23) or header[1:3] not in (b'\x03\x01', b'\x03\x03') or size > 16640:
                raise DecryptionError('Unsupported TLS record framing.', 'unsupported_profile')
            if len(self.pending) < 5 + size:
                return
            body = bytes(self.pending[5:5 + size])
            del self.pending[:5 + size]
            self.count += 1
            if self.count > MAX_RECORDS_PER_CONNECTION:
                raise DecryptionError('TLS record count exceeds profile.', 'budget_exhausted')
            yield header, body

    def finish(self):
        if self.pending:
            raise DecryptionError('Incomplete TLS record header.' if len(self.pending) < 5 else 'Incomplete TLS record body.',
                                  'incomplete')


class HelloCollector:
    """Accumulates handshake records until the first handshake message is complete."""
    def __init__(self, expected):
        self.expected = expected
        self.data = b''
        self.records = []
        self.body = None

    def add(self, header, body):
        if header[0] != 22:
            raise DecryptionError('Capture must include complete ClientHello and ServerHello.', 'unsupported_profile')
        self.data += body
        self.records.append((header, body))
        if len(self.data) > MAX_STREAM:
            raise DecryptionError('Handshake exceeds profile limit.', 'budget_exhausted')
        if len(self.data) >= 4 and len(self.data) >= 4 + int.from_bytes(self.data[1:4], 'big'):
            end = 4 + int.from_bytes(self.data[1:4], 'big')
            if self.data[0] != self.expected:
                raise DecryptionError('Unsupported initial TLS handshake layout.', 'unsupported_profile')
            self.body = self.data[4:end]
            self.trailing = len(self.data) != end
            return True
        return False


class Tls13Direction:
    def __init__(self, sender, suite, random, keys):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
        self.digest, key_size = SUITES[suite]
        self.cipher_class = ChaCha20Poly1305 if suite == 0x1303 else AESGCM
        self.key_size = key_size
        self.phase, self.sequence, self.pending, self.count, self.updates = 'HANDSHAKE_TRAFFIC_SECRET', 0, b'', 0, 0
        self.ciphers, self.secrets = {}, {}
        for phase_name in ('HANDSHAKE_TRAFFIC_SECRET', 'TRAFFIC_SECRET_0'):
            secret = keys.get((sender + '_' + phase_name, random))
            if secret is None:
                raise KeyError(sender + '_' + phase_name)
            if len(secret) != hashlib.new(self.digest).digest_size:
                raise DecryptionError('Secret length does not match cipher suite.', 'unsupported_profile')
            self.secrets[phase_name] = secret
            self._install(phase_name)
        self.plain_bytes = 0

    def _install(self, phase_name):
        secret = self.secrets[phase_name]
        self.ciphers[phase_name] = (self.cipher_class(expand(secret, b'key', self.key_size, self.digest)),
                                    expand(secret, b'iv', 12, self.digest))

    @property
    def epoch(self):
        return 'handshake' if self.phase == 'HANDSHAKE_TRAFFIC_SECRET' else 'application' + ('' if not self.updates else '+%d' % self.updates)

    def record(self, header, body):
        """One protected record in; application plaintext (possibly empty) out, or DecryptionError."""
        from cryptography.exceptions import InvalidTag
        if header[0] == 20 and body == b'\x01':
            return b''
        if header[0] != 23 or header[1:3] != b'\x03\x03':
            raise DecryptionError('Unexpected record after hello; early data and renegotiation are unsupported.', 'unsupported_profile')
        cipher, iv = self.ciphers[self.phase]
        nonce = bytes(a ^ b for a, b in zip(iv, self.sequence.to_bytes(12, 'big')))
        try:
            decoded = cipher.decrypt(nonce, body, header)
        except InvalidTag:
            raise DecryptionError('TLS authentication failed: wrong keys, missing records or modified ciphertext. '
                                  'No plaintext classification published.', 'authentication_failed') from None
        self.sequence += 1
        self.count += 1
        content = decoded.rstrip(b'\x00')
        if not content:
            raise DecryptionError('TLS inner content type is missing.', 'unsupported_profile')
        kind, content = content[-1], content[:-1]
        if len(content) > 16384:
            raise DecryptionError('TLS inner plaintext exceeds record limit.', 'unsupported_profile')
        if kind == 22:
            self.pending += content
            if len(self.pending) > MAX_STREAM:
                raise DecryptionError('Handshake exceeds profile limit.', 'budget_exhausted')
            while len(self.pending) >= 4:
                size = int.from_bytes(self.pending[1:4], 'big')
                if len(self.pending) < 4 + size:
                    break
                message, self.pending = self.pending[:4 + size], self.pending[4 + size:]
                if message[0] == 24:
                    if (self.phase != 'TRAFFIC_SECRET_0' or size != 1 or message[4] not in (0, 1) or self.pending
                            or self.updates >= 32):
                        raise DecryptionError('Invalid TLS KeyUpdate boundary or update budget exceeded.', 'unsupported_profile')
                    self.secrets[self.phase] = expand(self.secrets[self.phase], b'traffic upd',
                                                      hashlib.new(self.digest).digest_size, self.digest)
                    self._install(self.phase)
                    self.sequence = 0
                    self.updates += 1
                if message[0] == 20:
                    if self.phase != 'HANDSHAKE_TRAFFIC_SECRET' or size != hashlib.new(self.digest).digest_size or self.pending:
                        raise DecryptionError('Unexpected Finished message.', 'unsupported_profile')
                    self.phase, self.sequence = 'TRAFFIC_SECRET_0', 0
            return b''
        if kind == 23:
            if self.phase != 'TRAFFIC_SECRET_0' or self.pending:
                raise DecryptionError('Application data before handshake completion.', 'unsupported_profile')
            self.plain_bytes += len(content)
            if self.plain_bytes > MAX_STREAM:
                raise DecryptionError('Decrypted payload exceeds 256 KiB profile.', 'budget_exhausted')
            return content
        if kind != 21 or len(content) != 2:
            raise DecryptionError('Unsupported TLS inner content.', 'unsupported_profile')
        return b''

    def finish(self):
        if self.pending or self.phase != 'TRAFFIC_SECRET_0':
            raise DecryptionError('Incomplete encrypted handshake.', 'incomplete')


class Tls12Direction:
    def __init__(self, key, iv):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        self.cipher = AESGCM(key)
        self.iv = iv
        self.active = self.finished = False
        self.seq = self.count = self.plain_bytes = 0
        self.pending = b''

    @property
    def epoch(self):
        return 'application' if self.finished else 'handshake'

    def record(self, header, body):
        from cryptography.exceptions import InvalidTag
        kind = header[0]
        if not self.active:
            if kind == 20:
                if body != b'\x01' or self.pending:
                    raise DecryptionError('Invalid TLS 1.2 ChangeCipherSpec boundary.', 'unsupported_profile')
                self.active = True
                return b''
            if kind != 22:
                raise DecryptionError('Unexpected plaintext TLS 1.2 record.', 'unsupported_profile')
            self.pending += body
            while len(self.pending) >= 4:
                length = int.from_bytes(self.pending[1:4], 'big')
                if length > MAX_STREAM:
                    raise DecryptionError('TLS 1.2 handshake exceeds profile.', 'budget_exhausted')
                if len(self.pending) < length + 4:
                    break
                self.pending = self.pending[length + 4:]
            return b''
        if header[1:3] != b'\x03\x03' or kind not in (21, 22, 23) or len(body) < 24:
            raise DecryptionError('Unsupported protected TLS 1.2 record.', 'unsupported_profile')
        length = len(body) - 24
        if length > 16384:
            raise DecryptionError('TLS 1.2 plaintext exceeds record limit.', 'unsupported_profile')
        aad = self.seq.to_bytes(8, 'big') + header[:3] + length.to_bytes(2, 'big')
        try:
            content = self.cipher.decrypt(self.iv + body[:8], body[8:], aad)
        except InvalidTag:
            raise DecryptionError('TLS authentication failed: wrong keys, missing records or modified ciphertext.',
                                  'authentication_failed') from None
        self.seq += 1
        self.count += 1
        if kind == 22:
            if self.finished:
                raise DecryptionError('TLS 1.2 renegotiation is outside the profile.', 'unsupported_profile')
            self.pending += content
            if len(self.pending) >= 4:
                if self.pending[:4] != b'\x14\x00\x00\x0c' or len(self.pending) > 16:
                    raise DecryptionError('Unexpected TLS 1.2 encrypted handshake.', 'unsupported_profile')
                if len(self.pending) == 16:
                    self.finished, self.pending = True, b''
            return b''
        if kind == 23:
            if not self.finished or self.pending:
                raise DecryptionError('TLS 1.2 application data before Finished.', 'unsupported_profile')
            self.plain_bytes += len(content)
            if self.plain_bytes > MAX_STREAM:
                raise DecryptionError('Decrypted payload exceeds 256 KiB profile.', 'budget_exhausted')
            return content
        if len(content) != 2 or self.pending:
            raise DecryptionError('Invalid TLS 1.2 alert.', 'unsupported_profile')
        return b''

    def finish(self):
        if not self.finished or self.pending:
            raise DecryptionError('Incomplete TLS 1.2 handshake.', 'incomplete')


def _extensions(data, forbid_43=False):
    """Walk a ServerHello extension block; returns {kind: value}; duplicates and overruns are errors."""
    seen = {}
    while data:
        if len(data) < 4:
            raise DecryptionError('Truncated ServerHello extension.', 'unsupported_profile')
        kind, size = struct.unpack('!HH', data[:4])
        if size > len(data) - 4 or kind in seen or (forbid_43 and kind == 43):
            raise DecryptionError('Invalid ServerHello extension.', 'unsupported_profile')
        seen[kind] = data[4:4 + size]
        data = data[4 + size:]
    return seen


class TlsConnection:
    """Incremental decoder for one connection; see the module docstring for states and codes."""
    def __init__(self, keys, client, server):
        self.keys = keys
        self.client, self.server = client, server
        self.framers = {client: RecordFramer(), server: RecordFramer()}
        self.hellos = {client: HelloCollector(1), server: HelloCollector(2)}
        self.queued = {client: deque(), server: deque()}
        self.directions = {}
        self.state = 'awaiting_hello'
        self.processed = 0        # records framed or authenticated: finish() stops when a pass does nothing
        self.reason_code = self.reason = None
        self.version = self.suite = self.random = None
        self.records_authenticated = 0
        self.plaintext = {client: 0, server: 0}
        self._keys_version = None

    # ----- input ---------------------------------------------------------------
    @property
    def terminal(self):
        return self.state in ('complete', 'failed')

    def fail(self, error):
        if not self.terminal:
            self.state, self.reason_code, self.reason = 'failed', getattr(error, 'code', 'unsupported_profile'), str(error)
            self.queued = {self.client: deque(), self.server: deque()}
        return []

    def feed(self, endpoint, data):
        if self.terminal:
            return
        try:
            self.framers[endpoint].feed(data)
        except DecryptionError as error:
            self.fail(error)

    def has_work(self):
        if self.terminal:
            return False
        if self.state == 'awaiting_keys':
            return getattr(self.keys, 'version', None) != self._keys_version
        if any(f.ready() for f in self.framers.values()):
            return True
        # Records queued behind an incomplete peer hello are not work yet: nothing can decode them.
        return bool(self.directions) and any(self.queued.values())

    # ----- work -----------------------------------------------------------------
    def _frame(self):
        for endpoint, framer in self.framers.items():
            for header, body in framer.records():
                self.processed += 1
                hello = self.hellos[endpoint]
                if hello.body is None:
                    hello.add(header, body)
                else:
                    self.queued[endpoint].append((header, body))

    def _negotiate(self):
        ch, sh = self.hellos[self.client].body, self.hellos[self.server].body
        if self.hellos[self.client].trailing:
            raise DecryptionError('Unsupported initial TLS handshake layout.', 'unsupported_profile')
        if len(ch) < 35 or len(sh) < 40 or ch[:2] != b'\x03\x03' or sh[:2] != b'\x03\x03':
            raise DecryptionError('Unsupported TLS hello.', 'unsupported_profile')
        self.random = ch[2:34]
        sid = sh[34]
        offset = 35 + sid
        if sid > 32 or offset + 5 > len(sh):
            raise DecryptionError('Malformed ServerHello.', 'unsupported_profile')
        suite = int.from_bytes(sh[offset:offset + 2], 'big')
        if sh[offset + 2] != 0:
            raise DecryptionError('TLS compression is unsupported.', 'unsupported_profile')
        extensions = sh[offset + 5:]
        if int.from_bytes(sh[offset + 3:offset + 5], 'big') != len(extensions):
            raise DecryptionError('Malformed ServerHello extensions.', 'unsupported_profile')
        if suite in SUITES12:
            _extensions(extensions, forbid_43=True)
            self.version, self.suite = 'TLS 1.2', suite
            # TLS 1.2 directions consume the plaintext handshake from the start, hellos included.
            for endpoint in (self.client, self.server):
                self.queued[endpoint] = deque(self.hellos[endpoint].records + list(self.queued[endpoint]))
            return
        if suite not in SUITES:
            raise DecryptionError('Unsupported TLS cipher suite; supported: TLS 1.3 AEAD and TLS 1.2 ECDHE-RSA AES-GCM.',
                                  'unsupported_profile')
        if self.hellos[self.server].trailing:
            raise DecryptionError('Unsupported initial TLS handshake layout.', 'unsupported_profile')
        if sh[2:34] == HRR_RANDOM:
            raise DecryptionError('HelloRetryRequest is outside the POC profile.', 'unsupported_profile')
        if _extensions(extensions).get(43) != b'\x03\x04':
            raise DecryptionError('TLS 1.3 was not selected.', 'unsupported_profile')
        self.version, self.suite = 'TLS 1.3', suite

    def _start_directions(self):
        """Derive both directions' keys from the provider; False while the secrets are not there yet."""
        self._keys_version = getattr(self.keys, 'version', None)
        if self.version == 'TLS 1.2':
            master = self.keys.get(('CLIENT_RANDOM', self.random))
            if master is None:
                return False
            if len(master) != 48:
                raise DecryptionError('TLS 1.2 requires a matching CLIENT_RANDOM master secret.', 'unsupported_profile')
            digest, size = SUITES12[self.suite]
            sh = self.hellos[self.server].body
            block = prf(master, b'key expansion' + sh[2:34] + self.random, 2 * size + 8, digest)
            self.directions = {self.client: Tls12Direction(block[:size], block[2 * size:2 * size + 4]),
                               self.server: Tls12Direction(block[size:2 * size], block[2 * size + 4:])}
            return True
        try:
            self.directions = {self.client: Tls13Direction('CLIENT', self.suite, self.random, self.keys),
                               self.server: Tls13Direction('SERVER', self.suite, self.random, self.keys)}
        except KeyError:
            self.directions = {}
            return False
        return True

    def advance(self, budget=64):
        """Do at most `budget` records of work; returns the PlaintextDeltas released (possibly none)."""
        if self.terminal:
            return []
        try:
            self._frame()
            if self.suite is None:
                if self.hellos[self.client].body is None or self.hellos[self.server].body is None:
                    self.state = 'awaiting_hello'
                    return []
                self._negotiate()
            if not self.directions:
                if not self._start_directions():
                    self.state = 'awaiting_keys'
                    return []
            self.state = 'decrypting'
            released = []
            while budget > 0 and any(self.queued.values()):
                for endpoint in (self.client, self.server):
                    queue = self.queued[endpoint]
                    if not queue or budget <= 0:
                        continue
                    header, body = queue.popleft()
                    budget -= 1
                    self.processed += 1
                    direction = self.directions[endpoint]
                    content = direction.record(header, body)
                    self.records_authenticated += 1
                    if content:
                        self.plaintext[endpoint] += len(content)
                        released.append(PlaintextDelta(endpoint, direction.epoch, content))
            return released
        except DecryptionError as error:
            return self.fail(error)

    def finish(self):
        """The owner says the stream ended: complete, or fail with a typed reason. Idempotent."""
        if self.terminal:
            return self.state
        try:
            for framer in self.framers.values():
                framer.finish()
            while not self.terminal:
                before = self.processed
                self.advance(4096)
                if self.processed == before:
                    break
            if self.terminal:
                return self.state
            if self.suite is None:
                raise DecryptionError('Capture must include complete ClientHello and ServerHello.', 'incomplete')
            if not self.directions:
                raise DecryptionError('Matching handshake and application secrets are required for both directions.'
                                      if self.version == 'TLS 1.3' else 'TLS 1.2 requires a matching CLIENT_RANDOM master secret.',
                                      'awaiting_keys')
            for direction in self.directions.values():
                direction.finish()
            self.state = 'complete'
        except DecryptionError as error:
            self.fail(error)
        return self.state

    def metadata(self):
        out = {'version': self.version, 'cipher_suite': hex(self.suite) if self.suite is not None else None,
               'authenticated_records': self.records_authenticated,
               'client_plaintext_bytes': self.plaintext[self.client], 'server_plaintext_bytes': self.plaintext[self.server],
               'state': self.state}
        if self.reason_code:
            out['reason_code'] = self.reason_code
        return out
