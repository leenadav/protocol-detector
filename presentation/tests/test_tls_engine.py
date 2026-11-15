"""Stage 4 (A02, A09): the incremental TLS engine, independent of packet capture."""
import os
import struct
import unittest
import server as _server  # noqa: F401 - registers the engine root for a checkout
from poc_decryption import DecryptionError, KeyProvider, SUITES, expand, read_keys
from poc_decryption.engine import PlaintextDelta, RecordFramer, TlsConnection
from poc_decryption.demo import fixture

C, S = ('192.0.2.10', 51000), ('198.51.100.20', 443)


def record(kind, body):
    return bytes([kind]) + b'\x03\x03' + len(body).to_bytes(2, 'big') + body


def handshake(kind, body):
    return bytes([kind]) + len(body).to_bytes(3, 'big') + body


class Synthetic13:
    """A synthetic TLS 1.3 exchange for one suite: independent of OpenSSL, every record under our control."""
    def __init__(self, suite):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
        self.suite = suite
        self.digest, self.size = SUITES[suite]
        self.random = os.urandom(32)
        self.secret_size = 48 if self.digest == 'sha384' else 32
        self.keys = {(sender + '_' + phase, self.random): os.urandom(self.secret_size)
                     for sender in ('CLIENT', 'SERVER') for phase in ('HANDSHAKE_TRAFFIC_SECRET', 'TRAFFIC_SECRET_0')}
        self.cipher_class = ChaCha20Poly1305 if suite == 0x1303 else AESGCM
        self.ch = record(22, handshake(1, b'\x03\x03' + self.random + b'\x00'))
        self.sh = record(22, handshake(2, b'\x03\x03' + os.urandom(32) + b'\x00' + struct.pack('!H', suite)
                                        + b'\x00\x00\x06\x00\x2b\x00\x02\x03\x04'))

    def keylog(self):
        return ''.join('%s %s %s\n' % (label, random.hex(), secret.hex()) for (label, random), secret in self.keys.items())

    def encrypted(self, sender, phase, seq, body, kind, secret=None):
        secret = secret or self.keys[(sender + '_' + phase, self.random)]
        cipher = self.cipher_class(expand(secret, b'key', self.size, self.digest))
        iv = expand(secret, b'iv', 12, self.digest)
        nonce = bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, 'big')))
        inner = body + bytes([kind]) + b'\x00\x00'
        header = b'\x17\x03\x03' + (len(inner) + 16).to_bytes(2, 'big')
        return header + cipher.encrypt(nonce, inner, header)

    def finished(self, sender):
        return self.encrypted(sender, 'HANDSHAKE_TRAFFIC_SECRET', 0, handshake(20, b'F' * self.secret_size), 22)

    def app(self, sender, seq, body, secret=None):
        return self.encrypted(sender, 'TRAFFIC_SECRET_0', seq, body, 23, secret)

    def streams(self, client_app=(b'hello',), server_app=(b'hello',)):
        client = self.ch + self.finished('CLIENT') + b''.join(self.app('CLIENT', i, b) for i, b in enumerate(client_app))
        server = self.sh + self.finished('SERVER') + b''.join(self.app('SERVER', i, b) for i, b in enumerate(server_app))
        return client, server


def run(connection, client, server, step=None):
    """Feed both directions (optionally `step` bytes at a time, interleaved) and collect plaintext per endpoint."""
    plain = {C: bytearray(), S: bytearray()}
    step = step or max(len(client), len(server))
    for offset in range(0, max(len(client), len(server)), step):
        connection.feed(C, client[offset:offset + step])
        connection.feed(S, server[offset:offset + step])
        while connection.has_work():
            for delta in connection.advance(3):
                plain[delta.endpoint].extend(delta.data)
    return plain


class FramerTests(unittest.TestCase):
    def test_records_are_framed_once_across_arbitrary_splits(self):
        body = os.urandom(300)
        wire = record(23, body) * 3
        for step in (1, 2, 7, 100, len(wire)):
            framer = RecordFramer()
            out = []
            for offset in range(0, len(wire), step):
                framer.feed(wire[offset:offset + step])
                out.extend(framer.records())
            self.assertEqual([b for _, b in out], [body] * 3, step)
            framer.finish()
        framer = RecordFramer()
        framer.feed(wire[:-1])
        list(framer.records())
        with self.assertRaises(DecryptionError) as caught:
            framer.finish()
        self.assertEqual(caught.exception.code, 'incomplete')


class IncrementalEngineTests(unittest.TestCase):
    def test_every_suite_split_records_and_epoch_provenance(self):
        for suite in SUITES:
            with self.subTest(suite=suite):
                synthetic = Synthetic13(suite)
                client, server = synthetic.streams((b'GET ', b'/ HTTP/1.1\r\n\r\n'), (b'HTTP/1.1 200 OK\r\n\r\n',))
                for step in (1, 5, 64, None):
                    connection = TlsConnection(synthetic.keys, C, S)
                    plain = run(connection, client, server, step)
                    self.assertEqual(connection.finish(), 'complete', step)
                    self.assertEqual((bytes(plain[C]), bytes(plain[S])), (b'GET / HTTP/1.1\r\n\r\n', b'HTTP/1.1 200 OK\r\n\r\n'))
                    self.assertEqual(connection.records_authenticated, 5)
                connection = TlsConnection(synthetic.keys, C, S)
                connection.feed(C, client)
                connection.feed(S, server)
                deltas = []
                while connection.has_work():
                    deltas.extend(connection.advance(1))
                self.assertTrue(all(isinstance(d, PlaintextDelta) and d.epoch == 'application' for d in deltas))
                self.assertEqual({d.endpoint for d in deltas}, {C, S})

    def test_late_keys_wake_the_connection_and_one_record_is_decrypted_once(self):
        synthetic = Synthetic13(0x1301)
        client, server = synthetic.streams()
        keys = KeyProvider()
        connection = TlsConnection(keys, C, S)
        connection.feed(C, client)
        connection.feed(S, server)
        self.assertEqual(connection.advance(), [])
        self.assertEqual(connection.state, 'awaiting_keys')
        self.assertFalse(connection.has_work())                 # nothing to do until the provider changes
        keys.append('# unrelated\nCLIENT_RANDOM ' + os.urandom(32).hex() + ' ' + os.urandom(48).hex() + '\n')
        self.assertTrue(connection.has_work())                  # the provider changed: ask once more
        self.assertEqual(connection.advance(), [])
        self.assertEqual(connection.state, 'awaiting_keys')
        self.assertFalse(connection.has_work())
        keys.append(synthetic.keylog())
        plain = b''.join(d.data for d in connection.advance())
        self.assertEqual(plain, b'hellohello')
        self.assertEqual(connection.records_authenticated, 4)
        self.assertEqual(connection.advance(), [])
        self.assertEqual(connection.records_authenticated, 4)   # no re-decryption on later calls
        connection.feed(C, synthetic.app('CLIENT', 1, b' more'))
        self.assertEqual(b''.join(d.data for d in connection.advance()), b' more')
        self.assertEqual(connection.records_authenticated, 5)
        self.assertEqual(connection.finish(), 'complete')

    def test_key_update_mid_stream_incrementally(self):
        synthetic = Synthetic13(0x1302)
        client, server = synthetic.streams()
        connection = TlsConnection(synthetic.keys, C, S)
        run(connection, client, server)
        update = synthetic.encrypted('CLIENT', 'TRAFFIC_SECRET_0', 1, handshake(24, b'\x00'), 22)
        updated = expand(synthetic.keys[('CLIENT_TRAFFIC_SECRET_0', synthetic.random)], b'traffic upd', synthetic.secret_size, 'sha384')
        after = synthetic.app('CLIENT', 0, b' after update', updated)
        connection.feed(C, update + after[:10])
        self.assertEqual(connection.advance(), [])              # the update applied; the next record is incomplete
        connection.feed(C, after[10:])
        deltas = connection.advance()
        self.assertEqual([(d.epoch, d.data) for d in deltas], [('application+1', b' after update')])
        self.assertEqual(connection.finish(), 'complete')

    def test_failures_are_typed_and_publish_nothing_afterwards(self):
        synthetic = Synthetic13(0x1301)
        client, server = synthetic.streams((b'first',), (b'reply',))
        cases = {
            'authentication_failed': (client[:-1] + bytes([client[-1] ^ 1]) + synthetic.app('CLIENT', 1, b'never'), server),
            'unsupported_profile': (client + record(21, b'\x01\x00') + synthetic.app('CLIENT', 1, b'never'), server),
        }
        wrong = {key: bytes(len(value)) for key, value in synthetic.keys.items()}
        for code, (c, s) in cases.items():
            with self.subTest(code=code):
                connection = TlsConnection(synthetic.keys, C, S)
                plain = run(connection, c, s)
                self.assertEqual(connection.state, 'failed')
                self.assertEqual(connection.reason_code, code)
                self.assertNotIn(b'never', bytes(plain[C]))
                connection.feed(C, synthetic.app('CLIENT', 2, b'late'))
                self.assertEqual(connection.advance(), [])
                self.assertEqual(connection.finish(), 'failed')
        connection = TlsConnection(wrong, C, S)
        run(connection, client, server)
        self.assertEqual((connection.state, connection.reason_code), ('failed', 'authentication_failed'))
        # A missing record (sequence gap) is an authentication failure too: the nonce no longer matches.
        gap_client = synthetic.ch + synthetic.finished('CLIENT') + synthetic.app('CLIENT', 1, b'skipped seq 0')
        connection = TlsConnection(synthetic.keys, C, S)
        run(connection, gap_client, server)
        self.assertEqual(connection.reason_code, 'authentication_failed')
        # Application data in the handshake epoch is an invalid epoch.
        early = synthetic.ch + synthetic.encrypted('CLIENT', 'HANDSHAKE_TRAFFIC_SECRET', 0, b'early', 23)
        connection = TlsConnection(synthetic.keys, C, S)
        run(connection, early, server)
        self.assertEqual(connection.reason_code, 'unsupported_profile')
        # close_notify is accepted and releases nothing; a malformed KeyUpdate fails the connection.
        alert = synthetic.app('CLIENT', 1, b'')[:0] + synthetic.encrypted('CLIENT', 'TRAFFIC_SECRET_0', 1, b'\x01\x00', 21)
        connection = TlsConnection(synthetic.keys, C, S)
        plain = run(connection, client + alert, server)
        self.assertEqual((bytes(plain[C]), connection.finish()), (b'first', 'complete'))
        bad = synthetic.encrypted('CLIENT', 'TRAFFIC_SECRET_0', 1, handshake(24, b'\x02'), 22)
        connection = TlsConnection(synthetic.keys, C, S)
        run(connection, client + bad, server)
        self.assertEqual(connection.reason_code, 'unsupported_profile')
        self.assertIn('KeyUpdate', connection.reason)
        # Ending without secrets or inside a record is reported as such, never as decrypted.
        connection = TlsConnection(KeyProvider(), C, S)
        run(connection, client, server)
        self.assertEqual(connection.finish(), 'failed')
        self.assertEqual(connection.reason_code, 'awaiting_keys')
        connection = TlsConnection(synthetic.keys, C, S)
        run(connection, client[:-3], server)
        self.assertEqual((connection.finish(), connection.reason_code), ('failed', 'incomplete'))

    def test_long_lived_stream_costs_new_bytes_only(self):
        synthetic = Synthetic13(0x1303)
        client, server = synthetic.streams((), ())
        connection = TlsConnection(synthetic.keys, C, S)
        run(connection, client, server)
        total = 0
        for index in range(600):
            chunk = synthetic.app('CLIENT', index, bytes([index % 251]) * 200)
            connection.feed(C, chunk)
            deltas = connection.advance(8)
            total += sum(len(d.data) for d in deltas)
            self.assertEqual(len(deltas), 1)                     # exactly the new record, every time
        self.assertEqual((total, connection.records_authenticated), (600 * 200, 602))
        self.assertEqual(connection.finish(), 'complete')
        self.assertEqual(connection.plaintext[C], 600 * 200)

    def test_openssl_fixtures_through_the_incremental_path(self):
        for version, cipher in (('1.3', None), ('1.2', 'ECDHE-RSA-AES128-GCM-SHA256'), ('1.2', 'ECDHE-RSA-AES256-GCM-SHA384')):
            with self.subTest(version=version, cipher=cipher):
                _, keylog, client, server = fixture(version, cipher)
                keys = KeyProvider()
                connection = TlsConnection(keys, C, S)
                plain = run(connection, client, server, step=97)
                self.assertEqual(connection.state, 'awaiting_keys')
                keys.append(keylog)
                while connection.has_work():
                    for delta in connection.advance(2):
                        plain[delta.endpoint].extend(delta.data)
                self.assertEqual(connection.finish(), 'complete')
                self.assertTrue(bytes(plain[C]).startswith(b'PROPFIND /documents'))
                self.assertTrue(bytes(plain[S]).startswith(b'HTTP/1.1 207'))
                self.assertEqual(connection.version, 'TLS ' + version)


class KeyProviderTests(unittest.TestCase):
    def test_append_indexes_new_lines_once_and_keeps_bounds(self):
        synthetic = Synthetic13(0x1301)
        provider = KeyProvider()
        self.assertEqual(provider.append(synthetic.keylog()), 4)
        self.assertEqual(provider.version, 1)
        self.assertEqual(provider.append(synthetic.keylog()), 0)      # same lines again: nothing new
        self.assertEqual(provider.version, 1)
        self.assertTrue(provider.has(synthetic.random))
        self.assertEqual(read_keys(synthetic.keylog()), provider.keys)
        with self.assertRaises(DecryptionError) as caught:
            provider.append('CLIENT_TRAFFIC_SECRET_0 %s %s\n' % (synthetic.random.hex(), '00' * 32))
        self.assertEqual(caught.exception.code, 'unsupported_profile')  # a secret must never change under a random
        with self.assertRaises(DecryptionError) as caught:
            provider.append('x' * 262145)
        self.assertEqual(caught.exception.code, 'budget_exhausted')
        with self.assertRaises(DecryptionError):
            provider.append(b'not text')


if __name__ == '__main__':
    unittest.main()
