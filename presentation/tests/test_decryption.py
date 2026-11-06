import json
import os
import struct
import unittest
import server
from poc_decryption import DecryptionError, read_keys, decrypt_streams, records, expand
from poc_decryption.capture import analyze_capture
from poc_decryption.demo import fixture


class DecryptionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.capture, cls.keylog, cls.client, cls.server = fixture()

    def test_openssl_encrypted_webdav_and_no_secret_or_payload_output(self):
        result = analyze_capture(self.capture, self.keylog)
        self.assertEqual(result['decrypted'], 1)
        connection = result['connections'][0]
        self.assertEqual(connection['application'], 'webdav')
        self.assertEqual(connection['inner_protocol'], 'http/1.1')
        self.assertGreater(connection['authenticated_records'], 2)
        encoded = json.dumps(result)
        for forbidden in ('/documents', 'demo.invalid', self.keylog.splitlines()[-1].split()[-1]):
            self.assertNotIn(forbidden, encoded)
        self.assertTrue(any(e['source'].startswith('decrypted') for e in connection['evidence']))

    def test_wrong_keys_missing_keys_and_tampering_fail_closed(self):
        keys = read_keys(self.keylog)
        bad = {key: bytes(len(value)) for key, value in keys.items()}
        for candidate in ({}, bad):
            with self.assertRaises(DecryptionError):
                decrypt_streams(self.client, self.server, candidate)
        modified = self.client[:-1] + bytes([self.client[-1] ^ 1])
        with self.assertRaisesRegex(DecryptionError, 'authentication failed'):
            decrypt_streams(modified, self.server, keys)
        result = analyze_capture(self.capture, '')
        self.assertEqual(result['decrypted'], 0)
        self.assertNotIn('application', result['connections'][0])

    def test_record_truncation_and_malformed_lengths(self):
        for data in (self.client[:-1], b'\x17\x03\x03\xff\xff', b'\x17\x03'):
            with self.assertRaises(DecryptionError):
                list(records(data))

    def test_key_log_validation_and_bounds(self):
        with self.assertRaises(DecryptionError):
            read_keys('x' * 262145)
        line = next(line for line in self.keylog.splitlines() if line.startswith('CLIENT_TRAFFIC_SECRET_0'))
        fields = line.split()
        with self.assertRaises(DecryptionError):
            read_keys(line + '\n' + ' '.join(fields[:2] + ['00' * (len(fields[2]) // 2)]))
        with self.assertRaises(DecryptionError):
            read_keys('CLIENT_TRAFFIC_SECRET_0 invalid invalid')

    def test_missing_and_conflicting_tcp_segments(self):
        from capture_stream import PcapStreamDecoder
        from make_sample_pcap import pcap_bytes
        decoder = PcapStreamDecoder()
        frames = [record.data for record in decoder.feed(self.capture)]
        missing = analyze_capture(pcap_bytes(frames[:3] + frames[4:]), self.keylog)
        self.assertEqual(missing['decrypted'], 0)
        conflict = bytearray(frames[2]); conflict[-1] ^= 1
        bad = analyze_capture(pcap_bytes(frames + [bytes(conflict)]), self.keylog)
        self.assertEqual(bad['decrypted'], 0)
        self.assertIn('Conflicting', bad['connections'][0]['reason'])

    def test_all_cipher_suites_epoch_reset_and_keyupdate_rejection(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
        from poc_decryption import SUITES
        def record(kind, body):
            return bytes([kind]) + b'\x03\x03' + len(body).to_bytes(2, 'big') + body
        def handshake(kind, body):
            return bytes([kind]) + len(body).to_bytes(3, 'big') + body
        for suite, (digest, size) in SUITES.items():
            with self.subTest(suite=suite):
                random = os.urandom(32)
                ch = record(22, handshake(1, b'\x03\x03' + random + b'\x00'))
                sh = record(22, handshake(2, b'\x03\x03' + os.urandom(32) + b'\x00' + struct.pack('!H', suite) + b'\x00\x00\x06\x00\x2b\x00\x02\x03\x04'))
                secret_size = 48 if digest == 'sha384' else 32
                keys = {(sender+'_'+phase, random): os.urandom(secret_size)
                        for sender in ('CLIENT','SERVER') for phase in ('HANDSHAKE_TRAFFIC_SECRET','TRAFFIC_SECRET_0')}
                def encrypted(sender, phase, seq, body, kind):
                    secret = keys[(sender+'_'+phase, random)]
                    cipher = (ChaCha20Poly1305 if suite == 0x1303 else AESGCM)(expand(secret,b'key',size,digest))
                    iv = expand(secret,b'iv',12,digest)
                    nonce = bytes(a^b for a,b in zip(iv,seq.to_bytes(12,'big')))
                    inner = body + bytes([kind]) + b'\x00\x00'
                    header = b'\x17\x03\x03' + (len(inner)+16).to_bytes(2,'big')
                    return header+cipher.encrypt(nonce,inner,header)
                streams = []
                for sender, initial in (('CLIENT',ch),('SERVER',sh)):
                    streams.append(initial + encrypted(sender,'HANDSHAKE_TRAFFIC_SECRET',0,handshake(20,b'F'*secret_size),22)
                                   + encrypted(sender,'TRAFFIC_SECRET_0',0,b'hello',23))
                cp, sp, _ = decrypt_streams(*streams, keys)
                self.assertEqual((cp,sp),(b'hello',b'hello'))
                update = encrypted('CLIENT','TRAFFIC_SECRET_0',1,handshake(24,b'\x00'),22)
                key = ('CLIENT_TRAFFIC_SECRET_0',random)
                old = keys[key]
                keys[key] = expand(old,b'traffic upd',secret_size,digest)
                after = encrypted('CLIENT','TRAFFIC_SECRET_0',0,b' after update',23)
                keys[key] = old
                cp, _, _ = decrypt_streams(streams[0]+update+after, streams[1], keys)
                self.assertEqual(cp,b'hello after update')
                bad_update = encrypted('CLIENT','TRAFFIC_SECRET_0',1,handshake(24,b'\x02'),22)
                with self.assertRaisesRegex(DecryptionError,'KeyUpdate'):
                    decrypt_streams(streams[0]+bad_update,streams[1],keys)

    def test_tls12_openssl_suites_and_failures(self):
        for cipher in ('ECDHE-RSA-AES128-GCM-SHA256','ECDHE-RSA-AES256-GCM-SHA384'):
            with self.subTest(cipher=cipher):
                cap, log, client, server_wire = fixture('1.2',cipher)
                result = analyze_capture(cap,log)
                self.assertEqual(result['connections'][0]['application'],'webdav')
                self.assertEqual(result['connections'][0]['version'],'TLS 1.2')
                keys = read_keys(log)
                for broken in (client[:-1],client[:-1]+bytes([client[-1]^1])):
                    with self.assertRaises(DecryptionError): decrypt_streams(broken,server_wire,keys)
                with self.assertRaises(DecryptionError): decrypt_streams(client,server_wire,{})
                wrong={k:b'\x00'*48 for k in keys}
                with self.assertRaises(DecryptionError): decrypt_streams(client,server_wire,wrong)

    def test_worker_api_never_returns_keys(self):
        result = server.run_decryption_worker(b'', demo=True)
        self.assertEqual(result['connections'][0]['application'], 'webdav')
        self.assertEqual(result['decrypted'],3)
        self.assertEqual([r['application'] for r in result['connections']],['webdav','web-browsing','resp'])
        self.assertEqual([r['version'] for r in result['connections']],['TLS 1.3','TLS 1.2','TLS 1.2'])
        self.assertNotIn('keylog', result)
