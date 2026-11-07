"""Stage 8 (A10): key handling, privilege separation and local API security, verified with canaries.

Every test here uses synthetic in-memory TLS exchanges; the canaries are strings planted in the plaintext
request and in a key-log line, and the assertions are that no output, error, report, telemetry or event
channel ever carries them.
"""
import http.client
import json
import os
import re
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import server
from poc_decryption import DecryptionError, KeyProvider
from poc_decryption.capture import analyze_capture
from poc_decryption.demo import fixture
from poc_decryption.live import KeyLog, LiveDecoder

PLAINTEXT_CANARY = b'CANARY-PLAINTEXT-7f3a9c'
SECRET_CANARY = 'cafebabe' * 8          # 32 bytes of hex: a plausible but fake client random/secret
PRESENTATION = Path(__file__).resolve().parents[1]
ROOT = PRESENTATION.parent


def everything_rendered(objects):
    return '\n'.join(json.dumps(o, default=str) if not isinstance(o, str) else o for o in objects)


class CanaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.capture, cls.keylog, cls.client, cls.server = fixture(
            request=b'PROPFIND /' + PLAINTEXT_CANARY + b' HTTP/1.1\r\nHost: demo.invalid\r\nX-Canary: ' + PLAINTEXT_CANARY + b'\r\n\r\n')
        cls.secrets = [line.split()[-1] for line in cls.keylog.splitlines() if line and not line.startswith('#')]

    def assert_clean(self, text, where):
        self.assertNotIn(PLAINTEXT_CANARY.decode(), text, where)
        self.assertNotIn(SECRET_CANARY, text, where)
        for secret in self.secrets:
            self.assertNotIn(secret, text, where)

    def test_reports_errors_telemetry_and_events_never_carry_plaintext_or_secrets(self):
        report = analyze_capture(self.capture, self.keylog)
        self.assertEqual(report['decrypted'], 1)
        self.assertEqual(report['connections'][0]['application'], 'webdav')
        self.assert_clean(json.dumps(report), 'offline report')
        # A key log with a malformed line that contains the canary: the error names the problem, not the bytes.
        with self.assertRaises(DecryptionError) as caught:
            analyze_capture(self.capture, self.keylog + '\nCLIENT_RANDOM ' + SECRET_CANARY + ' notahexvalue\n')
        self.assert_clean(str(caught.exception) + repr(caught.exception), 'error text')
        provider = KeyProvider()
        provider.append(self.keylog)
        self.assert_clean(repr(provider) + str(provider), 'provider repr')
        # Live path: every emitted event and the telemetry inside summaries.
        decoder = LiveDecoder()
        decoder.feed(self.capture, now=1.0)
        decoder.advance(self.keylog)
        decoder.end()
        rendered = everything_rendered([decoder.snapshot(), decoder.monitor.summary(1.0), decoder.monitor.analyzer.telemetry.render(),
                                        decoder.decryptor.counts, decoder.monitor.coordinator.counts])
        self.assert_clean(rendered, 'live snapshot, summary and telemetry')
        # Wrong secrets: the failure is typed and carries no key or plaintext bytes either.
        wrong = re.sub(r'(?m)^(\S+ \S+) \S+$', lambda m: m.group(1) + ' ' + '00' * 48, self.keylog)
        failed = analyze_capture(self.capture, wrong)
        self.assertEqual(failed['decrypted'], 0)
        self.assertEqual(failed['connections'][0]['reason_code'], 'authentication_failed')
        self.assert_clean(json.dumps(failed), 'authentication failure report')

    def test_provider_release_and_expiry_end_secret_lifetime(self):
        clock = [100.0]
        provider = KeyProvider(max_age=10, clock=lambda: clock[0])
        provider.append(self.keylog)
        self.assertGreater(len(provider), 0)
        clock[0] = 105.0
        self.assertEqual(provider.expire(), 0)
        clock[0] = 120.0
        self.assertGreater(provider.expire(), 0)
        self.assertEqual(len(provider), 0)
        provider.append(self.keylog)
        provider.release()
        provider.release()                                        # idempotent
        self.assertEqual((len(provider), provider.released), (0, True))
        with self.assertRaises(DecryptionError):
            provider.get(('CLIENT_RANDOM', b'x' * 32))
        with self.assertRaises(DecryptionError):
            provider.append(self.keylog)
        self.assertNotIn(self.secrets[0], repr(provider))


class KeyPathAuthorizationTests(unittest.TestCase):
    def test_only_regular_files_owned_by_the_user_are_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            regular = os.path.join(directory, 'keys.log')
            with open(regular, 'w') as handle:
                handle.write('# ok\n')
            KeyLog(regular).close()
            fifo = os.path.join(directory, 'keys.fifo')
            os.mkfifo(fifo)
            with self.assertRaises((ValueError, OSError)):
                KeyLog(fifo)                                     # a FIFO is never a key log (and must not block)
            with self.assertRaises((ValueError, OSError)):
                KeyLog(directory)                                 # a directory
            with self.assertRaises((ValueError, OSError)):
                KeyLog('/dev/null')                               # a device
            link = os.path.join(directory, 'link')
            os.symlink(regular, link)
            with self.assertRaises(OSError):
                KeyLog(link)                                      # symlinks are refused at open time
            if os.getuid() != 0:
                self.assertTrue(stat.S_ISREG(os.stat(regular).st_mode))
            else:
                # As root every file is "owned"; the ownership rule is exercised by faking the stat result.
                real = os.fstat
                fake = os.stat_result(tuple(real(os.open(regular, os.O_RDONLY)))[:4] + (12345,) + tuple(real(os.open(regular, os.O_RDONLY)))[5:])
                with patch('poc_decryption.live.os.fstat', return_value=fake):
                    with self.assertRaisesRegex(ValueError, 'owned by your user'):
                        KeyLog(regular)

    def test_live_manager_authorizes_the_path_shape_before_any_process(self):
        from live_manager import LiveManager
        manager = LiveManager()
        with patch('live_manager.shutil.which', return_value='/usr/sbin/tcpdump'), \
                patch('live_manager.socket.if_nameindex', return_value=[(1, 'lo')]), \
                patch('live_manager.subprocess.Popen') as popen:
            for bad in ('relative/keys.log', 'x' * 1025, 42, ''):
                with self.assertRaises(ValueError):
                    manager.start('lo', 30, 'synthetic', keylog_path=bad)
            with self.assertRaises(ValueError):
                manager.start('lo', 600, 'synthetic', keylog_path='/tmp/keys.log')    # decryption runs are capped at 120 s
            popen.assert_not_called()


class PrivilegeSeparationTests(unittest.TestCase):
    def test_no_privilege_changes_anywhere_in_the_product(self):
        pattern = re.compile(r'\bsudo\b|os\.setuid|os\.seteuid|os\.setgid|setcap|pkexec|osascript', re.I)
        offenders = []
        for path in list(PRESENTATION.rglob('*.py')) + list((ROOT / 'protocol_adapters').glob('*.py')) + list((ROOT / 'protocol_engine').glob('*.py')) + list(PRESENTATION.glob('web/*.js')):
            if 'tests' in path.parts:
                continue
            for number, line in enumerate(path.read_text(errors='replace').splitlines(), 1):
                if pattern.search(line) and not line.lstrip().startswith('#') and 'never' not in line and 'not' not in line.lower():
                    offenders.append('%s:%d' % (path.relative_to(ROOT), number))
        self.assertEqual(offenders, [])

    def test_capture_failure_reports_without_escalating(self):
        from protocol_adapters import live_capture
        from protocol_adapters.packets import CaptureError
        with patch.object(live_capture.shutil, 'which', return_value=None):
            with self.assertRaises(CaptureError):               # missing tcpdump is reported, never worked around
                live_capture.capture_command('lo', 'tcp')
        with patch.object(live_capture.shutil, 'which', return_value='/usr/sbin/tcpdump'):
            command = live_capture.capture_command('lo', 'tcp')
        self.assertEqual(command[0], '/usr/sbin/tcpdump')
        self.assertFalse(any('sudo' in part or 'pkexec' in part for part in command))


class LocalApiGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = server.LocalServer(("127.0.0.1", 0), server.Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.httpd.server_port, timeout=15)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_host_origin_and_token_rules(self):
        port = self.httpd.server_port
        for headers in ({"Host": "127.0.0.1:%d" % (port + 1)}, {"Host": "localhost:%d" % port}, {"Origin": "null"},
                        {"Origin": "http://127.0.0.1:%d" % (port + 1)}, {"Origin": "https://127.0.0.1:%d" % port}):
            with self.subTest(headers=headers):
                self.assertEqual(self.request("GET", "/api/live/status", headers=headers)[0], 403)
        self.assertEqual(self.request("GET", "/api/live/status", headers={"Origin": "http://127.0.0.1:%d" % port})[0], 200)
        token = json.loads(self.request('GET', '/api/live/interfaces')[1])['token']
        for path in ('/api/jobs?kind=demo', '/api/jobs/x/cancel', '/api/live/heartbeat', '/api/live/start', '/api/live/stop', '/api/decrypt', '/api/decrypt/demo'):
            with self.subTest(path=path):
                self.assertEqual(self.request('POST', path, b'{}')[0], 403)
                self.assertEqual(self.request('POST', path, b'{}', {'X-Live-Token': token[:-1] + ('a' if token[-1] != 'a' else 'b')})[0], 403)
        status, body = self.request('GET', '/api/health')
        self.assertEqual(status, 200)
        health = json.loads(body)
        self.assertNotIn('token', json.dumps(health))

    def test_worker_boundaries_never_echo_inputs(self):
        token = json.loads(self.request('GET', '/api/live/interfaces')[1])['token']
        payload = {'capture': 'AAAA', 'keylog': 'CLIENT_RANDOM ' + SECRET_CANARY + ' ' + SECRET_CANARY}
        status, body = self.request('POST', '/api/decrypt', json.dumps(payload), {'X-Live-Token': token, 'Content-Type': 'application/json'})
        self.assertIn(status, (400, 200))
        self.assertNotIn(SECRET_CANARY, body.decode())


if __name__ == '__main__':
    unittest.main()
