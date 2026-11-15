"""Stage 6 (A08): bounded jobs, admission control, side-effect-free status, idempotent stop."""
import http.client
import json
import sys
import threading
import time
import unittest
from unittest.mock import patch

import server
from jobs import AdmissionError, JobRunner
from live_manager import LiveManager

SLEEPER = [sys.executable, '-c', 'import sys,time; time.sleep(float(sys.stdin.readline() or 2)); print("{}")']


def sleeper(kind, payload):
    return SLEEPER, payload


class JobRunnerTests(unittest.TestCase):
    def test_admission_lifetime_cancel_and_shutdown_are_explicit(self):
        runner = JobRunner(sleeper, max_running=1, max_queued=1, lifetime=0.5)
        try:
            running = runner.submit('sleep', b'5\n')
            queued = runner.submit('sleep', b'0\n')
            with self.assertRaises(AdmissionError):
                runner.submit('sleep', b'0\n')                       # third: rejected at once, nothing blocks
            self.assertEqual(runner.counts['rejected'], 1)
            before = runner.get(running['id'])
            self.assertEqual(before['state'], 'running')
            self.assertEqual(runner.get(running['id']), before)      # a read changes nothing
            finished = runner.wait(running['id'], 3)
            self.assertEqual((finished['state'], 'lifetime' in finished['reason']), ('expired', True))
            self.assertEqual(runner.wait(queued['id'], 3)['state'], 'done')
            cancelled = runner.submit('sleep', b'5\n')
            self.assertEqual(runner.cancel(cancelled['id'])['state'], 'cancelled')
            self.assertEqual(runner.cancel(cancelled['id'])['state'], 'cancelled')   # idempotent
            self.assertIsNone(runner.cancel('nope'))
            late = runner.submit('sleep', b'5\n')
            runner.shutdown()
            runner.shutdown()
            self.assertEqual(runner.get(late['id'])['state'], 'cancelled')
            self.assertIn('shut down', runner.get(late['id'])['reason'])
            with self.assertRaises(AdmissionError):
                runner.submit('sleep', b'0\n')
        finally:
            runner.shutdown()

    def test_outcomes_are_retained_boundedly(self):
        runner = JobRunner(sleeper, max_running=2, max_queued=8, lifetime=5, retain=3)
        try:
            ids = [runner.submit('sleep', b'0\n')['id'] for _ in range(5)]
            for job_id in ids:
                runner.wait(job_id, 5)
            kept = [job_id for job_id in ids if runner.get(job_id) is not None]
            self.assertLessEqual(len(kept), 3)
            self.assertEqual(kept[-1], ids[-1])
        finally:
            runner.shutdown()


class FakeProcess:
    def __init__(self):
        self.returncode = None
        self.signals = []
        self.pid = 4242
        self.stdout = type('S', (), {'readline': staticmethod(lambda n=0: time.sleep(0.05) or b''), 'close': staticmethod(lambda: None)})()
        self.stdin = None

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.returncode = 0 if self.returncode is None else self.returncode
        return self.returncode

    def send_signal(self, signal_number):
        self.signals.append(signal_number)
        self.returncode = 0


class LiveControlTests(unittest.TestCase):
    def test_concurrent_starts_create_one_run_and_status_is_side_effect_free(self):
        manager = LiveManager()
        started, errors = [], []
        fakes = []

        def popen(*args, **kwargs):
            time.sleep(0.05)                                        # widen the race window
            process = FakeProcess()
            fakes.append(process)
            return process

        def start():
            try:
                started.append(manager.start('lo', 30, 'synthetic'))
            except ValueError as error:
                errors.append(str(error))
        with patch('live_manager.shutil.which', return_value='/usr/sbin/tcpdump'), \
                patch('live_manager.socket.if_nameindex', return_value=[(1, 'lo')]), \
                patch('live_manager.subprocess.Popen', side_effect=popen):
            threads = [threading.Thread(target=start) for _ in range(6)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual((len(started), len(fakes)), (1, 1))
            self.assertEqual(len(errors), 5)
            run_id = started[0]['run_id']
            lease = manager.lease
            time.sleep(0.02)
            snapshot = manager.snapshot()                            # a status read does not renew the lease
            self.assertEqual(manager.lease, lease)
            self.assertEqual(snapshot['run_id'], run_id)
            self.assertFalse(manager.heartbeat('another-run'))       # another run's heartbeat changes nothing
            self.assertEqual(manager.lease, lease)
            self.assertTrue(manager.heartbeat(run_id))
            self.assertGreater(manager.lease, lease)
            manager.stop(run_id='another-run')                       # stopping another run is a no-op
            self.assertEqual(fakes[0].signals, [])
            manager.stop(run_id=run_id)
            manager.stop()                                           # idempotent
            self.assertEqual(len(fakes[0].signals), 1)
            manager.thread.join(timeout=2)


class HTTPControlTests(unittest.TestCase):
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

    def request(self, method, path, body=None, headers=None, timeout=30):
        connection = http.client.HTTPConnection("127.0.0.1", self.httpd.server_port, timeout=timeout)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, json.loads(response.read() or b'null')
        finally:
            connection.close()

    def test_jobs_api_and_control_latency_under_load(self):
        token = self.request('GET', '/api/live/interfaces')[1]['token']
        headers = {'X-Live-Token': token}
        self.assertEqual(self.request('POST', '/api/jobs?kind=demo')[0], 403)
        status, job = self.request('POST', '/api/jobs?kind=demo', headers=headers)
        self.assertEqual((status, job['state'] in ('queued', 'running')), (202, True))
        # Control reads answer while the worker runs: each well under the agreed one-second budget.
        slowest = 0.0
        for _ in range(5):
            started = time.monotonic()
            code, snapshot = self.request('GET', '/api/live/status')
            slowest = max(slowest, time.monotonic() - started)
            self.assertEqual(code, 200)
        self.assertLess(slowest, 1.0)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            code, job = self.request('GET', '/api/jobs/' + job['id'])
            if job['state'] not in ('queued', 'running'):
                break
            time.sleep(0.2)
        self.assertEqual(job['state'], 'done')
        self.assertEqual(len(job['result']['sessions']), 18)
        self.assertEqual(self.request('GET', '/api/jobs/unknown')[0], 404)
        code, cancelled = self.request('POST', '/api/jobs/' + job['id'] + '/cancel', headers=headers)
        self.assertEqual((code, cancelled['state']), (200, 'done'))        # cancel after completion is a no-op
        code, info = self.request('GET', '/api/server')
        self.assertEqual((code, info['jobs']['max_running'], info['handlers']), (200, 2, server.MAX_HANDLERS))
        self.assertEqual(self.request('POST', '/api/jobs?kind=bogus', headers=headers)[0], 400)

    def test_heartbeat_and_stop_are_token_guarded_and_idempotent(self):
        token = self.request('GET', '/api/live/interfaces')[1]['token']
        self.assertEqual(self.request('POST', '/api/live/heartbeat', b'{}')[0], 403)
        code, result = self.request('POST', '/api/live/heartbeat', json.dumps({'run_id': 'x'}), {'X-Live-Token': token})
        self.assertEqual((code, result['renewed']), (200, False))
        for _ in range(2):
            code, result = self.request('POST', '/api/live/stop', json.dumps({'run_id': 'x'}), {'X-Live-Token': token})
            self.assertEqual((code, result['state']), (200, 'idle'))

    def test_handler_pool_rejects_beyond_its_bound_without_queueing(self):
        port = self.httpd.server_port
        holders = []
        try:
            for _ in range(server.MAX_HANDLERS):
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.connect()
                connection.sock.sendall(b"POST /api/analyze HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nContent-Length: 10\r\n\r\n" % port)
                holders.append(connection)                           # bodies never arrive: handlers stay busy
            time.sleep(0.3)
            code, body = self.request('GET', '/api/live/status', timeout=5)
            self.assertEqual(code, 503)
            self.assertIn('retry', body['error'].lower())
        finally:
            for connection in holders:
                connection.close()
        time.sleep(0.5)
        self.assertEqual(self.request('GET', '/api/live/status')[0], 200)
        self.assertGreaterEqual(self.httpd.rejected, 1)


if __name__ == '__main__':
    unittest.main()
