import json
import subprocess
import sys
import unittest
from unittest.mock import patch

import server
from live_manager import LiveManager, ROOT


class LiveBridgeTests(unittest.TestCase):
    def test_retention_is_bounded_and_loss_retracts_sessions(self):
        manager = LiveManager()
        for i in range(1000):
            manager.ingest({'type': 'classification', 'status': 'identified'})
            manager.ingest({'type': 'session', 'app': 'ssh'})
        result = manager.snapshot()
        self.assertEqual(len(result['events']), 200)
        self.assertEqual(len(result['sessions']), 500)
        self.assertEqual(result['sessions_total'], 1000)
        manager.ingest({'type': 'capture_gap', 'reason': 'loss'})
        self.assertEqual(manager.snapshot()['sessions'], [])

    def test_invalid_options_never_spawn(self):
        manager = LiveManager()
        with patch.object(manager, 'interfaces', return_value={'interfaces': ['lo0', 'en0']}), patch('live_manager.subprocess.Popen') as spawn:
            for interface, duration, scope in [('-i', 30, 'all'), ('lo0', True, 'all'), ('lo0', 601, 'all'), ('en0', 30, 'synthetic'), ('lo0', 30, 'bad')]:
                with self.assertRaises(ValueError):
                    manager.start(interface, duration, scope)
            spawn.assert_not_called()

    def test_pinned_live_engine_stream_contract(self):
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'engine/live_capture.py'),
                                 '--stdin', '--json', '--all-events', '--fingerprints'],
                                input=server.demo_bytes(), capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        manager = LiveManager()
        for line in result.stdout.splitlines():
            manager.ingest(json.loads(line))
        snapshot = manager.snapshot()
        self.assertEqual(len(snapshot['sessions']), 18)
        self.assertEqual(snapshot['summary']['counts']['packets'], 111)
        self.assertTrue(any(e.get('event') == 'shifted' for e in snapshot['events']))
        self.assertEqual(snapshot['summary']['capture_quality'], 'unverified')

    def test_watchdog_cannot_stop_replacement_process(self):
        manager = LiveManager()
        with patch('live_manager.subprocess.Popen') as process:
            manager.process = process
            manager.stop(expected=object())
            process.send_signal.assert_not_called()
