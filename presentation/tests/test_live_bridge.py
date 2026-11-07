import json
import subprocess
import unittest
from unittest.mock import patch

import server
from live_manager import LiveManager


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
        from live_manager import engine_command, engine_cwd
        result = subprocess.run(engine_command('protocol_adapters.live_capture') + ['--stdin', '--json', '--all-events', '--fingerprints'],
                                input=server.demo_bytes(), capture_output=True, timeout=10, cwd=engine_cwd())
        self.assertEqual(result.returncode, 0, result.stderr)
        manager = LiveManager()
        for line in result.stdout.splitlines():
            manager.ingest(json.loads(line))
        snapshot = manager.snapshot()
        self.assertEqual(len(snapshot['sessions']), 18)
        self.assertEqual(snapshot['summary']['counts']['packets'], 111)
        self.assertTrue(any(e.get('event') == 'shifted' for e in snapshot['events']))
        self.assertEqual(snapshot['summary']['capture_quality'], 'unverified')

    def test_state_view_is_light_and_cursor_pages_rebuild_the_snapshot_sessions(self):
        """A14: the page reads control state and the event log by cursor; the reduced view equals the legacy snapshot."""
        from live_manager import engine_command, engine_cwd
        from protocol_adapters.events import EventLog
        result = subprocess.run(engine_command('protocol_adapters.live_capture') + ['--stdin', '--json', '--all-events', '--fingerprints'],
                                input=server.demo_bytes(), capture_output=True, timeout=10, cwd=engine_cwd())
        manager = LiveManager()
        manager.log = EventLog('cap-test')
        manager.capture_id = 'cap-test'
        manager.state = 'running'
        lease_before = manager.lease
        for line in result.stdout.splitlines():
            manager.ingest(json.loads(line))
        control = manager.state_view()
        self.assertEqual(set(control) - {'decryption_summary'}, {'state', 'interface', 'error', 'run_id', 'capture_id', 'lease_seconds_left',
                                                                  'summary', 'events_total', 'sessions_total', 'cursor'})
        for heavy in ('events', 'sessions', 'decryption'):
            self.assertNotIn(heavy, control)
        self.assertEqual(manager.lease, lease_before)                                  # reading state renews nothing
        self.assertEqual(control['summary']['counts']['packets'], 111)
        # cursor pages: every retained event exactly once, then nothing new on the same cursor
        cursor, seen = 0, []
        while True:
            page = manager.events_since(cursor, 50)
            seen.extend(e['sequence'] for e in page['events'])
            if not page['events']:
                break
            cursor = page['cursor']
        self.assertEqual(seen, sorted(set(seen)))
        self.assertFalse(page['reset_required'])
        self.assertEqual(manager.events_since(cursor, 50)['events'], [])
        # the reduced view names the same sessions as the legacy snapshot, with the summary
        snapshot = manager.snapshot()
        view = page['view']
        final = [v for v in view['sessions'] if v['status'] == 'final']
        self.assertEqual(len(final), len(snapshot['sessions']))
        self.assertEqual(sorted(v['session']['app'] for v in final), sorted(s['app'] for s in snapshot['sessions']))
        self.assertEqual(view['summary']['counts']['packets'], 111)
        # a cursor older than retention is a reset, never a window with a hole
        small = LiveManager()
        small.log = EventLog('cap-small', retention=5)
        small.capture_id = 'cap-small'
        for i in range(20):
            small.ingest({'type': 'classification', 'status': 'identified', 'app': 'x%d' % i})
        self.assertTrue(small.events_since(1, 50)['reset_required'])
        self.assertFalse(small.events_since(small.events_since(0, 50)['cursor'], 50)['reset_required'])

    def test_watchdog_cannot_stop_replacement_process(self):
        manager = LiveManager()
        with patch('live_manager.subprocess.Popen') as process:
            manager.process = process
            manager.stop(expected=object())
            process.send_signal.assert_not_called()
