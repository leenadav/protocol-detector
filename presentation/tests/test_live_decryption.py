import os
import tempfile
import unittest
import server  # noqa: F401 - registers the engine root for a checkout; see protocol_adapters
from poc_decryption.demo import fixture
from poc_decryption.live import KeyLog, LiveDecoder, LIMIT
from live_manager import LiveManager


class LiveDecryptionTests(unittest.TestCase):
    def test_fragmented_pipe_and_delayed_keys(self):
        capture, keys, _, _ = fixture()
        decoder = LiveDecoder()
        for offset in range(0, len(capture), 37):
            decoder.feed(capture[offset:offset+37], now=1.0)
        decoder.advance('')
        self.assertEqual(decoder.snapshot()['decrypted'], 0)
        self.assertEqual(decoder.snapshot()['connections'][0]['status'], 'awaiting_keys')
        decoder.advance(keys)                                  # late keys wake only the waiting connection
        self.assertEqual(decoder.snapshot()['connections'][0]['application'], 'webdav')
        self.assertEqual(decoder.snapshot()['decrypted'], 1)
        decoder.decoder.end()

    def test_incomplete_pipe_frame_not_interpreted(self):
        capture, keys, _, _ = fixture()
        decoder = LiveDecoder()
        decoder.feed(capture[:31], now=1.0)
        self.assertEqual(decoder.snapshot()['frames'], 0)
        decoder.feed(capture[31:], now=1.0)
        decoder.advance(keys)
        self.assertEqual(decoder.snapshot()['decrypted'], 1)

    def test_status_reads_do_no_work_and_new_records_are_decrypted_once(self):
        """Stage 4 (A02): unchanged input + repeated snapshots = zero additional authentication."""
        capture, keys, _, _ = fixture()
        decoder = LiveDecoder()
        decoder.feed(capture, now=1.0)
        decoder.advance(keys)
        authenticated = decoder.decryptor.counts['records_authenticated']
        self.assertGreater(authenticated, 2)
        for _ in range(5):
            decoder.snapshot()
            decoder.advance(keys)                              # same key text again: nothing new to index
        self.assertEqual(decoder.decryptor.counts['records_authenticated'], authenticated)
        self.assertEqual(decoder.keys.version, 1)

    def test_key_log_growth_partial_lines_truncation_rotation_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'keys')
            with open(path, 'w') as f:
                f.write('# initial\npartial')
            reader = KeyLog(path)
            try:
                self.assertEqual(reader.read(), '# initial\n')             # the partial line waits
                self.assertEqual(reader.read(), '')                        # nothing new: nothing re-read
                with open(path, 'a') as f:
                    f.write(' line\n')
                self.assertEqual(reader.read(), 'partial line\n')         # append-only: new bytes only
                with open(path, 'a') as f:
                    f.write('x'*262145)
                with self.assertRaises(ValueError): reader.read()
            finally: reader.close()
            with open(path, 'w') as f:
                f.write('A B C\nD E F\n')
            reader = KeyLog(path)
            try:
                self.assertEqual(reader.read(), 'A B C\nD E F\n')
                with open(path, 'w') as f:
                    f.write('short\n')                                     # truncated in place
                with self.assertRaisesRegex(ValueError, 'truncated'): reader.read()
            finally: reader.close()
            reader = KeyLog(path)
            try:
                reader.read()
                os.replace(path + '.new', path) if os.path.exists(path + '.new') else None
                with open(path + '.new', 'w') as f:
                    f.write('rotated\n')
                os.replace(path + '.new', path)                            # rotation: a different inode
                with self.assertRaisesRegex(ValueError, 'rotated'): reader.read()
            finally: reader.close()
            os.symlink(path, path+'link')
            with self.assertRaises(OSError): KeyLog(path+'link')

    def test_budget_and_revocation(self):
        decoder = LiveDecoder()
        decoder.consumed = LIMIT
        with self.assertRaises(ValueError): decoder.feed(b'x')
        manager = LiveManager()
        manager.ingest({'type':'decryption','report':{'connections':[{'application':'webdav'}]}})
        manager.ingest({'type':'decryption','report':{'connections':[]}})
        self.assertEqual(manager.snapshot()['decryption']['report']['connections'], [])


class LiveShutdownWiringTests(unittest.TestCase):
    """Exercises poc_decryption.live.main() end to end: the real selector loop, tick, SIGINT handling and
    final snapshot, with a synthetic capture source standing in for tcpdump (no interface, no network).

    Stage 1c regression for review finding A04: the decryption live path never calls analyzer.expire or
    analyzer.finish, so a connection that never sends FIN gets no final session when the run stops. The
    component-level reproduction is in tools/stage0_baseline.py; this one goes through the actual wiring.
    Stage 3 made the decryption path drive the shared SessionCoordinator (tick each second, end at stop), so the
    no-FIN test below is a plain passing regression now; it was an expectedFailure from stage 1c until then.
    """

    def run_live(self, capture, keylog, duration=1):
        import io, json, sys
        from contextlib import redirect_stdout
        from unittest.mock import patch
        from poc_decryption import live as live_module
        emitted = []
        with tempfile.TemporaryDirectory() as directory:
            pcap_path = os.path.join(directory, 'synthetic.pcap')
            key_path = os.path.join(directory, 'keys.log')
            with open(pcap_path, 'wb') as handle:
                handle.write(capture)
            with open(key_path, 'w') as handle:
                handle.write(keylog)
            # The stand-in "tcpdump": writes the synthetic capture to stdout, then, like tcpdump, waits for
            # SIGINT, prints its statistics on stderr and exits 0. main() sends that SIGINT when its own
            # duration elapses, so the real stop path (signal, stats, final snapshot) is what runs.
            fake = [sys.executable, '-c',
                    'import signal,sys,time\n'
                    'def done(*_):\n'
                    '    sys.stderr.write("3 packets captured\\n0 packets dropped by kernel\\n"); sys.stderr.flush(); sys.exit(0)\n'
                    'signal.signal(signal.SIGINT, done)\n'
                    'sys.stdout.buffer.write(open(sys.argv[1],"rb").read()); sys.stdout.flush()\n'
                    'time.sleep(30)', pcap_path]
            with patch.object(live_module, 'capture_command', lambda interface, bpf: fake), \
                    patch.object(live_module, 'emit', emitted.append), \
                    patch.object(sys, 'argv', ['live.py', '--interface', 'lo', '--filter', 'tcp', '--duration', str(duration)]), \
                    patch.object(sys, 'stdin', io.StringIO(json.dumps({'keylog_path': key_path}) + '\n')), \
                    redirect_stdout(io.StringIO()):
                code = live_module.main()
        return code, emitted

    def test_run_ends_cleanly_and_emits_final_decryption_report(self):
        import json, sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
        import schema_check
        capture, keylog, _, _ = fixture()
        code, emitted = self.run_live(capture, keylog)
        self.assertEqual(code, 0, [e for e in emitted if e.get('type') == 'error'])
        final = [e for e in emitted if e.get('type') == 'decryption' and e.get('provisional') is False]
        self.assertEqual(len(final), 1)
        self.assertEqual(final[0]['report']['decrypted'], 1)
        self.assertEqual(final[0]['report']['connections'][0]['application'], 'webdav')
        self.assertTrue(any(e.get('type') == 'summary' for e in emitted))
        schema = schema_check.load('live-event')
        for event in emitted:                                   # stage 4: decryption events conform too
            self.assertEqual(schema_check.validate(json.loads(json.dumps(event)), schema), [], event.get('type'))
        encoded = json.dumps(emitted)
        for forbidden in ('/documents', 'demo.invalid', keylog.splitlines()[-1].split()[-1]):
            self.assertNotIn(forbidden, encoded)

    def test_no_fin_connection_gets_a_final_session_at_stop(self):
        from protocol_adapters.make_sample_pcap import frame, pcap_bytes
        client, peer = ('192.0.2.10', 52000), ('198.51.100.20', 80)
        request = b'GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n'
        capture = pcap_bytes([frame(client, peer, 999, 0, 2), frame(peer, client, 4999, 1000, 18),
                              frame(client, peer, 1000, 5000, 24, request)])   # no FIN ever
        code, emitted = self.run_live(capture, '')
        self.assertEqual(code, 0)
        sessions = [e for e in emitted if 'app' in e and e.get('type') not in ('classification', 'summary', 'decryption')]
        self.assertEqual(len(sessions), 1, 'the run stopped but the un-finished connection was never finalized (A04)')
