import os
import tempfile
import unittest
import server
from poc_decryption.demo import fixture
from poc_decryption.live import KeyLog, LiveDecoder, LIMIT
from live_manager import LiveManager


class LiveDecryptionTests(unittest.TestCase):
    def test_fragmented_pipe_and_delayed_keys(self):
        capture, keys, _, _ = fixture()
        decoder = LiveDecoder()
        for offset in range(0, len(capture), 37):
            decoder.feed(capture[offset:offset+37])
        self.assertEqual(decoder.snapshot('')['decrypted'], 0)
        self.assertEqual(decoder.snapshot(keys)['connections'][0]['application'], 'webdav')
        decoder.decoder.end()

    def test_incomplete_pipe_frame_not_interpreted(self):
        capture, keys, _, _ = fixture()
        decoder = LiveDecoder()
        decoder.feed(capture[:31])
        self.assertEqual(decoder.snapshot(keys)['frames'], 0)
        decoder.feed(capture[31:])
        self.assertEqual(decoder.snapshot(keys)['decrypted'], 1)

    def test_key_log_growth_partial_lines_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'keys')
            with open(path, 'w') as f:
                f.write('# initial\npartial')
            reader = KeyLog(path)
            try:
                self.assertEqual(reader.read(), '# initial\n')
                with open(path, 'a') as f:
                    f.write(' line\n')
                self.assertEqual(reader.read(), '# initial\npartial line\n')
                with open(path, 'a') as f:
                    f.write('x'*262145)
                with self.assertRaises(ValueError): reader.read()
            finally: reader.close()
            os.symlink(path, path+'link')
            with self.assertRaises(OSError): KeyLog(path+'link')

    def test_budget_and_revocation(self):
        decoder = LiveDecoder()
        decoder.data = bytearray(LIMIT)
        with self.assertRaises(ValueError): decoder.feed(b'x')
        manager = LiveManager()
        manager.ingest({'type':'decryption','report':{'connections':[{'application':'webdav'}]}})
        manager.ingest({'type':'decryption','report':{'connections':[]}})
        self.assertEqual(manager.snapshot()['decryption']['report']['connections'], [])
