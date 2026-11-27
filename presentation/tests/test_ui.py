"""Stage 6 (A14): frontend store unit tests (Node) and browser tests (Playwright) when the toolchain exists.

Both are skipped, with the reason printed, when Node or Playwright with a Chromium is not available; the
canonical CI job states which of them ran. They never reach the network: the page is served by the Go service
(`protodetect serve`) on 127.0.0.1 and every capture is the synthetic demonstration or a routed fixture. PRO-403:
the Python LocalServer and its browser test went with the Python reference.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent / 'ui'
GO_BINARY = Path(__file__).resolve().parents[2] / 'go' / 'bin' / 'protodetect'
NODE = shutil.which('node')


def playwright_available():
    if NODE is None:
        return False
    probe = subprocess.run([NODE, '-e', "require('playwright'); console.log('ok')"], capture_output=True, text=True, timeout=30)
    return probe.returncode == 0


class StoreUnitTests(unittest.TestCase):
    @unittest.skipIf(NODE is None, 'node is not installed')
    def test_store_reducer_and_selectors(self):
        result = subprocess.run([NODE, str(HERE / 'store.test.js')], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('store tests ok', result.stdout)


@unittest.skipUnless(GO_BINARY.is_file(), 'the Go binary is not built (make go-build)')
class GoServiceBrowserTests(unittest.TestCase):
    """PRO-402: the same dashboard suite against `protodetect serve` with the Python engine moved aside.

    The service runs from a directory that holds only the page (web/), SOURCE.json and a copy of the binary: no
    protocol_engine, protocol_adapters or server.py is reachable from it, so the demo capture, the catalog, the
    analysis and the decryption showcase all come from the Go binary.
    """

    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        root = Path(cls.folder.name) / 'presentation'
        root.mkdir()
        shutil.copytree(str(HERE.parents[1] / 'web'), str(root / 'web'))
        shutil.copy2(str(HERE.parents[1] / 'SOURCE.json'), str(root / 'SOURCE.json'))
        binary = Path(cls.folder.name) / 'protodetect'
        shutil.copy2(str(GO_BINARY), str(binary))
        env = {k: v for k, v in os.environ.items() if not k.startswith('PROTODETECT_')}
        cls.process = subprocess.Popen([str(binary), 'serve', '--port', '0', '--root', str(root)], cwd=cls.folder.name,
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
        line = cls.process.stdout.readline().decode()
        cls.port = int(line.rsplit(':', 1)[1]) if 'http://127.0.0.1:' in line else None

    @classmethod
    def tearDownClass(cls):
        cls.process.send_signal(2)
        cls.process.wait(timeout=20)
        cls.process.stdout.close()
        cls.folder.cleanup()

    @unittest.skipUnless(playwright_available(), 'Playwright for Node (with a Chromium) is not available')
    def test_dashboard_in_a_real_browser_on_the_go_service(self):
        self.assertIsNotNone(self.port, 'protodetect serve did not print its address')
        result = subprocess.run([NODE, str(HERE / 'browser.test.js'), str(self.port)], capture_output=True,
                                text=True, timeout=240, env=dict(os.environ), cwd=self.folder.name)
        sys.stdout.write(result.stdout)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('browser tests ok', result.stdout)


if __name__ == '__main__':
    unittest.main()
