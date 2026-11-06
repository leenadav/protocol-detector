"""Stage 6 (A14): frontend store unit tests (Node) and browser tests (Playwright) when the toolchain exists.

Both are skipped, with the reason printed, when Node or Playwright with a Chromium is not available; the
canonical CI job states which of them ran. They never reach the network: the page is served by a LocalServer
on 127.0.0.1 and every capture is the synthetic demonstration or a routed fixture.
"""
import os
import shutil
import subprocess
import sys
import threading
import unittest
from pathlib import Path

import server

HERE = Path(__file__).resolve().parent / 'ui'
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


class BrowserTests(unittest.TestCase):
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

    @unittest.skipUnless(playwright_available(), 'Playwright for Node (with a Chromium) is not available')
    def test_dashboard_in_a_real_browser(self):
        env = dict(os.environ)
        result = subprocess.run([NODE, str(HERE / 'browser.test.js'), str(self.httpd.server_port)], capture_output=True,
                                text=True, timeout=240, env=env)
        sys.stdout.write(result.stdout)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('browser tests ok', result.stdout)


if __name__ == '__main__':
    unittest.main()
