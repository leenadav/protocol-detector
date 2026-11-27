"""The launcher's service (PRO-402, 2026-11-25): the Go `protodetect serve`, always. There is no Python backend
to select and no fallback; without the binary the launcher refuses to start."""
import contextlib
import io
import json
import os
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path
import unittest.mock as mock
from urllib.request import Request, urlopen

import launch

GO_BINARY = Path(__file__).resolve().parents[2] / "go" / "bin" / "protodetect"


class ServerCommandTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("PROTODETECT_GO_BINARY", None)

    def test_the_service_is_the_go_binary(self):
        command = launch.server_command(8765, binary="/opt/protodetect")
        self.assertEqual(command, ["/opt/protodetect", "serve", "--port", "8765", "--root", str(launch.ROOT)])

    def test_no_python_backend_is_selectable(self):
        os.environ["PROTODETECT_BACKEND"] = "python"           # ignored: there is no backend to choose
        self.assertEqual(launch.server_command(8766, binary="/opt/protodetect")[:2], ["/opt/protodetect", "serve"])
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            launch.main(["--backend", "python"])             # the option itself is gone
        self.assertNotIn("server.py", " ".join(launch.server_command(8766, binary="/opt/protodetect")))

    def test_without_a_binary_it_refuses(self):
        with mock.patch.object(launch, "go_binary", return_value=None):
            with self.assertRaises(SystemExit) as refused:
                launch.server_command(8765)
            self.assertIn("not installed", str(refused.exception))
            with mock.patch.object(launch.subprocess, "Popen") as popen, self.assertRaises(SystemExit):
                launch.main([])
            popen.assert_not_called()

    def test_the_lookup(self):
        os.environ["PROTODETECT_GO_BINARY"] = sys.executable   # any executable file
        self.assertEqual(launch.go_binary(), sys.executable)
        os.environ["PROTODETECT_GO_BINARY"] = str(launch.ROOT / "SOURCE.json")   # not executable
        self.assertIsNone(launch.go_binary())

    def test_the_launcher_imports_no_engine(self):
        source = (launch.ROOT / "launch.py").read_text()
        for name in ("protocol_engine", "protocol_adapters", "server.py", "sys.executable"):
            self.assertNotIn(name, source)


class ReuseTests(unittest.TestCase):
    """SR-63: a running server is reused only when its catalog names this build's digest (PRO-403: the launcher's
    own rule, kept in Python with the launcher)."""

    def serve(self, body):
        import http.server
        import threading

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - the http.server hook name
                payload = body if self.path == "/api/catalog" else b"{}"
                self.send_response(200 if self.path == "/api/catalog" else 404)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return "http://127.0.0.1:{}".format(server.server_address[1])

    def test_a_running_server_is_reused_only_on_a_matching_build_digest(self):
        url = self.serve(json.dumps({"source": {"build_digest": "a" * 64}}).encode())
        self.assertTrue(launch.matching_server(url, "a" * 64))
        self.assertFalse(launch.matching_server(url, "b" * 64))
        self.assertFalse(launch.matching_server(url, None))
        self.assertFalse(launch.matching_server(self.serve(b"{}"), "a" * 64))
        self.assertFalse(launch.matching_server(self.serve(b"not json"), "a" * 64))
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            closed = probe.getsockname()[1]
        self.assertFalse(launch.matching_server("http://127.0.0.1:{}".format(closed), "a" * 64))


@unittest.skipUnless(GO_BINARY.is_file(), "the Go binary is not built (make go-build)")
class GoServiceTests(unittest.TestCase):
    def test_the_go_service_serves_the_build_the_launcher_expects(self):
        """The command the launcher starts answers on the port it was given, with this build's digest."""
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        process = subprocess.Popen(launch.server_command(port, binary=str(GO_BINARY)), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            self.assertIn("http://127.0.0.1:{}".format(port), process.stdout.readline().decode())
            url = "http://127.0.0.1:{}".format(port)
            expected = json.loads((launch.ROOT / "SOURCE.json").read_text())["build_digest"]
            for _ in range(100):
                if launch.matching_server(url, expected):
                    break
                time.sleep(0.1)
            self.assertTrue(launch.matching_server(url, expected))
            with urlopen(Request(url + "/api/health"), timeout=5) as response:
                self.assertEqual(json.load(response)["build_digest"], expected)
        finally:
            process.send_signal(2)
            process.wait(timeout=20)
        self.assertEqual(process.returncode, 0)


if __name__ == "__main__":
    unittest.main()
