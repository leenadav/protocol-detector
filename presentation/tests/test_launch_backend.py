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


class FakeService:
    """A local stand-in answering /api/catalog and /api/health like server.py (python: a version) or Go (null)."""

    def __init__(self, digest, python):
        import http.server
        import threading
        bodies = {"/api/catalog": {"source": {"build_digest": digest}}, "/api/health": {"build_digest": digest, "python": python}}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = json.dumps(bodies.get(self.path, {})).encode()
                self.send_response(200 if self.path in bodies else 404)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *arguments):
                pass

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.url = "http://127.0.0.1:{}".format(self.httpd.server_address[1])
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class GoOnlyReuseTests(unittest.TestCase):
    """PRO-192: the launcher never reuses a running Python reference server of the same build as the Go service."""

    def serve(self, python):
        service = FakeService("digest-1", python)
        self.addCleanup(service.close)
        return service.url

    def test_health_tells_the_services_apart(self):
        self.assertEqual(launch.server_backend(self.serve(None)), "go")
        self.assertEqual(launch.server_backend(self.serve("3.9.18")), "python")
        self.assertIsNone(launch.server_backend(self.serve(7)))
        self.assertIsNone(launch.server_backend("http://127.0.0.1:9"))

    def test_only_the_go_service_of_this_build_matches(self):
        python, go = self.serve("3.9.18"), self.serve(None)
        self.assertTrue(launch.same_build(python, "digest-1"))
        self.assertFalse(launch.matching_server(python, "digest-1"))
        self.assertTrue(launch.matching_server(go, "digest-1"))
        self.assertFalse(launch.matching_server(go, "digest-2"))

    def run_main(self, running, environment=None):
        """main() with port 8765 held by `running` ("go", "python" or None for unknown; this build) and every
        other port free; a service the launcher starts is the Go service."""
        expected = json.loads((launch.ROOT / "SOURCE.json").read_text())["build_digest"]
        first = "http://127.0.0.1:8765"
        started, opened = [], []

        class Started:
            def __init__(self, command):
                started.append(list(command))

            def poll(self):
                return None

            def wait(self, timeout=None):
                return 0

        def same_build(url, digest):
            self.assertEqual(digest, expected)
            return url == first or bool(started)

        def server_backend(url):
            return running if url == first else "go"

        printed = []
        with mock.patch.dict(os.environ, environment or {}), mock.patch.object(launch, "same_build", same_build), \
                mock.patch.object(launch, "server_backend", server_backend), \
                mock.patch.object(launch.subprocess, "Popen", Started), \
                mock.patch.object(launch, "go_binary", return_value="/opt/protodetect"), \
                mock.patch.object(launch.webbrowser, "open", opened.append), \
                mock.patch("builtins.print", lambda *a, **k: printed.append(" ".join(map(str, a)))):
            launch.main([])
        return started, opened, printed

    def test_a_running_python_server_of_this_build_is_skipped(self):
        started, opened, printed = self.run_main("python")
        self.assertEqual([command[3] for command in started], ["8766"])
        self.assertEqual(opened, ["http://127.0.0.1:8766"])
        self.assertTrue(any("Skipping http://127.0.0.1:8765" in line and "Go service" in line for line in printed))
        self.assertFalse(any(line.startswith("Opening") for line in printed))

    def test_the_environment_variable_does_not_bring_python_back(self):
        started, opened, _ = self.run_main("python", {"PROTODETECT_BACKEND": "python"})
        self.assertEqual([command[3] for command in started], ["8766"])
        self.assertEqual(opened, ["http://127.0.0.1:8766"])

    def test_a_service_of_unknown_kind_is_skipped(self):
        started, opened, _ = self.run_main(None)
        self.assertEqual([command[3] for command in started], ["8766"])

    def test_a_running_go_service_is_opened(self):
        started, opened, printed = self.run_main("go")
        self.assertEqual((started, opened), ([], ["http://127.0.0.1:8765"]))
        self.assertIn("Opening http://127.0.0.1:8765", printed)


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
