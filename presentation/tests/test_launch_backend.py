"""The launcher's choice of service (migration M8, 2026-11-17): the Go `protodetect serve` when its binary is
installed, the Python server.py on request (`--backend python`, PROTODETECT_BACKEND=python) or without a binary;
`--backend go` never falls back."""
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
        os.environ.pop("PROTODETECT_BACKEND", None)

    def test_go_is_the_default_when_installed(self):
        command = launch.server_command(8765, binary="/opt/protodetect")
        self.assertEqual(command, ["/opt/protodetect", "serve", "--port", "8765", "--root", str(launch.ROOT), "--python", sys.executable])

    def test_python_on_request(self):
        python = [sys.executable, "-B", str(launch.ROOT / "server.py"), "--port", "8766"]
        self.assertEqual(launch.server_command(8766, "python", binary="/opt/protodetect"), python)
        os.environ["PROTODETECT_BACKEND"] = "python"
        self.assertEqual(launch.server_command(8766, binary="/opt/protodetect"), python)

    def test_flag_wins_over_the_environment(self):
        os.environ["PROTODETECT_BACKEND"] = "python"
        self.assertEqual(launch.server_command(8765, "go", binary="/opt/protodetect")[:2], ["/opt/protodetect", "serve"])

    def test_without_a_binary(self):
        with mock.patch.object(launch, "go_binary", return_value=None):
            self.assertEqual(launch.server_command(8765)[-3:], [str(launch.ROOT / "server.py"), "--port", "8765"])
            with self.assertRaises(SystemExit) as refused:
                launch.server_command(8765, "go")
            self.assertIn("not installed", str(refused.exception))

    def test_unknown_backend(self):
        os.environ["PROTODETECT_BACKEND"] = "rust"
        with self.assertRaises(SystemExit):
            launch.server_command(8765, binary="/opt/protodetect")

    def test_the_lookup_is_the_adapters(self):
        os.environ["PROTODETECT_GO_BINARY"] = sys.executable   # any executable file
        self.assertEqual(launch.go_binary(), sys.executable)


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


class ExplicitBackendReuseTests(unittest.TestCase):
    """PRO-192: an explicit backend never reuses a running instance of the other service with the same build."""

    def serve(self, python):
        service = FakeService("digest-1", python)
        self.addCleanup(service.close)
        return service.url

    def test_health_tells_the_services_apart(self):
        self.assertEqual(launch.server_backend(self.serve(None)), "go")
        self.assertEqual(launch.server_backend(self.serve("3.9.18")), "python")
        self.assertIsNone(launch.server_backend(self.serve(7)))
        self.assertIsNone(launch.server_backend("http://127.0.0.1:9"))

    def test_an_explicit_backend_matches_only_its_own_service(self):
        python, go = self.serve("3.9.18"), self.serve(None)
        self.assertFalse(launch.matching_server(python, "digest-1", "go"))
        self.assertTrue(launch.matching_server(go, "digest-1", "go"))
        self.assertFalse(launch.matching_server(go, "digest-1", "python"))
        self.assertTrue(launch.matching_server(python, "digest-1", "python"))
        self.assertFalse(launch.matching_server(go, "digest-2", "go"))

    def test_without_an_explicit_backend_the_same_build_is_reused(self):
        self.assertTrue(launch.matching_server(self.serve("3.9.18"), "digest-1"))
        self.assertTrue(launch.matching_server(self.serve(None), "digest-1"))

    def run_main(self, argv, running, environment=None, fresh="go"):
        """main() with port 8765 held by `running` ("go" or "python", this build) and every other port free;
        a service the launcher starts reports `fresh`."""
        expected = json.loads((launch.ROOT / "SOURCE.json").read_text())["build_digest"]
        first = "http://127.0.0.1:8765"
        started, opened = [], []

        class Started:
            def __init__(self, command):
                started.append(command)

            def poll(self):
                return None

            def wait(self, timeout=None):
                return 0

        def same_build(url, digest):
            self.assertEqual(digest, expected)
            return url == first or (url != first and bool(started))

        def server_backend(url):
            return running if url == first else fresh

        printed = []
        with mock.patch.dict(os.environ, environment or {}), mock.patch.object(launch, "same_build", same_build), \
                mock.patch.object(launch, "server_backend", server_backend), \
                mock.patch.object(launch.subprocess, "Popen", Started), \
                mock.patch.object(launch, "server_command", lambda port, backend=None: ["serve", str(port), backend]), \
                mock.patch.object(launch.webbrowser, "open", opened.append), \
                mock.patch("builtins.print", lambda *a, **k: printed.append(" ".join(map(str, a)))):
            launch.main(argv)
        return started, opened, printed

    def setUp(self):
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("PROTODETECT_BACKEND", None)

    def test_backend_go_skips_a_running_python_service(self):
        started, opened, printed = self.run_main(["--backend", "go"], "python")
        self.assertEqual(started, [["serve", "8766", "go"]])
        self.assertEqual(opened, ["http://127.0.0.1:8766"])
        self.assertTrue(any("Skipping http://127.0.0.1:8765" in line and "go backend" in line for line in printed))
        self.assertFalse(any(line.startswith("Opening") for line in printed))

    def test_the_environment_variable_is_an_explicit_backend_too(self):
        started, opened, _ = self.run_main([], "python", {"PROTODETECT_BACKEND": "go"})
        self.assertEqual(started, [["serve", "8766", None]])
        self.assertEqual(opened, ["http://127.0.0.1:8766"])

    def test_backend_python_skips_a_running_go_service(self):
        started, opened, _ = self.run_main(["--backend", "python"], "go", fresh="python")
        self.assertEqual([command[1] for command in started], ["8766"])
        self.assertEqual(opened, ["http://127.0.0.1:8766"])

    def test_a_matching_service_is_opened(self):
        started, opened, printed = self.run_main(["--backend", "go"], "go")
        self.assertEqual((started, opened), ([], ["http://127.0.0.1:8765"]))
        self.assertIn("Opening http://127.0.0.1:8765", printed)

    def test_without_an_explicit_backend_any_service_of_this_build_is_opened(self):
        started, opened, _ = self.run_main([], "python")
        self.assertEqual((started, opened), ([], ["http://127.0.0.1:8765"]))


@unittest.skipUnless(GO_BINARY.is_file(), "the Go binary is not built (make go-build)")
class GoServiceTests(unittest.TestCase):
    def test_the_go_service_serves_the_build_the_launcher_expects(self):
        """The command the launcher starts answers on the port it was given, with this build's digest."""
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        process = subprocess.Popen(launch.server_command(port, "go", binary=str(GO_BINARY)), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
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
