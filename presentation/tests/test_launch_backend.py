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
from unittest import mock
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
