"""The Makefile gates never mask a failure (Codex checkpoint finding on stage 6).

`presentation-check` must propagate the presentation suite's exit status when the dependency is present and
skip, with a message, only when it is absent; `presentation-test` must accept an interpreter path relative to
the repository root although it changes into presentation/.
"""
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MAKE = shutil.which("make")


def shim(directory, name, body):
    path = Path(directory) / name
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def run(args, env=None):
    return subprocess.run([MAKE, "--no-print-directory"] + args, cwd=str(ROOT), capture_output=True, text=True, timeout=120,
                          env=dict(os.environ, **(env or {})))


@unittest.skipIf(MAKE is None, "make is not installed")
class PresentationGateTests(unittest.TestCase):
    def test_failing_suite_fails_the_check_and_missing_dependency_skips(self):
        with tempfile.TemporaryDirectory(dir=str(ROOT)) as directory:
            relative = os.path.relpath(directory, ROOT)
            # An interpreter that has the dependency and whose test run fails.
            shim(directory, "py-fail", 'case "$*" in *"import cryptography"*) exit 0;; esac\necho "suite ran in $(pwd)"; exit 7\n')
            result = run(["presentation-check", "PYTHON=%s/py-fail" % relative])
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("suite ran in", result.stdout)
            self.assertNotIn("skipped", result.stdout)
            # A submake that cannot run (the Codex reproduction): still a failure, never "skipped".
            result = run(["presentation-check", "PYTHON=%s/py-fail" % relative, "MAKE=false"])
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn("skipped", result.stdout)
            # Without the dependency the check skips, says so, and exits 0.
            shim(directory, "py-none", 'case "$*" in *"import cryptography"*) exit 1;; esac\nexit 0\n')
            result = run(["presentation-check", "PYTHON=%s/py-none" % relative])
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("skipped", result.stdout)

    def test_relative_interpreter_path_survives_the_directory_change(self):
        with tempfile.TemporaryDirectory(dir=str(ROOT)) as directory:
            relative = os.path.relpath(directory, ROOT)
            shim(directory, "python", 'echo "argv=$* cwd=$(pwd)"; exit 0\n')
            result = run(["presentation-test", "PYTHON=%s/python" % relative])
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("-m unittest discover -s tests -v", result.stdout)
            self.assertTrue(result.stdout.strip().endswith("cwd=" + str(ROOT / "presentation")), result.stdout)


if __name__ == "__main__":
    unittest.main()
