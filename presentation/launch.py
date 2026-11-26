"""Launch the local showcase; reuse only a matching instance, never stop another app.

The service is the Go engine's `protodetect serve` (PRO-402, Lee's decision of 2026-11-25: Go is the product).
There is no Python backend to select and no fallback: without the binary the launcher refuses to start and says
how to build it. The binary is found as everywhere else: PROTODETECT_GO_BINARY, then go/bin/protodetect of a
source checkout (`make go-build`), then `protodetect-go` on PATH.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
from urllib.request import urlopen
import webbrowser

ROOT = Path(__file__).resolve().parent
MISSING = "The Go engine binary is not installed (make go-build, or set PROTODETECT_GO_BINARY)."


def go_binary():
    """The Go engine's binary, or None: PROTODETECT_GO_BINARY, then go/bin/protodetect, then protodetect-go."""
    named = os.environ.get("PROTODETECT_GO_BINARY")
    if named:
        return named if os.path.isfile(named) and os.access(named, os.X_OK) else None
    built = ROOT.parent / "go" / "bin" / "protodetect"
    if built.is_file() and os.access(str(built), os.X_OK):
        return str(built)
    return shutil.which("protodetect-go")


def server_command(port, binary=None):
    """argv of the service on `port`: the Go binary serving this presentation directory."""
    binary = binary or go_binary()
    if binary is None:
        raise SystemExit(MISSING)
    return [binary, "serve", "--port", str(port), "--root", str(ROOT)]


def matching_server(url, expected):
    try:
        with urlopen(url + "/api/catalog", timeout=1) as response:
            catalog = json.load(response)
        return catalog.get("source", {}).get("build_digest") == expected
    except (OSError, ValueError):
        return False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.parse_args(argv)
    expected = json.loads((ROOT / "SOURCE.json").read_text())["build_digest"]   # whole build, not only the engine commit
    command = server_command(0)              # refuse early, before probing ports, when the binary is missing
    for port in range(8765, 8776):
        url = "http://127.0.0.1:{}".format(port)
        if matching_server(url, expected):
            print("Opening " + url)
            webbrowser.open(url)
            return
        command[3] = str(port)
        process = subprocess.Popen(command)
        for _ in range(30):
            if process.poll() is not None:
                break
            if matching_server(url, expected):
                print("\nProtocol Observatory is ready: " + url)
                print("Keep this Terminal window open while presenting. Press Ctrl+C to stop.\n")
                webbrowser.open(url)
                try:
                    process.wait()
                except KeyboardInterrupt:
                    process.terminate()
                    process.wait(timeout=5)
                return
            time.sleep(0.1)
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
    raise SystemExit("Could not start on ports 8765–8775. Close another demo instance and try again.")


if __name__ == "__main__":
    main()
