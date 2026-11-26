"""Launch the local showcase; reuse only a matching instance, never stop another app.

The service is the Go engine's `protodetect serve` when its binary is installed (migration M8, Lee's decision of
2026-11-17), the Python server.py otherwise. The Python server stays available on request: `--backend python`
or PROTODETECT_BACKEND=python. `--backend go` (or PROTODETECT_BACKEND=go) refuses to start without the binary
instead of falling back, and a running instance of the other service is never reused for an explicit backend:
/api/health tells them apart (`python` is the interpreter version in server.py, null in the Go service). The binary is found as everywhere else: PROTODETECT_GO_BINARY, then go/bin/protodetect
of a source checkout, then `protodetect-go` on PATH.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.request import urlopen
import webbrowser

ROOT = Path(__file__).resolve().parent
BACKENDS = ("go", "python")


def go_binary():
    """The Go engine's binary, or None (the adapters' own lookup; None when they cannot be imported)."""
    if str(ROOT.parent) not in sys.path:
        sys.path.insert(0, str(ROOT.parent))       # an unpacked checkout, as server.py does
    try:
        from protocol_adapters.analyze_pcap import go_binary as lookup
    except ImportError:
        return None
    return lookup()


def server_command(port, backend=None, binary=None):
    """argv of the service on `port`: Go unless the Python server was requested or no binary is installed."""
    requested = backend or os.environ.get("PROTODETECT_BACKEND") or None
    if requested is not None and requested not in BACKENDS:
        raise SystemExit("Unknown backend {!r}; use go or python".format(requested))
    if requested != "python":
        binary = binary or go_binary()
        if binary is not None:
            return [binary, "serve", "--port", str(port), "--root", str(ROOT), "--python", sys.executable]
        if requested == "go":
            raise SystemExit("The Go backend binary is not installed (make go-build, or set PROTODETECT_GO_BINARY).")
    return [sys.executable, "-B", str(ROOT / "server.py"), "--port", str(port)]


def requested_backend(backend=None):
    """The backend asked for by `--backend` or PROTODETECT_BACKEND, or None when the choice is left to the launcher."""
    return backend or os.environ.get("PROTODETECT_BACKEND") or None


def server_backend(url):
    """The backend of the service at `url` from its /api/health, or None when it cannot tell."""
    try:
        with urlopen(url + "/api/health", timeout=1) as response:
            health = json.load(response)
    except (OSError, ValueError):
        return None
    if not isinstance(health, dict) or "python" not in health:
        return None
    if health["python"] is None:
        return "go"                                   # go/internal/serve: the service runs no interpreter of its own
    return "python" if isinstance(health["python"], str) else None


def same_build(url, expected):
    try:
        with urlopen(url + "/api/catalog", timeout=1) as response:
            catalog = json.load(response)
        return catalog.get("source", {}).get("build_digest") == expected
    except (OSError, ValueError, AttributeError):
        return False


def matching_server(url, expected, backend=None):
    """The service at `url` serves this build and, when a backend was requested, is that backend."""
    return same_build(url, expected) and (backend is None or server_backend(url) == backend)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--backend", choices=BACKENDS, help="the service: go (default when installed) or python")
    args = parser.parse_args(argv)
    expected = json.loads((ROOT / "SOURCE.json").read_text())["build_digest"]   # whole build, not only the engine commit
    backend = requested_backend(args.backend)
    if backend is not None and backend not in BACKENDS:
        raise SystemExit("Unknown backend {!r}; use go or python".format(backend))
    for port in range(8765, 8776):
        url = "http://127.0.0.1:{}".format(port)
        if same_build(url, expected):
            if matching_server(url, expected, backend):
                print("Opening " + url)
                webbrowser.open(url)
                return
            print("Skipping {}: it is not the {} backend that was requested.".format(url, backend))
            continue                                  # the port is taken: never reuse or stop the other service
        process = subprocess.Popen(server_command(port, args.backend))
        for _ in range(30):
            if process.poll() is not None:
                break
            if matching_server(url, expected, backend):
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
