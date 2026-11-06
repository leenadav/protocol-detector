"""Launch the local showcase; reuse only a matching instance, never stop another app."""
import json
from pathlib import Path
import subprocess
import sys
import time
from urllib.request import urlopen
import webbrowser

ROOT = Path(__file__).resolve().parent


def matching_server(url, expected):
    try:
        with urlopen(url + "/api/catalog", timeout=1) as response:
            catalog = json.load(response)
        return catalog.get("source", {}).get("build_digest") == expected
    except (OSError, ValueError):
        return False


def main():
    expected = json.loads((ROOT / "SOURCE.json").read_text())["build_digest"]   # whole build, not only the engine commit
    for port in range(8765, 8776):
        url = "http://127.0.0.1:{}".format(port)
        if matching_server(url, expected):
            print("Opening " + url)
            webbrowser.open(url)
            return
        process = subprocess.Popen([sys.executable, "-B", str(ROOT / "server.py"), "--port", str(port)])
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
