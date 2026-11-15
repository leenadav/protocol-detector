"""Build manifest for the whole product (stage 1b / A16): engine, adapters, presentation, schemas, tools.

Usage: python3 -B tools/build_manifest.py --write presentation/SOURCE.json
       python3 -B tools/build_manifest.py --check presentation/SOURCE.json

One manifest identifies every component with its version and the sha256 of every shipped file, so the
launcher and health endpoint can refuse a mismatched build (A16) and tests can prove the tree is the one
described. Captures, key material, caches and build output are never listed.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COMPONENTS = {
    "engine": ("protocol_engine", ("protocol_engine/**/*.py",)),
    "adapters": ("protocol_adapters", ("protocol_adapters/*.py", "packets.py", "link_packets.py", "capture_stream.py",
                                       "sessions.py", "analyze_pcap.py", "live_capture.py", "make_sample_pcap.py",
                                       "protocol_fixtures.py", "proxy_demo.py", "protodetect.py", "detectors.py")),
    "presentation": ("presentation", ("presentation/*.py", "presentation/poc_decryption/*.py", "presentation/web/*",
                                      "presentation/requirements-decryption.txt")),
    "schemas": ("schemas", ("schemas/*.json",)),
}
EXCLUDED_SUFFIXES = (".pcap", ".pcapng", ".pyc", ".log", ".keys", ".pem", ".key")


def version():
    text = (ROOT / "pyproject.toml").read_text()
    return re.search(r'^version\s*=\s*"([^"\n]+)"', text, re.MULTILINE).group(1)


def git(*args):
    try:
        return subprocess.run(["git", *args], cwd=str(ROOT), capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def build():
    files = []
    for name, (root, patterns) in COMPONENTS.items():
        for pattern in patterns:
            for path in sorted(ROOT.glob(pattern)):
                relative = path.relative_to(ROOT).as_posix()
                if path.is_file() and not relative.endswith(EXCLUDED_SUFFIXES) and "__pycache__" not in relative:
                    files.append({"path": relative, "component": name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    digest = hashlib.sha256("\n".join(entry["path"] + " " + entry["sha256"] for entry in files).encode()).hexdigest()
    return {"repository": "leenadav/protocol-detector", "version": version(), "commit": git("rev-parse", "HEAD"),
            "branch": git("rev-parse", "--abbrev-ref", "HEAD"), "build_digest": digest,
            "components": {name: {"root": root, "version": version(), "files": sum(1 for f in files if f["component"] == name)}
                           for name, (root, _) in COMPONENTS.items()},
            "files": files}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write", metavar="FILE")
    parser.add_argument("--check", metavar="FILE")
    args = parser.parse_args()
    manifest = build()
    if args.write:
        Path(args.write).write_text(json.dumps(manifest, indent=2) + "\n")
        print("manifest written: %d files, build digest %s" % (len(manifest["files"]), manifest["build_digest"][:16]))
    if args.check:
        stored = json.loads(Path(args.check).read_text())
        stale = [entry["path"] for entry in manifest["files"] if entry not in stored["files"]]
        extra = [entry["path"] for entry in stored["files"] if entry not in manifest["files"]]
        if stale or extra or stored.get("version") != manifest["version"]:
            print("manifest stale: %d changed/new, %d removed, version %s vs %s" % (len(stale), len(extra), stored.get("version"), manifest["version"]))
            for path in (stale + extra)[:20]:
                print("  " + path)
            sys.exit(1)
        print("manifest ok: %d files, build digest %s" % (len(manifest["files"]), manifest["build_digest"][:16]))
    if not args.write and not args.check:
        print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
