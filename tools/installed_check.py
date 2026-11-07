"""Installed-artifact check (stage 8, A16; A01): build the wheel, install it into an empty environment with
the decryption extra from the hash-pinned lock, run the presentation suite against the installed engine, and
start the installed application itself (`python -m protocol_observatory.server`) from a directory with no
checkout to prove replay, the frontend and decryption all come from the one artifact.

The presentation directory is copied to a temporary location whose parent holds no checkout, so `server.py`'s
root registration finds nothing and every `protocol_engine`/`protocol_adapters` import must come from the
installed wheel. Network: the wheel comes from the local build; cryptography is installed from the index
with `--require-hashes` from presentation/requirements-decryption.lock.txt (skip with --no-extra to run the
engine-only part offline).
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(command, **kwargs):
    print("$ " + " ".join(str(c) for c in command), flush=True)
    return subprocess.run(command, check=True, **kwargs)  # noqa: S603 - fixed argv built here


def product_check(python, env_dir, work):
    import http.client
    import json
    import socket
    import time
    probe = ("import protocol_observatory, protocol_observatory.server as s; from pathlib import Path;"
             "assert 'site-packages' in protocol_observatory.__file__, protocol_observatory.__file__;"
             "assert (Path(s.__file__).parent / 'web' / 'index.html').is_file(); print('installed application ok:', protocol_observatory.__file__)")
    run([str(python), "-I", "-c", probe], cwd=str(work))
    scripts = env_dir / ("Scripts" if os.name == "nt" else "bin")
    launcher = scripts / ("protocol-observatory.exe" if os.name == "nt" else "protocol-observatory")
    if not launcher.exists():
        raise SystemExit("console script protocol-observatory was not installed")
    with socket.socket() as probe_socket:
        probe_socket.bind(("127.0.0.1", 0))
        port = probe_socket.getsockname()[1]
    empty = work / "empty"
    empty.mkdir(exist_ok=True)
    server = subprocess.Popen([str(python), "-I", "-m", "protocol_observatory.server", "--port", str(port)],  # noqa: S603
                              cwd=str(empty), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def request(method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()
    try:
        deadline = time.time() + 30
        while True:
            try:
                status, body = request("GET", "/api/health")
                if status == 200:
                    break
            except OSError:
                pass
            if server.poll() is not None or time.time() > deadline:
                raise SystemExit("installed server did not come up: " + (server.stdout.read() if server.stdout else ""))
            time.sleep(0.2)
        health = json.loads(body)
        status, page = request("GET", "/")
        assert status == 200 and b"Protocol Observatory" in page, "frontend not served from the installed package"
        catalog = json.loads(request("GET", "/api/catalog")[1])
        assert catalog["source"]["build_digest"] == health["build_digest"], "catalog and health disagree on the build"
        token = json.loads(request("GET", "/api/live/interfaces")[1])["token"]
        job = json.loads(request("POST", "/api/jobs?kind=demo", headers={"X-Live-Token": token})[1])
        for _ in range(300):
            job = json.loads(request("GET", "/api/jobs/" + job["id"])[1])
            if job["state"] not in ("queued", "running"):
                break
            time.sleep(0.2)
        assert job["state"] == "done" and len(job["result"]["sessions"]) == 18, "demo replay from the installed artifact: " + json.dumps(job)[:300]
        decrypt = json.loads(request("POST", "/api/decrypt/demo", headers={"X-Live-Token": token})[1])
        decrypted = decrypt.get("decrypted", (decrypt.get("report") or {}).get("decrypted", 0))
        assert decrypted >= 1 and "error" not in decrypt, "decryption demo from the installed artifact: " + json.dumps(decrypt)[:300]
        print("installed product ok: server, frontend, demo replay (18 sessions) and decryption demo ({} decrypted) from the wheel; launcher {}".format(
            decrypted, launcher.name))
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--no-extra", action="store_true", help="engine-only: no cryptography, presentation suite skipped")
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp)
        dist = work / "dist"
        run([args.python, "-m", "build", "--wheel", "--outdir", str(dist), str(ROOT)], stdout=subprocess.DEVNULL)
        wheel = next(dist.glob("*.whl"))
        run([args.python, "-B", str(ROOT / "tools/check_wheel.py"), str(wheel)])
        env_dir = work / "venv"
        venv.EnvBuilder(with_pip=True, clear=True).create(str(env_dir))
        python = env_dir / ("Scripts" if os.name == "nt" else "bin") / "python"
        run([str(python), "-m", "pip", "install", "--quiet", "--no-index", "--find-links", str(dist), "protocol-stream-engine"])
        if not args.no_extra:
            run([str(python), "-m", "pip", "install", "--quiet", "--require-hashes", "-r", str(ROOT / "presentation/requirements-decryption.lock.txt")])
        # 1. Engine from the wheel classifies a synthetic capture with no checkout on the path.
        probe = ("import sys, protocol_engine, protocol_adapters; from protocol_adapters.make_sample_pcap import pcap_bytes, sample_frames;"
                 "from protocol_adapters.analyze_pcap import Analyzer; from protocol_adapters.capture_stream import PcapStreamDecoder;"
                 "from protocol_adapters.link_packets import decode_frame;"
                 "assert 'site-packages' in protocol_engine.__file__ and 'site-packages' in protocol_adapters.__file__, protocol_engine.__file__;"
                 "out=[]; a=Analyzer(on_session=out.append); d=PcapStreamDecoder();"
                 "[a.process(r.timestamp, decode_frame(r.data, r.linktype)) for r in d.feed(pcap_bytes(sample_frames()))]; a.finish('eof');"
                 "assert len(out)==2 and all('layers' in s for s in out), out; print('installed engine ok:', [s['app'] for s in out])")
        run([str(python), "-I", "-c", probe], cwd=str(work))
        if args.no_extra:
            print("installed check ok (engine only)")
            return 0
        # 2. A01: the whole product from the installed artifact: the server module, its web assets, the demo
        #    analysis job, the decryption demo and the console script, from a directory holding no checkout.
        product_check(python, env_dir, work)
        # 3. The presentation suite against the installed engine (no checkout next to the copy).
        copy = work / "app" / "presentation"
        shutil.copytree(ROOT / "presentation", copy, ignore=shutil.ignore_patterns("__pycache__", "tests/ui/node_modules"))
        shutil.copytree(ROOT / "schemas", work / "app" / "schemas")
        (work / "app" / "tools").mkdir()
        for name in ("schema_check.py", "build_manifest.py"):
            shutil.copy(ROOT / "tools" / name, work / "app" / "tools" / name)
        result = subprocess.run([str(python), "-B", "-m", "unittest", "discover", "-s", "tests", "-q"], cwd=str(copy),  # noqa: S603
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=900)
        lines = result.stdout.splitlines()
        print("\n".join(lines[-6:]))
        if result.returncode:
            import collections
            heads = collections.Counter(line.split(" (")[0] for line in lines if line.startswith(("ERROR:", "FAIL:")))
            causes = collections.Counter(line.strip() for line in lines if "Error" in line and not line.startswith(("ERROR:", "FAIL:", "  File", "Traceback")))
            print("failing tests:", dict(heads.most_common(5)))
            print("causes:", dict(causes.most_common(5)))
            print("installed check FAILED: presentation suite against the installed wheel")
            return 1
        print("installed check ok: wheel built, installed with the decryption extra, engine imported from site-packages, presentation suite green")
        return 0


if __name__ == "__main__":
    sys.exit(main())
