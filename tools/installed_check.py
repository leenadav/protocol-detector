"""Installed-artifact check (stage 8, A16): build the wheel, install it into an empty environment with the
decryption extra from the hash-pinned lock, and run the presentation suite against the installed engine.

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
        # 2. The presentation suite against the installed engine (no checkout next to the copy).
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
