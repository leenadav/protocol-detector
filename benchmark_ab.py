"""Stable A/B CPU comparison of two source trees on identical synthetic flows.

Each tree runs in its own interpreter; the two are alternated several times and
the minimum per-flow time (constructor cost subtracted) is reported. Minimum of
repeated runs is robust against the host noise that defeats percentile-based
paired harnesses on shared machines (see BENCHMARK-V023.md). Both trees are
byte-compiled first: CPython runs code loaded from source without a cached
.pyc measurably slower (about +50% on these flows), which silently penalizes a
fresh checkout used as a baseline (BENCHMARK-V024.md). Synthetic packets only;
no sockets, capture or output I/O are timed.
"""
import argparse
import compileall
import json
import subprocess
import sys
from pathlib import Path

WORKER = r'''
import json, sys, timeit
root = sys.argv[1]; sys.path.insert(0, root)
from live_capture import CaptureMonitor
from capture_stream import CaptureRecord
from make_sample_pcap import A, B, REQUEST, frame, udp_frame
from protocol_fixtures import DNS, DTLS, TLS_SERVER13
from proxy_demo import client_hello
options = json.loads(sys.argv[2])
hs = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18)]
cases = {'http_flow': hs + [frame(A, B, 1000, 9000, 24, REQUEST)],
         'tls_flow': hs + [frame(A, B, 1000, 9000, 24, client_hello())],
         'tls_server13': hs + [frame(B, A, 9000, 1000, 24, TLS_SERVER13)],
         'ssh_flow': hs + [frame(A, B, 1000, 9000, 24, b'SSH-2.0-demo\r\n')],
         'dns_datagram': [udp_frame(A, B, DNS)], 'dtls_datagram': [udp_frame(A, B, DTLS)],
         'udp_unknown': [udp_frame(A, B, b'\xff' * 32)]}
kwargs = {}
try:
    from protocol_engine import Config
    if options.get('fingerprints') and 'fingerprints' in Config.__dataclass_fields__:
        kwargs['fingerprints'] = True
except Exception:
    pass
out = {}
for name, frames in cases.items():
    recs = [CaptureRecord(i, d, len(d), 1) for i, d in enumerate(frames)]
    def run():
        m = CaptureMonitor(lambda e: None, **kwargs)
        for r in recs: m.accept(r, r.timestamp)
    def ctor():
        CaptureMonitor(lambda e: None, **kwargs)
    n = options['flows']
    best = min(timeit.repeat(run, number=n, repeat=options['repeat'])) / n * 1e6
    base = min(timeit.repeat(ctor, number=n, repeat=options['repeat'])) / n * 1e6
    out[name] = round(best - base, 1)
print(json.dumps(out))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, help="Other source tree to compare with the current one")
    parser.add_argument("--alternations", type=int, default=3)
    parser.add_argument("--flows", type=int, default=400)
    parser.add_argument("--repeat", type=int, default=7)
    parser.add_argument("--fingerprints", action="store_true", help="Enable fingerprints where the tree supports them")
    args = parser.parse_args()
    if not 1 <= args.alternations <= 20 or not 10 <= args.flows <= 5000 or not 1 <= args.repeat <= 30:
        parser.error("Invalid limits")
    roots = {"current": Path(__file__).resolve().parent}
    if args.baseline:
        roots["baseline"] = args.baseline.resolve()
    options = json.dumps({"flows": args.flows, "repeat": args.repeat, "fingerprints": args.fingerprints})
    for root in roots.values():
        compileall.compile_dir(str(root / "protocol_engine"), quiet=1)
        for module in root.glob("*.py"):
            compileall.compile_file(str(module), quiet=1)
    results = {label: {} for label in roots}
    for _ in range(args.alternations):
        for label, root in roots.items():
            output = subprocess.run([sys.executable, "-c", WORKER, str(root), options], capture_output=True, check=True, timeout=600)
            for case, value in json.loads(output.stdout).items():
                results[label][case] = min(value, results[label].get(case, value))
    print(json.dumps({"method": "min over alternations x repeat of mean per-flow time, constructor subtracted; microseconds",
                      "alternations": args.alternations, "flows": args.flows, "repeat": args.repeat,
                      "fingerprints": args.fingerprints, "results": results}, indent=2))


if __name__ == "__main__":
    main()
