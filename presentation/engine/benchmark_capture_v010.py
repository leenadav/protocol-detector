"""Compare actual capture adapter versions in isolated Python subprocesses.

Synthetic packets only, no sockets/capture. Timed work excludes monitor creation
and output I/O. FIN intentionally has different completion semantics in v0.9.
"""
import argparse
import hashlib
import json
from pathlib import Path
import random
import statistics
import subprocess
import sys
import time


def distribution(values):
    ordered = sorted(values)
    return {key: round(value / 1000, 3) for key, value in
            (('p50_us', statistics.median(ordered)), ('p95_us', ordered[int((len(ordered) - 1) * .95)]),
             ('p99_us', ordered[int((len(ordered) - 1) * .99)]))}


def worker(root, iterations):
    sys.path.insert(0, str(root))
    from live_capture import CaptureMonitor
    from capture_stream import CaptureRecord
    from make_sample_pcap import A, B, REQUEST, frame, udp_frame
    from protocol_fixtures import DNS
    handshake = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18)]
    cases = {'http_flow': handshake + [frame(A, B, 1000, 9000, 24, REQUEST)],
             'partial_fin': handshake + [frame(A, B, 1000, 9000, 25, b'GET ')],
             'dns_datagram': [udp_frame(A, B, DNS)]}
    result = {}
    for name, frames in cases.items():
        records = [CaptureRecord(i, data, len(data), 1) for i, data in enumerate(frames)]
        samples = []
        for index in range(50 + iterations):
            monitor = CaptureMonitor(lambda event: None)
            start = time.perf_counter_ns()
            for record in records:
                monitor.accept(record, record.timestamp)
            elapsed = time.perf_counter_ns() - start
            if name != 'partial_fin' and monitor.counts['identified'] != 1:
                raise RuntimeError('Adapter identification failed')
            if name == 'partial_fin':
                stream = next(iter(monitor.analyzer.manager.connections.values()))['directions'][A]
                status = stream.inspector.observation.status
                if status not in ('detecting', 'incomplete'):
                    raise RuntimeError('Unexpected FIN result')
            else:
                status = 'identified'
            if index >= 50:
                samples.append(elapsed)
        result[name] = {'times_ns': samples, 'status': status, 'packets': len(frames)}
    digest = hashlib.sha256()
    paths = sorted((root / 'protocol_engine').glob('*.py')) + [root / n for n in
             ('live_capture.py', 'capture_stream.py', 'link_packets.py', 'analyze_pcap.py', 'sessions.py', 'packets.py', 'detectors.py')]
    for path in paths:
        digest.update(str(path.relative_to(root)).encode() + b'\0' + path.read_bytes())
    return {'cases': result, 'source_sha256': digest.hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--worker-root', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--iterations', type=int, default=500)
    parser.add_argument('--rounds', type=int, default=5)
    args = parser.parse_args()
    if not 10 <= args.iterations <= 10000 or not 1 <= args.rounds <= 20:
        parser.error('Invalid iteration/round limits')
    if args.worker_root:
        print(json.dumps(worker(args.worker_root.resolve(), args.iterations)))
        return
    roots = {'current': Path(__file__).resolve().parent}
    if args.baseline: roots['baseline'] = args.baseline.resolve()
    samples, result = {}, {'cases': {}, 'source_sha256': {}, 'iterations': args.iterations, 'rounds': args.rounds,
                           'scope': 'Decoded synthetic packets to events, excludes construction/capture/output; FIN baseline may remain detecting'}
    rng = random.Random(1010)
    for _ in range(args.rounds):
        versions = list(roots); rng.shuffle(versions)
        for version in versions:
            output = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()), '--worker-root', str(roots[version]),
                                     '--iterations', str(args.iterations)], capture_output=True, check=True, timeout=60)
            report = json.loads(output.stdout)
            result['source_sha256'][version] = report['source_sha256']
            for name, data in report['cases'].items():
                values = samples.setdefault((name, version), []); values.extend(data['times_ns'])
                result['cases'].setdefault(name, {})[version] = {'flow': distribution(values), 'status': data['status'], 'packets': data['packets']}
    result['benchmark_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
