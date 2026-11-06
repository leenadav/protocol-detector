"""Compare bounded Stream.feed CPU cost; no network or protocol parsing.

Recording counter replaces Inspector to isolate reassembly. Stream construction,
state preparation/copying, assertions and JSON are outside the timer. Real
capture-adapter regressions are measured separately with real inspectors.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys
import time


class Counter:
    def __init__(self):
        self.delivered = 0
        self.invalidated = False

    def feed(self, payload):
        self.delivered += len(payload)
        return ()

    def invalidate(self, reason):
        self.invalidated = True
        return ()


def fixtures():
    data = bytes(range(256)) * 256
    return {
        'in_order_1400': ([], [(0, data[:1400])], False),
        'duplicate_1400': ([(0, data[:1400])], [(0, data[:1400])], False),
        'duplicate_64k': ([(0, data)], [(0, data)], False),
        'pending_duplicate_1400': ([(1400, data[1400:2800])], [(1400, data[1400:2800])], False),
        'two_reverse_segments_1400': ([], [(700, data[700:1400]), (0, data[:700])], False),
        'fill_one_byte_gap_64k': ([(1, data[1:])], [(0, data[:1])], False),
        'partial_overlap_1400': ([(0, data[:1400])], [(700, data[700:2100])], False),
        'alternating_holes_64k': ([(i, data[i:i+1]) for i in range(1, 65536, 2)], [(0, data)], False),
        'duplicate_conflict_first_64k': ([(0, data)], [(0, b'X' + data[1:])], True),
        'duplicate_conflict_last_64k': ([(0, data)], [(0, data[:-1] + b'X')], True),
        'mixed_conflict_last_64k': ([(65535, data[-1:])], [(0, data[:-1] + b'X')], True),
    }


def distribution(values):
    values = sorted(values)
    return {key: round(value / 1000, 3) for key, value in
            (('p50_us', statistics.median(values)), ('p95_us', values[int((len(values)-1)*.95)]),
             ('p99_us', values[int((len(values)-1)*.99)]))}


def worker(root, iterations):
    sys.path.insert(0, str(root))
    from sessions import Stream, StreamError
    cases = {}
    for name, (setup, operations, conflict) in fixtures().items():
        template = Stream(0, 65536, Counter, False)
        expected = {}
        for offset, payload in setup:
            template.feed(offset, payload)
            expected.update((offset+i, value) for i, value in enumerate(payload))
        if not conflict:
            for offset, payload in operations:
                expected.update((offset+i, value) for i, value in enumerate(payload))
        ready = 0
        while ready in expected:
            ready += 1
        values = []
        for index in range(30 + iterations):
            stream = copy.copy(template)
            stream.buffer = template.buffer.copy()
            stream.present = template.present.copy()
            stream.inspector = Counter()
            caught = False
            start = time.perf_counter_ns()
            try:
                for offset, payload in operations:
                    stream.feed(offset, payload)
            except StreamError:
                caught = True
            elapsed = time.perf_counter_ns() - start
            if caught != conflict or stream.inspector.invalidated != conflict:
                raise RuntimeError('Conflict assertion failed: ' + name)
            if stream.stored != len(expected) or stream.contiguous != ready:
                raise RuntimeError('Reassembly assertion failed: ' + name)
            if stream.inspector.delivered != ready - template.contiguous:
                raise RuntimeError('Delivery assertion failed: ' + name)
            if index >= 30:
                values.append(elapsed)
        cases[name] = values
    return {'cases': cases, 'sessions_sha256': hashlib.sha256((root/'sessions.py').read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--worker-root', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--iterations', type=int, default=200)
    parser.add_argument('--rounds', type=int, default=5)
    args = parser.parse_args()
    if not 10 <= args.iterations <= 10000 or not 1 <= args.rounds <= 20:
        parser.error('Invalid sample/round limits')
    if args.worker_root:
        print(json.dumps(worker(args.worker_root.resolve(), args.iterations)))
        return
    roots = {'current': Path(__file__).resolve().parent}
    if args.baseline:
        roots['baseline'] = args.baseline.resolve()
    result = {'cases': {}, 'source_sha256': {}, 'iterations': args.iterations, 'rounds': args.rounds,
              'python': sys.version, 'platform': platform.platform(),
              'scope': 'Stream.feed only with counter inspector; preparation/copy/assertions excluded; GC enabled'}
    samples = {}
    rng = random.Random(11011)
    for _ in range(args.rounds):
        versions = list(roots); rng.shuffle(versions)
        for version in versions:
            output = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()), '--worker-root', str(roots[version]),
                                     '--iterations', str(args.iterations)], capture_output=True, check=True, timeout=60)
            report = json.loads(output.stdout)
            result['source_sha256'][version] = report['sessions_sha256']
            for name, values in report['cases'].items():
                combined = samples.setdefault((name, version), [])
                combined.extend(values)
                result['cases'].setdefault(name, {})[version] = distribution(combined)
    result['benchmark_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    fixture_hash = hashlib.sha256()
    for name, (setup, operations, conflict) in fixtures().items():
        fixture_hash.update(name.encode() + bytes([conflict]))
        for group in (setup, operations):
            fixture_hash.update(len(group).to_bytes(4, 'big'))
            for offset, payload in group:
                fixture_hash.update(offset.to_bytes(4, 'big') + len(payload).to_bytes(4, 'big') + payload)
    result['fixture_sha256'] = fixture_hash.hexdigest()
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
