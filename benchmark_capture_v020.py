"""Compare actual capture adapter versions in isolated Python subprocesses.

Synthetic packets only, no sockets/capture. Timed work excludes monitor creation
and output I/O. Measures ordinary paths and DTLS datagram recognition; status and event counts are reported.
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
    from protocol_fixtures import DNS, DATAGRAM_CASES
    from proxy_demo import client_hello
    body = b"git-upload-pack /project.git\0host=example.com\0\0version=2\0"
    git_request = ("%04x" % (len(body)+4)).encode() + body
    handshake = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18)]
    wrap_handshake = [frame(A, B, 2**32-1, 0, 2), frame(B, A, 8999, 0, 18)]
    giop = bytes.fromhex('47494f500102000300000010000000010000000000000004') + b'demo'
    dcerpc = bytes.fromhex('05000b03100000004800000001000000b810b810000000000100000000000100') + bytes(range(1,17)) + bytes.fromhex('01000000045d888aeb1cc9119fe808002b10486002000000')
    socks = b'\x05\x01\x00\x05\x01\x00\x01\xc0\x00\x02\x01\x01\xbb'
    def server_hello(ext, cipher, retry=False):
        random = bytes.fromhex('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c') if retry else bytes(range(32))
        body = b'\x03\x03'+random+b'\0'+cipher.to_bytes(2,'big')+b'\0'+len(ext).to_bytes(2,'big')+ext
        h = b'\x02'+len(body).to_bytes(3,'big')+body
        return b'\x16\x03\x03'+len(h).to_bytes(2,'big')+h
    cases = {'tls_server12': handshake + [frame(B,A,9000,1000,24,server_hello(bytes.fromhex('001000050003026832'),0xc02f))],
             'tls_server13': handshake + [frame(B,A,9000,1000,24,server_hello(bytes.fromhex('002b0002030400330024001d0020')+bytes(32),0x1301))],
             'tls_retry': handshake + [frame(B,A,9000,1000,24,server_hello(bytes.fromhex('002b0002030400330002001d'),0x1301,True))],
             'dcerpc_flow': handshake + [frame(A,B,1000,9000,24,dcerpc)],
             'socks_flow': handshake + [frame(A,B,1000,9000,24,socks)],
             'giop_flow': handshake + [frame(A,B,1000,9000,24,giop)],
             'http_giop_method': handshake + [frame(A,B,1000,9000,24,b'GIOP / HTTP/1.1\r\nHost: example.com\r\n\r\n')],
             'git_flow': handshake + [frame(A,B,1000,9000,24,git_request)],
             'http_git_method': handshake + [frame(A,B,1000,9000,24,b'0033git-upload-pack / HTTP/1.1\r\nHost: example.com\r\n\r\n')],
             'tls_flow': handshake + [frame(A,B,1000,9000,24,client_hello())],
             'ssh_flow': handshake + [frame(A,B,1000,9000,24,b'SSH-2.0-demo\r\n')],
             'http_flow': handshake + [frame(A, B, 1000, 9000, 24, REQUEST)],
             'partial_fin': handshake + [frame(A, B, 1000, 9000, 25, b'GET ')],
             'dns_datagram': [udp_frame(A, B, DNS)],
             'reordered_http': handshake + [frame(A,B,1011,9000,24,REQUEST[11:]), frame(A,B,1000,9000,24,REQUEST[:11])],
             'leading_duplicate': wrap_handshake + [frame(A,B,0,9000,24,REQUEST), frame(A,B,2**32-1,9000,24,b'X'+REQUEST)],
             'old_payload_after_fin': handshake + [frame(A,B,1000,9000,25,REQUEST), frame(A,B,998,9000,24,b'X')],
             'pre_origin_fin': wrap_handshake + [frame(A,B,2**32-2,9000,25,b'X'), frame(A,B,0,9000,24,REQUEST)],
             'control_rejection': handshake + [frame(A,B,1000,9000,25,REQUEST), frame(A,B,1000+len(REQUEST),9000,24,b'X')],
             'leading_conflict': wrap_handshake + [frame(A,B,0,9000,24,REQUEST), frame(A,B,2**32-1,9000,24,b'XX'+REQUEST[1:])]}
    body = b'\xfe\xfd' + bytes(range(32)) + b'\0\0\0\x02\xc0\x2f\x01\0'
    h = b'\x01'+len(body).to_bytes(3,'big')+bytes(5)+len(body).to_bytes(3,'big')+body
    dtls = b'\x16\xfe\xff'+bytes(8)+len(h).to_bytes(2,'big')+h
    cases['dtls_datagram'] = [udp_frame(A,B,dtls)]
    cases['udp_unknown'] = [udp_frame(A,B,b'\xff'*32)]
    for data, protocol in DATAGRAM_CASES:
        if protocol != 'dtls': cases['udp_'+protocol.replace('/','_')] = [udp_frame(A,B,data)]
    result = {}
    for name, frames in cases.items():
        records = [CaptureRecord(i, data, len(data), 1) for i, data in enumerate(frames)]
        samples = []
        for index in range(50 + iterations):
            events = []
            monitor = CaptureMonitor(events.append)
            start = time.perf_counter_ns()
            for record in records:
                monitor.accept(record, record.timestamp)
            elapsed = time.perf_counter_ns() - start
            if name not in ('partial_fin', 'pre_origin_fin', 'git_flow', 'giop_flow', 'dcerpc_flow', 'tls_server12', 'tls_server13', 'tls_retry', 'dtls_datagram', 'udp_unknown') and monitor.counts['identified'] != 1:
                raise RuntimeError('Adapter identification failed')
            if name == 'partial_fin':
                stream = next(iter(monitor.analyzer.manager.connections.values()))['directions'][A]
                status = stream.inspector.observation.status
                if status not in ('detecting', 'incomplete'):
                    raise RuntimeError('Unexpected FIN result')
            elif name in ('git_flow','giop_flow','dcerpc_flow','tls_server12','tls_server13','tls_retry','dtls_datagram','udp_unknown'):
                status = monitor.analyzer.last_classification.status
            elif name in ('leading_conflict', 'control_rejection', 'pre_origin_fin', 'old_payload_after_fin'):
                status = events[-1]['status']
                if status not in ('identified', 'invalidated'):
                    raise RuntimeError('Unexpected conflict status')
            else:
                status = 'identified'
            if index >= 50:
                samples.append(elapsed)
        result[name] = {'times_ns': samples, 'status': status, 'packets': len(frames), 'invalidations_counted': monitor.counts['invalidated']}
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
                           'scope': 'Decoded synthetic packets to events, excludes construction/capture/output; new DTLS profile: baseline unknown, current validates; existing UDP and TCP cases retained'}
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
                result['cases'].setdefault(name, {})[version] = {'flow': distribution(values), 'status': data['status'], 'packets': data['packets'], 'invalidations_counted': data['invalidations_counted']}
    result['benchmark_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
