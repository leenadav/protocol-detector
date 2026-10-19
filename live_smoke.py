"""Opt-in real loopback capture verification; creates only local test traffic.

Requires permission to capture the selected loopback interface. No external
connections, packet files, or elevated Python process are used.
"""
import argparse
import json
import selectors
import socket
import subprocess
import sys
import threading
import time
from live_capture import capture_command, run_capture
from protocol_fixtures import GIT, RADIUS, FASTCGI, RSYNC, BGP, SMB311, DNS, SNMP, TFTP, STOMP, STOMP_SERVER, NATS_CONNECT, NATS_INFO, IMAP, RDP, MYSQL, MONGODB, MONGODB_CHECKSUM
from proxy_demo import client_hello


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interface', default='lo0' if sys.platform == 'darwin' else 'lo')
    profile = parser.add_mutually_exclusive_group()
    profile.add_argument('--radius', action='store_true', help='Verify explicit-candidate RADIUS over local UDP')
    profile.add_argument('--database', choices=('mysql', 'mongodb'), help='Verify an explicit-candidate database profile')
    args = parser.parse_args()
    sockets, process, worker = [], None, None
    failures, events = [], []
    try:
        for family, kind, address in ((socket.AF_INET, socket.SOCK_STREAM, '127.0.0.1'),
                                      (socket.AF_INET, socket.SOCK_DGRAM, '127.0.0.1')):
            sock = socket.socket(family, kind)
            sockets.append(sock)
            sock.settimeout(2)
            sock.bind((address, 0))
            if kind == socket.SOCK_STREAM:
                sock.listen(4)
        tcp4, udp = sockets
        bpf = '(tcp port {} or udp port {}) and host 127.0.0.1'.format(
            tcp4.getsockname()[1], udp.getsockname()[1])
        process = subprocess.Popen(capture_command(args.interface, bpf), stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, bufsize=0)
        # Do not generate traffic until capture has actually opened the interface.
        ready, diagnostic = False, bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stderr, selectors.EVENT_READ)
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and not ready:
                for _, _ in selector.select(.1):
                    data = process.stderr.read(4096)
                    if not data:
                        raise RuntimeError('Capture failed: ' + diagnostic.decode('utf-8', 'replace'))
                    diagnostic.extend(data)
                    if len(diagnostic) > 8192:
                        raise RuntimeError('Capture startup diagnostics exceeded limit')
                    ready = b'listening on' in diagnostic
            if not ready:
                raise RuntimeError('Capture did not become ready within three seconds')

        def generate():
            try:
                request = b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n'
                listener = tcp4
                profiles = ((request, False), (BGP, False), (SMB311, False),
                                             (client_hello(), False), (STOMP, False), (NATS_CONNECT, False),
                                             (IMAP, True), (RDP, False), (STOMP_SERVER, True), (NATS_INFO, True), (FASTCGI, False), (RSYNC, True), (GIT, False))
                if args.database:
                    profiles = ((MYSQL, True),) if args.database == 'mysql' else ((MONGODB, False), (MONGODB_CHECKSUM, False))
                if args.radius:
                    profiles = ()
                for payload, from_server in profiles:
                    with socket.socket(listener.family, socket.SOCK_STREAM) as client:
                        client.settimeout(2)
                        client.connect(listener.getsockname())
                        with listener.accept()[0] as server:
                            server.settimeout(2)
                            sender, receiver = (server, client) if from_server else (client, server)
                            sender.sendall(payload)
                            sender.shutdown(socket.SHUT_WR)
                            received = bytearray()
                            while len(received) < len(payload):
                                chunk = receiver.recv(4096)
                                if not chunk:
                                    raise RuntimeError('Unexpected test stream EOF')
                                received.extend(chunk)
                            if bytes(received) != payload:
                                raise RuntimeError('Loopback payload mismatch')
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                    for payload in (() if args.database else (RADIUS,) if args.radius else (DNS, SNMP, TFTP)):
                        sender.sendto(payload, udp.getsockname())
                        if udp.recv(4096) != payload:
                            raise RuntimeError('Loopback UDP payload mismatch')
            except Exception as exc:
                failures.append(str(exc))

        worker = threading.Thread(target=generate, name='loopback-test-traffic', daemon=True)
        worker.start()
        status = run_capture(process.stdout, events.append, duration=2, stats_interval=0, process=process, tcp_hint=args.database, udp_hint='radius' if args.radius else None)
        worker.join(timeout=3)
        if worker.is_alive() or failures:
            raise RuntimeError('Traffic generation failed: ' + repr(failures))
        found = {event['protocol'] for event in events if event['type'] == 'classification' and event['status'] == 'identified'}
        expected = {'http/1.1', 'bgp/4', 'smb2', 'tls', 'dns', 'snmp/2c', 'tftp', 'stomp', 'nats', 'imap', 'rdp', 'fastcgi/1', 'rsync', 'git'}
        if args.database:
            expected = {args.database}
        if args.radius:
            expected = {'radius'}
        ipv4_only = all(event['source'][0] == '127.0.0.1' and event['destination'][0] == '127.0.0.1'
                        for event in events if event['type'] == 'classification')
        if status or not expected <= found or not ipv4_only:
            raise RuntimeError('Capture verification failed: ' + repr({'status': status, 'missing': sorted(expected - found), 'ipv4_only': ipv4_only, 'events': events}))
        print(json.dumps({'status': 'passed', 'traffic': 'local synthetic TCP/UDP over real loopback capture',
                          'protocols': sorted(found), 'candidate_hint': args.database or ('radius' if args.radius else None),
                          'ipv4_only': ipv4_only, 'summary': events[-1]}, indent=2))
        return 0
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        if process is not None:
            process.stdout.close()
            process.stderr.close()
        for sock in sockets:
            sock.close()
        if worker is not None:
            worker.join(timeout=3)


if __name__ == '__main__':
    raise SystemExit(main())
