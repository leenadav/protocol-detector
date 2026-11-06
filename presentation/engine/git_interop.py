"""Opt-in Git client verification against a synthetic IPv4 loopback server.

No repository is read or written. Git user/system configuration is disabled.
Run manually with Python 3.9+ and an installed Git executable.
"""
import json
import os
import shutil
import socket
import subprocess
from protocol_engine import Inspector
from live_capture import CaptureMonitor
from capture_stream import CaptureRecord
from make_sample_pcap import A, B, frame


def read_exact(connection, size):
    data = bytearray()
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise RuntimeError('Git client ended before completing its request')
        data.extend(chunk)
    return bytes(data)


def verify_version(git_binary, environment, version):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(3)
        port = listener.getsockname()[1]
        command = [git_binary, '-c', 'protocol.version=' + str(version), 'ls-remote',
                   'git://127.0.0.1:' + str(port) + '/synthetic.git']
        process = subprocess.Popen(command, env=environment, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        try:
            with listener.accept()[0] as connection:
                connection.settimeout(3)
                header = read_exact(connection, 4)
                size = int(header, 16)
                if not 5 <= size <= 65520:
                    raise RuntimeError('Client request length outside pkt-line limits')
                request = header + read_exact(connection, size - 4)
                connection.sendall(b'0000')  # Synthetic empty reference listing.
            _, errors = process.communicate(timeout=3)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
        if process.returncode:
            raise RuntimeError('Local Git client failed: ' + errors.decode('utf-8', 'replace'))
    engine = Inspector()
    engine.feed(request)
    if engine.observation.application_protocol != 'git':
        raise RuntimeError('Canonical client request was not identified as Git')
    events = []
    monitor = CaptureMonitor(events.append)
    frames = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18)]
    frames.extend(frame(A, B, 1000 + index, 9000, 24, request[index:index + 1])
                  for index in range(len(request)))
    for index, data in enumerate(frames):
        monitor.accept(CaptureRecord(index, data, len(data), 1), index / 100.)
    if len(events) != 1 or events[0]['protocol'] != 'git':
        raise RuntimeError('Bytewise capture adapter verification failed')
    return {'requested_version': version, 'request_bytes': len(request),
            'status': engine.observation.status,
            'version_offers': [e.value for e in engine.observation.evidence if e.field == 'offered_version'],
            'live_adapter_bytewise_identifications': len(events), 'git_exit_code': process.returncode}


def main():
    git_binary = shutil.which('git')
    if git_binary is None:
        raise SystemExit('Git executable is required')
    environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    environment.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_CONFIG_SYSTEM=os.devnull, GIT_TERMINAL_PROMPT='0')
    results = [verify_version(git_binary, environment, version) for version in (0, 1, 2)]
    report = {'git_version': subprocess.check_output([git_binary, '--version'], text=True).strip(),
              'scope': 'Canonical Git client to synthetic IPv4 loopback server only; no repository or external traffic',
              'cases': results}
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
