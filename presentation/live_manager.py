"""Bounded live metadata bridge; the pinned engine owns capture and parsing."""
from collections import deque
import json
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parent
ENGINE = ROOT.parent     # one engine source (stage 1b)


class LiveManager:
    def __init__(self):
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.RLock()
        self.process = None
        self.thread = None
        self.state = 'idle'
        self.events = deque(maxlen=200)
        self.sessions = deque(maxlen=500)
        self.summary = {}
        self.error = None
        self.sequence = 0
        self.session_count = 0
        self.lease = 0
        self.interface = None
        self.decryption = None

    def interfaces(self):
        return {'interfaces': [name for _, name in socket.if_nameindex()
                               if re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', name)],
                'available': bool(shutil.which('tcpdump')), 'token': self.token}

    def start(self, interface, duration=120, scope='all', keylog_path=None):
        with self.lock:
            if self.process is not None and self.process.poll() is None:
                raise ValueError('A live capture is already running.')
            if self.thread is not None and self.thread.is_alive():
                raise ValueError('Previous capture is still stopping.')
            if interface not in self.interfaces()['interfaces'] or interface.startswith('-'):
                raise ValueError('Select an available network interface.')
            if type(duration) is not int or not 5 <= duration <= 600:
                raise ValueError('Duration must be 5–600 seconds.')
            if scope not in ('all', 'synthetic'):
                raise ValueError('Invalid capture scope.')
            if scope == 'synthetic' and interface not in ('lo0', 'lo'):
                raise ValueError('Local synthetic capture requires lo0 or lo.')
            if not shutil.which('tcpdump'):
                raise ValueError('tcpdump is not installed on this computer.')
            if keylog_path is not None:
                if not isinstance(keylog_path, str) or not Path(keylog_path).is_absolute() or len(keylog_path) > 1024:
                    raise ValueError('Enter the absolute path of the browser key log.')
                if duration > 120:
                    raise ValueError('Live decryption is limited to 120 seconds per sample.')
            # Exclude the dashboard itself to avoid capturing its polling traffic.
            bpf = '(tcp or udp) and not (host 127.0.0.1 and tcp portrange 8765-8775)'
            if scope == 'synthetic':
                bpf = 'host 127.0.0.1 and tcp port 45991'
            command = [sys.executable, '-B', str(ENGINE / 'live_capture.py'),
                       '--interface', interface, '--filter', bpf, '--duration', str(duration),
                       '--max-packets', '100000', '--max-connections', '128',
                       '--byte-limit', '16384', '--idle-timeout', '15',
                       '--stats-interval', '1', '--all-events', '--fingerprints', '--json']
            if keylog_path is not None:
                command = [sys.executable, '-B', str(ROOT / 'poc_decryption/live.py'),
                           '--interface', interface, '--filter', bpf, '--duration', str(duration)]
            self.events.clear()
            self.sessions.clear()
            self.summary = {}
            self.decryption = None
            self.error = None
            self.sequence = self.session_count = 0
            self.interface = interface
            self.lease = time.monotonic()
            self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                            stdin=subprocess.PIPE if keylog_path is not None else subprocess.DEVNULL,
                                            start_new_session=True, bufsize=65536)
            if keylog_path is not None:
                self.process.stdin.write((json.dumps({'keylog_path': keylog_path})+'\n').encode())
                self.process.stdin.close()
            self.state = 'running'
            self.thread = threading.Thread(target=self._read, daemon=True)
            self.thread.start()
            threading.Thread(target=self._watch, args=(self.process, duration), daemon=True).start()
        return self.snapshot()

    def ingest(self, event):
        with self.lock:
            kind = event.get('type')
            if kind == 'decryption':
                self.decryption = event
            elif kind in ('progress', 'summary'):
                self.summary = event
            elif kind == 'session':
                self.session_count += 1
                event = dict(event, id='L-{:06d}'.format(self.session_count), events=[])
                self.sessions.append(event)
            elif kind in ('classification', 'capture_gap', 'error'):
                self.sequence += 1
                self.events.append(dict(event, sequence=self.sequence))
                if kind == 'error':
                    self.error = event.get('reason', 'Capture failed')
                if kind == 'capture_gap':
                    # Never retain apparently valid session verdicts across reported capture loss.
                    self.sessions.clear()

    def _read(self):
        process = self.process
        try:
            while True:
                line = process.stdout.readline(131073)
                if not line:
                    break
                if len(line) > 131072 or not line.endswith(b'\n'):
                    raise ValueError('Live metadata exceeded its size limit.')
                self.ingest(json.loads(line))
            code = process.wait(timeout=5)
            with self.lock:
                if code not in (0, 2) and not self.error:
                    self.error = 'Capture process exited unexpectedly ({}).'.format(code)
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            with self.lock:
                self.error = str(error)
            self.stop()
        finally:
            process.stdout.close()
            with self.lock:
                self.state = 'failed' if self.error else 'stopped'

    def _watch(self, process, duration):
        deadline = time.monotonic() + duration + 5
        while process.poll() is None:
            time.sleep(1)
            with self.lock:
                expired = time.monotonic() - self.lease > 30
            if expired or time.monotonic() > deadline:
                self.stop(process)
                return

    def stop(self, expected=None):
        with self.lock:
            process = self.process
            if expected is not None and process is not expected:
                return
            if process is None or process.poll() is not None:
                return
            self.state = 'stopping'
            try:
                process.send_signal(signal.SIGINT)
            except ProcessLookupError:
                return
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            # Only this run's process group, created above, is terminated.
            import os
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=2)

    def snapshot(self):
        with self.lock:
            self.lease = time.monotonic()
            return {'state': self.state, 'interface': self.interface, 'error': self.error,
                    'decryption': self.decryption,
                    'events': list(self.events), 'sessions': list(self.sessions),
                    'summary': self.summary, 'events_total': self.sequence,
                    'sessions_total': self.session_count, 'retained_sessions': len(self.sessions)}
