"""Bounded live metadata bridge; the pinned engine owns capture and parsing."""
from collections import deque
import json
from pathlib import Path
from protocol_adapters.events import EventLog, public_state, reduce
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
MAX_RUN_SECONDS = 600    # stage 6 (A08): no run outlives this, whatever the client asked or did


def engine_command(module):
    """argv prefix that runs an engine module: the checkout's package when one is beside the app, else the
    installed package (stage 8, installed-artifact parity). Always `-m`, never a path that may not exist."""
    return [sys.executable, '-B', '-m', module]


def engine_cwd():
    """Working directory for engine workers: the checkout root when present so `-m` resolves its packages."""
    return str(ENGINE) if (ENGINE / 'protocol_adapters').exists() else None


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
        self.capture_id = None
        self.log = None          # stage 2 (A06): the versioned, bounded event log of the current run
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
            command = engine_command('protocol_adapters.live_capture') + [
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
            self.capture_id = secrets.token_hex(8)
            self.log = EventLog(self.capture_id)
            self.interface = interface
            self.lease = time.monotonic()
            self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                            stdin=subprocess.PIPE if keylog_path is not None else subprocess.DEVNULL,
                                            start_new_session=True, bufsize=65536, cwd=engine_cwd())
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
            if self.log is not None and kind in ('session', 'classification', 'capture_gap', 'error', 'summary', 'decryption'):
                try:
                    self.log.wrap_and_append(event)
                except ValueError:
                    pass                      # a malformed worker line never breaks the legacy path below
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
        deadline = time.monotonic() + min(duration, MAX_RUN_SECONDS) + 5     # server-enforced maximum lifetime
        while process.poll() is None:
            time.sleep(1)
            with self.lock:
                expired = time.monotonic() - self.lease > 30
            if expired or time.monotonic() > deadline:
                self.stop(process)
                return

    def stop(self, expected=None, run_id=None):
        """Idempotent (stage 6): stopping an already stopped run, or naming another run, changes nothing."""
        with self.lock:
            process = self.process
            if expected is not None and process is not expected:
                return
            if run_id is not None and run_id != self.capture_id:
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

    def reset(self, run_id):
        """M0: "Clear sessions & reset capture", scoped to the run it names.

        Stops the named run if it is still running and clears every retained result of it (events,
        sessions, summary, decryption report, event log); the next start is a fresh run and a fresh log. A
        request naming another run (a stale tab, or no run) changes nothing and says so. Key-log files on
        disk are never touched: the manager only ever reads the path the user gave for one run.
        """
        with self.lock:
            if run_id is None or run_id != self.capture_id:
                return {'reset': False, 'reason': 'stale' if run_id else 'no_run', 'run_id': self.capture_id}
            process = self.process
        if process is not None and process.poll() is None:
            self.stop(run_id=run_id)
        with self.lock:
            if run_id != self.capture_id:
                return {'reset': False, 'reason': 'stale', 'run_id': self.capture_id}
            self.events.clear()
            self.sessions.clear()
            self.summary = {}
            self.decryption = None
            self.error = None
            self.sequence = self.session_count = 0
            self.log = None
            self.capture_id = None
            self.interface = None
            if self.state in ('running', 'stopping'):
                self.state = 'stopped'
            return {'reset': True, 'reason': 'cleared', 'run_id': None}

    def heartbeat(self, run_id):
        """Stage 6 (A08): the one place that renews the dashboard lease, scoped to the run it names.

        Reading status no longer keeps a capture alive; a client that wants the run to continue sends the
        run id it is watching. A heartbeat for another run (an older tab) changes nothing.
        """
        with self.lock:
            if run_id is not None and run_id == self.capture_id and self.process is not None and self.process.poll() is None:
                self.lease = time.monotonic()
                return True
            return False

    def snapshot(self):
        """Side-effect free (stage 6): no lease renewal, no scheduling; safe to poll from any client."""
        with self.lock:
            return {'state': self.state, 'interface': self.interface, 'error': self.error, 'run_id': self.capture_id,
                    'lease_seconds_left': max(0, int(30 - (time.monotonic() - self.lease))) if self.state == 'running' else None,
                    'decryption': self.decryption,
                    'events': list(self.events), 'sessions': list(self.sessions),
                    'summary': self.summary, 'events_total': self.sequence,
                    'sessions_total': self.session_count, 'retained_sessions': len(self.sessions),
                    'capture_id': self.capture_id, 'cursor': self.log.snapshot()['cursor'] if self.log else 0}

    def state_view(self):
        """A14: the control state alone (no events, sessions or reports); side-effect free, cheap to poll.

        The live page combines it with cursor reads of the event log (`events_since`); the legacy `snapshot`
        stays for compatibility and tests.
        """
        with self.lock:
            return {'state': self.state, 'interface': self.interface, 'error': self.error, 'run_id': self.capture_id,
                    'capture_id': self.capture_id,
                    'lease_seconds_left': max(0, int(30 - (time.monotonic() - self.lease))) if self.state == 'running' else None,
                    'summary': self.summary, 'events_total': self.sequence, 'sessions_total': self.session_count,
                    'cursor': self.log.snapshot()['cursor'] if self.log else 0,
                    'decryption_summary': ({k: self.decryption.get(k) for k in ('provisional', 'capture_quality')} | {'decrypted': (self.decryption.get('report') or {}).get('decrypted')}) if isinstance(self.decryption, dict) else None}

    def events_since(self, cursor=0, limit=500):
        """Stage 2 (A06): cursor read of the versioned log plus the reduced session view.

        Re-polling the same cursor repeats nothing new; a cursor older than what is retained returns
        reset_required so the client rebuilds from the full read instead of showing a window with a hole.
        """
        with self.lock:
            if self.log is None:
                return {'capture_id': None, 'events': [], 'cursor': 0, 'reset_required': False, 'view': None}
            page = self.log.read(cursor, limit)
            page['capture_id'] = self.capture_id
            page['view'] = self.view()
            return page

    def view(self):
        """The session view reduced from the whole retained log; identical whether built live or replayed."""
        if self.log is None:
            return None
        state = public_state(reduce(self.log.snapshot()['events']))
        return {'quality': state['quality'], 'retracted_total': state['retracted_total'],
                'sessions': [dict(id=sid, **{k: v for k, v in view.items() if k != 'classifications'},
                                  classifications=len(view['classifications']))
                             for sid, view in state['sessions'].items()],
                'errors': state['errors'], 'last_sequence': state['last_sequence'], 'summary': state.get('summary')}
