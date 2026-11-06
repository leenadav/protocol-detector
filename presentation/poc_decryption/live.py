"""Bounded live POC: capture and key-log decoding in one Python worker (stage 4: incremental).

tcpdump supplies raw packets only. The SessionCoordinator (shared with the plain live path) reassembles each
connection once; the Decryptor authenticates each new record once, in bounded slices between pipe reads; the
key log is read append-only; a status snapshot performs no parsing and no cryptography (A02). This remains a
POC profile (TLS 1.2 ECDHE-RSA AES-GCM and TLS 1.3 AEAD with a key log), not a production TLS engine.
"""
import argparse
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))                    # this script runs as a worker: make the presentation package importable
sys.path.insert(0, str(ROOT.parent))             # and the one engine source
from protocol_adapters.capture_stream import PcapStreamDecoder
from protocol_adapters.coordinator import RetentionBudget
from protocol_adapters.live_capture import CaptureDiagnostics, CaptureMonitor, capture_command
from poc_decryption import MAX_STREAM, DecryptionError, KeyProvider
from poc_decryption.decryptor import Decryptor

LIMIT = 2 * 1024 * 1024          # captured bytes accepted per run (the capture itself is not retained)
MAX_FRAMES = 20000
MAX_KEYLOG = 262144
MAX_CONNECTIONS = 64
WORK_QUANTUM = 64                # records per connection per slice between pipe reads
ERROR_CODES = {
    'capture_failed': 'Capture failed; check tcpdump permission and selected interface.',
    'capture_loss': 'Capture loss reported; decrypted results invalidated.',
    'key_log': 'Key log unreadable, rotated, truncated or outside the POC format; decrypted results invalidated.',
    'budget': 'Live decryption reached a POC budget (bytes, frames, connections or key-log size); restart for a new sample.',
    'internal': 'Live decryption stopped on an internal error; results invalidated.',
}


class KeyLogError(ValueError):
    def __init__(self, message, code='key_log'):
        super().__init__(message)
        self.code = code


class KeyLog:
    """Append-only reader of an NSS key-log file: each read returns only the new complete lines (A02).

    Truncation (the file shrank) and rotation (a different file now sits at the path) are reported as
    KeyLogError instead of being silently re-read from the start: secrets indexed from the old content stay
    valid for the connections that used them, but a run cannot tell which later lines belong to which file.
    """
    def __init__(self, path):
        self.path = path
        self.fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        info = os.fstat(self.fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            self.close()
            raise KeyLogError('Choose a regular key-log file owned by your user.')
        self.inode = (info.st_dev, info.st_ino)
        self.offset = 0
        self.partial = b''

    def read(self):
        info = os.fstat(self.fd)
        try:
            current = os.stat(self.path)
        except OSError:
            current = None
        if current is None or (current.st_dev, current.st_ino) != self.inode:
            raise KeyLogError('Key log was rotated or removed.')
        if info.st_size < self.offset:
            raise KeyLogError('Key log was truncated.')
        if info.st_size > MAX_KEYLOG:
            raise KeyLogError('Live key log exceeds 256 KiB.', 'budget')
        if info.st_size == self.offset:
            return ''
        os.lseek(self.fd, self.offset, os.SEEK_SET)
        raw = os.read(self.fd, MAX_KEYLOG + 1 - self.offset)
        self.offset += len(raw)
        data = self.partial + raw
        # Browsers append asynchronously; never parse a partly written line.
        cut = data.rfind(b'\n') + 1
        self.partial = data[cut:]
        if len(self.partial) > 4096:
            raise KeyLogError('Key log line is too long.')
        try:
            return data[:cut].decode('ascii')
        except UnicodeDecodeError:
            raise KeyLogError('Key log is not ASCII.') from None

    def close(self):
        os.close(self.fd)


class LiveDecoder:
    """Owns the pcap stream decoder and the Decryptor; the coordinator (inside the monitor) owns the bytes."""
    def __init__(self, monitor=None, keys=None):
        if monitor is None:
            monitor = CaptureMonitor(lambda event: None, max_connections=MAX_CONNECTIONS, byte_limit=16384,
                                     all_events=True, retain=RetentionBudget(per_direction=MAX_STREAM, connections=MAX_CONNECTIONS))
        if monitor.coordinator.retain is None:
            raise ValueError('LiveDecoder needs a CaptureMonitor with a retention budget')
        self.monitor = monitor
        self.keys = keys if keys is not None else KeyProvider()
        self.decryptor = Decryptor(monitor.coordinator, self.keys)
        self.decoder = PcapStreamDecoder()
        self.frames = 0
        self.consumed = 0

    def feed(self, chunk, now=None):
        self.consumed += len(chunk)
        if self.consumed > LIMIT:
            raise DecryptionError('Live decryption reached its 2 MiB capture budget; restart for a new sample.', 'budget_exhausted')
        records = self.decoder.feed(chunk)
        self.frames += len(records)
        if self.frames > MAX_FRAMES:
            raise DecryptionError('Live decryption reached 20,000 frames.', 'budget_exhausted')
        now = time.monotonic() if now is None else now
        for record in records:
            self.monitor.accept(record, now)
        self.decryptor.pump()

    def advance(self, keylog_text=None, quantum=WORK_QUANTUM, rounds=16):
        """Append new key-log lines (if any) and do one bounded slice of decoding work."""
        if keylog_text:
            self.keys.append(keylog_text)
        self.decryptor.pump()
        return self.decryptor.work(quantum, rounds)

    def end(self, reason='Capture stopped before initial message completed'):
        self.decoder.end()
        self.monitor.coordinator.end(reason)
        self.decryptor.pump()
        self.decryptor.work(1 << 20, 1)

    def snapshot(self):
        """A status read: assembles cached rows, performs no parsing and no cryptography."""
        result = dict(self.decryptor.report(self.frames, 0))
        result['profile'] = 'Live TLS 1.2/1.3 POC; incremental record authentication; capture quality provisional until stop.'
        return result


def emit(event):
    print(json.dumps(event), flush=True)


def limit_cpu(seconds):
    """Mirror the offline worker: a CPU budget, not only a supervisor wall-clock timeout (A07)."""
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (seconds, seconds + 5))
    except (ImportError, ValueError, OSError):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--interface', required=True)
    parser.add_argument('--filter', required=True)
    parser.add_argument('--duration', type=int, required=True)
    args = parser.parse_args()
    process = keys = None
    monitor = CaptureMonitor(emit, max_connections=MAX_CONNECTIONS, byte_limit=16384, all_events=True,
                             retain=RetentionBudget(per_direction=MAX_STREAM, connections=MAX_CONNECTIONS))
    decoder = LiveDecoder(monitor)
    started = time.monotonic()
    diagnostics = CaptureDiagnostics()
    stopped = False
    def stop(*_):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    limit_cpu(max(10, args.duration // 2 + 10))
    error = None
    try:
        # Path goes through stdin, not the process argument list.
        options = json.loads(sys.stdin.readline(4096))
        keys = KeyLog(options['keylog_path'])
        decoder.advance(keys.read())
        process = subprocess.Popen(capture_command(args.interface, args.filter),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, 'packets')
            selector.register(process.stderr, selectors.EVENT_READ, 'diagnostics')
            deadline, tick = time.monotonic() + args.duration, 0
            stopping_at = None
            while selector.get_map():
                now = time.monotonic()
                if (stopped or now >= deadline) and stopping_at is None:
                    process.send_signal(signal.SIGINT)
                    stopping_at = now
                if stopping_at is not None and now - stopping_at > 3:
                    process.kill()
                    break
                for selected, _ in selector.select(0.2):
                    chunk = os.read(selected.fd, 65536)
                    if not chunk:
                        selector.unregister(selected.fileobj)
                    elif selected.data == 'packets':
                        decoder.feed(chunk, now)
                        decoder.advance()                  # one bounded slice per read: the pipe keeps draining
                    else:
                        diagnostics.feed(chunk)
                if now >= tick:
                    monitor.coordinator.tick(now)          # stage 3 (A04): idle expiry happens here
                    decoder.advance(keys.read())           # append-only key log; late keys wake waiting connections
                    emit(monitor.summary(now - started))
                    emit(dict(type='decryption', report=decoder.snapshot(), provisional=True))
                    tick = time.monotonic() + 1
            process.wait(timeout=3)
        diagnostics.end()
        drops = sum(diagnostics.stats.get(k, 0) for k in ('dropped_by_kernel', 'dropped_by_interface'))
        if process.returncode != 0:
            raise KeyLogError(ERROR_CODES['capture_failed'], 'capture_failed')
        if drops:
            raise KeyLogError(ERROR_CODES['capture_loss'], 'capture_loss')
        decoder.advance(keys.read())
        # Stage 3 (A04): finalize every connection still tracked, exactly once, before the final report.
        decoder.end()
        emit(dict(type='decryption', report=decoder.snapshot(), provisional=False,
                  capture_stats=diagnostics.stats,
                  capture_quality='no_kernel_drops_reported' if 'dropped_by_kernel' in diagnostics.stats else 'unverified'))
        emit(monitor.summary(time.monotonic() - started, final=True, capture_stats=diagnostics.stats))
    except Exception as failure:          # noqa: BLE001 - every failure is mapped to a sanitized code below
        # Never echo key-file contents, paths, or parser input in diagnostics: only a code and its fixed text.
        if isinstance(failure, KeyLogError):
            code = failure.code
        elif isinstance(failure, DecryptionError):
            code = 'budget' if failure.code == 'budget_exhausted' else 'key_log'
        elif isinstance(failure, (OSError, KeyError, json.JSONDecodeError)):
            code = 'key_log'
        else:
            code = 'internal'
        error = ERROR_CODES[code]
        monitor.invalidate_all(error, scope='all_observations_this_capture')
        emit({'type': 'decryption', 'report': {'connections': [], 'frames': decoder.frames, 'decrypted': 0}})
        emit({'type': 'error', 'reason': error, 'code': code})
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()
            process.stderr.close()
        if keys is not None:
            keys.close()
    return 1 if error else 0


if __name__ == '__main__':
    sys.exit(main())
