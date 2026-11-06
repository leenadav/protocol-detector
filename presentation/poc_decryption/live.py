"""Bounded live POC: capture and key-log decoding in one Python worker.

tcpdump supplies raw packets only. Snapshots are revalidated at most once per
second; this deliberately is not a production incremental TLS record engine.
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
from protocol_adapters.live_capture import CaptureDiagnostics, CaptureMonitor, capture_command
from poc_decryption.capture import analyze_capture

LIMIT = 2 * 1024 * 1024


class KeyLog:
    def __init__(self, path):
        self.fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        info = os.fstat(self.fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            self.close()
            raise ValueError('Choose a regular key-log file owned by your user.')

    def read(self):
        if os.fstat(self.fd).st_size > 262144:
            raise ValueError('Live key log exceeds 256 KiB.')
        os.lseek(self.fd, 0, os.SEEK_SET)
        raw = os.read(self.fd, 262145)
        if len(raw) > 262144:
            raise ValueError('Live key log exceeds 256 KiB.')
        # Browsers append asynchronously; never parse a partly written line.
        return raw[:raw.rfind(b'\n') + 1].decode('ascii')

    def close(self):
        os.close(self.fd)


class LiveDecoder:
    def __init__(self, monitor=None):
        self.data = bytearray()
        self.monitor = monitor
        self.decoder = PcapStreamDecoder()
        self.frames = 0

    def feed(self, chunk):
        if len(self.data) + len(chunk) > LIMIT:
            raise ValueError('Live decryption reached its 2 MiB capture budget; restart for a new sample.')
        records = self.decoder.feed(chunk)
        self.frames += len(records)
        if self.monitor is not None:
            for record in records:
                self.monitor.accept(record, time.monotonic())
        if self.frames > 20000:
            raise ValueError('Live decryption reached 20,000 frames.')
        self.data.extend(chunk)

    def snapshot(self, keys):
        # Exclude an incomplete pipe frame, but retain it for the next read.
        end = len(self.data) - len(self.decoder.buffer)
        if end < 24:
            return {'connections': [], 'decrypted': 0, 'frames': 0}
        result = analyze_capture(bytes(self.data[:end]), keys)
        result['profile'] = 'Live TLS 1.2/1.3 POC; bounded snapshots; capture quality provisional until stop.'
        return result


def emit(event):
    print(json.dumps(event), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--interface', required=True)
    parser.add_argument('--filter', required=True)
    parser.add_argument('--duration', type=int, required=True)
    args = parser.parse_args()
    process = keys = None
    monitor = CaptureMonitor(emit, max_connections=64, byte_limit=16384, all_events=True)
    decoder = LiveDecoder(monitor)
    started = time.monotonic()
    diagnostics = CaptureDiagnostics()
    stopped = False
    def stop(*_):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    error = None
    try:
        # Path goes through stdin, not the process argument list.
        options = json.loads(sys.stdin.readline(4096))
        keys = KeyLog(options['keylog_path'])
        keys.read()
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
                        decoder.feed(chunk)
                    else:
                        diagnostics.feed(chunk)
                if now >= tick:
                    emit(monitor.summary(now-started))
                    emit(dict(type='decryption', report=decoder.snapshot(keys.read()), provisional=True))
                    tick = time.monotonic() + 1
            process.wait(timeout=3)
        decoder.decoder.end()
        diagnostics.end()
        drops = sum(diagnostics.stats.get(k, 0) for k in ('dropped_by_kernel', 'dropped_by_interface'))
        if process.returncode != 0:
            raise ValueError('Capture failed; check tcpdump permission and selected interface.')
        if drops:
            raise ValueError('Capture loss reported; decrypted results invalidated.')
        emit(dict(type='decryption', report=decoder.snapshot(keys.read()), provisional=False,
                  capture_stats=diagnostics.stats,
                  capture_quality='no_kernel_drops_reported' if 'dropped_by_kernel' in diagnostics.stats else 'unverified'))
        emit(monitor.summary(time.monotonic()-started, final=True, capture_stats=diagnostics.stats))
    except Exception:
        # Never echo key-file contents, paths, or parser input in diagnostics.
        error = 'Live decryption stopped: permission, capture/key-log format, loss or POC budget failure. Results invalidated.'
        monitor.invalidate_all(error, scope='all_observations_this_capture')
        emit({'type': 'decryption', 'report': {'connections': [], 'frames': decoder.frames, 'decrypted': 0}})
        emit({'type': 'error', 'reason': error})
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
