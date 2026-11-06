"""Stage 0 baseline: reproduce the architecture review's runtime findings on the current head.

Usage: python3 -B tools/stage0_baseline.py   (needs cryptography, see presentation/requirements-decryption.txt)

Synthetic, in-memory traffic only; no capture, no key log on disk beyond a temporary file. Each line is a
measurement the later stages must change (A02, A04, A07) or must keep (the fixed counts). Re-run it after
each stage and compare.
"""
import os
import sys
import tempfile
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "presentation"), str(ROOT)]

import poc_decryption.capture as capture_module  # noqa: E402
from live_capture import CaptureMonitor  # noqa: E402
from make_sample_pcap import frame, pcap_bytes  # noqa: E402
from poc_decryption.demo import fixture  # noqa: E402
from poc_decryption.live import KeyLog, LiveDecoder  # noqa: E402
from sessions import Stream  # noqa: E402


def counting_decrypt():
    calls = {"decrypt_streams": 0, "bytes_analyzed": 0}
    real_decrypt, real_analyze = capture_module.decrypt_streams, capture_module.analyze_capture

    def decrypt(*args, **kwargs):
        calls["decrypt_streams"] += 1
        return real_decrypt(*args, **kwargs)

    def analyze(data, keylog):
        calls["bytes_analyzed"] += len(data)
        return real_analyze(data, keylog)
    return calls, decrypt, analyze


def a02_unchanged_snapshots(capture, keylog, snapshots=5):
    import poc_decryption.live as live_module
    calls, decrypt, analyze = counting_decrypt()
    capture_module.decrypt_streams, live_module.analyze_capture = decrypt, analyze
    try:
        decoder = LiveDecoder()
        decoder.feed(capture)
        for _ in range(snapshots):
            decoder.snapshot(keylog)
    finally:
        import importlib
        importlib.reload(capture_module)
        importlib.reload(live_module)
    return calls


def a02_growth(capture, keylog, steps=10):
    """Feed the same capture in `steps` chunks with one snapshot after each: bytes re-analyzed vs bytes fed."""
    import poc_decryption.live as live_module
    calls, decrypt, analyze = counting_decrypt()
    capture_module.decrypt_streams, live_module.analyze_capture = decrypt, analyze
    try:
        decoder = LiveDecoder()
        size = -(-len(capture) // steps)
        for offset in range(0, len(capture), size):
            decoder.feed(capture[offset:offset + size])
            decoder.snapshot(keylog)
    finally:
        import importlib
        importlib.reload(capture_module)
        importlib.reload(live_module)
    return len(capture), calls["bytes_analyzed"], calls["decrypt_streams"]


def a02_keylog_rereads(keylog, ticks=5):
    with tempfile.TemporaryDirectory() as folder:
        path = os.path.join(folder, "keys.log")
        with open(path, "w") as handle:
            handle.write(keylog)
        log = KeyLog(path)
        try:
            return len(keylog.encode()), sum(len(log.read().encode()) for _ in range(ticks))
        finally:
            log.close()


def a04_no_fin_finalization():
    """A TCP connection that never sends FIN: sessions emitted when each live path stops."""
    client, server = ("192.0.2.10", 52000), ("198.51.100.20", 80)
    request = b"GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n"
    data = pcap_bytes([frame(client, server, 999, 0, 2), frame(server, client, 4999, 1000, 18),
                       frame(client, server, 1000, 5000, 24, request)])
    results = {}
    for name, finishes in (("live_capture (calls analyzer.finish)", True), ("poc_decryption.live (no finish)", False)):
        emitted = []
        monitor = CaptureMonitor(emitted.append, max_connections=64, byte_limit=16384, all_events=True)
        decoder = LiveDecoder(monitor)
        decoder.feed(data)
        if finishes:
            monitor.analyzer.finish("Capture input EOF before initial message completed")
        results[name] = sum(1 for event in emitted if event.get("type") != "classification" and "app" in event)
    return results


def a07_stream_allocation(limit=256 * 1024, flows=64):
    stream = Stream(0, limit)
    per_direction = len(stream.buffer) + len(stream.present)
    tracemalloc.start()
    streams = [Stream(0, limit) for _ in range(2 * flows)]
    current, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    del streams
    return per_direction, current


def main():
    capture, keylog, _, _ = fixture()
    calls = a02_unchanged_snapshots(capture, keylog)
    print("A02 five unchanged snapshots: decrypt_streams calls = %d, bytes re-analyzed = %d (capture %d bytes)"
          % (calls["decrypt_streams"], calls["bytes_analyzed"], len(capture)))
    fed, analyzed, decrypts = a02_growth(capture, keylog)
    print("A02 growth, 10 chunks with a snapshot after each: %d bytes fed, %d bytes analyzed (%.1fx), %d decrypt calls"
          % (fed, analyzed, analyzed / fed, decrypts))
    size, read = a02_keylog_rereads(keylog)
    print("A02 key log: %d-byte file, 5 ticks read %d bytes (%.0fx)" % (size, read, read / size))
    for name, sessions in a04_no_fin_finalization().items():
        print("A04 no-FIN connection, sessions emitted at stop via %s: %d" % (name, sessions))
    per_direction, traced = a07_stream_allocation()
    print("A07 Stream at 256 KiB limit: %d bytes allocated per direction at creation; 64 bidirectional flows: %.1f MiB traced"
          % (per_direction, traced / 1048576))


if __name__ == "__main__":
    main()
