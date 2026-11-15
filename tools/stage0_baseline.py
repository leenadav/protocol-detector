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

from live_capture import CaptureMonitor  # noqa: E402
from make_sample_pcap import frame, pcap_bytes  # noqa: E402
from poc_decryption.demo import fixture  # noqa: E402
from poc_decryption.live import KeyLog, LiveDecoder  # noqa: E402
from sessions import Stream  # noqa: E402


def a02_unchanged_snapshots(capture, keylog, snapshots=5):
    """Stage 4: records authenticated and plaintext bytes released, before vs after 5 unchanged status reads."""
    decoder = LiveDecoder()
    decoder.feed(capture, now=1.0)
    decoder.advance(keylog)
    before = dict(decoder.decryptor.counts)
    for _ in range(snapshots):
        decoder.snapshot()
        decoder.advance(keylog)
    after = decoder.decryptor.counts
    return {"decrypt_streams": after["records_authenticated"] - before["records_authenticated"],
            "bytes_analyzed": after["plaintext_bytes"] - before["plaintext_bytes"],
            "first_pass_records": before["records_authenticated"]}


def a02_growth(capture, keylog, steps=10):
    """Feed the same capture in `steps` chunks with one snapshot after each: plaintext re-released vs released once."""
    decoder = LiveDecoder()
    size = -(-len(capture) // steps)
    for offset in range(0, len(capture), size):
        decoder.feed(capture[offset:offset + size], now=1.0)
        decoder.advance(keylog)
        decoder.snapshot()
    counts = decoder.decryptor.counts
    return len(capture), counts["plaintext_bytes"], counts["records_authenticated"]


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
    # Stage 3: both live paths stop through SessionCoordinator.end (live_capture.main and
    # poc_decryption.live.main); the last line keeps the pre-stage-3 number (no lifecycle call at all).
    # The real stop path of the decryption POC is driven end to end by
    # presentation/tests/test_live_decryption.py::LiveShutdownWiringTests.
    for name, stop in (("live_capture (coordinator.end)", "end"), ("poc_decryption.live (coordinator.end)", "end"),
                       ("no lifecycle call (pre-stage-3 decryption path)", None)):
        emitted = []
        from protocol_adapters.coordinator import RetentionBudget
        monitor = CaptureMonitor(emitted.append, max_connections=64, byte_limit=16384, all_events=True,
                                 retain=RetentionBudget(connections=64))
        decoder = LiveDecoder(monitor)
        decoder.feed(data)
        if stop == "end":
            monitor.coordinator.end("Capture input EOF before initial message completed")
        results[name] = sum(1 for event in emitted if event.get("type") != "classification" and "app" in event)
    return results


def a07_stream_allocation(limit=256 * 1024, flows=64):
    stream = Stream(0, limit)
    per_direction = stream.allocated
    tracemalloc.start()
    streams = [Stream(0, limit) for _ in range(2 * flows)]
    current, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    del streams
    return per_direction, current


def main():
    capture, keylog, _, _ = fixture()
    calls = a02_unchanged_snapshots(capture, keylog)
    print("A02 five unchanged snapshots: records re-authenticated = %d, plaintext re-released = %d bytes (first pass %d records, capture %d bytes)"
          % (calls["decrypt_streams"], calls["bytes_analyzed"], calls["first_pass_records"], len(capture)))
    fed, analyzed, decrypts = a02_growth(capture, keylog)
    print("A02 growth, 10 chunks with a snapshot after each: %d bytes fed, %d plaintext bytes released in total (%.2fx of the wire), %d records authenticated"
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
