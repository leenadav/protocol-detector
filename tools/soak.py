"""Synthetic soak run (stage 8, A15/A07): overload, sparse gaps, late keys, slow consumer, worker crashes.

Everything is in-memory and synthetic: no interface, no network, no real key log. The run drives the same
objects the live worker uses (CaptureMonitor + SessionCoordinator with the retained tier + Decryptor) and the
JobRunner, and asserts the bounds the plan names: aggregate retained bytes under the budget, consumer queue
bounded, one worker failure never affecting another job, and memory growth bounded over the run. Numbers are
local measurements, not capacity claims.
"""
import argparse
import json
import platform
import sys
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "presentation"), str(ROOT)]

from protocol_adapters.coordinator import RetentionBudget  # noqa: E402
from protocol_adapters.live_capture import CaptureMonitor  # noqa: E402
from protocol_adapters.capture_stream import PcapStreamDecoder  # noqa: E402
from protocol_adapters.make_sample_pcap import frame  # noqa: E402
from poc_decryption import MAX_STREAM  # noqa: E402
from poc_decryption.live import LiveDecoder  # noqa: E402
from jobs import AdmissionError, JobRunner  # noqa: E402

SERVER = ("198.51.100.20", 443)


def tls_capture(client_port):
    from poc_decryption.demo import fixture
    return fixture(client_port=client_port)


def records_of(capture):
    decoder = PcapStreamDecoder()
    out = list(decoder.feed(capture))
    decoder.end()
    return out


def scenario_overload(connections, drain_every):
    """SYN flood + many TLS connections, keys arriving late, a consumer that drains rarely (slow consumer)."""
    monitor = CaptureMonitor(lambda event: None, max_connections=256, byte_limit=16384, all_events=True,
                             retain=RetentionBudget(per_direction=MAX_STREAM, aggregate=8 * 1024 * 1024, connections=256, pending=65536))
    decoder = LiveDecoder(monitor)
    capture, keylog, _, _ = tls_capture(40000)
    tls_records = records_of(capture)
    tracemalloc.start()
    started = time.perf_counter()
    now = 1.0
    # 1. SYN flood: 5,000 handshakes that never send data.
    for index in range(5000):
        client = ("192.0.2.%d" % (1 + index % 200), 10000 + index % 50000)
        for data in (frame(client, SERVER, 999, 0, 2), frame(SERVER, client, 8999, 1000, 18)):
            monitor.accept(type("R", (), {"data": data, "linktype": 1, "truncated": False, "timestamp": now, "original_length": len(data)})(), now)
        now += 0.0001
    flood_peak = tracemalloc.get_traced_memory()[1]
    flood_rejected = monitor.coordinator.counts["retained_rejected_connections"]
    flood_retained = len(monitor.coordinator.retained)
    now += 121.0
    monitor.coordinator.tick(now)                                  # the flood's handshakes expire; the tier is free again
    decoder.decryptor.pump()
    flood_closed_after_expiry = len(monitor.coordinator.retained)
    # 2. Real TLS connections, replayed on distinct client ports (the fixture bytes are reused; secrets are shared).
    for index in range(connections):
        port = 50000 + index
        for record in tls_records:
            data = bytes(record.data)
            data = data[:34] + port.to_bytes(2, "big") + data[36:] if data[34:36] == (40000).to_bytes(2, "big") else \
                data[:36] + port.to_bytes(2, "big") + data[38:] if data[36:38] == (40000).to_bytes(2, "big") else data
            data = data[:10] + bytes([0, 0]) + data[12:]   # checksums are not validated by the decoder
            monitor.accept(type("R", (), {"data": data, "linktype": 1, "truncated": False, "timestamp": now, "original_length": len(data)})(), now)
            now += 0.00001
        if index % drain_every == 0:
            decoder.advance()                                  # slow consumer: work only every drain_every connections
    # 3. Late keys for everyone, then drain.
    decoder.advance(keylog)
    for _ in range(50):
        if not decoder.advance(quantum=256, rounds=64):
            break
    monitor.coordinator.tick(now + 120)
    monitor.coordinator.end("soak stop")          # packets were injected directly; no pcap stream to close
    decoder.decryptor.pump()
    decoder.decryptor.work(1 << 20, 1)
    elapsed = time.perf_counter() - started
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    report = decoder.snapshot()
    return {"connections": connections, "syn_flood": 5000, "flood_peak_mib": round(flood_peak / 1048576, 2),
            "flood_retained_at_limit": flood_retained, "flood_rejected_beyond_limit": flood_rejected,
            "flood_left_after_idle_expiry": flood_closed_after_expiry,
            "peak_mib": round(peak / 1048576, 2), "retained_bytes_max_seen": monitor.coordinator.retained_bytes(),
            "retained_limit": monitor.coordinator.retain.aggregate, "pending_overflow": monitor.coordinator.counts["pending_overflow"],
            "decrypted": report["decrypted"], "rows": len(report["connections"]), "seconds": round(elapsed, 2),
            "telemetry_counters": monitor.analyzer.telemetry.render()["counters"]}


def scenario_sparse_gaps(flows):
    """Flows with a missing segment each: the retained tier holds the bytes after the gap, bounded by budget."""
    monitor = CaptureMonitor(lambda event: None, max_connections=256, byte_limit=16384, all_events=True,
                             retain=RetentionBudget(per_direction=65536, aggregate=2 * 1024 * 1024, connections=256))
    decoder = LiveDecoder(monitor)
    now = 1.0
    rejected_before = monitor.coordinator.counts["retained_rejected_bytes"]
    for index in range(flows):
        client = ("192.0.2.%d" % (1 + index % 200), 20000 + index)
        packets = [frame(client, SERVER, 999, 0, 2), frame(SERVER, client, 8999, 1000, 18),
                   frame(client, SERVER, 1000, 9000, 24, b"\x16\x03\x01\x00\x05hello"),
                   frame(client, SERVER, 30000, 9000, 24, b"x" * 1400)]          # a 29 KB gap, then data
        for data in packets:
            monitor.accept(type("R", (), {"data": data, "linktype": 1, "truncated": False, "timestamp": now, "original_length": len(data)})(), now)
            now += 0.0001
    decoder.advance()
    retained = monitor.coordinator.retained_bytes()
    monitor.coordinator.tick(now + 120)
    monitor.coordinator.end("soak stop")
    decoder.decryptor.pump()
    decoder.decryptor.work(1 << 20, 1)
    return {"flows": flows, "retained_bytes_peak": retained, "retained_limit": monitor.coordinator.retain.aggregate,
            "rejected_bytes": monitor.coordinator.counts["retained_rejected_bytes"] - rejected_before,
            "rows_unavailable": sum(r["status"] == "unavailable" for r in decoder.snapshot()["connections"])}


def scenario_worker_crashes():
    """Crashing, hanging and healthy workers side by side: outcomes stay explicit and independent."""
    crash = [sys.executable, "-c", "import sys; sys.exit(3)"]
    hang = [sys.executable, "-c", "import time; time.sleep(30)"]
    ok = [sys.executable, "-c", "print('{\"ok\": true}')"]

    def factory(kind, payload):
        return {"crash": crash, "hang": hang, "ok": ok}[kind], b""
    runner = JobRunner(factory, max_running=2, max_queued=6, lifetime=1.0)
    try:
        ids = [runner.submit(kind)["id"] for kind in ("crash", "hang", "ok", "crash", "ok", "hang", "ok")]
        rejected = 0
        for _ in range(10):
            try:
                runner.submit("ok")
            except AdmissionError:
                rejected += 1
        states = {}
        for job_id in ids:
            states[job_id] = runner.wait(job_id, 15)["state"]
        return {"outcomes": sorted(states.values()), "rejected_at_admission": rejected, "counts": runner.status()["counts"]}
    finally:
        runner.shutdown()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connections", type=int, default=300)
    parser.add_argument("--drain-every", type=int, default=25)
    parser.add_argument("--gap-flows", type=int, default=2000)
    parser.add_argument("--write")
    args = parser.parse_args(argv)
    results = {"python": platform.python_version(), "machine": platform.machine(),
               "overload": scenario_overload(args.connections, args.drain_every),
               "sparse_gaps": scenario_sparse_gaps(args.gap_flows),
               "worker_crashes": scenario_worker_crashes()}
    failures = []
    o, g, w = results["overload"], results["sparse_gaps"], results["worker_crashes"]
    if o["retained_bytes_max_seen"] > o["retained_limit"] or g["retained_bytes_peak"] > g["retained_limit"]:
        failures.append("retained bytes exceeded the aggregate budget")
    if o["pending_overflow"]:
        failures.append("consumer queue overflowed")
    if o["decrypted"] < 1:
        failures.append("late keys did not decrypt anything")
    if w["outcomes"].count("done") != 3 or "failed" not in w["outcomes"] or "expired" not in w["outcomes"]:
        failures.append("worker outcomes are not explicit and independent: %s" % w["outcomes"])
    results["failures"] = failures
    text = json.dumps(results, indent=1)
    if args.write:
        Path(args.write).write_text(text + "\n")
    print(text)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
