"""D11: separated performance measurements on the local host (never a capacity claim).

Four measurements, each with its own method, reported side by side instead of one blended number:

  cpu          CPU time per flow split by layer: frame decode (link_packets), engine (Inspector.feed on
               the payload alone) and the whole adapter path (Analyzer.process: reassembly, lifecycle,
               verdict). Per-call perf_counter samples, warm-up excluded, process_time for the share of
               CPU; the adapter overhead is "adapter minus engine minus decode".
  bytes        bytes-to-identification per family: the shortest prefix of each labelled stream fixture
               that already identifies the family (the engine's own answer, searched over prefixes),
               with the fixture length and the bytes the engine inspected.
  queue        consumer-queue wait in the SessionCoordinator under drain cadences (every 1 / 25 / 250
               packets): events drained, p50/p99 wait on the capture clock and the maximum depth; the
               wait is a property of the consumer's cadence, not of the engine.
  memory       tracemalloc bytes per connection for the states held at once: SYN-only (handshake never
               completed), identified and closed both ways (retired), identified but half-closed (the
               server direction still tracked), and half a message retained while waiting for more bytes.
  breakdown    cProfile of the adapter path on the small HTTP flow: the functions that carry the adapter
               overhead, by cumulative share, so the separation above points at code.

Synthetic frames in memory; single process; the host is named in the report. The numbers are local CPU
work and allocation on that host and say nothing about a production SWG's end-to-end latency, about
throughput on other hardware, or about long-running behaviour (no 24-hour soak was run).
"""
import argparse
import json
import platform
import statistics
import sys
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from protocol_adapters.analyze_pcap import Analyzer  # noqa: E402
from protocol_adapters.coordinator import RetentionBudget  # noqa: E402
from protocol_adapters.link_packets import decode_frame  # noqa: E402
from protocol_adapters.live_capture import CaptureMonitor  # noqa: E402
from protocol_adapters.make_sample_pcap import frame, udp_frame  # noqa: E402
from protocol_adapters.protocol_fixtures import DNS, STREAM_CASES, client_hello_with  # noqa: E402
from protocol_engine import Config, Inspector  # noqa: E402
from protocol_engine.descriptors import build  # noqa: E402
from protocol_engine.registry import PARSERS  # noqa: E402

DESCRIPTORS = build()
CLIENT, SERVER = ("192.0.2.10", 52000), ("198.51.100.20", 8000)
REQUEST = b"GET /index.html HTTP/1.1\r\nHost: perf.example\r\nUser-Agent: perf/1\r\nAccept: */*\r\n\r\n"
LONG_HEADERS = b"GET / HTTP/1.1\r\nHost: perf.example\r\n" + b"X-Padding: " + b"a" * 6000 + b"\r\n\r\n"
UNKNOWN = bytes(range(200, 256)) * 4


class Record:
    __slots__ = ("data", "linktype", "truncated", "timestamp", "original_length")

    def __init__(self, data, timestamp):
        self.data, self.linktype, self.truncated, self.timestamp, self.original_length = data, 1, False, timestamp, len(data)


def quantiles(samples):
    ordered = sorted(samples)
    pick = lambda q: ordered[min(len(ordered) - 1, int(round(q * (len(ordered) - 1))))]  # noqa: E731
    return {"p50_us": round(pick(0.5) / 1000, 2), "p95_us": round(pick(0.95) / 1000, 2), "p99_us": round(pick(0.99) / 1000, 2),
            "mean_us": round(statistics.fmean(ordered) / 1000, 2), "samples": len(ordered)}


def connection_frames(client, server, payload, chunk=None):
    frames = [frame(client, server, 999, 0, 2), frame(server, client, 8999, 1000, 18), frame(client, server, 1000, 9000, 16)]
    pieces = [payload] if chunk is None else [payload[i:i + chunk] for i in range(0, len(payload), chunk)]
    seq = 1000
    for piece in pieces:
        frames.append(frame(client, server, seq, 9000, 24, piece))
        seq += len(piece)
    frames.append(frame(client, server, seq, 9000, 17))
    return frames


# -- 1. CPU by layer ---------------------------------------------------------------------------------

def cpu_profile(iterations):
    hello = client_hello_with([(0, b"\x00\x0f\x00\x00\x0cperf.example")])
    flows = {"http_small": (REQUEST, None), "http_fragmented_32": (LONG_HEADERS, 32), "tls_client_hello": (hello, None),
             "tls_client_hello_16": (hello, 16), "unknown_payload": (UNKNOWN, None)}
    out = {}
    warm = 20
    for name, (payload, chunk) in flows.items():
        frames = connection_frames(CLIENT, SERVER, payload, chunk)
        decode_ns, engine_ns, adapter_ns = [], [], []
        cpu_decode = cpu_engine = cpu_adapter = 0.0
        pieces = [payload] if chunk is None else [payload[i:i + chunk] for i in range(0, len(payload), chunk)]
        for iteration in range(iterations + warm):
            # decode layer: every frame of the connection
            started_cpu = time.process_time()
            started = time.perf_counter_ns()
            packets = [decode_frame(data, 1) for data in frames]
            elapsed = time.perf_counter_ns() - started
            cpu_d = time.process_time() - started_cpu
            # engine layer: the payload through one Inspector, same chunking
            inspector = Inspector(Config())
            started_cpu = time.process_time()
            started = time.perf_counter_ns()
            for piece in pieces:
                inspector.feed(piece)
            inspector.end("fin")
            engine = time.perf_counter_ns() - started
            cpu_e = time.process_time() - started_cpu
            # adapter path: the decoded packets through a fresh Analyzer (reassembly, lifecycle, verdict)
            analyzer = Analyzer(on_session=lambda record: None, idle_timeout=60)
            started_cpu = time.process_time()
            started = time.perf_counter_ns()
            for index, packet in enumerate(packets):
                analyzer.process(index * 0.001, packet)
            analyzer.finish("eof")
            adapter = time.perf_counter_ns() - started
            cpu_a = time.process_time() - started_cpu
            if iteration >= warm:
                decode_ns.append(elapsed)
                engine_ns.append(engine)
                adapter_ns.append(adapter)
                cpu_decode += cpu_d
                cpu_engine += cpu_e
                cpu_adapter += cpu_a
        total_cpu = cpu_decode + cpu_engine + cpu_adapter
        out[name] = {"frames": len(frames), "payload_bytes": len(payload),
                     "decode": quantiles(decode_ns), "engine": quantiles(engine_ns), "adapter_path": quantiles(adapter_ns),
                     "adapter_overhead_us_p50": round(max(0.0, quantiles(adapter_ns)["p50_us"] - quantiles(engine_ns)["p50_us"] - quantiles(decode_ns)["p50_us"]), 2),
                     "cpu_share": {"decode": round(cpu_decode / total_cpu, 3) if total_cpu else None,
                                   "engine": round(cpu_engine / total_cpu, 3) if total_cpu else None,
                                   "adapter_path": round(cpu_adapter / total_cpu, 3) if total_cpu else None},
                     "engine_bytes_inspected": inspector.metrics.bytes_inspected}
    return out


# -- 2. bytes to identification ---------------------------------------------------------------------

def family_of(label):
    return (label or "").split("/", 1)[0]


def identifies(data, family, hint):
    inspector = Inspector(Config(), protocol_hint=hint)
    inspector.feed(data)
    observation = inspector.observation
    return observation.status == "identified" and family_of(observation.application_protocol or observation.encryption) == family, inspector


def bytes_to_identification():
    rows = {}
    for data, label in STREAM_CASES:
        family = family_of(label)
        hint = family if DESCRIPTORS[family].requires_hint and family in PARSERS else None
        whole, inspector = identifies(data, family, hint)
        if not whole:
            continue
        # The shortest prefix that identifies: identification is monotone in the prefix for a
        # self-delimiting message, but a linear scan is kept to avoid assuming it.
        shortest = len(data)
        for cut in range(1, len(data) + 1):
            if identifies(data[:cut], family, hint)[0]:
                shortest = cut
                break
        row = rows.setdefault(family, {"fixtures": 0, "shortest_prefix": [], "fixture_bytes": [], "inspected_bytes": []})
        row["fixtures"] += 1
        row["shortest_prefix"].append(shortest)
        row["fixture_bytes"].append(len(data))
        row["inspected_bytes"].append(inspector.metrics.bytes_inspected)
    table = {}
    for family in sorted(rows):
        row = rows[family]
        table[family] = {"fixtures": row["fixtures"], "shortest_prefix_min": min(row["shortest_prefix"]),
                         "shortest_prefix_max": max(row["shortest_prefix"]), "fixture_bytes_max": max(row["fixture_bytes"]),
                         "inspected_bytes_max": max(row["inspected_bytes"])}
    all_prefixes = [value for row in rows.values() for value in row["shortest_prefix"]]
    return {"families": table, "summary": {"fixtures": len(all_prefixes), "median_shortest_prefix": statistics.median(all_prefixes) if all_prefixes else None,
                                           "max_shortest_prefix": max(all_prefixes) if all_prefixes else None}}


# -- 3. queue wait under consumer cadences ----------------------------------------------------------

def queue_profile(connections, cadences):
    out = {}
    hello = client_hello_with([])
    for cadence in cadences:
        monitor = CaptureMonitor(lambda event: None, max_connections=max(256, connections), byte_limit=16384, idle_timeout=60,
                                 retain=RetentionBudget(per_direction=65536, aggregate=64 * 1024 * 1024, connections=max(64, connections), pending=1 << 20))
        now = 0.0
        depth_max = 0
        packets = 0
        started = time.perf_counter_ns()
        for index in range(connections):
            client = ("192.0.2.%d" % (1 + index % 200), 10000 + index)
            for data in connection_frames(client, ("198.51.100.20", 443), hello):
                monitor.accept(Record(data, now), now)
                now += 0.0005
                packets += 1
                depth_max = max(depth_max, len(monitor.coordinator._pending))
                if packets % cadence == 0:
                    monitor.coordinator.drain()
            monitor.coordinator.tick(now)
        monitor.coordinator.drain()
        elapsed_ms = (time.perf_counter_ns() - started) / 1e6
        rendered = monitor.analyzer.telemetry.render()
        wait = rendered["histograms"].get("queue.wait_seconds", {})
        out["drain_every_%d" % cadence] = {"packets": packets, "events_drained": rendered["counters"].get("queue.drained", 0),
                                          "queue_depth_max": depth_max, "wait_p50_s": wait.get("p50"), "wait_p99_s": wait.get("p99"),
                                          "wait_max_s": round(wait["max"], 4) if wait.get("max") is not None else None, "wall_ms": round(elapsed_ms, 1),
                                          "us_per_packet": round(elapsed_ms * 1000 / packets, 2)}
    return out


# -- 4. memory per connection state -----------------------------------------------------------------

def memory_profile(connections):
    out = {}
    scenarios = {
        "syn_only": lambda client: [frame(client, SERVER, 999, 0, 2)],
        "identified_closed_both_ways": lambda client: connection_frames(client, SERVER, REQUEST) + [frame(SERVER, client, 9000, 1000 + len(REQUEST) + 1, 17)],
        "identified_half_closed": lambda client: connection_frames(client, SERVER, REQUEST),
        "half_message_retained": lambda client: connection_frames(client, SERVER, REQUEST, None)[:3] + [frame(client, SERVER, 1000, 9000, 24, REQUEST[:20])],
    }
    for name, builder in scenarios.items():
        analyzer = Analyzer(on_session=lambda record: None, max_connections=connections + 16, idle_timeout=3600)
        tracemalloc.start()
        base = tracemalloc.get_traced_memory()[0]
        for index in range(connections):
            client = ("192.0.2.%d" % (1 + index % 200), 10000 + index)
            for data in builder(client):
                analyzer.process(0.001 * index, decode_frame(data, 1))
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        out[name] = {"connections": connections, "tracked_now": len(analyzer.tracked),
                     "bytes_per_connection_held": round((current - base) / connections),
                     "peak_bytes_per_connection": round((peak - base) / connections)}
        analyzer.finish("eof")
    datagrams = Analyzer(on_session=lambda record: None, idle_timeout=3600)
    tracemalloc.start()
    base = tracemalloc.get_traced_memory()[0]
    for index in range(connections):
        datagrams.process(0.001 * index, decode_frame(udp_frame(("192.0.2.%d" % (1 + index % 200), 20000 + index), ("198.51.100.53", 53), DNS), 1))
    current, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    out["udp_flow_identified"] = {"connections": connections, "flows_now": len(datagrams.udp_flows), "bytes_per_connection_held": round((current - base) / connections)}
    return out


# -- 5. where the adapter overhead goes ---------------------------------------------------------------

def breakdown_profile(flows=300, top=8):
    import cProfile
    import pstats
    packets = [decode_frame(data, 1) for data in connection_frames(CLIENT, SERVER, REQUEST)]
    profiler = cProfile.Profile()
    profiler.enable()
    for _ in range(flows):
        analyzer = Analyzer(on_session=lambda record: None, idle_timeout=60)
        for index, packet in enumerate(packets):
            analyzer.process(index * 0.001, packet)
        analyzer.finish("eof")
    profiler.disable()
    stats = pstats.Stats(profiler)
    total = stats.total_tt
    rows = []
    for (filename, line, function), (calls, _, _, cumulative, _) in stats.stats.items():
        if "protocol_" not in filename or function in ("process", "finish", "<lambda>"):
            continue
        rows.append({"function": "%s:%s" % (Path(filename).name, function), "calls_per_flow": round(calls / flows, 1),
                     "cumulative_us_per_flow": round(cumulative * 1e6 / flows, 1), "share": round(cumulative / total, 3) if total else None})
    rows.sort(key=lambda row: -row["cumulative_us_per_flow"])
    return {"flows": flows, "total_us_per_flow": round(total * 1e6 / flows, 1), "top": rows[:top]}


# -- report ----------------------------------------------------------------------------------------

def run(iterations=200, queue_connections=300, memory_connections=1000, cadences=(1, 25, 250), sections=("cpu", "bytes", "queue", "memory", "breakdown")):
    report = {"environment": {"python": platform.python_version(), "platform": platform.platform(), "iterations": iterations,
                              "queue_connections": queue_connections, "memory_connections": memory_connections},
              "scope": "Local single-process measurements on synthetic frames; not a capacity, SWG latency or long-run claim."}
    if "cpu" in sections:
        report["cpu"] = cpu_profile(iterations)
    if "bytes" in sections:
        report["bytes_to_identification"] = bytes_to_identification()
    if "queue" in sections:
        report["queue"] = queue_profile(queue_connections, cadences)
    if "memory" in sections:
        report["memory"] = memory_profile(memory_connections)
    if "breakdown" in sections:
        report["breakdown"] = breakdown_profile()
    return report


def render(report):
    env = report["environment"]
    lines = ["# Performance profile (D11)", "",
             "`python3 -B tools/perf_profile.py` on %s, Python %s; %d iterations per CPU case, %d connections for the queue "
             "measurement, %d for memory. %s" % (env["platform"], env["python"], env["iterations"], env["queue_connections"],
                                                  env["memory_connections"], report["scope"]), ""]
    if "cpu" in report:
        lines += ["## CPU per flow by layer (µs, p50 / p95 / p99)", "",
                  "| flow | frames | payload | decode | engine | adapter path | adapter overhead p50 | CPU share decode/engine/adapter |",
                  "|---|---|---|---|---|---|---|---|"]
        for name, row in report["cpu"].items():
            fmt = lambda q: "%.1f / %.1f / %.1f" % (q["p50_us"], q["p95_us"], q["p99_us"])  # noqa: E731
            share = row["cpu_share"]
            lines.append("| %s | %d | %d | %s | %s | %s | %.1f | %s / %s / %s |" % (
                name, row["frames"], row["payload_bytes"], fmt(row["decode"]), fmt(row["engine"]), fmt(row["adapter_path"]),
                row["adapter_overhead_us_p50"], share["decode"], share["engine"], share["adapter_path"]))
        lines += ["", "The adapter path includes the engine and reassembly; its overhead is the difference of medians and is a "
                  "property of the Python adapter, not of the parsers.", ""]
    if "bytes_to_identification" in report:
        summary = report["bytes_to_identification"]["summary"]
        lines += ["## Bytes to identification", "",
                  "%d fixtures identified; median shortest identifying prefix %s bytes, maximum %s bytes." % (
                      summary["fixtures"], summary["median_shortest_prefix"], summary["max_shortest_prefix"]), "",
                  "| family | fixtures | shortest prefix min–max | fixture bytes max | inspected max |", "|---|---|---|---|---|"]
        for family, row in report["bytes_to_identification"]["families"].items():
            lines.append("| %s | %d | %d–%d | %d | %d |" % (family, row["fixtures"], row["shortest_prefix_min"], row["shortest_prefix_max"],
                                                          row["fixture_bytes_max"], row["inspected_bytes_max"]))
        lines += ["", "The shortest prefix is the engine's own earliest identification of each fixture; a profile that needs the whole "
                  "message reports the fixture length.", ""]
    if "queue" in report:
        lines += ["## Consumer-queue wait by drain cadence", "",
                  "| drain every | packets | events drained | depth max | wait p50 / p99 / max (capture s) | µs per packet |", "|---|---|---|---|---|---|"]
        for name, row in report["queue"].items():
            lines.append("| %s | %d | %d | %d | %s / %s / %s | %.1f |" % (name.replace("drain_every_", ""), row["packets"], row["events_drained"],
                                                                        row["queue_depth_max"], row["wait_p50_s"], row["wait_p99_s"], row["wait_max_s"], row["us_per_packet"]))
        lines += ["", "Wait is measured on the capture clock between enqueue and drain (`queue.wait_seconds`); it grows with the consumer's "
                  "cadence while the per-packet CPU does not.", ""]
    if "memory" in report:
        lines += ["## Memory per connection state (tracemalloc)", "", "| state | connections | held bytes / connection | peak bytes / connection |", "|---|---|---|---|"]
        for name, row in report["memory"].items():
            lines.append("| %s | %d | %d | %s |" % (name, row["connections"], row["bytes_per_connection_held"], row.get("peak_bytes_per_connection", "—")))
        lines += ["", "Held bytes are what stays allocated while the connection is tracked; retired connections hold their session "
                  "record only until the sink consumes it.", ""]
    if "breakdown" in report:
        lines += ["## Where the adapter path spends its time (cProfile, small HTTP flow)", "",
                  "| function | calls / flow | cumulative µs / flow | share |", "|---|---|---|---|"]
        for row in report["breakdown"]["top"]:
            lines.append("| %s | %.1f | %.1f | %s |" % (row["function"], row["calls_per_flow"], row["cumulative_us_per_flow"], row["share"]))
        lines += ["", "Cumulative shares overlap (callers include callees); profiling overhead inflates absolute numbers, the ranking is the point.", ""]
    lines += ["These are local measurements on the named host. They are not throughput or capacity figures for any production "
              "deployment, and no long-running soak is claimed here (docs/SOAK-V065.md describes the bounded synthetic soak)."]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--iterations", type=int, default=200)
    parser.add_argument("--queue-connections", type=int, default=300)
    parser.add_argument("--memory-connections", type=int, default=1000)
    parser.add_argument("--sections", default="cpu,bytes,queue,memory,breakdown")
    parser.add_argument("--write", help="Markdown report path")
    parser.add_argument("--json", help="JSON report path")
    args = parser.parse_args(argv)
    if not 5 <= args.iterations <= 10000 or not 10 <= args.queue_connections <= 100000 or not 10 <= args.memory_connections <= 100000:
        parser.error("iterations 5..10000, connections 10..100000")
    report = run(args.iterations, args.queue_connections, args.memory_connections, sections=tuple(args.sections.split(",")))
    text = render(report)
    if args.write:
        Path(args.write).write_text(text, encoding="utf-8")
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(text if not (args.write or args.json) else text.splitlines()[2])
    return 0


if __name__ == "__main__":
    sys.exit(main())
