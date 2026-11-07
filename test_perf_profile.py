"""D11: separated performance measurements (CPU by layer, bytes to identification, queue wait, memory) and the queue-wait telemetry."""
import json
import os
import tempfile
import unittest

from protocol_adapters.coordinator import RetentionBudget, SessionCoordinator
from protocol_adapters.analyze_pcap import Analyzer
from protocol_adapters.link_packets import decode_frame
from protocol_adapters.make_sample_pcap import frame
from protocol_engine import content
from tools import perf_profile

CLIENT, SERVER = ("192.0.2.10", 52000), ("198.51.100.20", 80)
REQUEST = b"GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n"


class QueueWaitTelemetryTests(unittest.TestCase):
    def test_drain_records_capture_clock_wait_per_event(self):
        analyzer = Analyzer(on_session=lambda record: None, idle_timeout=60)
        coordinator = SessionCoordinator(analyzer, emit=None, retain=RetentionBudget(per_direction=4096, aggregate=65536, connections=8, pending=64))
        frames = [frame(CLIENT, SERVER, 999, 0, 2), frame(SERVER, CLIENT, 4999, 1000, 18), frame(CLIENT, SERVER, 1000, 5000, 24, REQUEST)]
        for index, data in enumerate(frames):
            coordinator.accept(decode_frame(data, 1), 1.0 + index)
        self.assertGreater(len(coordinator._pending), 0)
        coordinator.tick(10.0)                                  # the consumer drains late: every event waited on the capture clock
        items = coordinator.drain()
        self.assertTrue(all(isinstance(item, tuple) and isinstance(item[0], str) for item in items))   # items unchanged for consumers
        rendered = analyzer.telemetry.render()
        wait = rendered["histograms"]["queue.wait_seconds"]
        self.assertEqual(wait["count"], len(items))
        self.assertGreaterEqual(wait["min"], 7.0)
        self.assertEqual(rendered["counters"]["queue.drained"], len(items))
        self.assertEqual(coordinator.drain(), [])
        self.assertEqual(rendered["counters"]["queue.drained"], len(items))   # an empty drain adds nothing


class ProfileTests(unittest.TestCase):
    def test_sections_are_separate_and_bounded(self):
        report = perf_profile.run(iterations=5, queue_connections=12, memory_connections=20, cadences=(1, 5))
        self.assertEqual(set(report) - {"environment", "scope"}, {"cpu", "bytes_to_identification", "queue", "memory", "breakdown"})
        self.assertIn("not a capacity", report["scope"])
        for name, row in report["cpu"].items():
            for layer in ("decode", "engine", "adapter_path"):
                self.assertGreater(row[layer]["p50_us"], 0.0, (name, layer))
                self.assertEqual(row[layer]["samples"], 5 if layer != "decode" else 5)
            self.assertAlmostEqual(sum(row["cpu_share"].values()), 1.0, places=2)
        summary = report["bytes_to_identification"]["summary"]
        self.assertGreater(summary["fixtures"], 100)
        self.assertLessEqual(summary["max_shortest_prefix"], 65536)
        http = report["bytes_to_identification"]["families"]["http"]
        self.assertLessEqual(http["shortest_prefix_max"], http["fixture_bytes_max"])
        waits = report["queue"]
        self.assertEqual(set(waits), {"drain_every_1", "drain_every_5"})
        self.assertLessEqual(waits["drain_every_1"]["queue_depth_max"], 1)
        self.assertGreater(waits["drain_every_5"]["queue_depth_max"], waits["drain_every_1"]["queue_depth_max"])
        self.assertGreaterEqual(waits["drain_every_5"]["wait_p99_s"], waits["drain_every_1"]["wait_p99_s"])
        memory = report["memory"]
        self.assertLess(memory["identified_closed_both_ways"]["bytes_per_connection_held"], memory["identified_half_closed"]["bytes_per_connection_held"])
        self.assertLess(memory["syn_only"]["bytes_per_connection_held"], memory["half_message_retained"]["bytes_per_connection_held"])
        self.assertEqual(memory["identified_closed_both_ways"]["tracked_now"], 0)
        self.assertTrue(report["breakdown"]["top"])
        text = perf_profile.render(report)
        self.assertIn("## CPU per flow by layer", text)
        self.assertIn("## Bytes to identification", text)
        self.assertIn("## Consumer-queue wait", text)
        self.assertIn("## Memory per connection state", text)
        self.assertIn("not throughput or capacity figures", text)

    def test_command_line_writes_both_reports(self):
        with tempfile.TemporaryDirectory() as folder:
            md, js = os.path.join(folder, "p.md"), os.path.join(folder, "p.json")
            self.assertEqual(perf_profile.main(["--iterations", "5", "--queue-connections", "10", "--memory-connections", "10",
                                                "--sections", "cpu,memory", "--write", md, "--json", js]), 0)
            with open(js, encoding="utf-8") as handle:
                data = json.load(handle)
            self.assertIn("cpu", data)
            self.assertNotIn("queue", data)
            self.assertTrue(os.path.getsize(md) > 200)

    def test_content_digest_is_cached_so_analyzer_construction_stays_cheap(self):
        content.digest()
        import time
        started = time.perf_counter()
        for _ in range(50):
            Analyzer(on_session=lambda record: None)
        per_analyzer_ms = (time.perf_counter() - started) * 1000 / 50
        self.assertLess(per_analyzer_ms, 2.0, per_analyzer_ms)            # was ~3 ms with the digest recomputed each time
        self.assertEqual(content.pinned()["digest"], content.digest(content.CURRENT))


if __name__ == "__main__":
    unittest.main()
