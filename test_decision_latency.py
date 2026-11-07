"""P2 of the stage-6 review: decision latency is measured separately from session lifetime."""
import unittest

from protocol_adapters.analyze_pcap import Analyzer
from protocol_adapters.link_packets import decode_frame
from protocol_adapters.make_sample_pcap import frame, udp_frame
from protocol_adapters.protocol_fixtures import DNS

CLIENT, SERVER = ("192.0.2.10", 52000), ("198.51.100.20", 80)


class DecisionLatencyTests(unittest.TestCase):
    def test_long_lived_connection_identified_early(self):
        records = []
        analyzer = Analyzer(on_session=records.append, idle_timeout=1000)
        packets = [(0.0, frame(CLIENT, SERVER, 999, 0, 2)), (0.01, frame(SERVER, CLIENT, 8999, 1000, 18)),
                   (0.02, frame(CLIENT, SERVER, 1000, 9000, 24, b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"))]
        for when, data in packets:
            analyzer.process(when, decode_frame(data, 1))
        analyzer.process(300.0, decode_frame(frame(CLIENT, SERVER, 1035, 9000, 17), 1))   # FIN long after the decision
        analyzer.process(300.5, decode_frame(frame(SERVER, CLIENT, 9000, 1036, 17), 1))
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["app"], "web-browsing")
        self.assertAlmostEqual(record["decision"]["first_seconds"], 0.02, places=6)
        self.assertAlmostEqual(record["decision"]["stable_seconds"], 0.02, places=6)
        rendered = analyzer.telemetry.render()["histograms"]
        self.assertEqual(rendered["time_to_first_decision_seconds"]["max"], 0.02)
        self.assertEqual(rendered["session_lifetime_seconds"]["max"], 300.5)
        self.assertNotIn("time_to_verdict_seconds", rendered)

    def test_undecided_connection_reports_no_decision_and_udp_flows_decide_on_first_datagram(self):
        records = []
        analyzer = Analyzer(on_session=records.append, idle_timeout=1000)
        analyzer.process(0.0, decode_frame(frame(CLIENT, SERVER, 999, 0, 2), 1))
        analyzer.process(0.01, decode_frame(frame(SERVER, CLIENT, 8999, 1000, 18), 1))
        analyzer.process(5.0, decode_frame(udp_frame(CLIENT, ("198.51.100.20", 53), DNS), 1))
        analyzer.finish("eof")
        tcp = next(r for r in records if r["transport"] == "tcp")
        udp = next(r for r in records if r["transport"] == "udp")
        self.assertNotIn("decision", tcp)
        self.assertEqual(udp["decision"], {"first_seconds": 0.0, "stable_seconds": 0.0})
        histograms = analyzer.telemetry.render()["histograms"]
        self.assertEqual(histograms["time_to_first_decision_seconds"]["count"], 1)
        self.assertEqual(histograms["session_lifetime_seconds"]["count"], 2)


if __name__ == "__main__":
    unittest.main()
