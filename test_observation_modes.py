"""D05: observation modes per detector; incomplete observation is distinguished from unsupported protocol."""
import unittest

from protocol_adapters.analyze_pcap import Analyzer
from protocol_adapters.link_packets import decode_frame
from protocol_adapters.make_sample_pcap import frame
from protocol_adapters.protocol_fixtures import MQTT5
from protocol_engine.descriptors import MIDSTREAM_FAMILIES, build
from protocol_engine.policy import Policy

CLIENT, SERVER = ("192.0.2.10", 52000), ("198.51.100.20", 80)
REQUEST = b"GET /second HTTP/1.1\r\nHost: a.example\r\n\r\n"
RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
TLS_APP_DATA = b"\x17\x03\x03\x00\x20" + bytes(range(32))


def analyzer(mode="handshake", **options):
    records = []
    return Analyzer(on_session=records.append, idle_timeout=1000, observation=mode, **options), records


def feed(an, when, source, destination, seq, ack, flags, payload=b""):
    return an.process(when, decode_frame(frame(source, destination, seq, ack, flags, payload), 1))


class DescriptorModeTests(unittest.TestCase):
    def test_every_tcp_family_declares_its_modes(self):
        descriptors = build()
        for family, descriptor in descriptors.items():
            if "tcp" in descriptor.transports:
                self.assertIn("handshake", descriptor.observation, family)
                self.assertEqual("midstream" in descriptor.observation, family in MIDSTREAM_FAMILIES, family)
            else:
                self.assertEqual(descriptor.observation, ("datagram",))
        self.assertNotIn("tls", MIDSTREAM_FAMILIES)        # a ClientHello profile never recurs mid-connection
        self.assertNotIn("mqtt", MIDSTREAM_FAMILIES)


class AsymmetricTests(unittest.TestCase):
    def test_client_side_only_capture(self):
        packets = [(0.0, CLIENT, SERVER, 999, 0, 2), (0.1, CLIENT, SERVER, 1000, 5000, 24, REQUEST), (0.2, CLIENT, SERVER, 1000 + len(REQUEST), 5000, 17)]
        # Default mode: unchanged, the handshake is required.
        an, records = analyzer()
        for item in packets:
            feed(an, *item)
        an.finish("eof")
        self.assertEqual((records[0]["app"], records[0]["engine_status"]), ("incomplete", "no_handshake"))
        self.assertEqual(records[0]["observation"]["mode"], "handshake")
        # Asymmetric mode: the client direction is identified; the record says one side was seen.
        an, records = analyzer("asymmetric")
        for item in packets:
            feed(an, *item)
        an.finish("eof")
        record = records[0]
        self.assertEqual((record["app"], record["client_protocol"]), ("web-browsing", "http/1.1"))
        self.assertEqual(record["observation"], {"mode": "asymmetric", "handshake_observed": False, "directions_seen": ["client"], "roles": "observed"})
        self.assertEqual(an.counts["asymmetric_connections"], 1)

    def test_asymmetric_mode_keeps_handshake_validation(self):
        an, records = analyzer("asymmetric")
        feed(an, 0.0, CLIENT, SERVER, 999, 0, 2)
        self.assertTrue(feed(an, 0.1, SERVER, CLIENT, 8999, 1000, 18).startswith("Tracking both"))   # a real SYN-ACK still works
        an2, _ = analyzer("asymmetric")
        feed(an2, 0.0, CLIENT, SERVER, 999, 0, 2)
        self.assertTrue(feed(an2, 0.1, SERVER, CLIENT, 8999, 4242, 18).startswith("INVALIDATED"))    # wrong ACK is still rejected
        an3, _ = analyzer("asymmetric")
        feed(an3, 0.0, CLIENT, SERVER, 999, 0, 2)
        self.assertTrue(feed(an3, 0.1, SERVER, CLIENT, 9000, 1000, 24, RESPONSE).startswith("SKIP"))  # server data before client data: skipped
        an4, _ = analyzer("asymmetric")
        self.assertTrue(feed(an4, 0.0, CLIENT, SERVER, 1000, 5000, 24, REQUEST).startswith("SKIP"))   # no SYN at all: not asymmetric, midstream


class MidstreamTests(unittest.TestCase):
    def test_keepalive_request_on_a_message_boundary_is_identified_and_marked(self):
        an, records = analyzer("midstream")
        self.assertIn("HTTP=MATCH", feed(an, 0.0, CLIENT, SERVER, 7000, 9000, 24, REQUEST))
        feed(an, 0.1, SERVER, CLIENT, 9000, 7000 + len(REQUEST), 24, RESPONSE)
        an.finish("eof")
        record = records[0]
        self.assertEqual((record["app"], record["client_protocol"], record["server_protocol"]), ("web-browsing", "http/1.1", "http/1.1"))
        self.assertEqual(record["observation"], {"mode": "midstream", "handshake_observed": False, "directions_seen": ["client", "server"],
                                                 "roles": "assumed-from-first-segment"})
        self.assertEqual(an.counts["midstream_connections"], 1)

    def test_unobserved_start_is_not_unknown_protocol(self):
        an, records = analyzer("midstream")
        feed(an, 0.0, CLIENT, SERVER, 7000, 9000, 24, TLS_APP_DATA)          # encrypted records mid-connection
        an.finish("eof")
        record = records[0]
        self.assertEqual((record["app"], record["engine_status"]), ("incomplete", "midstream"))
        self.assertIn("cannot be told from an unobserved start", record["reasons"][0])
        self.assertNotEqual(record["app"], "unknown-tcp")
        # Default mode never tracks it at all.
        an, records = analyzer()
        self.assertTrue(feed(an, 0.0, CLIENT, SERVER, 7000, 9000, 24, TLS_APP_DATA).startswith("SKIP"))
        an.finish("eof")
        self.assertEqual(records, [])

    def test_initial_message_profiles_are_not_accepted_midstream(self):
        an, records = analyzer("midstream")
        feed(an, 0.0, CLIENT, ("198.51.100.20", 1883), 7000, 9000, 24, MQTT5)   # a CONNECT that happens to start a segment
        an.finish("eof")
        record = records[0]
        self.assertEqual((record["app"], record["engine_status"]), ("incomplete", "midstream"))
        self.assertIn("not accepted without an observed start", record["reasons"][0])
        # The same bytes after a handshake identify as before: handshake validation is unchanged.
        an, records = analyzer("midstream")
        feed(an, 0.0, CLIENT, ("198.51.100.20", 1883), 999, 0, 2)
        feed(an, 0.1, ("198.51.100.20", 1883), CLIENT, 8999, 1000, 18)
        feed(an, 0.2, CLIENT, ("198.51.100.20", 1883), 1000, 9000, 24, MQTT5)
        an.finish("eof")
        self.assertEqual((records[0]["app"], records[0]["observation"]["mode"]), ("mqtt", "handshake"))

    def test_tuple_reuse_after_a_midstream_observation(self):
        an, records = analyzer("midstream")
        feed(an, 0.0, CLIENT, SERVER, 7000, 9000, 24, REQUEST)
        self.assertEqual(feed(an, 1.0, CLIENT, SERVER, 999, 0, 2), "SYN: waiting for SYN-ACK")      # a new connection on the tuple
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["observation"]["mode"], "midstream")
        feed(an, 1.1, SERVER, CLIENT, 8999, 1000, 18)
        feed(an, 1.2, CLIENT, SERVER, 1000, 9000, 24, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")
        an.finish("eof")
        self.assertEqual(records[1]["observation"]["mode"], "handshake")
        self.assertEqual(records[1]["app"], "web-browsing")

    def test_policy_can_require_a_handshake_observation(self):
        import json
        policy = Policy.from_json(json.dumps({"default": "alert", "rules": [
            {"name": "allow-web-after-handshake", "action": "allow", "match": {"apps": ["web-browsing"], "observation": ["handshake"]}}]}))
        an, records = analyzer("midstream", policy=policy)
        feed(an, 0.0, CLIENT, SERVER, 7000, 9000, 24, REQUEST)
        an.finish("eof")
        self.assertEqual((records[0]["policy"]["action"], records[0]["policy"]["predicates"]["observation"]), ("alert", "midstream"))
        self.assertIn("observation is midstream", " ".join(records[0]["policy"]["reasons"]))


if __name__ == "__main__":
    unittest.main()
