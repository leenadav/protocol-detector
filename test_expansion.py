import json
import random
import struct
import tempfile
import unittest
import zlib
from pathlib import Path
from protocol_engine import Config, DatagramInspector, Inspector
from protocol_engine.datagram import VALIDATORS
from protocol_engine.wire import dns
from protocol_fixtures import (BITTORRENT, COAP, DATAGRAM_CASES, DHCP, DNS, HINTED_DATAGRAM_CASES, HINTED_STREAM_CASES, LDAP, MEMCACHED,
                               POSTGRESQL, POSTGRESQL_SSL, RTSP, SIP, STREAM_CASES, STUN, SYSLOG)
from proxy_demo import client_hello


class ExpansionTests(unittest.TestCase):
    def stream(self, data, **kwargs):
        inspector = Inspector(**kwargs)
        inspector.feed(data)
        return inspector

    def test_completed_text_parser_is_released_without_cyclic_gc(self):
        import gc
        import weakref
        was_enabled = gc.isenabled()
        gc.disable()
        try:
            for data in (b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", SIP, RTSP):
                first_end = data.index(b"\r\n") + 2
                inspector = self.stream(data[:first_end])
                reference = weakref.ref(inspector._parser)
                inspector.feed(data[first_end:])
                self.assertEqual(inspector.observation.status, "identified")
                self.assertIsNone(reference())
        finally:
            if was_enabled:
                gc.enable()

    def test_all_new_stream_protocols_all_split_points(self):
        for data, protocol in STREAM_CASES:
            expected = self.stream(data).observation
            self.assertEqual(expected.application_protocol, protocol, expected)
            for split in range(len(data) + 1):
                inspector = Inspector()
                inspector.feed(data[:split])
                inspector.feed(data[split:])
                self.assertEqual(inspector.observation, expected, (protocol, split))
                self.assertEqual(inspector.metrics.bytes_inspected, len(data))
                self.assertEqual(inspector.metrics.candidates_selected, 1)

    def test_single_byte_feeds_and_no_premature_match(self):
        for data, protocol in STREAM_CASES:
            inspector = Inspector()
            for offset, byte in enumerate(data):
                self.assertEqual(inspector.observation.status, "detecting", (protocol, offset))
                inspector.feed(bytes([byte]))
            self.assertEqual(inspector.observation.application_protocol, protocol)
            self.assertEqual(inspector.metrics.bytes_inspected, len(data))

    def test_eof_terminal_bypass_and_next_message_not_consumed(self):
        for data, _ in STREAM_CASES:
            partial = self.stream(data[:-1])
            partial.end()
            self.assertEqual(partial.observation.status, "incomplete")
            inspector = self.stream(data + b"later" * 100)
            if any(e.field == "shift" for e in inspector.observation.evidence):
                # The message announced a protocol change (for example RDP requesting TLS):
                # bytes after it are inspected once by the shifted phase, then ignored.
                self.assertEqual(inspector.observation.status, "identified")
                continue
            self.assertEqual(inspector.metrics.bytes_inspected, len(data))
            calls = inspector.metrics.parser_calls
            inspector.feed(b"later" * 10000)
            self.assertEqual(inspector.metrics.parser_calls, calls)

    def test_new_protocols_work_inside_tls(self):
        hello = client_hello()
        for data, protocol in STREAM_CASES:
            inspector = self.stream(hello)
            inspector.feed_decrypted(data)
            self.assertEqual(inspector.observation.application_protocol, protocol)
            self.assertEqual(inspector.observation.encryption, "tls")
            self.assertTrue(any(e.field == "application_protocol" and e.source == "decrypted"
                                for e in inspector.observation.evidence))

    def test_prefix_collisions_preserve_http_extension_methods(self):
        for method in (b"RFB", b"RTSP", b"SIP", b"0", b"01", b"00000", b"OPTIONS", b"REGISTER", b"INVITE"):
            data = method + b" / HTTP/1.1\r\nHost: example.com\r\n\r\n"
            for split in range(len(data) + 1):
                inspector = Inspector()
                inspector.feed(data[:split])
                inspector.feed(data[split:])
                self.assertEqual(inspector.observation.application_protocol, "http/1.1", (method, split))

    def test_candidate_hints_are_not_classification(self):
        for hint in ("dns", "stun", "postgresql", "ldap", "memcached"):
            result = self.stream(b"not a protocol" * 20, protocol_hint=hint).observation
            self.assertNotEqual(result.status, "identified", hint)
        for hint in VALIDATORS:
            self.assertNotEqual(DatagramInspector().inspect(b"garbage", hint).status, "identified")
        with self.assertRaises(ValueError):
            Inspector(protocol_hint="not-registered")
        with self.assertRaises(ValueError):
            DatagramInspector().inspect(DNS, "not-registered")

    def test_dns_tcp_large_length_uses_explicit_candidate(self):
        # The first length byte can collide with any other protocol signature.
        response = bytearray(DNS)
        response[2:4] = b"\x81\x80"
        response[6:8] = b"\x00\x01"
        response += b"\xc0\x0c" + struct.pack("!HHIH", 65000, 1, 0, 6000) + b"x" * 6000
        framed = len(response).to_bytes(2, "big") + response
        self.assertEqual(self.stream(framed, protocol_hint="dns").observation.application_protocol, "dns")

    def test_datagram_protocols_and_no_state_leak_between_messages(self):
        inspector = DatagramInspector()
        for data, protocol in DATAGRAM_CASES:
            result = inspector.inspect(data)
            self.assertEqual(result.status, "identified", (protocol, result))
            self.assertEqual(result.application_protocol or result.encryption, protocol)
            self.assertEqual(result.transport, "udp")
            self.assertEqual(result.scope, "datagram")
            self.assertIsNone(result.application)
        self.assertEqual(inspector.inspect(b"").status, "unknown")
        self.assertEqual(inspector.metrics.updates, len(DATAGRAM_CASES) + 1)
        for data, _ in DATAGRAM_CASES:
            self.assertNotEqual(inspector.inspect(data[:3]).status, "identified")
        self.assertNotEqual(inspector.inspect(DNS + DNS).status, "identified")

    def test_udp_datagram_budget_and_types(self):
        inspector = DatagramInspector(Config(max_bytes=64))
        self.assertEqual(inspector.inspect(b"x" * 65).status, "budget_exhausted")
        self.assertEqual(inspector.metrics.bytes_inspected, 0)
        for value in (None, bytearray(), "text"):
            with self.assertRaises(TypeError):
                inspector.inspect(value)

    def test_ambiguous_dns_coap_is_not_arbitrarily_identified(self):
        from protocol_engine.wire import coap
        ambiguous = bytearray(DNS)
        ambiguous[:4] = b"\x41\x01\x81\x80"
        ambiguous[6:8] = b"\x00\x01"
        ambiguous += b"\x00" + struct.pack("!HHIH", 1, 1, 0, 4) + bytes(4)
        data = bytes(ambiguous)
        self.assertEqual(dns(data, Config())[0], "dns")
        self.assertEqual(coap(data, Config())[0], "coap")
        inspector = DatagramInspector()
        result = inspector.inspect(data)
        self.assertEqual(result.status, "unknown")
        self.assertIn("Ambiguous", result.reason)
        self.assertEqual(inspector.metrics.parser_calls, 2)
        self.assertEqual(inspector.inspect(data, "dns").application_protocol, "dns")
        ambiguous[6:8] = b"\x00\x80"
        # A competing interpretation that exceeds its bound cannot be silently
        # ignored to return the other interpretation as a unique identification.
        self.assertEqual(coap(bytes(ambiguous), Config())[0], "coap")
        self.assertEqual(inspector.inspect(bytes(ambiguous)).status, "budget_exhausted")

    def test_catalog_is_immutable_and_demo_covers_every_family(self):
        from dataclasses import FrozenInstanceError
        from protocol_engine import supported_protocols
        from protocol_demo import examples
        catalog = supported_protocols()
        self.assertIsInstance(catalog, tuple)
        with self.assertRaises(FrozenInstanceError):
            catalog[0].family = "changed"
        observed = set()
        for _, data in examples():
            result = self.stream(data).observation
            if result.status == "identified":
                name = result.application_protocol or result.encryption
                observed.add("http2" if name == "http/2" else name.split("/", 1)[0])
        for data, _ in DATAGRAM_CASES:
            result = DatagramInspector().inspect(data)
            observed.add((result.application_protocol or result.encryption).split("/", 1)[0])
        for data, _, hint in HINTED_DATAGRAM_CASES:
            observed.add(DatagramInspector().inspect(data, hint).application_protocol.split("/", 1)[0])
        for data, _, hint in HINTED_STREAM_CASES:
            observed.add(self.stream(data, protocol_hint=hint).observation.application_protocol)
        self.assertEqual(observed, {entry.family for entry in catalog})

    def test_dns_compressed_response_and_common_rdata(self):
        response = bytearray(DNS)
        response[2:4] = b"\x81\x80"
        response[6:8] = b"\x00\x01"
        for kind, body in ((1, b"\xc0\x00\x02\x01"), (28, bytes(16)),
                           (5, b"\xc0\x0c"), (15, b"\x00\x0a\xc0\x0c"),
                           (6, b"\xc0\x0c\xc0\x0c" + bytes(20)), (16, b"\x03txt")):
            data = bytes(response) + b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 60, len(body)) + body
            self.assertEqual(DatagramInspector().inspect(data).application_protocol, "dns", kind)
        edns = bytearray(DNS)
        edns[10:12] = b"\x00\x01"
        edns += b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 4) + b"\xfd\xe8\x00\x00"
        self.assertEqual(DatagramInspector().inspect(bytes(edns)).application_protocol, "dns")

    def test_dns_pointer_cycles_non_boundaries_truncation_and_counts(self):
        for name in (b"\xc0\x0c", b"\xc0\x0d", b"\xc0\x00", b"\x40bad", b"\xff\xff"):
            bad = DNS[:12] + name + b"\x00\x01\x00\x01"
            self.assertNotEqual(DatagramInspector().inspect(bad).status, "identified")
        for end in range(12, len(DNS)):
            self.assertNotEqual(DatagramInspector().inspect(DNS[:end]).status, "identified")
        excessive = DNS[:6] + b"\x00\x80" + DNS[8:]
        self.assertEqual(DatagramInspector().inspect(excessive).status, "budget_exhausted")
        truncated = DNS[:2] + b"\x03" + DNS[3:]
        self.assertEqual(DatagramInspector().inspect(truncated).status, "unknown")

    def test_stun_fingerprint_integrity_and_attributes(self):
        prefix = STUN[:2] + b"\x00\x08" + STUN[4:]
        fingerprint = (zlib.crc32(prefix) & 0xffffffff) ^ 0x5354554e
        valid = prefix + b"\x80\x28\x00\x04" + fingerprint.to_bytes(4, "big")
        self.assertEqual(DatagramInspector().inspect(valid).application_protocol, "stun")
        self.assertEqual(self.stream(valid).observation.application_protocol, "stun")
        self.assertEqual(DatagramInspector().inspect(valid[:-1] + bytes([valid[-1] ^ 1])).status, "malformed")
        for attr in (b"\x00\x08\x00\x00", b"\x00\x20\x00\x01xxxx", b"\x80\x28\x00\x00"):
            bad = STUN[:2] + len(attr).to_bytes(2, "big") + STUN[4:] + attr
            self.assertEqual(DatagramInspector().inspect(bad).status, "malformed")
        self.assertEqual(DatagramInspector().inspect(b"\x00\x03" + STUN[2:]).status, "unknown")

    def test_dhcp_options_operation_and_cookie(self):
        inspector = DatagramInspector()
        for data in (DHCP[:-1], DHCP[:-1] + b"\x35\x01\x01\xff", DHCP[:-1] + b"\xffx",
                     b"\x02" + DHCP[1:], DHCP[:2] + b"\x11" + DHCP[3:]):
            self.assertEqual(inspector.inspect(data).status, "malformed", data[-10:])
        overloaded = DHCP[:-1] + b"\x34\x01\x01\xff"
        self.assertEqual(inspector.inspect(overloaded).status, "unknown")
        offer = b"\x02" + DHCP[1:-2] + b"\x02\xff"
        self.assertEqual(inspector.inspect(offer).application_protocol, "dhcp/4")

    def test_coap_options_payload_and_empty_requires_hint(self):
        inspector = DatagramInspector()
        for data in (COAP + b"\xffbody", COAP[:5] + b"\xd0\x00"):
            self.assertEqual(inspector.inspect(data).application_protocol, "coap")
        for data in (COAP + b"\xff", COAP[:5] + b"\xf1x", COAP[:5] + b"\xdd", COAP[:5] + b"\xbf"):
            self.assertEqual(inspector.inspect(data).status, "malformed")
        empty = b"\x60\x00\x12\x34"
        self.assertEqual(inspector.inspect(empty).status, "unknown")
        self.assertEqual(inspector.inspect(empty, "coap").application_protocol, "coap")

    def test_syslog_structure_escapes_and_date(self):
        inspector = DatagramInspector()
        for data in (SYSLOG, b'<0>1 - - - - - -', b'<1>1 - - - - - [id x="\\q"]',
                     b'<191>1 - - - - - [id x="a\\]b\\\"c\\\\d"][second] log'):
            self.assertEqual(inspector.inspect(data).application_protocol, "syslog/5424", data)
        for data in (SYSLOG.replace(b"<34>", b"<192>"), SYSLOG.replace(b"10-19", b"02-31"),
                     SYSLOG.replace(b'key="value"', b'key="bad]value"'),
                     b'<1>1 - - - - - [id x="a" x="b"]', b'<1>1 - - - - - [id][id]',
                     SYSLOG.replace(b'12:00:00Z', b'12:00:00+00:99')):
            self.assertEqual(inspector.inspect(data).status, "malformed", data)

    def test_postgresql_startup_and_negotiation_are_distinct(self):
        self.assertEqual(self.stream(POSTGRESQL_SSL).observation.scope, "negotiation_request")
        self.assertIsNone(self.stream(POSTGRESQL_SSL).observation.encryption)
        for data in (POSTGRESQL[:-1],):
            self.assertEqual(self.stream(data).observation.status, "detecting")
        bad = POSTGRESQL.replace(b"user", b"xxxx")
        self.assertEqual(self.stream(bad).observation.status, "malformed")
        huge = b"\x00\x10\x00\x00" + POSTGRESQL[4:8]
        self.assertEqual(self.stream(huge).observation.status, "budget_exhausted")

    def test_rfb_and_bittorrent_scope_and_limits(self):
        for version in (b"003", b"007", b"008"):
            result = self.stream(b"RFB 003." + version + b"\n").observation
            self.assertEqual(result.application_protocol, "rfb")
            self.assertEqual(result.scope, "protocol_header")
        self.assertEqual(self.stream(BITTORRENT, config=Config(max_bytes=64)).observation.status, "budget_exhausted")
        self.assertEqual(self.stream(b"\x13BitTorrent protocoX" + bytes(48)).observation.status, "malformed")

    def test_memcached_command_shapes_and_limits(self):
        set_request = struct.pack("!BBHBBHIIQ", 128, 1, 1, 8, 0, 0, 12, 0, 0) + bytes(8) + b"kval"
        self.assertEqual(self.stream(set_request).observation.application_protocol, "memcached/binary")
        for index, value in ((4, 8), (5, 1), (6, 1)):
            bad = bytearray(MEMCACHED)
            bad[index] = value
            self.assertEqual(self.stream(bytes(bad)).observation.status, "malformed")
        huge = bytearray(set_request[:24]);huge[8:12] = (1000000).to_bytes(4, "big")
        self.assertEqual(self.stream(bytes(huge)).observation.status, "budget_exhausted")

    def test_ldap_bind_ber_and_no_credentials_in_observation(self):
        for index, value in ((4, 0), (5, 0x61), (9, 2), (10, 5), (12, 0x81)):
            bad = bytearray(LDAP);bad[index] = value
            self.assertNotEqual(self.stream(bytes(bad), protocol_hint="ldap").observation.status, "identified")
        for data in (b"\x30\x80" + bytes(10), b"\x30\x84\x7f\xff\xff\xff"):
            self.assertIn(self.stream(data, protocol_hint="ldap").observation.status, ("malformed", "budget_exhausted"))
        secret = b"secret-pass"
        bind = b"\x02\x01\x03\x04\x00\x80" + bytes([len(secret)]) + secret
        inner = b"\x02\x01\x01\x60" + bytes([len(bind)]) + bind
        result = self.stream(b"\x30" + bytes([len(inner)]) + inner).observation
        self.assertEqual(result.application_protocol, "ldap/3")
        self.assertNotIn("secret-pass", repr(result))

    def test_sip_rtsp_headers_and_http_disambiguation(self):
        for data in (SIP, SIP.replace(b"Via:", b"v:").replace(b"From:", b"f:").replace(b"To:", b"t:").replace(b"Call-ID:", b"i:")):
            self.assertEqual(self.stream(data).observation.application_protocol, "sip/2.0")
        for data in (SIP.replace(b"1 OPTIONS", b"1 INVITE"), SIP.replace(b"Max-Forwards: 70\r\n", b""),
                     SIP.replace(b"Call-ID:", b"Other:"), SIP.replace(b"Content-Length: 0", b"Content-Length: x")):
            self.assertEqual(self.stream(data).observation.status, "malformed")
        self.assertEqual(self.stream(RTSP.replace(b"RTSP/1.0", b"RTSP/2.0")).observation.application_protocol, "rtsp/2.0")
        self.assertEqual(self.stream(RTSP.replace(b"CSeq: 1\r\n", b"")).observation.status, "malformed")
        self.assertEqual(DatagramInspector().inspect(SIP + b"extra").status, "malformed")
        self.assertEqual(DatagramInspector().inspect(SIP.replace(b"Content-Length: 0", b"Content-Length: 4") + b"body").status, "identified")

    def test_seeded_stream_mutations_fragmentation_equivalence(self):
        rng = random.Random(52026)
        for base, _ in STREAM_CASES:
            for _ in range(150):
                changed = bytearray(base)
                changed[rng.randrange(len(changed))] = rng.randrange(256)
                data = bytes(changed)
                whole = self.stream(data)
                fragmented = Inspector()
                for pos in range(0, len(data), 3):
                    fragmented.feed(data[pos:pos + 3])
                whole.end();fragmented.end()
                self.assertEqual(whole.observation, fragmented.observation, data)
                self.assertLessEqual(fragmented.metrics.bytes_inspected, len(data))
                self.assertLessEqual(fragmented.metrics.candidates_selected, 1)

    def test_seeded_datagram_mutations_and_random_noise_never_crash(self):
        rng = random.Random(51926)
        inspector = DatagramInspector()
        for base, _ in DATAGRAM_CASES:
            for _ in range(300):
                changed = bytearray(base)
                changed[rng.randrange(len(changed))] = rng.randrange(256)
                result = inspector.inspect(bytes(changed))
                self.assertIn(result.status, ("identified", "unknown", "malformed", "budget_exhausted"))
        for size in range(300):
            data = bytes(rng.randrange(256) for _ in range(size))
            for hint in (None, *VALIDATORS):
                inspector.inspect(data, hint)

    def test_tcp_reassembly_compatibility_adapter(self):
        from sessions import SessionManager
        for data, protocol in STREAM_CASES:
            manager = SessionManager()
            a,b = ("192.0.2.1", 50000), ("192.0.2.2", 54321)
            manager.open_connection(a,b,100,200)
            manager.feed(a,b,105,data[5:])
            snapshot = manager.feed(a,b,100,data[:5])
            self.assertEqual(snapshot.classification.application_protocol, protocol)
            self.assertEqual(sum(r.status == "MATCH" for r in snapshot.results), 1)

    def test_udp_packet_lengths_vlan_and_old_tcp_api(self):
        from make_sample_pcap import A, B, udp_frame
        from packets import PacketError, UDPPacket, decode_packet, decode_tcp
        original = udp_frame(A, B, DNS)
        packet = decode_packet(original)
        self.assertIsInstance(packet, UDPPacket)
        self.assertEqual((packet.source, packet.destination, packet.payload), (A, B, DNS))
        vlan = original[:12] + b"\x81\x00\x00\x01\x08\x00" + original[14:]
        self.assertEqual(decode_packet(vlan), packet)
        with self.assertRaises(PacketError):
            decode_tcp(original)
        for size in (0, 7, 8, len(DNS) + 9):
            changed = bytearray(original)
            changed[38:40] = size.to_bytes(2, "big")
            with self.assertRaises(PacketError):
                decode_packet(bytes(changed))
        with self.assertRaises(PacketError):
            decode_packet(original[:-1])

    def test_mixed_pcap_end_to_end_readable_and_json(self):
        import contextlib
        import io
        from analyze_pcap import Analyzer, analyze
        from make_sample_pcap import expanded_frames, pcap_bytes
        from packets import decode_packet
        analyzer = Analyzer()
        identified = []
        frames = expanded_frames()
        for timestamp, frame in enumerate(frames):
            analyzer.process(timestamp, decode_packet(frame))
            for event in analyzer.last_events:
                if event.observation.status == "identified":
                    identified.append((event.observation.transport, event.observation.application_protocol or event.observation.encryption))
        expected = [("tcp", name) for _, name in STREAM_CASES] + [("udp", name) for _, name in DATAGRAM_CASES]
        self.assertEqual(identified, expected)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mixed.pcap"
            path.write_bytes(pcap_bytes(frames))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                counts = analyze(path, json_output=True, events_only=True)
            rows = [json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual(counts["udp"], len(DATAGRAM_CASES))
            retired = [row for row in rows if row.get("type") == "stream_end"]
            classified = [row for row in rows if "frame" in row]
            unobserved = [row for row in retired if row["classification"]["status"] == "incomplete"]
            self.assertEqual(len(unobserved), len(STREAM_CASES))  # Unobserved reverse directions.
            for row in retired:
                if row not in unobserved:
                    # A request that announced a protocol shift (RDP TLS offer, PostgreSQL SSLRequest)
                    # ended without shifted bytes: the identification stands and says so.
                    self.assertEqual(row["classification"]["status"], "identified")
                    self.assertIn({"field": "shifted_payload", "value": "incomplete"},
                                  [{"field": e["field"], "value": e["value"]} for e in row["classification"]["evidence"]])
            self.assertEqual(len(classified), len(expected))
            self.assertEqual(classified[-1]["classification"]["transport"], "udp")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(analyze(path), counts)

    def test_mqtt5_connect_and_will_properties(self):
        from test_messaging import vector, remaining_length

        def packet(props=b"", flags=2, client=b"demo", tail=b""):
            body = b"\x00\x04MQTT\x05" + bytes([flags]) + b"\x00\x3c" + remaining_length(len(props)) + props + vector(client) + tail
            return b"\x10" + remaining_length(len(body)) + body

        props = (b"\x11\x00\x00\x00\x3c\x21\x00\x10\x27\x00\x01\x00\x00"
                 b"\x22\x00\x00\x19\x01\x17\x00" + b"\x26" + vector(b"key") + vector(b"value") +
                 b"\x26" + vector(b"key") + vector(b"another") +
                 b"\x15" + vector(b"method") + b"\x16" + vector(b"secret"))
        for data in (packet(props), packet(flags=0, client=b""), packet(flags=0x42, tail=vector(b"password"))):
            inspector = Inspector()
            for byte in data:
                inspector.feed(bytes([byte]))
            self.assertEqual(inspector.observation.application_protocol, "mqtt/5.0")
            self.assertNotIn("secret", repr(inspector.observation))
        will_props = b"\x01\x01\x18\x00\x00\x00\x01\x08" + vector(b"response/topic")
        tail = remaining_length(len(will_props)) + will_props + vector(b"will/topic") + vector(b"message")
        self.assertEqual(self.stream(packet(flags=6, tail=tail)).observation.application_protocol, "mqtt/5.0")
        for bad in (b"\x21\x00\x00", b"\x27\x00\x00\x00\x00", b"\x19\x02", b"\x19\x00\x19\x01",
                    b"\x16" + vector(b"secret"), b"\x03" + vector(b"wrong context"), b"\xff\xff\xff\x80"):
            self.assertEqual(self.stream(packet(bad)).observation.status, "malformed", bad)
        bad_tail = b"\x02\x01\x01" + vector(b"will/topic") + vector(b"\xff")
        self.assertEqual(self.stream(packet(flags=6, tail=bad_tail)).observation.status, "malformed")
        excessive = (b"\x26" + vector(b"k") + vector(b"v")) * 129
        self.assertEqual(self.stream(packet(excessive)).observation.status, "budget_exhausted")


if __name__ == "__main__":
    unittest.main()
