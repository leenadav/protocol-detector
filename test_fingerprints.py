"""Derived handshake fingerprints: JA3/JA4 (client), JA3S/JA4S (server), HASSH, HTTP/2 SETTINGS."""
import hashlib
import io
import json
import struct
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from analyze_pcap import Analyzer, analyze
from capture_stream import CaptureRecord
from live_capture import CaptureMonitor
from make_sample_pcap import A, B, frame, pcap_bytes, udp_frame
from packets import decode_packet
from protocol_engine import Config, DatagramInspector, Inspector
from protocol_engine.fingerprints import GREASE, h2_settings_fingerprint, hassh, ja3, ja3s, ja4, ja4_raw, ja4s
from protocol_engine.parsers import ClientHelloInfo
from protocol_fixtures import DTLS, STREAM_CASES, TLS_RETRY, TLS_SERVER12, TLS_SERVER13
from protocol_demo import HTTP2
from proxy_demo import client_hello

FP = Config(fingerprints=True)


def hello(ciphers, extensions, version=0x0303):
    """Synthetic ClientHello with explicit cipher/extension lists; extension payloads are structural."""
    body = b"\x03\x03" + bytes(32) + b"\x00" + len(ciphers * 2).to_bytes(2, "big") + b"".join(c.to_bytes(2, "big") for c in ciphers) + b"\x01\x00"
    ext = b"".join(k.to_bytes(2, "big") + len(v).to_bytes(2, "big") + v for k, v in extensions)
    body += len(ext).to_bytes(2, "big") + ext
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def namelist(value):
    return struct.pack("!I", len(value)) + value


def kexinit(lists=None, first_follows=0, reserved=bytes(4), msg=20, padding=None):
    lists = lists or [b"curve25519-sha256,ecdh-sha2-nistp256", b"ssh-ed25519,rsa-sha2-512", b"aes128-ctr,aes256-gcm@openssh.com",
                      b"aes128-ctr", b"hmac-sha2-256,umac-128-etm@openssh.com", b"hmac-sha2-256", b"none,zlib@openssh.com", b"none", b"", b""]
    payload = bytes([msg]) + bytes(range(16)) + b"".join(namelist(v) for v in lists) + bytes([first_follows]) + reserved
    if padding is None:
        padding = 8 - ((len(payload) + 5) % 8)
        padding = padding + 8 if padding < 4 else padding
    return struct.pack("!IB", len(payload) + 1 + padding, padding) + payload + bytes(padding), lists


class AlgorithmTests(unittest.TestCase):
    def test_ja4_matches_independent_computation_and_grease_rules(self):
        info = ClientHelloInfo()
        info.version, info.supported_versions = 0x0303, (0x0a0a, 0x0304, 0x0303)
        info.ciphers = (0x1a1a, 0x1301, 0x1302, 0xc02b, 0x00ff)
        info.extensions = (0x2a2a, 0, 23, 65281, 10, 11, 35, 16, 5, 13, 51, 45, 43)
        info.alpn = ("h2", "http/1.1")
        info.signature_algorithms = (0x0403, 0x0a0a, 0x0804)
        ciphers_sorted = sorted(c for c in info.ciphers if c not in GREASE)
        extensions = [e for e in info.extensions if e not in GREASE and e not in (0, 16)]
        expected_b = hashlib.sha256(",".join("%04x" % c for c in ciphers_sorted).encode()).hexdigest()[:12]
        expected_c = hashlib.sha256((",".join("%04x" % e for e in sorted(extensions)) + "_0403,0804").encode()).hexdigest()[:12]
        self.assertEqual(ja4(info), "t13d0412h2_{}_{}".format(expected_b, expected_c))
        self.assertTrue(ja4_raw(info).startswith("t13d0412h2_00ff,1301,1302,c02b_0005,000a"))
        info.supported_versions, info.alpn, info.extensions = (), (), tuple(e for e in info.extensions if e != 0)
        self.assertEqual(ja4(info)[:10], "t12i041100")
        info.alpn = ("hex:ab",)
        self.assertEqual(ja4(info)[8:10], "ab")
        info.alpn = ("hex:30abcd31",)
        self.assertEqual(ja4(info)[8:10], "01")
        info.alpn = ("x",)
        self.assertEqual(ja4(info)[8:10], "xx")
        info.ciphers = (0x0a0a,)
        self.assertEqual(ja4(info).split("_")[1], "000000000000")
        self.assertEqual(ja4(info, "q")[0], "q")
        self.assertEqual(len(GREASE), 16)

    def test_ja4s_specification_example_and_ja3s(self):
        # FoxIO JA4S example: TLS 1.3, cipher 0x1301, extensions 0x002b and 0x0033, no ALPN.
        self.assertEqual(ja4s(0x0304, 0x1301, (0x2b, 0x33), ()), "t130200_1301_a56c5b993250")
        self.assertEqual(ja4s(0x0303, 0xc02f, (16,), ("h2",))[:9], "t1201h2_c")
        self.assertEqual(ja3s(771, 0x1301, (43, 51)), hashlib.md5(b"771,4865,43-51", usedforsecurity=False).hexdigest())

    def test_ja3_and_hassh_and_h2_match_definitions(self):
        info = ClientHelloInfo()
        info.version, info.ciphers, info.extensions, info.groups, info.point_formats = 771, (4865, 0x0a0a, 49195), (0, 0x1a1a, 10, 11), (29, 23), (0,)
        self.assertEqual(ja3(info), hashlib.md5(b"771,4865-49195,0-10-11,29-23,0", usedforsecurity=False).hexdigest())
        self.assertEqual(hassh(b"kex-a,kex-b", b"enc", b"mac", b"none"), hashlib.md5(b"kex-a,kex-b;enc;mac;none", usedforsecurity=False).hexdigest())
        self.assertEqual(h2_settings_fingerprint([(1, 65536), (3, 1000), (4, 6291456)]), "1:65536;3:1000;4:6291456")


class EngineTests(unittest.TestCase):
    def derived(self, observation):
        return {e.field: e.value for e in observation.evidence if e.strength == "derived"}

    def test_client_hello_fingerprints_only_when_enabled(self):
        plain = Inspector(); plain.feed(client_hello())
        self.assertEqual(self.derived(plain.observation), {})
        fp = Inspector(FP); fp.feed(client_hello())
        derived = self.derived(fp.observation)
        self.assertEqual(set(derived), {"ja4", "ja3"})
        self.assertRegex(derived["ja4"], r"^t1[23]d\d\d\d\dh2_[0-9a-f]{12}_[0-9a-f]{12}$")
        self.assertRegex(derived["ja3"], r"^[0-9a-f]{32}$")
        for split in range(1, len(client_hello()), 37):
            inspector = Inspector(FP)
            inspector.feed(client_hello()[:split]); inspector.feed(client_hello()[split:])
            self.assertEqual(self.derived(inspector.observation), derived)
        synthetic = hello([0x1301, 0x0a0a], [(0, b"\x00\x0e\x00\x00\x0bexample.com"), (0x2b, b"\x02\x03\x04"), (0x0a0a, b"")])
        result = Inspector(FP); result.feed(synthetic)
        self.assertEqual(result.observation.status, "identified")
        self.assertTrue(self.derived(result.observation)["ja4"].startswith("t13d0102"))

    def test_server_hello_fingerprints(self):
        server13 = Inspector(FP); server13.feed(TLS_SERVER13)
        self.assertEqual(self.derived(server13.observation)["ja4s"], "t130200_1301_a56c5b993250")
        server12 = Inspector(FP); server12.feed(TLS_SERVER12)
        self.assertEqual(self.derived(server12.observation)["ja4s"][:9], "t1201h2_c")
        retry = Inspector(FP); retry.feed(TLS_RETRY)
        self.assertEqual(self.derived(retry.observation), {})  # a retry is not a completed server selection
        self.assertEqual(Inspector().feed(TLS_SERVER13)[0].observation.evidence[-1].strength, "asserted")

    def test_dtls_ja4_uses_protocol_d_and_dtls_version(self):
        result = DatagramInspector(FP).inspect(DTLS)
        self.assertTrue(self.derived(result)["ja4"].startswith("dd2i0100"))
        self.assertEqual(self.derived(DatagramInspector().inspect(DTLS)), {})

    def test_ssh_identification_then_hassh_refinement(self):
        packet, lists = kexinit()
        expected = hassh(lists[0], lists[2], lists[4], lists[6])
        banner = b"SSH-2.0-OpenSSH_9.6\r\n"
        inspector = Inspector(FP)
        events = inspector.feed(banner)
        self.assertEqual((events[0].kind, events[0].observation.status, events[0].observation.application_protocol), ("updated", "identified", "ssh"))
        self.assertIsNotNone(inspector._parser)  # kept for the KEXINIT continuation
        events = inspector.feed(packet)
        self.assertEqual((events[0].kind, self.derived(events[0].observation)), ("refined", {"hassh": expected}))
        self.assertIsNone(inspector._parser)
        self.assertEqual(inspector.feed(b"more"), ())
        data = banner + packet + b"trailing"
        for split in range(1, len(data), 11):
            split_inspector = Inspector(FP)
            kinds = [event.kind for event in split_inspector.feed(data[:split]) + split_inspector.feed(data[split:])]
            self.assertEqual(kinds, ["updated", "refined"], split)
            self.assertEqual(self.derived(split_inspector.observation)["hassh"], expected)
            self.assertEqual(split_inspector.metrics.bytes_inspected, len(banner) + len(packet))
        whole = Inspector(FP); whole.feed(data)
        self.assertEqual(self.derived(whole.observation)["hassh"], expected)
        plain = Inspector(); plain.feed(data)
        self.assertEqual((plain.observation.status, self.derived(plain.observation), plain.metrics.bytes_inspected), ("identified", {}, len(banner)))

    def test_ssh_continuation_never_downgrades_identification(self):
        banner = b"SSH-2.0-x\r\n"
        ended = Inspector(FP); ended.feed(banner)
        self.assertEqual(ended.end()[0].kind if ended.end() else None, None)
        self.assertEqual((ended.observation.status, ended._parser), ("identified", None))
        bad = Inspector(FP); bad.feed(banner)
        bad_packet, _ = kexinit(msg=21)
        self.assertEqual(bad.feed(bad_packet), ())
        self.assertEqual((bad.observation.status, bad._parser, self.derived(bad.observation)), ("identified", None, {}))
        for packet, _ in (kexinit(padding=2), kexinit(first_follows=2), kexinit(reserved=b"\x00\x00\x00\x01"),
                          kexinit(lists=[b"a\x00"] + [b""] * 9)):
            inspector = Inspector(FP); inspector.feed(banner)
            inspector.feed(packet)
            self.assertEqual((inspector.observation.status, self.derived(inspector.observation)), ("identified", {}))
        huge = Inspector(FP); huge.feed(banner)
        huge.feed(struct.pack("!I", 40000))
        self.assertEqual((huge.observation.status, huge._parser), ("identified", None))
        budget = Inspector(Config(fingerprints=True, max_bytes=64)); budget.feed(banner)
        budget.feed(bytes(60))
        self.assertEqual((budget.observation.status, budget._parser), ("identified", None))
        invalidated = Inspector(FP); invalidated.feed(banner)
        invalidated.invalidate("conflict")
        self.assertEqual(invalidated.observation.status, "invalidated")
        self.assertEqual(invalidated.feed(kexinit()[0]), ())

    def test_http2_settings_fingerprint_and_fixtures_unchanged(self):
        h2 = Inspector(FP); h2.feed(HTTP2)
        self.assertEqual(self.derived(h2.observation), {"h2_settings": ""})
        settings = HTTP2[:-9] + b"\x00\x00\x0c\x04\x00\x00\x00\x00\x00" + b"\x00\x03\x00\x00\x03\xe8\x00\x04\x00\x60\x00\x00"
        h2 = Inspector(FP); h2.feed(settings)
        self.assertEqual(self.derived(h2.observation), {"h2_settings": "3:1000;4:6291456"})
        for data, protocol in STREAM_CASES:
            plain, fp = Inspector(), Inspector(FP)
            plain.feed(data); fp.feed(data)
            self.assertEqual(plain.observation.status, fp.observation.status, protocol)
            self.assertEqual(plain.observation.application_protocol, fp.observation.application_protocol, protocol)


class IntegrationTests(unittest.TestCase):
    def test_session_records_and_live_events_carry_fingerprints(self):
        packet, lists = kexinit()
        frames = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18), frame(A, B, 1000, 9000, 24, client_hello()),
                  frame(B, A, 9000, 1000 + len(client_hello()), 24, TLS_SERVER13),
                  udp_frame(A, ("192.0.2.20", 443), DTLS)]
        records = []
        analyzer = Analyzer(on_session=records.append, fingerprints=True)
        for index, data in enumerate(frames):
            analyzer.process(index, decode_packet(data))
        analyzer.finish()
        tcp = next(record for record in records if record["transport"] == "tcp")
        self.assertEqual(set(tcp["fingerprints"]), {"ja4", "ja3", "ja4s", "ja3s"})
        self.assertEqual(tcp["fingerprints"]["ja4s"], "t130200_1301_a56c5b993250")
        udp = next(record for record in records if record["transport"] == "udp")
        self.assertTrue(udp["fingerprints"]["ja4"].startswith("dd2"))
        plain = []
        analyzer = Analyzer(on_session=plain.append)
        for index, data in enumerate(frames):
            analyzer.process(index, decode_packet(data))
        analyzer.finish()
        self.assertTrue(all("fingerprints" not in record for record in plain))
        events = []
        monitor = CaptureMonitor(events.append, fingerprints=True)
        ssh_frames = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18), frame(A, B, 1000, 9000, 24, b"SSH-2.0-demo\r\n"),
                      frame(A, B, 1014, 9000, 24, packet)]
        for index, data in enumerate(ssh_frames):
            monitor.accept(CaptureRecord(index, data, len(data), 1), index)
        classifications = [event for event in events if event["type"] == "classification"]
        self.assertEqual([event["event"] for event in classifications], ["updated", "refined"])
        self.assertEqual(classifications[1]["fingerprints"], {"hassh": hassh(lists[0], lists[2], lists[4], lists[6])})
        self.assertEqual(monitor.counts["identified"], 2)
        self.assertEqual(monitor.protocols["ssh"], 2)  # the refinement re-publishes the identification
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fp.pcap"
            path.write_bytes(pcap_bytes(frames))
            output = io.StringIO()
            with redirect_stdout(output):
                analyze(path, json_output=True, events_only=True, sessions=True, fingerprints=True)
            rows = [json.loads(line) for line in output.getvalue().splitlines()]
            session = next(row for row in rows if row.get("type") == "session" and row["transport"] == "tcp")
            self.assertIn("ja4", session["fingerprints"])


if __name__ == "__main__":
    unittest.main()
