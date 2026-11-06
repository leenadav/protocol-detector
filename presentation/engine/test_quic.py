"""QUIC v1/v2 Initial recognition, protection removal, CRYPTO assembly and bounds."""
import random
import unittest

from analyze_pcap import Analyzer
from make_sample_pcap import A, udp_frame
from packets import decode_packet
from protocol_engine import Config, DatagramInspector, SignatureSet
from protocol_engine.aes import encrypt_block, expand_key, gcm_seal
from protocol_engine.appid import classify
from protocol_engine.quic import V1, V2, QuicAssembler, _initial_keys, assemble, quic_probe
from protocol_fixtures import QUIC_INITIAL

DCID = bytes.fromhex("8394c8f03e515708")
# RFC 9001 A.2 CRYPTO frame payload (frame header 06 00 40f1 + ClientHello).
CRYPTO_FRAME = bytes.fromhex(
    "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b65786"
    "16d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e0005000501000000000033002600"
    "24001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e04030503060302030804080508"
    "06002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e5157080604"
    "8000ffff")
CLIENT_HELLO = CRYPTO_FRAME[4:]


def encode_varint(value):
    for prefix, size in ((0, 1), (1, 2), (2, 4), (3, 8)):
        if value < 1 << (8 * size - 2):
            return ((prefix << (8 * size - 2)) | value).to_bytes(size, "big")
    raise ValueError


def protect(version, dcid, scid, payload, packet_number=2, token=b"", pad_to=1200, first_bits=0):
    """Build a protected client Initial from a plaintext frame payload (test helper)."""
    key, iv, hp = _initial_keys(version, dcid)
    pn = packet_number.to_bytes(4, "big")
    payload = payload + bytes(max(0, pad_to - (7 + len(dcid) + len(scid) + 1 + len(token) + 2 + 4 + len(payload) + 16)))
    length = encode_varint(len(pn) + len(payload) + 16)
    header = (bytes([0xc3 | first_bits]) if version == V1 else bytes([0xd3 | first_bits])) + version.to_bytes(4, "big")
    header += bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + encode_varint(len(token)) + token + length + pn
    nonce = bytes(a ^ b for a, b in zip(iv, packet_number.to_bytes(12, "big")))
    sealed = gcm_seal(key, nonce, header, payload)
    pn_offset = len(header) - 4
    mask = encrypt_block(expand_key(hp), sealed[:16])
    protected = bytearray(header + sealed)
    protected[0] ^= mask[0] & 0x0f
    for index in range(4):
        protected[pn_offset + index] ^= mask[1 + index]
    return bytes(protected)


def crypto_frames(data, pieces):
    """Split ClientHello bytes into CRYPTO frames at the given cut offsets."""
    frames, cuts = [], [0] + list(pieces) + [len(data)]
    for start, end in zip(cuts, cuts[1:]):
        frames.append(b"\x06" + encode_varint(start) + encode_varint(end - start) + data[start:end])
    return frames


class VectorTests(unittest.TestCase):
    def test_rfc9001_client_initial_opens_to_the_published_client_hello(self):
        result = DatagramInspector(Config(fingerprints=True)).inspect(QUIC_INITIAL)
        self.assertEqual((result.status, result.encryption, result.hostname, result.offered_alpn), ("identified", "quic", "example.com", ("alpn",)))
        fields = {e.field: e.value for e in result.evidence}
        self.assertEqual((fields["quic_version"], fields["packet_type"], fields["initial_protection"], fields["crypto_assembly"]), ("1", "initial", "removed", "complete"))
        self.assertTrue(fields["ja4"].startswith("q13d0211an_"))
        self.assertIsNone(result.application_protocol)
        self.assertNotIn("8394c8f0", repr(result))  # connection IDs are never emitted

    def test_helper_reproduces_rfc9001_and_rfc9369_protected_packets(self):
        rebuilt = protect(V1, DCID, b"", CRYPTO_FRAME, pad_to=1200)
        self.assertEqual(rebuilt, QUIC_INITIAL)
        v2 = protect(V2, DCID, b"", CRYPTO_FRAME, pad_to=1200)
        self.assertEqual(v2[:32].hex(), "d76b3343cf088394c8f03e5157080000449ea0c95e82ffe67b6abcdb4298b485")  # RFC 9369 A.2
        result = DatagramInspector().inspect(v2)
        self.assertEqual((result.status, result.hostname), ("identified", "example.com"))
        self.assertEqual({e.field: e.value for e in result.evidence}["quic_version"], "2")
        key, iv, hp = _initial_keys(V2, DCID)
        self.assertEqual((key.hex(), iv.hex(), hp.hex()), ("8b1a0bc121284290a29e0971b5cd045d", "91f73e2351d8fa91660e909f", "45b95e15235d6f45a6b19cbcb0294ba9"))


class StructureTests(unittest.TestCase):
    def test_probe_truncations_and_header_bounds(self):
        inspector = DatagramInspector()
        self.assertTrue(quic_probe(QUIC_INITIAL))
        for cut in (0, 1, 4, 5, 6, 7, 20, 40, 100, 1199):
            self.assertNotEqual(inspector.inspect(QUIC_INITIAL[:cut]).status, "identified", cut)
        # Trailing bytes after the Initial are coalesced packets or padding (RFC 9000 12.2): still identified.
        self.assertEqual(inspector.inspect(QUIC_INITIAL + b"\x00" * 8).hostname, "example.com")
        for index, value in ((0, 0x80), (0, 0xe3), (1, 1), (4, 3), (5, 21), (5, 200)):
            changed = bytearray(QUIC_INITIAL); changed[index] = value
            self.assertNotEqual(inspector.inspect(bytes(changed)).hostname, "example.com", (index, value))
        short_header = bytes([0x40]) + QUIC_INITIAL[1:]
        self.assertFalse(quic_probe(short_header))
        self.assertNotEqual(inspector.inspect(short_header).encryption, "quic")

    def test_version_negotiation(self):
        inspector = DatagramInspector()
        packet = b"\xc0" + bytes(4) + b"\x08" + DCID + b"\x00" + V1.to_bytes(4, "big") + V2.to_bytes(4, "big")
        result = inspector.inspect(packet)
        self.assertEqual((result.status, result.encryption), ("identified", "quic"))
        self.assertEqual({e.field: e.value for e in result.evidence}["packet_type"], "version_negotiation")
        self.assertEqual(inspector.inspect(packet[:-1]).status, "malformed")
        self.assertEqual(inspector.inspect(packet[:-8]).status, "malformed")
        self.assertEqual(inspector.inspect(packet[:-8] + bytes(4 * 200)).status, "budget_exhausted")

    def test_protection_failures_are_reported_not_guessed(self):
        inspector = DatagramInspector()
        damaged = bytearray(QUIC_INITIAL); damaged[700] ^= 1
        result = inspector.inspect(bytes(damaged))
        self.assertEqual((result.status, result.hostname), ("identified", None))
        self.assertEqual({e.field: e.value for e in result.evidence}["initial_protection"], "unverified")
        self.assertIn("did not open", result.reason)
        other_dcid = protect(V1, b"\x01\x02\x03\x04", b"", CRYPTO_FRAME)
        wrong = bytearray(other_dcid); wrong[6] ^= 1  # DCID changed after sealing: keys no longer match
        self.assertEqual({e.field: e.value for e in inspector.inspect(bytes(wrong)).evidence}["initial_protection"], "unverified")
        reserved = protect(V1, DCID, b"", CRYPTO_FRAME, first_bits=0x08)  # reserved bit set under protection
        self.assertEqual({e.field: e.value for e in inspector.inspect(reserved).evidence}["initial_protection"], "unverified")
        off = DatagramInspector(Config(quic_decrypt=False)).inspect(QUIC_INITIAL)
        self.assertEqual((off.status, off.hostname, {e.field: e.value for e in off.evidence}["initial_protection"]), ("identified", None, "skipped"))
        big = DatagramInspector(Config(max_bytes=1100)).inspect(QUIC_INITIAL)
        self.assertEqual(big.status, "budget_exhausted")

    def test_frames_allowed_in_initial(self):
        inspector = DatagramInspector()
        ack = b"\x02" + encode_varint(5) + encode_varint(0) + encode_varint(1) + encode_varint(2) + encode_varint(0) + encode_varint(1)
        ping, close = b"\x01", b"\x1c" + encode_varint(0) + encode_varint(6) + encode_varint(3) + b"bye"
        payload = ping + ack + CRYPTO_FRAME + close
        self.assertEqual(inspector.inspect(protect(V1, DCID, b"\xaa\xbb", payload, token=b"tok")).hostname, "example.com")
        stream = protect(V1, DCID, b"", b"\x08" + b"\x00" * 10 + CRYPTO_FRAME)  # STREAM frame is not allowed in Initial
        result = inspector.inspect(stream)
        self.assertEqual((result.hostname, {e.field: e.value for e in result.evidence}["initial_protection"]), (None, "unverified"))
        self.assertIn("not permitted", result.reason)
        truncated_crypto = protect(V1, DCID, b"", b"\x06" + encode_varint(0) + encode_varint(500) + b"x" * 10, pad_to=0)
        self.assertEqual({e.field: e.value for e in inspector.inspect(truncated_crypto).evidence}["initial_protection"], "unverified")
        many = protect(V1, DCID, b"", b"\x01" * 200 + CRYPTO_FRAME)
        self.assertEqual(inspector.inspect(many).status, "budget_exhausted")
        junk_hello = protect(V1, DCID, b"", b"\x06" + encode_varint(0) + encode_varint(40) + b"\x01\x00\x00\x24" + b"\x03\x03" + bytes(34))
        self.assertEqual({e.field: e.value for e in inspector.inspect(junk_hello).evidence}["crypto_assembly"], "invalid")


class AssemblyTests(unittest.TestCase):
    def test_single_datagram_with_reordered_fragments(self):
        frames = crypto_frames(CLIENT_HELLO, [50, 120])
        payload = frames[2] + frames[0] + frames[1]
        self.assertEqual(DatagramInspector().inspect(protect(V1, DCID, b"", payload)).hostname, "example.com")
        self.assertIsNone(assemble([(0, CLIENT_HELLO[:10]), (20, CLIENT_HELLO[20:])]))  # gap
        self.assertEqual(assemble([(0, CLIENT_HELLO[:100]), (60, CLIENT_HELLO[60:])]), CLIENT_HELLO)  # overlap

    def test_cross_datagram_assembly_requires_an_assembler(self):
        first, second = crypto_frames(CLIENT_HELLO, [100])
        packets = [protect(V1, DCID, b"", first, packet_number=0), protect(V1, DCID, b"", second, packet_number=1)]
        stateless = DatagramInspector()
        for packet in packets:
            result = stateless.inspect(packet)
            self.assertEqual((result.status, result.hostname, {e.field: e.value for e in result.evidence}["crypto_assembly"]), ("identified", None, "partial"))
        assembler = QuicAssembler(max_connections=2)
        stateful = DatagramInspector(Config(), None, assembler)
        self.assertIsNone(stateful.inspect(packets[1]).hostname)
        completed = stateful.inspect(packets[0])
        self.assertEqual((completed.hostname, completed.offered_alpn), ("example.com", ("alpn",)))
        # Bounded store: a third connection evicts the oldest; oversized fragments are dropped.
        assembler.add(b"a", [(0, b"x")]); assembler.add(b"b", [(0, b"x")]); assembler.add(b"c", [(0, b"x")])
        self.assertEqual(len(assembler.entries), 2)
        self.assertNotIn(b"a", assembler.entries)
        self.assertIsNone(assembler.add(b"d", [(0, bytes(17000))]))
        self.assertNotIn(b"d", assembler.entries)
        self.assertIsNone(assembler.add(b"e", [(i * 10, b"0123456789") for i in range(9)]))
        assembler.clear()
        self.assertEqual(len(assembler.entries), 0)
        with self.assertRaises(TypeError):
            DatagramInspector(Config(), None, object())


class IntegrationTests(unittest.TestCase):
    def test_verdict_signatures_and_analyzer_flow(self):
        verdict = classify(DatagramInspector().inspect(QUIC_INITIAL), "udp", 443)
        self.assertEqual((verdict.app, verdict.category, verdict.port_usage, verdict.encryption), ("quic", "networking", "standard", "quic"))
        signatures = SignatureSet([{"name": "example-h3", "parent": "quic", "conditions": [
            {"context": "ssl-req-chello-sni", "operator": "equal-to", "value": "example.com"},
            {"context": "ssl-req-alpn", "operator": "equal-to", "value": "alpn"}]}])
        signed = DatagramInspector(Config(retain_contexts=True), signatures).inspect(QUIC_INITIAL)
        self.assertEqual(signed.application, "example-h3")
        self.assertEqual(classify(signed, "udp", 443, signatures=signatures).base_app, "quic")
        records = []
        analyzer = Analyzer(on_session=records.append, max_udp_flows=4)
        first, second = crypto_frames(CLIENT_HELLO, [100])
        for data in (protect(V1, DCID, b"", first, packet_number=0), protect(V1, DCID, b"", second, packet_number=1)):
            analyzer.process(0, decode_packet(udp_frame(A, ("192.0.2.20", 443), data)))
        self.assertEqual(analyzer.last_classification.hostname, "example.com")
        analyzer.finish()
        self.assertEqual((records[0]["app"], records[0]["packets"], records[0]["port_usage"]), ("quic", 2, "standard"))
        self.assertNotIn("hostname", records[0])
        self.assertEqual(analyzer.quic_assembler.max_connections, 4)
        self.assertTrue(analyzer.quic_assembler.entries)
        analyzer.quic_assembler.clear()

    def test_mutations_and_noise_stay_within_documented_statuses_and_time(self):
        import time
        rng = random.Random(9001)
        inspector = DatagramInspector(Config(fingerprints=True))
        start = time.monotonic()
        for _ in range(150):
            data = bytearray(QUIC_INITIAL)
            for _ in range(rng.randrange(1, 4)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            result = inspector.inspect(bytes(data))
            self.assertIn(result.status, ("identified", "unknown", "malformed", "budget_exhausted"))
            self.assertIsNone(result.application)
        for _ in range(100):
            noise = b"\xc0\x00\x00\x00\x01" + bytes(rng.randrange(256) for _ in range(rng.randrange(0, 1300)))
            self.assertIn(inspector.inspect(noise).status, ("identified", "unknown", "malformed", "budget_exhausted"))
        self.assertLess(time.monotonic() - start, 10.0)


if __name__ == "__main__":
    unittest.main()
