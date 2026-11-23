"""Migration M8: the Go `decrypt-capture` command against the Python reference on generated TLS captures.

    python3 -B migration/parity/decrypt_diff.py --binary PATH [--count 300] [--seed 1]

Every capture and key log is generated here, in memory, from seeded random secrets: TLS 1.3 (all three AEAD
suites) and TLS 1.2 ECDHE-RSA AES-GCM record streams whose plaintext carries protocols the engine names, plus
a few exchanges produced by OpenSSL in memory. Streams are cut into TCP segments with seeded faults (reordered,
duplicated, dropped and conflicting segments, segments before the stream origin, missing SYN or SYN-ACK, SYN
with data, early or missing FIN, RST, tuple reuse, more connections than the adapter holds), records are
flipped, truncated, repeated or dropped, and key logs lose lines, carry wrong secrets or malformed lines.
The reference (presentation/poc_decryption/capture.py analyze_capture_reference) runs in process; the Go binary gets the
same capture and key log on standard input. Reports must be equal as JSON text, refusals in class, message
and reason code. Nothing is written to disk and no secret is printed. Needs the `cryptography` package (the
reference decrypts with it): presentation/requirements-decryption.lock.txt.
"""
import argparse
import hashlib
import json
import random
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "presentation"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

SUITES13 = {0x1301: ("sha256", 16), 0x1302: ("sha384", 32), 0x1303: ("sha256", 32)}
SUITES12 = {0xc02f: ("sha256", 16), 0xc030: ("sha384", 32)}
NAMES = (b"example.com", b"www.youtube.com", b"chatgpt.com", b"demo.invalid", b"github.com")
EXCHANGES = (
    (b"GET / HTTP/1.1\r\nHost: demo.invalid\r\n\r\n", b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 0\r\n\r\n"),
    (b"PROPFIND /documents HTTP/1.1\r\nHost: demo.invalid\r\nDepth: 0\r\nContent-Length: 0\r\n\r\n", b"HTTP/1.1 207 Multi-Status\r\nContent-Length: 0\r\n\r\n"),
    (b"POST /svc HTTP/1.1\r\nHost: www.youtube.com\r\nContent-Type: application/grpc\r\nContent-Length: 0\r\n\r\n", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
    (b"*1\r\n$4\r\nPING\r\n", b"+PONG\r\n"),
    (b"SSH-2.0-OpenSSH_9.6\r\n", b"SSH-2.0-OpenSSH_9.6\r\n"),
    (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00", b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"),
    (b"\x10\x11\x00\x04MQTT\x05\x02\x00<\x00\x00\x04demo", b"\x20\x03\x00\x00\x00"),
    (b"", b""),
)


class Generator:
    def __init__(self, seed):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
        from poc_decryption import expand
        from poc_decryption.tls12 import prf
        self.rng = random.Random(seed)
        self.aesgcm, self.chacha, self.expand, self.prf = AESGCM, ChaCha20Poly1305, expand, prf
        self.real = []

    def rb(self, n):
        return bytes(self.rng.getrandbits(8) for _ in range(n))

    @staticmethod
    def rec(kind, body, version=b"\x03\x03"):
        return bytes([kind]) + version + struct.pack("!H", len(body)) + body

    @staticmethod
    def hs(kind, body):
        return bytes([kind]) + len(body).to_bytes(3, "big") + body

    @staticmethod
    def ext(kind, data):
        return struct.pack("!HH", kind, len(data)) + data

    def client_hello(self, client_random, tls13=True):
        rng, name = self.rng, self.rng.choice(NAMES)
        body = b"\x03\x03" + client_random + b"\x20" + self.rb(32) + b"\x00\x08\x13\x01\x13\x02\x13\x03\xc0\x2f\x01\x00"
        sni = self.ext(0, struct.pack("!HBH", len(name) + 3, 0, len(name)) + name)
        alpn = self.ext(16, b"\x00\x0c\x02h2\x08http/1.1") if rng.random() < 0.5 else b""
        extensions = (self.ext(43, b"\x02\x03\x04") if tls13 else b"") + (sni if rng.random() < 0.8 else b"") + alpn
        return self.hs(1, body + struct.pack("!H", len(extensions)) + extensions)

    def server_hello(self, suite, tls13=True, server_random=None):
        extensions = (self.ext(43, b"\x03\x04") if tls13 else b"") + self.ext(51, self.rb(36))
        body = b"\x03\x03" + (server_random or self.rb(32)) + b"\x20" + self.rb(32) + struct.pack("!H", suite) + b"\x00"
        return self.hs(2, body + struct.pack("!H", len(extensions)) + extensions)

    def payloads(self):
        request, response = self.rng.choice(EXCHANGES)
        if self.rng.random() < 0.1:
            request, response = self.rb(self.rng.randint(1, 300)), self.rb(self.rng.randint(1, 300))
        return request, response

    def session13(self):
        rng = self.rng
        suite = rng.choice(sorted(SUITES13))
        digest, size = SUITES13[suite]
        width = hashlib.new(digest).digest_size
        client_random = self.rb(32)
        secrets = {label: self.rb(width) for label in ("CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                                                       "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0")}
        owner = self

        class Side:
            def __init__(self, handshake, application):
                self.secrets, self.phase, self.sequence = {"h": handshake, "a": application}, "h", 0
                self.install()

            def install(self):
                secret = self.secrets[self.phase]
                cipher = owner.chacha if suite == 0x1303 else owner.aesgcm
                self.cipher, self.iv = cipher(owner.expand(secret, b"key", size, digest)), owner.expand(secret, b"iv", 12, digest)

            def record(self, kind, content, pad=0):
                inner = content + bytes([kind]) + bytes(pad)
                header = b"\x17\x03\x03" + struct.pack("!H", len(inner) + 16)
                nonce = bytes(a ^ b for a, b in zip(self.iv, self.sequence.to_bytes(12, "big")))
                self.sequence += 1
                return header + self.cipher.encrypt(nonce, inner, header)

            def application(self):
                self.phase, self.sequence = "a", 0
                self.install()

            def update(self):
                self.secrets["a"] = owner.expand(self.secrets["a"], b"traffic upd", width, digest)
                self.sequence = 0
                self.install()

        client_side = Side(secrets["CLIENT_HANDSHAKE_TRAFFIC_SECRET"], secrets["CLIENT_TRAFFIC_SECRET_0"])
        server_side = Side(secrets["SERVER_HANDSHAKE_TRAFFIC_SECRET"], secrets["SERVER_TRAFFIC_SECRET_0"])
        client = [self.rec(22, self.client_hello(client_random), rng.choice([b"\x03\x01", b"\x03\x03"]))]
        server = [self.rec(22, self.server_hello(suite))]
        if rng.random() < 0.5:
            server.append(self.rec(20, b"\x01"))
        messages = self.hs(8, b"\x00\x00") + self.hs(11, self.rb(rng.randint(10, 300))) + self.hs(15, self.rb(rng.randint(10, 80))) + self.hs(20, self.rb(width))
        if rng.random() < 0.3:
            cut = rng.randint(1, len(messages) - 1)
            server += [server_side.record(22, messages[:cut]), server_side.record(22, messages[cut:])]
        else:
            server.append(server_side.record(22, messages, rng.choice([0, 0, 5])))
        server_side.application()
        if rng.random() < 0.5:
            client.append(self.rec(20, b"\x01"))
        client.append(client_side.record(22, self.hs(20, self.rb(width))))
        client_side.application()
        request, response = self.payloads()
        for side, records, data in ((client_side, client, request), (server_side, server, response)):
            if rng.random() < 0.2:
                records.append(side.record(22, self.hs(4, self.rb(20))) if side is server_side else side.record(23, b""))
            if rng.random() < 0.15:
                records.append(side.record(22, self.hs(24, bytes([rng.choice([0, 1])]))))
                side.update()
            offset = 0
            while offset < len(data):
                size_ = rng.choice([1, 5, 40, len(data), len(data)])
                records.append(side.record(23, data[offset:offset + size_], rng.choice([0, 0, 3])))
                offset += size_
            for _ in range(rng.choice([0, 0, 0, 1, 3, 3, 150])):           # 150: more records than one work slice takes
                records.append(side.record(23, self.rb(rng.randint(0, 200))))
            if rng.random() < 0.3:
                records.append(side.record(21, b"\x01\x00"))
        keylog = "".join("%s %s %s\n" % (label, client_random.hex(), secret.hex()) for label, secret in secrets.items())
        return client, server, keylog

    def session12(self):
        rng = self.rng
        suite = rng.choice(sorted(SUITES12))
        digest, size = SUITES12[suite]
        client_random, server_random, master = self.rb(32), self.rb(32), self.rb(48)
        block = self.prf(master, b"key expansion" + server_random + client_random, 2 * size + 8, digest)
        keys = {"c": (self.aesgcm(block[:size]), block[2 * size:2 * size + 4]), "s": (self.aesgcm(block[size:2 * size]), block[2 * size + 4:])}
        sequences = {"c": 0, "s": 0}

        def encrypt(side, kind, content):
            cipher, iv = keys[side]
            explicit = self.rb(8)
            aad = sequences[side].to_bytes(8, "big") + bytes([kind]) + b"\x03\x03" + struct.pack("!H", len(content))
            sequences[side] += 1
            return self.rec(kind, explicit + cipher.encrypt(iv + explicit, content, aad))

        client = [self.rec(22, self.client_hello(client_random, tls13=False))]
        hello = self.server_hello(suite, tls13=False, server_random=server_random)
        rest = self.hs(11, self.rb(rng.randint(10, 200))) + self.hs(12, self.rb(40)) + self.hs(14, b"")
        server = [self.rec(22, hello + rest)] if rng.random() < 0.5 else [self.rec(22, hello), self.rec(22, rest)]
        client += [self.rec(22, self.hs(16, self.rb(66))), self.rec(20, b"\x01"), encrypt("c", 22, b"\x14\x00\x00\x0c" + self.rb(12))]
        server += [self.rec(20, b"\x01"), encrypt("s", 22, b"\x14\x00\x00\x0c" + self.rb(12))]
        request, response = self.payloads()
        for side, records, data in (("c", client, request), ("s", server, response)):
            offset = 0
            while offset < len(data):
                size_ = rng.choice([1, 5, 40, len(data), len(data)])
                records.append(encrypt(side, 23, data[offset:offset + size_]))
                offset += size_
            for _ in range(rng.choice([0, 0, 0, 1, 3, 3, 150])):
                records.append(encrypt(side, 23, self.rb(rng.randint(0, 200))))
            if rng.random() < 0.3:
                records.append(encrypt(side, 21, b"\x01\x00"))
        return client, server, "CLIENT_RANDOM %s %s\n" % (client_random.hex(), master.hex())

    def openssl(self):
        """One of a few exchanges OpenSSL produced in memory (its hellos are inside the passive TLS profile)."""
        if not self.real:
            from poc_decryption.demo import fixture
            for index, options in enumerate((dict(version="1.3"), dict(version="1.2", cipher="ECDHE-RSA-AES128-GCM-SHA256"),
                                             dict(version="1.2", cipher="ECDHE-RSA-AES256-GCM-SHA384"), dict(version="1.3"))):
                request, response = EXCHANGES[index]
                _, keylog, client, server = fixture(request=request, response=response, **options)
                self.real.append((client, server, keylog))
        client, server, keylog = self.rng.choice(self.real)
        return [client], [server], keylog

    def stream_faults(self, client, server, keylog):
        rng = self.rng
        for _ in range(rng.choice([0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2])):
            records = rng.choice([client, server])
            if not records:
                continue
            index, fault = rng.randrange(len(records)), rng.random()
            if fault < 0.3:
                data = bytearray(records[index])
                if data:
                    data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
                records[index] = bytes(data)
            elif fault < 0.45:
                del records[index]
            elif fault < 0.55:
                records.insert(index, records[index])
            elif fault < 0.65 and len(records) > 1:
                other = rng.randrange(len(records))
                records[index], records[other] = records[other], records[index]
            elif fault < 0.75:
                records[index] = records[index][:rng.randrange(len(records[index]) + 1)]
            elif fault < 0.85:
                records.insert(index, self.rec(rng.choice([20, 21, 22, 23, 24]), self.rb(rng.randint(0, 30))))
            else:
                records.append(self.rb(rng.randint(1, 6)))
        lines = keylog.splitlines()
        if lines and rng.random() < 0.15:
            del lines[rng.randrange(len(lines))]
        keylog = "".join(line + "\n" for line in lines)
        if lines and rng.random() < 0.05:
            keylog = keylog[:-10] + "0" * 9 + "\n"
        if rng.random() < 0.05:
            keylog = "# comment\r\n\n" + keylog + "SERVER_TRAFFIC_SECRET_1 aa bb\n"
        return b"".join(client), b"".join(server), keylog

    def connection(self, index):
        """(frames with relative order, key log) of one TCP connection carrying one generated exchange."""
        from protocol_adapters.make_sample_pcap import frame
        rng = self.rng
        kind = rng.random()
        if kind < 0.45:
            client, server, keylog = self.session13()
        elif kind < 0.75:
            client, server, keylog = self.session12()
        elif kind < 0.93:
            client, server, keylog = self.openssl()
        else:
            request, response = self.payloads()                   # not TLS at all: no row
            client, server, keylog = [request], [response], ""
        client, server, keylog = self.stream_faults(list(client), list(server), keylog)
        a = ("192.0.2.{}".format(10 + index % 200), 51000 + index)
        b = ("198.51.100.20", rng.choice([443, 443, 8443, 6379, 22]))
        isn = {a: rng.choice([999, 0xffffffff, 0xfffffff0, rng.randrange(1 << 32)]), b: rng.choice([8999, rng.randrange(1 << 32)])}
        origin = {a: (isn[a] + 1) % (1 << 32), b: (isn[b] + 1) % (1 << 32)}
        shape = rng.random() * 1.6                                   # the first 0.1 of the range are broken handshakes
        frames = []
        if shape >= 0.04:
            frames.append(frame(a, b, isn[a], 0, 2, b"x" if shape < 0.07 else b""))
        if shape >= 0.1:
            frames.append(frame(b, a, isn[b], origin[a], 18))
        elif shape >= 0.08:
            frames.append(frame(a, b, isn[b], origin[a], 18))            # a SYN-ACK from the client's side
        frames.append(frame(a, b, origin[a], origin[b], 16))
        queues = []
        for source, destination, data in ((a, b, client), (b, a, server)):
            segments, offset = [], 0
            while offset < len(data):
                size = rng.choice([1, 100, 536, 700, 1400, 1400, 9000])
                segments.append((offset, data[offset:offset + size]))
                offset += size
            fault = rng.random()
            if fault < 0.15:
                rng.shuffle(segments)
            elif fault < 0.25 and segments:
                segments.insert(rng.randrange(len(segments) + 1), segments[rng.randrange(len(segments))])
            elif fault < 0.28 and segments:
                at, body = rng.choice(segments)
                segments.insert(rng.randrange(len(segments) + 1), (at, bytes(value ^ 1 for value in body)))
            elif fault < 0.31 and segments:
                del segments[rng.randrange(len(segments))]
            elif fault < 0.325:
                segments.insert(rng.randrange(len(segments) + 1), (-rng.choice([1, 4, 2000]), b"before the origin"))
            elif fault < 0.34:
                segments.insert(rng.randrange(len(segments) + 1), (rng.choice([262144, 262140, 1 << 20]), b"beyond the window"))
            packets = [frame(source, destination, (origin[source] + at) % (1 << 32), 0, 24, body) for at, body in segments]
            ending = rng.random()
            if ending < 0.7:
                packets.append(frame(source, destination, (origin[source] + len(data) + rng.choice([0] * 12 + [-3, 5])) % (1 << 32), 0, 17))
                if rng.random() < 0.1:
                    packets.append(frame(source, destination, (origin[source] + len(data)) % (1 << 32), 0, 24, b"after the end"))
            elif ending < 0.78:
                packets.append(frame(source, destination, (origin[source] + len(data)) % (1 << 32), 0, 4))
            queues.append(packets)
        while queues[0] or queues[1]:
            queue = queues[0] if (queues[0] and (not queues[1] or rng.random() < 0.55)) else queues[1]
            frames.append(queue.pop(0))
        if rng.random() < 0.08:                                              # the tuple starts over
            frames.append(frame(a, b, (isn[a] + 77777) % (1 << 32), 0, 2))
            frames.append(frame(b, a, isn[b], (isn[a] + 77778) % (1 << 32), 18))
            frames.append(frame(a, b, (isn[a] + 77778) % (1 << 32), 0, 24, client[:300]))
        return frames, keylog

    def capture(self):
        """(capture bytes, key log text) of one generated case."""
        from protocol_adapters.make_sample_pcap import frame, udp_frame
        import analyze_diff
        rng = self.rng
        connections = [self.connection(index) for index in range(rng.choice([1, 1, 1, 2, 3, 5]))]
        keylog = "".join(text for _, text in connections)
        if rng.random() < 0.05:
            keylog = ""
        if rng.random() < 0.03:
            keylog += rng.choice(["too few fields\n", "CLIENT_RANDOM zz 00\n", "CLIENT_RANDOM " + "ab" * 32 + " " + "cd" * 20 + "\n"])
        if rng.random() < 0.02:
            keylog += "# padding\n" * 30000                                    # past the key-log budget
        queues, ordered = [list(frames) for frames, _ in connections], []
        if rng.random() < 0.5:
            while any(queues):
                queue = rng.choice([q for q in queues if q])
                ordered.append(queue.pop(0))
        else:
            for queue in queues:
                ordered.extend(queue)
        if rng.random() < 0.03:                                              # more connections than the adapter holds
            for index in range(70):
                ordered.insert(rng.randrange(len(ordered) + 1), frame(("192.0.2.9", 20000 + index), ("198.51.100.20", 443), 5, 0, 2))
        for _ in range(rng.choice([0, 0, 1, 3])):
            extra = rng.choice([udp_frame(("192.0.2.5", 5353), ("198.51.100.20", 53), b"\x124\x01\x00\x00\x01" + bytes(6) + b"\x03www\x00\x00\x01\x00\x01"),
                                bytes(rng.randrange(256) for _ in range(rng.randint(0, 80)))])
            ordered.insert(rng.randrange(len(ordered) + 1), extra)
        now, records = 1700000000.0, []
        for data in ordered:
            records.append([now, data, rng.random() < 0.004])
            now += rng.choice([0, 0, 0, 0.001, 0.5, 61, 200]) if rng.random() < 0.3 else 0.0001
        import io
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "capture")
            analyze_diff.write_capture(rng, path, records)
            with io.open(path, "rb") as handle:
                return handle.read(), keylog


def reference(capture, keylog):
    from poc_decryption import DecryptionError
    from poc_decryption.capture import analyze_capture_reference as analyze_capture
    from protocol_adapters.packets import CaptureError
    try:
        return 0, json.dumps(analyze_capture(capture, keylog))
    except DecryptionError as error:
        return 3, json.dumps({"error_type": "DecryptionError", "error": str(error), "code": error.code})
    except CaptureError as error:
        return 3, json.dumps({"error_type": "CaptureError", "error": str(error), "code": ""})


def approved_divergence(capture, keylog, status, actual):
    """PRO-260 (Lee, 2026-11-23; migration/STATUS.md "Frozen-Python exceptions"): Go recognises a ServerHello whose
    key_share selects a post-quantum hybrid group, which the frozen reference reports as unknown; the OpenSSL-made
    exchanges negotiate X25519MLKEM768 by default (OpenSSL 3.5 and later). A report that differs from the
    reference is approved only when it equals, byte for byte, the reference's report under that one change
    (migration/parity/pro260.py)."""
    import pro260
    with pro260.with_hybrid_groups():
        model_status, model = reference(capture, keylog)
    return model_status == status and model == actual


def shortfall(captures, kinds):
    """Why a run without a divergence still proved nothing (Codex PRO-20): no capture was compared, or no
    connection was decrypted (only refusals and unavailable rows)."""
    problems = []
    if captures < 1:
        problems.append("no capture was compared (--count {})".format(captures))
    if kinds.get("decrypted", 0) < 1:
        problems.append("no connection was decrypted")
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", required=True, help="the Go protodetect binary")
    parser.add_argument("--count", type=int, default=300)
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args(argv)
    try:
        generator = Generator(args.seed)
    except ImportError:
        print("decrypt parity FAILED: the reference needs the `cryptography` package "
              "(python3 -m pip install --require-hashes -r presentation/requirements-decryption.lock.txt)")
        return 1
    failures, kinds, applications, approved = [], {}, set(), 0
    for index in range(args.count):
        capture, keylog = generator.capture()
        status, expected = reference(capture, keylog)
        done = subprocess.run([args.binary, "decrypt-capture"], input=struct.pack(">Q", len(capture)) + capture + keylog.encode("utf-8"),  # noqa: S603
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=120)
        actual = done.stdout.decode("utf-8").rstrip("\n")
        result = json.loads(expected)
        for row in result.get("connections", ()):
            label = row["status"] if row["status"] != "unavailable" else "unavailable/" + row["reason_code"]
            kinds[label] = kinds.get(label, 0) + 1
            if row.get("application"):
                applications.add(row["application"])
        if "error" in result:
            kinds["refused"] = kinds.get("refused", 0) + 1
        if actual != expected and approved_divergence(capture, keylog, done.returncode, actual):
            approved += 1
        elif done.returncode != status or actual != expected:
            failures.append("case {} (seed {}): exit status {} (expected {}); reports {}".format(
                index, args.seed, done.returncode, status, "differ" if actual != expected else "equal"))
    for line in failures[:10]:
        print("decrypt mismatch:", line)
    problems = shortfall(args.count, kinds)
    for line in problems:
        print("decrypt parity FAILED:", line)
    print("decrypt parity: {} captures, {} mismatched, {} approved divergences (PRO-260) (seed {}); rows by status: {}; inner applications: {}".format(
        args.count, len(failures), approved, args.seed, ", ".join("{} {}".format(name, kinds[name]) for name in sorted(kinds)),
        ", ".join(sorted(applications)) or "none"))
    return 1 if failures or problems else 0


if __name__ == "__main__":
    sys.exit(main())
