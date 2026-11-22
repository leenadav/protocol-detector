#!/usr/bin/env python3
"""Randomized differential test: the Python reference is the oracle, the Go engine must agree on every case.

Each run draws COUNT cases from a seeded generator of valid-shaped client openings with randomized content:

  tls    TLS ClientHello records (cipher lists with GREASE, server names of varied shape and length, ALPN lists,
         supported_versions, groups, signature algorithms, key shares, padding, unknown and duplicated
         extensions, an outer ECH extension, legacy session ids and record versions);
  http   HTTP/1.x request heads (methods, request-target forms, versions, header sets, LF or CRLF, bodies);
  ssh    SSH identification lines (protocol versions, software and comment fields, preamble lines, an optional
         KEXINIT with random algorithm lists);
  quic   protected QUIC v1/v2 client Initials (connection-id lengths, tokens, packet numbers, ClientHello split
         into reordered CRYPTO frames with PING/PADDING, padded or short datagrams).

Every case is then varied the way traffic arrives: cut into random fragments, truncated at a random offset (with
the capture-ended end reason or none), given the correct or a wrong hint, or a tight byte budget. The Python
reference answers each case (cases.py runners: every event, the final observation, the metrics) and the Go
backend answers the same cases through `protodetect replay`; compare.py compares them exactly, after the same
canonicalization the committed parity cases use (no wall clock or generated id appears in these paths).

A mismatch fails unless its case id is in migration/parity/random_allow.json with a reason; an allow-list entry
that no longer mismatches on the seed it names fails too, so the list cannot go stale. The CI run is fixed
(seed 1, 2,000 cases, `make parity-random`, part of `make go-check`); a longer run takes any seed
(`make parity-random-long SEED=... COUNT=...`), and a failing seed reproduces exactly.

    python3 -B migration/parity/random_diff.py --binary go/bin/protodetect [--seed 1] [--count 2000] [--report FILE]
"""
import argparse
import json
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import cases as C  # noqa: E402
import compare  # noqa: E402
from protocol_adapters import protocol_fixtures as F  # noqa: E402
from protocol_engine.aes import encrypt_block, expand_key, gcm_seal  # noqa: E402
from protocol_engine.quic import V1, V2, _initial_keys  # noqa: E402

ALLOW = ROOT / "migration/parity/random_allow.json"
GREASE = [0x0a0a + 0x1010 * i for i in range(16)]
END = "Capture ended before initial message completed"
WORDS = ["www", "api", "cdn", "mail", "login", "example", "test", "a", "b1", "x-y", "xn--bcher-kva", "edge", "eu", "s3"]
TLDS = ["com", "net", "org", "io", "co.uk", "example", "invalid", "local", "xn--p1ai"]
HINTS = sorted(C.PARSERS)  # a stream hint names a registered parser (cases.run_stream drops any other)
UDP_HINTS = ["quic", "dns", "dtls", "stun", "sip", "ntp"]  # datagram hints must name a UDP validator


def u16(value):
    return value.to_bytes(2, "big")


def vec(data, width):
    return len(data).to_bytes(width, "big") + data


# -- TLS ClientHello ---------------------------------------------------------------------------------------------

def host(rng):
    shape = rng.random()
    if shape < 0.05:
        return ""
    if shape < 0.10:
        return "{}.{}.{}.{}".format(*(rng.randrange(256) for _ in range(4)))
    if shape < 0.15:
        return ".".join("a" * rng.randint(1, 63) for _ in range(rng.randint(1, 4)))[:rng.choice((63, 253, 300))]
    labels = [rng.choice(WORDS) for _ in range(rng.randint(0, 3))] + [rng.choice(WORDS), rng.choice(TLDS)]
    name = ".".join(labels)
    if rng.random() < 0.1:
        name = name.upper()
    if rng.random() < 0.05:
        name += "."
    if rng.random() < 0.03:
        name = name.replace(".", "..", 1)
    return name


def alpn(rng):
    names = [rng.choice([b"h2", b"http/1.1", b"h3", b"spdy/3", b"acme-tls/1", b"x" * rng.randint(1, 40), b""])
             for _ in range(rng.randint(1, 4))]
    return vec(b"".join(vec(n, 1) for n in names), 2)


def tls_hello(rng):
    exts = []
    if rng.random() < 0.85:
        name = host(rng).encode("ascii")
        exts.append((0, vec(b"\x00" + vec(name, 2), 2)))
    if rng.random() < 0.6:
        exts.append((16, alpn(rng)))
    if rng.random() < 0.7:
        versions = rng.sample([0x0304, 0x0303, 0x0302, rng.choice(GREASE)], rng.randint(1, 3))
        exts.append((43, vec(b"".join(u16(v) for v in versions), 1)))
    if rng.random() < 0.6:
        exts.append((10, vec(b"".join(u16(g) for g in rng.sample([0x001d, 0x0017, 0x0018, 0x11ec, rng.choice(GREASE)], 3)), 2)))
    if rng.random() < 0.5:
        exts.append((13, vec(b"".join(u16(s) for s in rng.sample([0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0201], 4)), 2)))
    if rng.random() < 0.4:
        exts.append((51, vec(u16(0x001d) + vec(bytes(rng.randrange(256) for _ in range(32)), 2), 2)))
    if rng.random() < 0.3:
        exts.append((45, b"\x01\x01"))
    if rng.random() < 0.3:
        exts.append((21, bytes(rng.randint(0, 300))))
    if rng.random() < 0.3:
        exts.append((rng.choice(GREASE), b"" if rng.random() < 0.5 else b"\x00"))
    if rng.random() < 0.2:
        exts.append((rng.randrange(60, 0xfe00), bytes(rng.randrange(256) for _ in range(rng.randint(0, 20)))))
    if rng.random() < 0.1:
        exts.append((0xfe0d, F.ech_outer(payload=bytes(rng.randint(16, 200)))))
    if rng.random() < 0.05 and exts:
        exts.append(rng.choice(exts))  # a duplicated extension: malformed
    rng.shuffle(exts)
    ciphers = rng.sample([0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xcca9, 0x009c, 0x000a, rng.choice(GREASE)], rng.randint(1, 6))
    data = F.client_hello_with(exts, ciphers=ciphers)
    if rng.random() < 0.2:
        session = bytes(rng.randrange(256) for _ in range(rng.choice((0, 32))))
        handshake = data[5:]
        body = handshake[4:]
        body = body[:34] + vec(session, 1) + body[35:]  # legacy_version and random are 34 bytes; then session_id
        handshake = b"\x01" + len(body).to_bytes(3, "big") + body
        data = data[:5 - 2] + u16(len(handshake)) + handshake
    if rng.random() < 0.15:
        data = data[:1] + rng.choice((b"\x03\x01", b"\x03\x02", b"\x03\x04", b"\x02\x00")) + data[3:]
    return data


# -- HTTP/1.x ---------------------------------------------------------------------------------------------------

def odd(rng, usual, unusual, rate=0.15):
    """Mostly a valid-shaped value, sometimes an edge case."""
    return rng.choice(unusual) if rng.random() < rate else rng.choice(usual)


def http_request(rng):
    method = odd(rng, ["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE"],
                 ["PRI", "get", "PROPFIND", "X" * rng.randint(1, 20)])
    target = odd(rng, ["/", "/index.html", "/a/b?c=d&e=f", "http://www.example.com/x", "/%7Euser", "/" + "p" * rng.randint(1, 200)],
                 ["www.example.com:443", "*", "/" + "p" * rng.randint(200, 3000), "/sp ace"])
    version = odd(rng, ["HTTP/1.1", "HTTP/1.0"], ["HTTP/2.0", "HTTP/0.9", "HTTP/1.12", "http/1.1", ""])
    eol = "\r\n" if rng.random() < 0.95 else "\n"
    line = method + " " + target + (" " + version if version else "")
    headers = []
    if rng.random() < 0.9:
        headers.append(("Host", host(rng) or "example.com"))
    pool = [("User-Agent", "client/" + str(rng.randint(1, 99))), ("Accept", "*/*"), ("Accept-Language", "en"),
            ("Connection", rng.choice(["keep-alive", "close"])), ("X-" + "h" * rng.randint(1, 30), "v"),
            ("Cookie", "k=" + "v" * rng.randint(0, 200)), ("Content-Type", "text/plain"), ("Empty", ""),
            ("Cache-Control", "no-cache"), ("Referer", "http://www.example.com/")]
    headers += rng.sample(pool, rng.randint(0, len(pool)))
    if rng.random() < 0.1:  # an upgrade, usually well formed
        headers = [h for h in headers if h[0] != "Connection"] + [("Connection", "Upgrade"), ("Upgrade", rng.choice(["websocket", "h2c"]))]
    if rng.random() < 0.08:  # one of the framing or header edge cases the profile rejects
        headers.append(rng.choice([("Transfer-Encoding", "chunked"), ("Upgrade", "websocket"), ("Host", "second.example"),
                                   ("Transfer-Encoding", "gzip, chunked")]))
    if rng.random() < 0.05:
        headers.append(("bad header", "x"))
    body = b""
    if rng.random() < 0.2:
        body = bytes(rng.randrange(32, 127) for _ in range(rng.randint(0, 64)))
        headers.append(("Content-Length", str(len(body) if rng.random() < 0.8 else len(body) + 5)))
    text = line + eol + "".join("{}: {}{}".format(k, v, eol) for k, v in headers)
    if rng.random() < 0.05 and headers:
        text += " folded" + eol
    if rng.random() < 0.9:
        text += eol
    return text.encode("latin-1") + body


# -- SSH --------------------------------------------------------------------------------------------------------

def ssh_opening(rng):
    version = odd(rng, ["2.0", "2.0", "1.99"], ["1.5", "3.0", ""])
    software = odd(rng, ["OpenSSH_9.6", "dropbear_2022.83", "libssh_0.10.6", "PuTTY_Release_0.80", "Go"], ["x" * rng.randint(1, 250), "", "a-b"])
    line = "SSH-" + version + "-" + software
    if rng.random() < 0.3:
        line += " " + rng.choice(["Ubuntu-3ubuntu13", "comment with spaces", "c" * rng.randint(1, 100)])
    eol = "\r\n" if rng.random() < 0.95 else "\n"
    data = b""
    if rng.random() < 0.1:
        data += b"".join(("pre line " + str(i) + eol).encode() for i in range(rng.randint(1, 3)))
    data += (line + eol).encode("latin-1")
    if rng.random() < 0.4:
        lists = [b"curve25519-sha256", b"diffie-hellman-group14-sha1", b"mlkem768x25519-sha256", b"ext-info-c"]
        data += F.ssh_kexinit(kex=b",".join(rng.sample(lists, rng.randint(1, 4))),
                              hostkeys=rng.choice([b"ssh-ed25519", b"ssh-rsa", b"rsa-sha2-512,ssh-ed25519"]),
                              ciphers=rng.choice([b"aes128-ctr", b"chacha20-poly1305@openssh.com", b"3des-cbc,aes256-gcm@openssh.com"]),
                              macs=rng.choice([b"hmac-sha2-256", b"hmac-md5", b"umac-64@openssh.com"]))
    return data


# -- QUIC Initial -----------------------------------------------------------------------------------------------

def varint(value):
    for prefix, size in ((0, 1), (1, 2), (2, 4), (3, 8)):
        if value < 1 << (8 * size - 2):
            return ((prefix << (8 * size - 2)) | value).to_bytes(size, "big")
    raise ValueError(value)


def protect(version, dcid, scid, payload, packet_number, token, pad_to):
    """A protected client Initial (RFC 9001 section 5; test_quic.py's helper)."""
    key, iv, hp = _initial_keys(version, dcid)
    pn = packet_number.to_bytes(4, "big")
    payload = payload + bytes(max(0, pad_to - (7 + len(dcid) + len(scid) + 1 + len(token) + 2 + 4 + len(payload) + 16)))
    header = bytes([0xc3 if version == V1 else 0xd3]) + version.to_bytes(4, "big")
    header += vec(dcid, 1) + vec(scid, 1) + varint(len(token)) + token + varint(len(pn) + len(payload) + 16) + pn
    nonce = bytes(a ^ b for a, b in zip(iv, packet_number.to_bytes(12, "big")))
    sealed = gcm_seal(key, nonce, header, payload)
    mask = encrypt_block(expand_key(hp), sealed[:16])
    out = bytearray(header + sealed)
    out[0] ^= mask[0] & 0x0f
    for index in range(4):
        out[len(header) - 4 + index] ^= mask[1 + index]
    return bytes(out)


def quic_initial(rng):
    hello = tls_hello(rng)[5:]  # the handshake message, without its record header
    cuts = sorted(rng.sample(range(1, len(hello)), min(rng.randint(0, 3), len(hello) - 1)))
    bounds = [0] + cuts + [len(hello)]
    frames = [b"\x06" + varint(a) + varint(b - a) + hello[a:b] for a, b in zip(bounds, bounds[1:])]
    if rng.random() < 0.5:
        rng.shuffle(frames)
    if rng.random() < 0.3:
        frames.insert(rng.randrange(len(frames) + 1), b"\x01")  # PING
    version = V1 if rng.random() < 0.7 else V2
    dcid = bytes(rng.randrange(256) for _ in range(rng.choice((8, 8, 0, 4, 20))))
    scid = bytes(rng.randrange(256) for _ in range(rng.choice((0, 8, 20))))
    token = bytes(rng.randrange(256) for _ in range(rng.choice((0, 0, 16))))
    return protect(version, dcid, scid, b"".join(frames), rng.randrange(1 << 20), token, rng.choice((1200, 1200, 1252, 600)))


GENERATORS = (("tls", tls_hello, "stream"), ("http", http_request, "stream"), ("ssh", ssh_opening, "stream"),
              ("quic", quic_initial, "datagram"))


# -- variants and cases -----------------------------------------------------------------------------------------

def stream_case(rng, cid, data):
    variant = rng.random()
    end, config, hint = "fin", {}, None
    if variant < 0.25 and len(data) > 1:
        data = data[:rng.randrange(1, len(data))]
        end = rng.choice((END, None, "fin"))
    if rng.random() < 0.15:
        hint = rng.choice(HINTS)
    if rng.random() < 0.08:
        config = {"max_bytes": rng.choice((64, 256, 1024))}
    cuts = sorted(set(rng.sample(range(1, len(data)), min(rng.randint(0, 6), max(0, len(data) - 1))))) if len(data) > 1 else []
    bounds = [0] + cuts + [len(data)]
    chunks = [data[a:b].hex() for a, b in zip(bounds, bounds[1:])]
    return {"id": cid, "kind": "stream", "label": cid.split("/")[1], "chunks": chunks, "hint": hint, "config": config, "end": end}


def datagram_case(rng, cid, data):
    if rng.random() < 0.2 and len(data) > 1:
        data = data[:rng.randrange(1, len(data))]
    hint = rng.choice(UDP_HINTS) if rng.random() < 0.15 else None
    return {"id": cid, "kind": "datagram", "label": cid.split("/")[1], "payload": data.hex(), "hint": hint, "config": {}}


def build(seed, count):
    rng = random.Random(seed)
    out = []
    for index in range(count):
        name, make, kind = GENERATORS[index % len(GENERATORS)]
        cid = "random/{}/{}/{:05d}".format(name, seed, index)
        data = make(rng)
        out.append(stream_case(rng, cid, data) if kind == "stream" else datagram_case(rng, cid, data))
    return out


def judge(mismatched, allow, seed, count):
    """Failures from the mismatches ({case id: compare item}) and the allow-list ({case id: reason}): a mismatch
    the list does not name, and a listed case of this run (same seed, index below count) that no longer
    mismatches, so the list cannot go stale."""
    failures = []
    for cid in sorted(mismatched):
        if cid not in allow:
            failures.append("engines differ on {}: {}".format(cid, mismatched[cid].get("differences", [])[:2]))
    for cid, reason in sorted(allow.items()):
        _, _, entry_seed, index = cid.split("/")
        if entry_seed == str(seed) and int(index) < count and cid not in mismatched:
            failures.append("{} is allowed ({}) but the engines now agree: remove it".format(cid, reason))
    return failures


def self_test():
    """The allow-list rules and the generator's determinism, without the Go binary."""
    item = {"differences": ["final.status"]}
    allow = {"random/tls/1/00003": "understood"}
    assert judge({}, {}, 1, 10) == []
    assert judge({"random/tls/1/00003": item}, allow, 1, 10) == []                      # allowed mismatch
    assert [f for f in judge({"random/http/1/00004": item}, allow, 1, 10) if "differ on random/http" in f]  # unlisted
    stale = judge({}, allow, 1, 10)                                                     # listed, now agrees
    assert len(stale) == 1 and "now agree" in stale[0], stale
    assert judge({}, allow, 2, 10) == [] and judge({}, allow, 1, 3) == []             # other seed, beyond count
    first, again = build(5, 40), build(5, 40)
    assert first == again and first != build(6, 40), "the generator must be deterministic per seed"
    assert {case["id"].split("/")[1] for case in first} == {name for name, _, _ in GENERATORS}
    print("random differential self-test: ok (allow-list judgment, stale entries, determinism, generators)")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", help="the Go protodetect binary (required unless --self-test)")
    parser.add_argument("--self-test", action="store_true", help="check the allow-list rules and determinism, then exit")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--count", type=int, default=2000)
    parser.add_argument("--report", help="write the failures and each mismatched case (input and both answers) as JSON here")
    parser.add_argument("--plant", action="store_true",
                        help="self-check: alter the reference's answer to the first case; the run must then fail on it")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.binary:
        parser.error("--binary is required")
    allow = json.loads(ALLOW.read_text(encoding="utf-8"))["allowed"]
    started = time.monotonic()
    doc = json.loads((ROOT / "migration/fixtures/cases.json").read_text(encoding="utf-8"))
    doc["cases"] = []
    for case in build(args.seed, args.count):
        case["expected"] = C.run_case(case)
        doc["cases"].append(case)
    if args.plant:
        first = doc["cases"][0]["expected"]
        observed = first.get("final") or first["observation"]
        observed["status"] = "unknown" if observed["status"] != "unknown" else "malformed"  # valid, but wrong
    failures = []
    with tempfile.TemporaryDirectory() as folder:
        path, out = Path(folder) / "cases.json", Path(folder) / "results.json"
        path.write_text(json.dumps(doc), encoding="utf-8")
        (Path(folder) / "content.json").write_bytes((ROOT / "migration/fixtures/content.json").read_bytes())
        done = subprocess.run([args.binary, "replay", "--cases", str(path), "--out", str(out)],  # noqa: S603
                              capture_output=True, text=True, check=False)
        if done.returncode != 0:
            print("random differential FAILED: go replay failed: " + done.stderr.strip()[:300])
            return 1
        report = compare.compare(doc, json.loads(out.read_text(encoding="utf-8")))
    mismatched = {item["id"]: item for item in report["mismatched"]}
    failures += judge(mismatched, allow, args.seed, args.count)
    if report["missing"] or report["unsupported"]:
        failures.append("go answered {} cases unsupported, {} missing".format(report["unsupported"], len(report["missing"])))
    kinds = {}
    for case in doc["cases"]:
        name = case["id"].split("/")[1]
        final = case["expected"].get("final") or case["expected"].get("observation") or {}
        kinds.setdefault(name, {}).setdefault(final.get("status", "?"), 0)
        kinds[name][final.get("status", "?")] += 1
    for line in failures[:20]:
        print("random differential FAILED:", line)
    if args.report:  # a nightly job uploads this: every failing case reproduces with its seed and index
        by_id = {case["id"]: case for case in doc["cases"]}
        Path(args.report).write_text(json.dumps({
            "seed": args.seed, "count": args.count, "compared": report["compared"], "matched": report["matched"],
            "failures": failures,
            "mismatched": [dict(mismatched[cid], case=by_id.get(cid)) for cid in sorted(mismatched) if cid not in allow],
        }, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print("random differential: seed {}, {} cases ({}), Go matched the reference on {} of {}, {} allowed, {} failures, {:.0f} s".format(
        args.seed, len(doc["cases"]), "; ".join("{} {}".format(k, dict(sorted(v.items()))) for k, v in sorted(kinds.items())),
        report["matched"], report["compared"], sum(1 for cid in mismatched if cid in allow), len(failures), time.monotonic() - started))
    if args.plant:
        planted = doc["cases"][0]["id"]
        caught = planted in mismatched and len(mismatched) == 1
        print("random differential self-check: planted difference on {} {}".format(planted, "caught" if caught else "MISSED"))
        return 0 if caught else 1
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
