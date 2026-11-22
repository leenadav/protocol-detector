#!/usr/bin/env python3
"""Adversarial identification: inputs built to deceive the detector, judged for honesty, in both engines.

Every case is synthetic and built here. Five kinds of deception (Lee, 2026-11-18):

  mimic      bytes that imitate another protocol's opening (a request line over binary, a banner prefix, a
             record header over noise, zeros);
  prefix     a protocol's prefix followed by a different protocol, or a stray byte before a valid opening;
  sni        a TLS server name that the certificate does not support (lookalikes, a known service's name over
             an unrelated certificate);
  port       a protocol on another protocol's port, and noise on well-known ports (TCP and UDP);
  fragment   the same bytes cut, reordered or overlapped to try to change the verdict.

Each case states what an honest detector may answer: either the identification the bytes support, or an
evidence-limited outcome (unknown, malformed, incomplete, invalidated, budget_exhausted). A session-level case
also requires that a server name stays a client assertion, never authenticated identity. An answer outside
that is a misidentification. Every misidentification must be listed in FINDINGS with its finding id; an
unlisted one fails, and so does a listed one that no longer reproduces. Both engines must give the same
answer to every case: the Python reference is computed here (migration/parity/cases.py runners) and the Go
backend answers through `protodetect replay`, compared exactly by compare.py.

    python3 -B migration/parity/adversarial.py --binary go/bin/protodetect
"""
import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import cases as C  # noqa: E402
import compare  # noqa: E402
from protocol_adapters import protocol_fixtures as F  # noqa: E402
from protocol_adapters.make_sample_pcap import frame, udp_frame  # noqa: E402

LIMITED = {"unknown", "malformed", "incomplete", "invalidated", "budget_exhausted", "detecting"}
CLIENT = ("192.0.2.10", 51000)
NAMED_BASES = ("structural", "client_assertion")      # what may name an application in a session record
OUTCOME_BASES = ("none", None)                        # an evidence-limited outcome claims no basis

# Misidentifications this suite knows of: case id -> finding id (see migration/STATUS.md, "Adversarial
# identification"). A listed case must still misidentify; anything else must be honest.
FINDINGS = {}

# Families that identify seeded random noise (the `noise` cases): (transport, family) -> finding id. The rate is
# reported; a listed family that no longer appears, or an unlisted one that does, fails the suite.
NOISE_FINDINGS = {("udp", "coap"): "F-ADV-1"}
NOISE_LENGTHS = (4, 8, 16, 32, 64, 128, 512)
NOISE_SEED, NOISE_COUNT = 7, 2000


def sni(host):
    name = host.encode("ascii")
    return (0, (len(name) + 3).to_bytes(2, "big") + b"\x00" + len(name).to_bytes(2, "big") + name)


def hello(host="www.example.com"):
    return F.client_hello_with([sni(host), (43, b"\x02\x03\x04")])


HTTP = b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"
NOISE = bytes((i * 151 + 7) % 256 for i in range(96))


def family(observation):
    """The family an identification names: "http/1.1" is http, "tls" is tls."""
    named = observation.get("application_protocol") or observation.get("encryption") or ""
    return named.split("/", 1)[0]


def stream(cid, chunks, allowed, hint=None, end="fin"):
    """A stream case: `allowed` is the set of families an identification may name (empty: none may)."""
    return {"id": "adversarial/" + cid, "kind": "stream", "label": "adversarial/" + cid.split("/")[0],
            "chunks": [c.hex() for c in chunks], "hint": hint, "config": {}, "end": end}, ("stream", frozenset(allowed))


def datagram(cid, payload, allowed, hint=None):
    return {"id": "adversarial/" + cid, "kind": "datagram", "label": "adversarial/" + cid.split("/")[0],
            "payload": payload.hex(), "hint": hint, "config": {}}, ("datagram", frozenset(allowed))


def session(cid, frames, allowed_apps, options=None):
    """A session case: every record's app must be in `allowed_apps`, and a named application must rest on the
    client's assertion or on structure, never on authenticated identity."""
    return {"id": "adversarial/" + cid, "kind": "session", "label": "adversarial/" + cid.split("/")[0],
            "packets": [C._packet(0.001 * i, f) for i, f in enumerate(frames)], "options": options or {}}, ("session", frozenset(allowed_apps))


def tcp(server, payload, reply=b"", cuts=(), order=None):
    frames = C._tcp_flow(CLIENT, server, payload, cuts=cuts, fin=not reply, order=order)
    if reply:
        frames.append(frame(server, CLIENT, 9000, 1000 + len(payload), 24, reply))
        frames.append(frame(CLIENT, server, 1000 + len(payload), 9000 + len(reply), 17))
    return frames


def build():
    out = []
    # -- mimic: another protocol's opening over the wrong body ------------------------------------------------
    out.append(stream("mimic/http-request-line-over-binary", [b"GET / HTTP/1.1\r\n" + NOISE + b"\r\n\r\n"], {"http"}))
    out.append(stream("mimic/http-request-line-only", [b"GET / HTTP/1.1\r\n"], {"http"}))
    out.append(stream("mimic/ssh-banner-prefix-over-binary", [b"SSH-2.0-" + NOISE], set()))
    out.append(stream("mimic/tls-record-header-over-noise", [b"\x16\x03\x01\x00\x60" + NOISE], set()))
    out.append(stream("mimic/tls-handshake-type-without-hello", [b"\x16\x03\x01\x00\x08\x01\x00\x00\x04\x03\x03\x00\x00"], set()))
    out.append(stream("mimic/zeros", [bytes(64)], set()))
    out.append(stream("mimic/dns-tcp-length-over-noise", [len(NOISE).to_bytes(2, "big") + NOISE], set()))
    out.append(stream("mimic/smtp-greeting-shape-binary", [b"220 " + NOISE + b"\r\n"], {"smtp"}))
    out.append(stream("mimic/http-response-line-from-client", [b"HTTP/1.1 200 OK\r\n" + NOISE], {"http"}))
    out.append(stream("mimic/proxy-v1-then-tls", [b"PROXY TCP4 192.0.2.1 198.51.100.1 1 443\r\n" + hello()], set()))
    out.append(datagram("mimic/dns-header-over-noise", b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + NOISE, set()))
    out.append(datagram("mimic/quic-long-header-over-noise", b"\xc0\x00\x00\x00\x01\x08" + NOISE, set()))
    # -- prefix: one protocol's opening, then another ------------------------------------------------------
    out.append(stream("prefix/http-then-tls", [HTTP + hello()], {"http"}))
    out.append(stream("prefix/stray-byte-then-tls", [b"\x00" + hello()], set()))
    out.append(stream("prefix/stray-byte-then-http", [b" " + HTTP], {"http"}))
    out.append(stream("prefix/ssh-banner-then-http", [b"SSH-2.0-OpenSSH_9.6\r\n" + HTTP], {"ssh"}))
    out.append(stream("prefix/tls-then-http", [hello() + HTTP], {"tls"}))
    out.append(stream("prefix/http-banner-crlf-then-ssh", [b"\r\n" + b"SSH-2.0-OpenSSH_9.6\r\n"], {"ssh"}))
    # -- sni: the server name disagrees with what the certificate could support ----------------------------
    for host, apps in (("www.youtube.com", {"youtube"}), ("www.youtube.com.attacker.example", {"ssl"}),
                       ("youtube.com.", {"youtube", "ssl"}), ("xn--yutube-wqa.com", {"ssl"}), ("WWW.YOUTUBE.COM", {"youtube", "ssl"})):
        out.append(session("sni/" + host.replace(".", "-"), tcp(("198.51.100.7", 443), hello(host), reply=F.TLS_SERVER12_CERTIFICATE),
                           apps, {"certificates": True}))
    # -- port: protocols on other protocols' ports, noise on well-known ports -------------------------------
    for name, port, payload, apps in (("ssh-on-443", 443, b"SSH-2.0-OpenSSH_9.6\r\n", {"ssh"}), ("tls-on-80", 80, hello(), {"ssl"}),
                                      ("http-on-22", 22, HTTP, {"web-browsing"}), ("noise-on-443", 443, NOISE, {"unknown-tcp", "incomplete"}),
                                      ("noise-on-22", 22, NOISE, {"unknown-tcp", "incomplete"}),
                                      ("noise-on-445", 445, NOISE, {"unknown-tcp", "incomplete"})):
        out.append(session("port/" + name, tcp(("198.51.100.8", port), payload), apps))
    for name, port, payload, apps in (("noise-on-53", 53, NOISE, {"unknown-udp"}), ("noise-on-443", 443, NOISE, {"unknown-udp"}),
                                      ("noise-on-5004", 5004, NOISE, {"unknown-udp"}), ("dns-on-443", 443, F.DNS, {"dns"}),
                                      ("noise-on-123", 123, NOISE[:48], {"unknown-udp", "ntp"})):
        out.append(session("port/udp-" + name, [udp_frame(CLIENT, ("198.51.100.9", port), payload)], apps))
    # -- fragment: the same bytes cut, reordered or overlapped --------------------------------------------
    data = hello()
    out.append(stream("fragment/tls-every-byte", [data[i:i + 1] for i in range(len(data))], {"tls"}))
    out.append(stream("fragment/http-every-byte", [HTTP[i:i + 1] for i in range(len(HTTP))], {"http"}))
    out.append(stream("fragment/tls-record-split", [data[:5] + data[5:9], data[9:]], {"tls"}))
    split = data[5:]
    two_records = b"\x16\x03\x03" + (20).to_bytes(2, "big") + split[:20] + b"\x16\x03\x03" + (len(split) - 20).to_bytes(2, "big") + split[20:]
    out.append(stream("fragment/tls-handshake-across-records", [two_records], {"tls"}))
    out.append(session("fragment/tls-reordered-segments", tcp(("198.51.100.7", 443), data, cuts=(7, 60), order=(2, 0, 1)), {"ssl"}))
    conflict = C._tcp_flow(CLIENT, ("198.51.100.7", 443), data, cuts=(40,), fin=False)
    conflict.append(frame(CLIENT, ("198.51.100.7", 443), 1010, 9000, 24, b"X" * 40))   # overlaps retained bytes with other bytes
    out.append(session("fragment/tls-conflicting-overlap", conflict, {"incomplete", "unknown-tcp", "ssl"}))
    http_conflict = C._tcp_flow(CLIENT, ("198.51.100.8", 80), HTTP, cuts=(10,), fin=False, order=(1, 0))
    http_conflict.append(frame(CLIENT, ("198.51.100.8", 80), 1000, 9000, 24, b"SSH-2.0-OpenSSH_9.6\r\n"[:10]))
    out.append(session("fragment/http-overlap-rewrites-start", http_conflict, {"incomplete", "unknown-tcp", "web-browsing"}))
    # -- noise: seeded random payloads, as a stream (with FIN) and as a datagram ----------------------------
    import random
    rng = random.Random(NOISE_SEED)
    for index in range(NOISE_COUNT):
        payload = bytes(rng.getrandbits(8) for _ in range(NOISE_LENGTHS[index % len(NOISE_LENGTHS)]))
        out.append(stream("noise/tcp-{:04d}".format(index), [payload], set()))
        out.append(datagram("noise/udp-{:04d}".format(index), payload, set()))
    return out


def judge(kind, allowed, result):
    """None when the answer is honest, else what was misidentified."""
    if kind in ("stream", "datagram"):
        final = result["final"] if kind == "stream" else result["observation"]
        status = final["status"]
        if status in LIMITED:
            return None
        named = family(final)
        return None if named in allowed else "identified as {} ({})".format(named, status)
    from protocol_engine.applications import OUTCOMES
    records = result.get("records") or []
    if not records:
        return "no session record"                     # a session case that produced nothing proves nothing
    problems = []
    for record in records:
        app = record.get("app")
        basis = ((record.get("layers") or {}).get("application") or {}).get("basis")
        if record.get("engine_status") == "identified" and app in ("unknown-tcp", "unknown-udp"):
            problems.append("identified yet unknown")
        if app in OUTCOMES:
            # An evidence-limited outcome (unknown-tcp, incomplete, not-applicable, ...) claims no identity evidence.
            if basis not in OUTCOME_BASES:
                problems.append("outcome {} with application basis {}".format(app, basis))
            continue
        if app not in allowed:
            problems.append("session app {}".format(app))
        # A named application stands on its validated structure, or (a server name) on the client's assertion; a
        # port hint, a content class or no basis at all is not identification evidence for an adversarial input.
        if basis not in NAMED_BASES:
            problems.append("application basis {}".format(basis))
    return "; ".join(problems) or None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", required=True, help="the Go protodetect binary")
    args = parser.parse_args(argv)
    built = build()
    doc = json.loads((ROOT / "migration/fixtures/cases.json").read_text(encoding="utf-8"))
    doc["cases"] = []
    rules = {}
    for case, rule in built:
        case["expected"] = C.run_case(case)
        doc["cases"].append(case)
        rules[case["id"]] = rule
    failures, honest, caught = [], 0, []
    noise_hits = {}
    for case in doc["cases"]:
        kind, allowed = rules[case["id"]]
        verdict = judge(kind, allowed, case["expected"])
        if case["id"].startswith("adversarial/noise/"):
            if verdict is None:
                honest += 1
                continue
            final = case["expected"]["final"] if kind == "stream" else case["expected"]["observation"]
            key = ("tcp" if kind == "stream" else "udp", family(final))
            noise_hits.setdefault(key, []).append(case["id"])
            continue
        listed = FINDINGS.get(case["id"])
        if verdict is None and listed:
            failures.append("{}: listed as {} but now honest".format(case["id"], listed))
        elif verdict is not None and not listed:
            failures.append("{}: misidentified, not listed: {}".format(case["id"], verdict))
        elif verdict is None:
            honest += 1
        else:
            caught.append("{} ({}): {}".format(case["id"], listed, verdict))
    for key, ids in sorted(noise_hits.items()):
        listed = NOISE_FINDINGS.get(key)
        line = "{}/{} identified {} of {} noise payloads (first: {})".format(key[0], key[1], len(ids), NOISE_COUNT, ids[0])
        if listed:
            caught.append("{} ({}): {}".format(key, listed, line))
        else:
            failures.append("noise misidentified, not listed: " + line)
    for key, listed in NOISE_FINDINGS.items():
        if key not in noise_hits:
            failures.append("{} listed as {} but no longer identifies noise".format(key, listed))
    with tempfile.TemporaryDirectory() as folder:
        path, out = Path(folder) / "cases.json", Path(folder) / "results.json"
        path.write_text(json.dumps(doc), encoding="utf-8")
        (Path(folder) / "content.json").write_bytes((ROOT / "migration/fixtures/content.json").read_bytes())   # replay reads the pack beside the cases
        done = subprocess.run([args.binary, "replay", "--cases", str(path), "--out", str(out)], capture_output=True, text=True, check=False)  # noqa: S603
        if done.returncode != 0:
            failures.append("go replay failed: " + done.stderr.strip()[:300])
        else:
            report = compare.compare(doc, json.loads(out.read_text(encoding="utf-8")))
            matched = report["matched"]
            for item in report["mismatched"][:10]:
                failures.append("engines differ on {}: {}".format(item["id"], item["differences"][:2]))
            if report["missing"] or report["unsupported"]:
                failures.append("go answered {} cases unsupported, {} missing".format(report["unsupported"], len(report["missing"])))
    for line in caught:
        print("adversarial finding:", line)
    for line in failures:
        print("adversarial FAILED:", line)
    print("adversarial: {} cases, {} honest, {} known findings, {} failures; Go matched the reference on {} of {}".format(
        len(doc["cases"]), honest, len(caught), len(failures), locals().get("matched", 0), len(doc["cases"])))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
