"""Migration M1: language-neutral differential cases generated from the Python reference.

A case is an input the engine or the adapter consumes plus the complete sequence of observations the
Python reference produced for it, canonicalized only where the plan allows (no wall clock exists in these
paths; generated identifiers do not appear; the content digest is replaced by the content release, since
the digest is an implementation detail of the hashing until M6 defines it). Reason sentences, evidence
basis, retractions, directions, boundaries, event ordering and metrics are kept verbatim.

Kinds:
  stream    chunks (hex) fed in order to one Inspector, optional hint/config, optional end reason;
            expected: every Event (kind, revision, observation), the final observation, the metrics.
  datagram  one payload through DatagramInspector; expected: observation and metrics.
  session   Ethernet frames (hex) with capture timestamps through the Analyzer; expected: per-packet
            events (the direction's new observations), the session records, and the finish outcome.

Python is the reference for supported semantics, not an oracle: a discrepancy is settled against the
documented profiles (PROTOCOLS.md) and an approved semantic delta recorded in migration/parity/deltas.json.
"""
import json
import random
import sys
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from protocol_adapters.analyze_pcap import Analyzer  # noqa: E402
from protocol_adapters.link_packets import decode_frame  # noqa: E402
from protocol_adapters.make_sample_pcap import frame, udp_frame  # noqa: E402
from protocol_adapters.protocol_fixtures import (DATAGRAM_CASES, DNS, HINTED_DATAGRAM_CASES, HINTED_STREAM_CASES,  # noqa: E402
                                                 STREAM_CASES, client_hello_with)
from protocol_engine import Config, DatagramInspector, Inspector  # noqa: E402
from protocol_engine import content  # noqa: E402
from protocol_engine.descriptors import build  # noqa: E402
from protocol_engine.registry import PARSERS  # noqa: E402

SCHEMA = 1
DESCRIPTORS = build()
CLIENT, SERVER = ("192.0.2.10", 52000), ("198.51.100.20", 8000)
CONFIG_FIELDS = ("max_bytes", "max_updates", "max_line", "max_headers", "max_crc32c_bytes", "retain_contexts", "fingerprints",
                 "quic_decrypt", "heuristics", "heuristic_bytes", "certificates", "continuation", "max_transactions")


def family_of(label):
    return (label or "").split("/", 1)[0]


# -- canonical forms ---------------------------------------------------------------------------------

def observation_dict(observation):
    data = asdict(observation)
    data["evidence"] = [[e["field"], e["value"], e["source"], e["strength"]] for e in data["evidence"]]
    data["offered_alpn"] = list(data["offered_alpn"])
    return data


def event_dict(event):
    return {"kind": event.kind, "revision": event.revision, "observation": observation_dict(event.observation)}


def metrics_dict(metrics):
    return asdict(metrics)


def record_dict(record):
    """A session record with only the content digest (implementation-specific until M6) replaced."""
    out = json.loads(json.dumps(record))
    if isinstance(out.get("content"), dict):
        out["content"] = {"version": out["content"].get("version")}
    return out


def config_dict(config):
    default = Config()
    return {name: getattr(config, name) for name in CONFIG_FIELDS if getattr(config, name) != getattr(default, name)}


def config_from(data):
    return Config(**(data or {}))


# -- running the Python reference -------------------------------------------------------------------

def run_stream(case):
    config = config_from(case.get("config"))
    hint = case.get("hint")
    inspector = Inspector(config, protocol_hint=hint if hint in PARSERS else None)
    events = []
    for chunk in case["chunks"]:
        events.extend(inspector.feed(bytes.fromhex(chunk)))
    if case.get("end"):
        events.extend(inspector.end(case["end"]))
    return {"events": [event_dict(e) for e in events], "final": observation_dict(inspector.observation),
            "metrics": metrics_dict(inspector.metrics)}


def run_datagram(case):
    inspector = DatagramInspector(config_from(case.get("config")))
    observation = inspector.inspect(bytes.fromhex(case["payload"]), case.get("hint"))
    return {"observation": observation_dict(observation), "metrics": metrics_dict(inspector.metrics)}


def stream_state(analyzer, packet):
    """M3 reassembly parity target: per direction of the packet's connection, the retained window after this
    packet (contiguous prefix length, stored bytes, highest retained end, digest of the contiguous prefix), or
    None once the connection is gone. Transport-level only: no observation enters this value."""
    import hashlib
    connection = analyzer.manager.connections.get(analyzer.manager.key(packet.source, packet.destination))
    if connection is None:
        return None
    out = {}
    for endpoint, stream in connection["directions"].items():
        out["{}:{}".format(*endpoint)] = {"contiguous": stream.contiguous, "stored": stream.stored, "highest_end": stream.highest_end,
                                         "digest": hashlib.sha256(bytes(stream.buffer[:stream.contiguous])).hexdigest()[:16]}
    return out


def run_session(case):
    records = []
    options = dict(case.get("options") or {})
    analyzer = Analyzer(on_session=records.append, idle_timeout=options.pop("idle_timeout", 60), **options)
    packets = []
    for index, packet in enumerate(case["packets"]):
        decoded = decode_frame(bytes.fromhex(packet["frame"]), packet.get("linktype", 1))
        message = analyzer.process(packet["t"], decoded)
        packets.append({"index": index, "message": message.split(" | ")[0] if message else message,
                        "events": [event_dict(e) for e in analyzer.last_events],
                        "peer_events": [[list(src), list(dst), event_dict(e)] for src, dst, e in getattr(analyzer, "peer_events", ())],
                        "streams": stream_state(analyzer, decoded),
                        "tables": [len(analyzer.tracked), len(analyzer.manager.connections), len(analyzer.udp_flows)]})
    analyzer.finish(case.get("finish") or "eof")
    return {"packets": packets, "records": [record_dict(r) for r in records]}


RUNNERS = {"stream": run_stream, "datagram": run_datagram, "session": run_session}


def run_case(case):
    return RUNNERS[case["kind"]](case)


# -- case generation ---------------------------------------------------------------------------------

def _hint_for(label):
    family = family_of(label)
    descriptor = DESCRIPTORS.get(family)
    if descriptor is not None and descriptor.requires_hint and family in PARSERS:
        return family
    return None


def _mutate(rng, data, count=2):
    out = bytearray(data)
    for _ in range(count):
        out[rng.randrange(len(out))] = rng.randrange(256)
    return bytes(out)


def stream_cases(seed=11, limit=None):
    rng = random.Random(seed)
    cases = []
    labelled = [(data, label, _hint_for(label)) for data, label in STREAM_CASES] + [(data, label, hint) for data, label, hint in HINTED_STREAM_CASES]
    if limit:
        labelled = labelled[:limit]
    for number, (data, label, hint) in enumerate(labelled):
        base = "stream/%03d-%s" % (number, label.replace("/", "_"))
        whole = data.hex()
        variants = [("whole", [whole], None), ("whole-fin", [whole], "fin"),
                    ("bytes", [data[i:i + 1].hex() for i in range(len(data))], "fin"),
                    ("sevens", [data[i:i + 7].hex() for i in range(0, len(data), 7)], "fin"),
                    ("half", [data[:max(1, len(data) // 2)].hex()], "Capture ended before initial message completed"),
                    ("mutated", [_mutate(rng, data).hex()], "fin")]
        for name, chunks, end in variants:
            case = {"id": base + "/" + name, "kind": "stream", "label": label, "chunks": chunks, "hint": hint, "config": {}, "end": end}
            cases.append(case)
    # continuation and budget variants on one HTTP request
    request = b"GET /a HTTP/1.1\r\nHost: a.example\r\n\r\n"
    second = b"POST /b HTTP/1.1\r\nHost: b.example\r\nContent-Length: 5\r\n\r\nhello"
    cases.append({"id": "stream/options/continuation", "kind": "stream", "label": "http", "chunks": [request.hex(), second.hex()],
                  "hint": None, "config": {"continuation": 4096}, "end": "fin"})
    cases.append({"id": "stream/options/byte-budget", "kind": "stream", "label": "http", "chunks": [(b"GET /" + b"a" * 200).hex()],
                  "hint": None, "config": {"max_bytes": 64}, "end": None})
    cases.append({"id": "stream/options/fingerprints", "kind": "stream", "label": "tls",
                  "chunks": [client_hello_with([(0, b"\x00\x0f\x00\x00\x0cperf.example")]).hex()], "hint": None,
                  "config": {"fingerprints": True}, "end": "fin"})
    return cases


def datagram_cases(seed=12, limit=None):
    rng = random.Random(seed)
    cases = []
    labelled = [(data, label, None) for data, label in DATAGRAM_CASES] + [(data, label, hint) for data, label, hint in HINTED_DATAGRAM_CASES]
    if limit:
        labelled = labelled[:limit]
    for number, (data, label, hint) in enumerate(labelled):
        base = "datagram/%03d-%s" % (number, label.replace("/", "_"))
        cases.append({"id": base + "/whole", "kind": "datagram", "label": label, "payload": data.hex(), "hint": hint, "config": {}})
        cases.append({"id": base + "/half", "kind": "datagram", "label": label, "payload": data[:max(1, len(data) // 2)].hex(), "hint": hint, "config": {}})
        cases.append({"id": base + "/mutated", "kind": "datagram", "label": label, "payload": _mutate(rng, data).hex(), "hint": hint, "config": {}})
    return cases


def _packet(t, data):
    return {"t": t, "linktype": 1, "frame": data.hex()}


def _tcp_flow(client, server, payload, cuts=(), isn=1000, sisn=9000, fin=True, order=None):
    frames = [frame(client, server, isn - 1, 0, 2), frame(server, client, sisn - 1, isn, 18), frame(client, server, isn, sisn, 16)]
    bounds = [0] + sorted(cuts) + [len(payload)]
    segments = [frame(client, server, isn + a, sisn, 24, payload[a:b]) for a, b in zip(bounds, bounds[1:]) if b > a]
    if order:
        segments = [segments[i] for i in order]
    frames += segments
    if fin:
        frames.append(frame(client, server, isn + len(payload), sisn, 17))
    return frames


def session_cases(limit=None):
    cases = []
    request = b"GET /a HTTP/1.1\r\nHost: a.example\r\n\r\n"
    chosen = []
    seen = set()
    for data, label in STREAM_CASES:
        family = family_of(label)
        if family in seen or DESCRIPTORS[family].requires_hint:
            continue
        seen.add(family)
        chosen.append((data, label))
        if limit and len(chosen) >= limit:
            break
    for number, (data, label) in enumerate(chosen):
        base = "session/%03d-%s" % (number, family_of(label))
        plain = _tcp_flow(CLIENT, SERVER, data)
        cases.append({"id": base + "/plain", "kind": "session", "label": label, "options": {}, "finish": "eof",
                      "packets": [_packet(0.001 * i, f) for i, f in enumerate(plain)]})
        cuts = sorted({len(data) // 3, 2 * len(data) // 3} - {0, len(data)})
        if cuts:
            split = _tcp_flow(CLIENT, SERVER, data, cuts)
            cases.append({"id": base + "/split", "kind": "session", "label": label, "options": {}, "finish": "eof",
                          "packets": [_packet(0.001 * i, f) for i, f in enumerate(split)]})
            pieces = len(cuts) + 1
            reordered = _tcp_flow(CLIENT, SERVER, data, cuts, order=list(range(pieces))[::-1])
            cases.append({"id": base + "/reordered", "kind": "session", "label": label, "options": {}, "finish": "eof",
                          "packets": [_packet(0.001 * i, f) for i, f in enumerate(reordered)]})
            # conflicting retransmission of the first segment before the rest
            changed = bytearray(data[:cuts[0]])
            changed[len(changed) // 2] ^= 0xff
            conflict = _tcp_flow(CLIENT, SERVER, data, cuts)
            conflict.insert(4, frame(CLIENT, SERVER, 1000, 9000, 24, bytes(changed)))
            cases.append({"id": base + "/conflict", "kind": "session", "label": label, "options": {}, "finish": "eof",
                          "packets": [_packet(0.001 * i, f) for i, f in enumerate(conflict)]})
    # lifecycle and mode cases on HTTP
    handshake = _tcp_flow(CLIENT, SERVER, request)
    cases.append({"id": "session/lifecycle/half-message-idle", "kind": "session", "label": "http", "options": {"idle_timeout": 30}, "finish": "eof",
                  "packets": [_packet(0.0, f) for f in _tcp_flow(CLIENT, SERVER, request[:12], fin=False)] +
                             [_packet(40.0, f) for f in _tcp_flow(("192.0.2.77", 40000), ("198.51.100.77", 7000), request)]})
    cases.append({"id": "session/lifecycle/rst", "kind": "session", "label": "http", "options": {}, "finish": "eof",
                  "packets": [_packet(0.0, f) for f in handshake[:3]] + [_packet(0.1, frame(CLIENT, SERVER, 1000, 9000, 4))]})
    cases.append({"id": "session/lifecycle/reuse", "kind": "session", "label": "http", "options": {}, "finish": "eof",
                  "packets": [_packet(0.001 * i, f) for i, f in enumerate(handshake + [frame(SERVER, CLIENT, 9000, 1000 + len(request) + 1, 17)]
                                                                            + _tcp_flow(CLIENT, SERVER, request, isn=70000, sisn=80000))]})
    client_only = [frame(CLIENT, SERVER, 999, 0, 2), frame(CLIENT, SERVER, 1000, 5000, 24, request), frame(CLIENT, SERVER, 1000 + len(request), 5000, 17)]
    for mode in ("handshake", "asymmetric"):
        cases.append({"id": "session/modes/client-only-" + mode, "kind": "session", "label": "http", "options": {"observation": mode}, "finish": "eof",
                      "packets": [_packet(0.001 * i, f) for i, f in enumerate(client_only)]})
    cases.append({"id": "session/modes/midstream-http", "kind": "session", "label": "http", "options": {"observation": "midstream"}, "finish": "eof",
                  "packets": [_packet(0.0, frame(CLIENT, SERVER, 5000, 7000, 24, request))]})
    cases.append({"id": "session/options/continuation", "kind": "session", "label": "http", "options": {"continuation": 4096}, "finish": "eof",
                  "packets": [_packet(0.001 * i, f) for i, f in enumerate(_tcp_flow(CLIENT, SERVER, request + request.replace(b"/a", b"/b")))]})
    cases.append({"id": "session/udp/dns", "kind": "session", "label": "dns", "options": {}, "finish": "eof",
                  "packets": [_packet(0.0, udp_frame(("192.0.2.12", 53001), ("198.51.100.53", 53), DNS))]})
    # QUIC: assembly across datagrams, a contradiction, and the sticky invalidation (D01/D02, round-2 repair)
    sys.path.insert(0, str(ROOT))
    from test_quic_isolation import CLIENT_HELLO, CUT, DCID, crypto_frames, initial, protect  # noqa: E402
    from protocol_engine.quic import V1  # noqa: E402
    qc, qs = ("192.0.2.10", 51000), ("192.0.2.20", 443)
    changed = bytearray(CLIENT_HELLO)
    changed[CUT + 3] ^= 0x55
    quic_frames = [initial(0), initial(1), initial(1, pieces=crypto_frames(bytes(changed), (CUT,))), protect(V1, DCID, b"", b"\x01")]
    cases.append({"id": "session/quic/assembly-conflict-sticky", "kind": "session", "label": "quic", "options": {"idle_timeout": 30}, "finish": "eof",
                  "packets": [_packet(0.1 * i, udp_frame(qc, qs, d)) for i, d in enumerate(quic_frames)]})
    cases.append({"id": "session/quic/reordered-assembly", "kind": "session", "label": "quic", "options": {"idle_timeout": 30}, "finish": "eof",
                  "packets": [_packet(0.1 * i, udp_frame(qc, qs, d)) for i, d in enumerate([initial(1), initial(0)])]})
    return cases


def generate(limit=None):
    return stream_cases(limit=limit) + datagram_cases(limit=limit) + session_cases(limit=limit)


def with_expectations(cases):
    for case in cases:
        case["expected"] = run_case(case)
    return cases


def document(cases, head=None):
    return {"schema": SCHEMA, "reference": {"backend": "python", "head": head, "content_release": content.CURRENT},
            "canonicalization": {"content.digest": "replaced by content.version (hash definition pending M6)",
                                 "wall_clock": "none in these paths; capture timestamps are inputs and kept",
                                 "identifiers": "none generated in these paths"},
            "cases": cases}


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--write", default=str(ROOT / "migration/fixtures/cases.json"))
    parser.add_argument("--limit", type=int, default=None, help="only the first N labelled fixtures per kind (smoke)")
    parser.add_argument("--head", default=None, help="the reference commit recorded in the file")
    args = parser.parse_args(argv)
    cases = with_expectations(generate(args.limit))
    Path(args.write).parent.mkdir(parents=True, exist_ok=True)
    Path(args.write).write_text(json.dumps(document(cases, args.head), indent=1, sort_keys=True) + "\n", encoding="utf-8")
    kinds = {}
    for case in cases:
        kinds[case["kind"]] = kinds.get(case["kind"], 0) + 1
    print("cases written: {} ({})".format(len(cases), ", ".join("%s %d" % item for item in sorted(kinds.items()))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
