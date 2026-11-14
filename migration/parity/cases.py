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
import struct
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
from protocol_engine.database import crc32c  # noqa: E402
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


def kerberos_vectors():
    """Kerberos KDC messages for M5 batch 17: requests with etype lists, replies with ticket and enc-part etypes,
    KRB-ERROR codes, and each rejection path of windows._kerberos_body (tags, order, required fields, pvno,
    msg-type, padata budget, times, microseconds, error codes, empty strings, minimal etype encoding)."""
    from protocol_adapters.protocol_fixtures import _ber, _krb_principal, krb_error, krb_rep

    def req(tag=0x6a, msg=b"\x0a", etypes=(b"\x12", b"\x11"), pvno=b"\x05", padata=None, body_extra=b"", order=None, omit=()):
        body_fields = [(0, _ber(0xa0, _ber(0x03, b"\x00\x40\x81\x00\x10"))),
                       (1, _ber(0xa1, _krb_principal(b"user"))),
                       (2, _ber(0xa2, _ber(0x1b, b"EXAMPLE.ORG"))),
                       (5, _ber(0xa5, _ber(0x18, b"20371231235959Z"))),
                       (7, _ber(0xa7, _ber(0x02, b"\x12\x34\x56\x78"))),
                       (8, _ber(0xa8, _ber(0x30, b"".join(_ber(0x02, e) for e in etypes))))]
        body = _ber(0x30, b"".join(v for n, v in body_fields if n not in omit) + body_extra)
        fields = [_ber(0xa1, _ber(0x02, pvno)), _ber(0xa2, _ber(0x02, msg))]
        if padata is not None:
            fields.append(_ber(0xa3, _ber(0x30, b"".join(_ber(0x30, _ber(0xa1, _ber(0x02, b"\x02"))) for _ in range(padata)))))
        fields.append(_ber(0xa4, body))
        if order:
            fields = [fields[i] for i in order]
        return _ber(tag, _ber(0x30, b"".join(fields)))

    def err(over=None):
        parts = {0: _ber(0xa0, _ber(2, b"\x05")), 1: _ber(0xa1, _ber(2, b"\x1e")), 4: _ber(0xa4, _ber(0x18, b"20260101120000Z")),
                 5: _ber(0xa5, _ber(2, b"\x01")), 6: _ber(0xa6, _ber(2, b"\x19")), 9: _ber(0xa9, _ber(0x1b, b"EXAMPLE.ORG")),
                 10: _ber(0xaa, _krb_principal(b"krbtgt")), 12: _ber(0xac, _ber(4, bytes(12)))}
        parts.update(over or {})
        return krb_error(fields=b"".join(v for k, v in sorted(parts.items()) if v is not None))

    def rep(enc_etype=b"\x12", ticket_etype=b"\x12", kvno=None, ticket_fields=4, cipher=bytes(32), tag=0x6b):
        msg = {0x6b: b"\x0b", 0x6d: b"\x0d"}[tag]
        enc = _ber(0xa0, _ber(2, enc_etype)) + (_ber(0xa1, _ber(2, kvno)) if kvno is not None else b"") + _ber(0xa2, _ber(4, cipher))
        tkt = [_ber(0xa0, _ber(2, b"\x05")), _ber(0xa1, _ber(0x1b, b"EXAMPLE.ORG")), _ber(0xa2, _krb_principal(b"krbtgt")),
               _ber(0xa3, _ber(0x30, _ber(0xa0, _ber(2, ticket_etype)) + _ber(0xa2, _ber(4, bytes(24)))))][:ticket_fields]
        fields = (_ber(0xa0, _ber(2, b"\x05")) + _ber(0xa1, _ber(2, msg)) + _ber(0xa3, _ber(0x1b, b"EXAMPLE.ORG"))
                  + _ber(0xa4, _krb_principal(b"user")) + _ber(0xa5, _ber(0x61, _ber(0x30, b"".join(tkt)))) + _ber(0xa6, _ber(0x30, enc)))
        return krb_rep(tag, fields=fields)

    return [
        ("as-req-aes", req()),
        ("tgs-req", req(0x6c, b"\x0c")),
        ("as-req-weak", req(etypes=(b"\x17", b"\x03", b"\x12", b"\x17"))),
        ("as-req-other-etype", req(etypes=(b"\x7f", b"\xff"))),
        ("as-req-negative-etype", req(etypes=(b"\xff\x80",))),
        ("as-req-nonminimal-etype", req(etypes=(b"\x00\x12",))),
        ("as-req-empty-etypes", req(etypes=())),
        ("as-req-33-etypes", req(etypes=(b"\x12",) * 33)),
        ("as-req-32-etypes", req(etypes=(b"\x11",) * 32)),
        ("as-req-no-nonce", req(omit=(7,))),
        ("as-req-padata", req(padata=2)),
        ("as-req-padata-budget", req(padata=33)),
        ("as-req-pvno4", req(pvno=b"\x04")),
        ("as-req-msgtype", req(msg=b"\x0c")),
        ("as-req-order", req(order=(1, 0, 2))),
        ("as-req-body-extra-field", req(body_extra=_ber(0xbf, b"\x00"))),
        ("as-rep", rep()),
        ("tgs-rep-rc4", rep(enc_etype=b"\x17", ticket_etype=b"\x17", tag=0x6d)),
        ("as-rep-kvno", rep(kvno=b"\x02")),
        ("as-rep-short-ticket", rep(ticket_fields=3)),
        ("as-rep-empty-cipher", rep(cipher=b"")),
        ("as-rep-bad-kvno", rep(kvno=b"")),
        ("error-preauth", err()),
        ("error-code-6", err({6: _ber(0xa6, _ber(2, b"\x06"))})),
        ("error-code-128", err({6: _ber(0xa6, _ber(2, b"\x00\x80"))})),
        ("error-code-wide", err({6: _ber(0xa6, _ber(2, b"\x00\x00\x19"))})),
        ("error-bad-time", err({4: _ber(0xa4, _ber(0x18, b"2026010112000Z0"))})),
        ("error-usec-max", err({5: _ber(0xa5, _ber(2, b"\x0f\x42\x3f"))})),
        ("error-usec-over", err({5: _ber(0xa5, _ber(2, b"\x0f\x42\x40"))})),
        ("error-usec-negative", err({5: _ber(0xa5, _ber(2, b"\xff"))})),
        ("error-empty-realm", err({9: _ber(0xa9, _ber(0x1b, b""))})),
        ("error-no-sname", err({10: None})),
        ("error-ctime", err({2: _ber(0xa2, _ber(0x18, b"20260101120000Z")), 3: _ber(0xa3, _ber(2, b"\x00"))})),
        ("error-etext", err({11: _ber(0xab, _ber(0x1b, b"text"))})),
        ("error-bad-edata", err({12: _ber(0xac, _ber(0x1b, b"x" * 40))})),
        ("unknown-tag", _ber(0x6e, _ber(0x30, bytes(60)))),
        ("trailing", req() + b"\x00"),
    ]


def kerberos_cases():
    """Kerberos over TCP (record marking) and UDP (M5 batch 17): every vector as a stream (whole / 1-byte / 7-byte /
    truncated) and as a datagram (whole / truncated), plus a padata budget at max_headers 1 and a TCP extension bit."""
    cases = []
    for number, (name, data) in enumerate(kerberos_vectors()):
        framed = len(data).to_bytes(4, "big") + data
        base = "stream/kerberos-%02d-%s" % (number, name)
        for variant, chunks, end in (("whole", [framed.hex()], "fin"), ("bytes", [framed[i:i + 1].hex() for i in range(len(framed))], "fin"),
                                     ("sevens", [framed[i:i + 7].hex() for i in range(0, len(framed), 7)], "fin"),
                                     ("half", [framed[:max(1, len(framed) // 2)].hex()], "Capture ended before initial message completed")):
            cases.append({"id": base + "/" + variant, "kind": "stream", "label": "kerberos", "chunks": chunks, "hint": None, "config": {}, "end": end})
        base = "datagram/kerberos-%02d-%s" % (number, name)
        cases.append({"id": base + "/whole", "kind": "datagram", "label": "kerberos", "payload": data.hex(), "hint": None, "config": {}})
        cases.append({"id": base + "/half", "kind": "datagram", "label": "kerberos", "payload": data[:max(1, len(data) // 2)].hex(), "hint": None, "config": {}})
    padded = dict(kerberos_vectors())["as-req-padata"]
    cases.append({"id": "stream/kerberos-options/padata-budget", "kind": "stream", "label": "kerberos",
                  "chunks": [(len(padded).to_bytes(4, "big") + padded).hex()], "hint": None, "config": {"max_headers": 1}, "end": "fin"})
    cases.append({"id": "datagram/kerberos-options/padata-budget", "kind": "datagram", "label": "kerberos", "payload": padded.hex(), "hint": None,
                  "config": {"max_headers": 1}})
    whole = dict(kerberos_vectors())["as-req-aes"]
    cases.append({"id": "stream/kerberos-options/extension-bit", "kind": "stream", "label": "kerberos",
                  "chunks": [((len(whole) | 0x80000000).to_bytes(4, "big") + whole).hex()], "hint": None, "config": {}, "end": "fin"})
    cases.append({"id": "stream/kerberos-options/byte-budget", "kind": "stream", "label": "kerberos",
                  "chunks": [(len(whole).to_bytes(4, "big") + whole).hex()], "hint": None, "config": {"max_bytes": 64}, "end": "fin"})
    return cases


def ldap_vectors():
    """LDAP messages for M5 batch 18: simple and SASL binds, GSS-SPNEGO credentials through every layout of
    gss.classify_token (NTLMSSP, direct Kerberos tokens, NegTokenInit, NegTokenResp, other mechanisms) and each of its
    rejection paths, BindResponse results with referrals and server credentials, extended requests and responses."""
    from protocol_adapters import protocol_fixtures as F
    b, der = F._ber, F.der

    def message(operation, message_id=b"\x01", extra=b""):
        return b(0x30, b(2, message_id) + operation + extra)

    def bind(auth, version=b"\x03", dn=b"", extra=b""):
        return message(b(0x60, b(2, version) + b(4, dn) + auth + extra))

    def sasl(mechanism, credentials=None, extra=b""):
        return bind(b(0xa3, b(4, mechanism) + (b(4, credentials) if credentials is not None else b"") + extra))

    def spnego(token):
        return sasl(b"GSS-SPNEGO", token)

    def response(code=0, matched=b"", diagnostic=b"", extra=b"", tag=0x61, message_id=b"\x01", controls=b""):
        return message(b(tag, b(0x0a, bytes((code,))) + b(4, matched) + b(4, diagnostic) + extra), message_id, controls)

    def extended(oid, value=None, message_id=b"\x01", controls=b""):
        return message(b(0x77, (b(0x80, oid) if oid is not None else b"") + (b(0x81, value) if value is not None else b"")), message_id, controls)

    def init(fields):
        return der(0x60, der(0x06, F.OID_SPNEGO) + der(0xa0, der(0x30, fields)))

    def resp(fields):
        return der(0xa1, der(0x30, fields))

    mechs = der(0xa0, der(0x30, der(0x06, F.OID_NTLMSSP)))
    krb = F.krb5_ap_req_message
    enc = F.krb5_encrypted
    int5, flags = b(0xa0, b(2, b"\x05")), b(0xa2, b(3, b"\x00\x20\x00\x00\x00"))
    ap = lambda *fields: F.krb5_gss(b(0x6e, b(0x30, b"".join(fields))))                       # noqa: E731
    ticket = lambda *fields: b(0xa3, b(0x61, b(0x30, b"".join(fields))))                        # noqa: E731
    realm, sname = b(0xa1, b(0x1b, b"EXAMPLE.ORG")), b(0xa2, F._krb_principal(b"cifs"))
    names = lambda count: b(0xa2, b(0x30, b(0xa0, b(2, b"\x01")) + b(0xa1, b(0x30, b(0x1b, b"n") * count))))   # noqa: E731
    msg14, auth = b(0xa1, b(2, b"\x0e")), b(0xa4, enc(40, kvno=False))
    good_ticket = b(0xa3, F.krb5_ticket())
    error = dict(kerberos_vectors())
    starttls, whoami = F.LDAP_STARTTLS_OID, b"1.3.6.1.4.1.4203.1.11.3"
    oid_u2u = F.OID_KRB5 + b"\x03"
    return [
        ("simple", bind(b(0x80, b""))),
        ("simple-dn", bind(b(0x80, b"placeholder"), dn="cn=tëst,dc=example".encode())),
        ("simple-bad-dn", bind(b(0x80, b""), dn=b"\xff\xfe")),
        ("simple-trailing", bind(b(0x80, b""), extra=b(4, b""))),
        ("v2", bind(b(0x80, b""), version=b"\x02")),
        ("no-auth", bind(b"")),
        ("auth-choice", bind(b(0x81, b""))),
        ("controls", message(b(0x60, b(2, b"\x03") + b(4, b"") + b(0x80, b"")), extra=b(0xa0, b""))),
        ("id-zero", message(b(0x60, b(2, b"\x03") + b(4, b"") + b(0x80, b"")), b"\x00")),
        ("id-negative", message(b(0x60, b(2, b"\x03") + b(4, b"") + b(0x80, b"")), b"\x80\x01")),
        ("id-wide", message(b(0x60, b(2, b"\x03") + b(4, b"") + b(0x80, b"")), b"\x01\x02\x03\x04\x05")),
        ("id-four", message(b(0x60, b(2, b"\x03") + b(4, b"") + b(0x80, b"")), b"\x7f\xff\xff\xff")),
        ("search", message(b(0x63, b""))),
        ("no-operation", message(b"")),
        ("sasl-plain", sasl(b"PLAIN", b"placeholder")),
        ("sasl-gssapi", sasl(b"GSSAPI", F.krb5_ap_req())),
        ("sasl-external-no-credentials", sasl(b"EXTERNAL")),
        ("sasl-scram", sasl(b"SCRAM-SHA-256", b"n,,n=user,r=nonce")),
        ("sasl-other", sasl(b"X-UNKNOWN_1", b"")),
        ("sasl-empty-mechanism", sasl(b"", b"x")),
        ("sasl-lowercase", sasl(b"plain", b"x")),
        ("sasl-long-mechanism", sasl(b"A" * 21, b"x")),
        ("sasl-trailing", sasl(b"PLAIN", b"x", extra=b(4, b""))),
        ("spnego-empty-credentials", spnego(b"")),
        ("spnego-no-credentials", sasl(b"GSS-SPNEGO")),
        ("spnego-ntlm-init", spnego(F.SPNEGO_NTLM_INIT)),
        ("spnego-ntlm-challenge", spnego(F.SPNEGO_NTLM_CHALLENGE)),
        ("spnego-ntlm-authenticate", spnego(F.SPNEGO_NTLM_AUTHENTICATE)),
        ("spnego-accept", spnego(F.SPNEGO_ACCEPT)),
        ("spnego-krb5-init", spnego(F.SPNEGO_KRB5_INIT)),
        ("spnego-mechs-only", spnego(F.SPNEGO_MECHS_ONLY)),
        ("raw-ntlm-negotiate", spnego(F.ntlmssp(1))),
        ("raw-ntlm-authenticate", spnego(F.ntlmssp(3, 64))),
        ("raw-ntlm-type-4", spnego(F.ntlmssp(4))),
        ("raw-ntlm-short", spnego(b"NTLMSSP\x00\x01\x00")),
        ("token-budget", spnego(b"NTLMSSP\x00" + (1).to_bytes(4, "little") + bytes(4085))),
        ("token-at-budget", spnego(b"NTLMSSP\x00" + (1).to_bytes(4, "little") + bytes(4084))),
        ("token-unknown-tag", spnego(b"\x30\x00")),
        ("gss-length-disagrees", spnego(b"\x60\x05\x06\x01\x2a")),
        ("gss-truncated-length", spnego(b"\x60")),
        ("gss-no-oid", spnego(der(0x60, b"\x04\x00"))),
        ("gss-other-mechanism", spnego(der(0x60, der(0x06, b"\x2a\x03") + b"opaque"))),
        ("gss-negoex-direct", spnego(der(0x60, der(0x06, F.OID_NEGOEX) + b"x"))),
        ("krb5-ap-req", spnego(F.krb5_ap_req())),
        ("krb5-ap-req-ms-oid", spnego(F.krb5_gss(krb(), oid=F.OID_MS_KRB5))),
        ("krb5-ap-rep", spnego(F.krb5_gss(F.krb5_ap_rep_message(), b"\x02\x00"))),
        ("krb5-error", spnego(F.krb5_gss(error["error-preauth"], b"\x03\x00"))),
        ("krb5-error-bad-code", spnego(F.krb5_gss(error["error-code-128"], b"\x03\x00"))),
        ("krb5-error-wrong-message", spnego(F.krb5_gss(error["as-rep"], b"\x03\x00"))),
        ("krb5-tgt-req", spnego(F.krb5_gss(F.krb5_tgt_req_message(), b"\x04\x00", oid_u2u))),
        ("krb5-tgt-req-bare", spnego(F.krb5_gss(F.krb5_tgt_req_message(False, False), b"\x04\x00", oid_u2u))),
        ("krb5-tgt-req-msgtype", spnego(F.krb5_gss(b(0x30, int5 + b(0xa1, b(2, b"\x0e"))), b"\x04\x00"))),
        ("krb5-tgt-req-empty-realm", spnego(F.krb5_gss(b(0x30, int5 + b(0xa1, b(2, b"\x10")) + b(0xa3, b(0x1b, b""))), b"\x04\x00"))),
        ("krb5-tok-id-unknown", spnego(F.krb5_gss(krb(), b"\x05\x00"))),
        ("krb5-tok-id-missing", spnego(der(0x60, der(0x06, F.OID_KRB5)))),
        ("krb5-tok-id-mismatch", spnego(F.krb5_gss(krb(), b"\x02\x00"))),
        ("krb5-trailing", spnego(der(0x60, der(0x06, F.OID_KRB5) + b"\x01\x00" + krb() + b"\x00"))),
        ("krb5-ap-req-pvno", spnego(ap(b(0xa0, b(2, b"\x04")), msg14, flags, good_ticket, auth))),
        ("krb5-ap-req-msgtype", spnego(ap(int5, b(0xa1, b(2, b"\x0f")), flags, good_ticket, auth))),
        ("krb5-ap-req-missing", spnego(ap(int5, msg14, flags, good_ticket))),
        ("krb5-ap-req-order", spnego(ap(msg14, int5, flags, good_ticket, auth))),
        ("krb5-ap-req-extra-field", spnego(ap(int5, msg14, flags, good_ticket, auth, b(0xa5, b"")))),
        ("krb5-ap-req-universal-field", spnego(ap(int5, msg14, flags, good_ticket, auth, b(0x04, b"")))),
        ("krb5-flags-short", spnego(ap(int5, msg14, b(0xa2, b(3, b"\x00\x20\x00\x00")), good_ticket, auth))),
        ("krb5-flags-empty", spnego(ap(int5, msg14, b(0xa2, b(3, b"")), good_ticket, auth))),
        ("krb5-flags-unused-8", spnego(ap(int5, msg14, b(0xa2, b(3, b"\x08\x20\x00\x00\x00\x00")), good_ticket, auth))),
        ("krb5-flags-padding-set", spnego(ap(int5, msg14, b(0xa2, b(3, b"\x04\x20\x00\x00\x00\x0f")), good_ticket, auth))),
        ("krb5-flags-padding-clear", spnego(ap(int5, msg14, b(0xa2, b(3, b"\x04\x20\x00\x00\x00\xf0")), good_ticket, auth))),
        ("krb5-flags-framing", spnego(ap(int5, msg14, b(0xa2, b(3, b"\x00\x20\x00\x00\x00") + b"\x05\x00"), good_ticket, auth))),
        ("krb5-ticket-vno", spnego(ap(int5, msg14, flags, ticket(b(0xa0, b(2, b"\x04")), realm, sname, b(0xa3, enc())), auth))),
        ("krb5-ticket-empty-realm", spnego(ap(int5, msg14, flags, ticket(int5, b(0xa1, b(0x1b, b"")), sname, b(0xa3, enc())), auth))),
        ("krb5-ticket-8-names", spnego(ap(int5, msg14, flags, ticket(int5, realm, names(8), b(0xa3, enc())), auth))),
        ("krb5-ticket-9-names", spnego(ap(int5, msg14, flags, ticket(int5, realm, names(9), b(0xa3, enc())), auth))),
        ("krb5-ticket-no-names", spnego(ap(int5, msg14, flags, ticket(int5, realm, names(0), b(0xa3, enc())), auth))),
        ("krb5-ticket-empty-cipher", spnego(ap(int5, msg14, flags, ticket(int5, realm, sname, b(0xa3, enc(0))), auth))),
        ("krb5-ticket-wide-etype", spnego(ap(int5, msg14, flags, ticket(int5, realm, sname, b(0xa3, b(0x30, b(0xa0, b(2, bytes(5))) + b(0xa2, b(4, b"x"))))), auth))),
        ("krb5-ticket-kvno-5", spnego(ap(int5, msg14, flags, ticket(int5, realm, sname, b(0xa3, b(0x30, b(0xa0, b(2, b"\x12")) + b(0xa1, b(2, bytes(5))) + b(0xa2, b(4, b"x"))))), auth))),
        ("krb5-ticket-kvno-6", spnego(ap(int5, msg14, flags, ticket(int5, realm, sname, b(0xa3, b(0x30, b(0xa0, b(2, b"\x12")) + b(0xa1, b(2, bytes(6))) + b(0xa2, b(4, b"x"))))), auth))),
        ("krb5-ap-rep-msgtype", spnego(F.krb5_gss(b(0x6f, b(0x30, int5 + b(0xa1, b(2, b"\x0e")) + b(0xa2, enc(24, kvno=False)))), b"\x02\x00"))),
        ("init-no-fields", spnego(init(b""))),
        ("init-empty-mechs", spnego(init(der(0xa0, der(0x30, b""))))),
        ("init-8-mechs", spnego(init(der(0xa0, der(0x30, der(0x06, F.OID_NEGOEX) * 8))))),
        ("init-9-mechs", spnego(init(der(0xa0, der(0x30, der(0x06, F.OID_NTLMSSP) * 9))))),
        ("init-unknown-mech", spnego(init(der(0xa0, der(0x30, der(0x06, b"\x2a\x03")))))),
        ("init-mechs-trailing", spnego(init(der(0xa0, der(0x30, der(0x06, F.OID_NTLMSSP)) + b"\x05\x00")))),
        ("init-all-fields", spnego(init(mechs + der(0xa1, b"\x03\x02\x00\x00") + der(0xa2, der(0x04, F.ntlmssp(1))) + der(0xa3, der(0x04, b"mic"))))),
        ("init-order", spnego(init(der(0xa2, der(0x04, F.ntlmssp(1))) + mechs))),
        ("init-empty-token", spnego(init(mechs + der(0xa2, der(0x04, b""))))),
        ("init-token-trailing", spnego(init(mechs + der(0xa2, der(0x04, b"x") + b"\x05\x00")))),
        ("init-token-overrides-mech", spnego(init(mechs + der(0xa2, der(0x04, F.krb5_ap_req()))))),
        ("init-token-other", spnego(init(mechs + der(0xa2, der(0x04, b"opaque"))))),
        ("init-token-gss-other", spnego(init(mechs + der(0xa2, der(0x04, der(0x60, der(0x06, b"\x2a\x03") + b"x")))))),
        ("init-token-bad-kerberos", spnego(init(mechs + der(0xa2, der(0x04, F.krb5_gss(krb(), b"\x09\x00")))))),
        ("init-token-bad-ntlm", spnego(init(mechs + der(0xa2, der(0x04, F.ntlmssp(9)))))),
        ("init-token-truncated-gss", spnego(init(mechs + der(0xa2, der(0x04, b"\x60"))))),
        ("init-token-gss-length-off", spnego(init(mechs + der(0xa2, der(0x04, b"\x60\x09\x06\x01\x2a"))))),
        ("init-trailing", spnego(der(0x60, der(0x06, F.OID_SPNEGO) + der(0xa0, der(0x30, mechs)) + b"\x05\x00"))),
        ("init-sequence-trailing", spnego(der(0x60, der(0x06, F.OID_SPNEGO) + der(0xa0, der(0x30, mechs) + b"\x05\x00")))),
        ("init-not-negtokeninit", spnego(der(0x60, der(0x06, F.OID_SPNEGO) + der(0xa1, b"")))),
        ("init-oid-only", spnego(der(0x60, der(0x06, F.OID_SPNEGO)))),
        ("resp-empty", spnego(resp(b""))),
        ("resp-states", spnego(resp(der(0xa0, der(0x0a, b"\x03"))))),
        ("resp-reject", spnego(resp(der(0xa0, der(0x0a, b"\x02"))))),
        ("resp-state-4", spnego(resp(der(0xa0, der(0x0a, b"\x04"))))),
        ("resp-state-wide", spnego(resp(der(0xa0, der(0x0a, b"\x00\x01"))))),
        ("resp-mech-only", spnego(resp(der(0xa1, der(0x06, F.OID_MS_KRB5))))),
        ("resp-unknown-mech-only", spnego(resp(der(0xa1, der(0x06, b"\x2a\x03"))))),
        ("resp-mech-trailing", spnego(resp(der(0xa1, der(0x06, F.OID_KRB5) + b"\x05\x00")))),
        ("resp-krb5-ap-rep", spnego(F.spnego_resp(0, F.OID_KRB5, F.krb5_gss(F.krb5_ap_rep_message(), b"\x02\x00")))),
        ("resp-token-only-ntlm", spnego(resp(der(0xa2, der(0x04, F.ntlmssp(3, 40)))))),
        ("resp-token-other-only", spnego(resp(der(0xa2, der(0x04, b"opaque"))))),
        ("resp-mic", spnego(resp(der(0xa0, der(0x0a, b"\x00")) + der(0xa3, der(0x04, b"mic"))))),
        ("resp-order", spnego(resp(der(0xa1, der(0x06, F.OID_KRB5)) + der(0xa0, der(0x0a, b"\x00"))))),
        ("resp-trailing", spnego(resp(der(0xa0, der(0x0a, b"\x00"))) + b"\x05\x00")),
        ("bind-response", response()),
        ("bind-response-invalid-credentials", response(49, b"", b"80090308: LdapErr: placeholder")),
        ("bind-response-in-progress", response(14, extra=b(0x87, F.SPNEGO_NTLM_CHALLENGE))),
        ("bind-response-other-code", response(123)),
        ("bind-response-code-124", response(124)),
        ("bind-response-referral", response(10, extra=b(0xa3, b(4, b"ldap://placeholder.example/")))),
        ("bind-response-16-referrals", response(10, extra=b(0xa3, b(4, b"u") * 16))),
        ("bind-response-17-referrals", response(10, extra=b(0xa3, b(4, b"u") * 17))),
        ("bind-response-empty-referral", response(10, extra=b(0xa3, b(4, b"")))),
        ("bind-response-bad-text", response(0, b"", b"\xc3")),
        ("bind-response-trailing", response(0, extra=b(4, b""))),
        ("bind-response-controls", response(0, controls=b(0xa0, b""))),
        ("starttls-request", extended(starttls)),
        ("starttls-request-value", extended(starttls, b"")),
        ("whoami-request", extended(whoami, message_id=b"\x02")),
        ("extended-request-other-value", extended(b"1.2.840.113556.1.4.1781", b"value")),
        ("extended-request-bad-oid", extended(b"1.02.3")),
        ("extended-request-arc-11-digits", extended(b"1.12345678901")),
        ("extended-request-arc-10-digits", extended(b"1.1234567890")),
        ("extended-request-single-arc", extended(b"1")),
        ("extended-request-first-arc-3", extended(b"3.1")),
        ("extended-request-31-arcs", extended(b"1" + b".1" * 31)),
        ("extended-request-30-arcs", extended(b"1" + b".1" * 30)),
        ("extended-request-no-name", extended(None)),
        ("extended-request-controls", extended(starttls, controls=b(0xa0, b""))),
        ("starttls-response", response(0, extra=b(0x8a, starttls), tag=0x78)),
        ("starttls-response-unnamed", response(0, tag=0x78)),
        ("starttls-response-refused", response(52, extra=b(0x8a, starttls), tag=0x78)),
        ("starttls-response-value", response(0, extra=b(0x8a, starttls) + b(0x8b, b""), tag=0x78)),
        ("extended-response-value", response(0, extra=b(0x8a, whoami) + b(0x8b, b"dn:placeholder"), tag=0x78)),
        ("extended-response-bad-name", response(0, extra=b(0x8a, b"x"), tag=0x78)),
        ("extended-response-trailing", response(0, extra=b(0x8b, b"") + b(0x8a, whoami), tag=0x78)),
        ("not-sequence", b"\x31" + bind(b(0x80, b""))[1:]),
        ("indefinite", b"\x30\x80\x02\x01\x01\x60\x00\x00\x00"),
    ]


def ldap_cases():
    """LDAP (M5 batch 18): every vector as a stream (whole / 1-byte / 7-byte / truncated), a ServerHello after the
    named StartTLS success (the ldap-starttls shift), and a byte budget below a bind's advertised size."""
    cases = []
    vectors = ldap_vectors()
    for number, (name, data) in enumerate(vectors):
        base = "stream/ldap-%03d-%s" % (number, name)
        for variant, chunks, end in (("whole", [data.hex()], "fin"), ("bytes", [data[i:i + 1].hex() for i in range(len(data))], "fin"),
                                     ("sevens", [data[i:i + 7].hex() for i in range(0, len(data), 7)], "fin"),
                                     ("half", [data[:max(1, len(data) // 2)].hex()], "Capture ended before initial message completed")):
            if variant == "bytes" and len(data) > 600:
                continue
            cases.append({"id": base + "/" + variant, "kind": "stream", "label": "ldap", "chunks": chunks, "hint": None, "config": {}, "end": end})
    named = dict(vectors)
    for name in ("starttls-response", "starttls-response-unnamed", "starttls-response-refused"):
        cases.append({"id": "stream/ldap-shift/" + name, "kind": "stream", "label": "ldap",
                      "chunks": [named[name].hex(), _tls_record(_server_hello()).hex()], "hint": None, "config": {}, "end": "fin"})
        cases.append({"id": "stream/ldap-shift/" + name + "-coalesced", "kind": "stream", "label": "ldap",
                      "chunks": [(named[name] + _tls_record(_server_hello())).hex()], "hint": None, "config": {}, "end": "fin"})
    cases.append({"id": "stream/ldap-options/byte-budget", "kind": "stream", "label": "ldap",
                  "chunks": [named["spnego-krb5-init"].hex()], "hint": None, "config": {"max_bytes": 64}, "end": "fin"})
    return cases


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
    cases.extend(tls_cases())
    cases.extend(text_cases())
    cases.extend(framed_cases())
    cases.extend(desktop_cases())
    cases.extend(database_cases())
    cases.extend(ics_cases())
    cases.extend(messaging_cases())
    cases.extend(tunnel_cases())
    cases.extend(service_cases())
    cases.extend(git_cases())
    cases.extend(session_cases_v())
    cases.extend(kerberos_cases())
    cases.extend(ldap_cases())
    cases.append({"id": "stream/options/fingerprints", "kind": "stream", "label": "tls",
                  "chunks": [client_hello_with([(0, b"\x00\x0f\x00\x00\x0cperf.example")]).hex()], "hint": None,
                  "config": {"fingerprints": True}, "end": "fin"})
    return cases


def _tls_ext(kind, value):
    return kind.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value


def _tls_record(data, version=b"\x03\x03"):
    return b"\x16" + version + len(data).to_bytes(2, "big") + data


_SERVER_RANDOM = bytes(range(32))


def _server_hello(extensions=None, cipher=0xc02f, session=b"", compression=0, version=b"\x03\x03", random_value=None):
    body = version + (_SERVER_RANDOM if random_value is None else random_value) + bytes([len(session)]) + session + cipher.to_bytes(2, "big") + bytes([compression])
    if extensions is not None:
        values = b"".join(_tls_ext(k, v) for k, v in extensions)
        body += len(values).to_bytes(2, "big") + values
    return b"\x02" + len(body).to_bytes(3, "big") + body


def tls_cases():
    """TLS hello vectors (the labelled fixture tables carry none): ClientHello variants with SNI, ALPN,
    supported_versions, ECH, weak suites, GREASE-free lists and malformed structures; ServerHello 1.2/1.3 and
    HelloRetryRequest; each as whole / 1-byte / 7-byte / truncated chunkings."""
    from protocol_adapters.protocol_fixtures import TLS_ECH_HELLO, ech_outer
    from test_tls_server import RETRY
    hellos = [
        ("plain", client_hello_with([])),
        ("sni", client_hello_with([(0, b"\x00\x12\x00\x00\x0fwww.example.com")])),
        ("sni-alpn-h2", client_hello_with([(0, b"\x00\x12\x00\x00\x0fwww.example.com"), (16, b"\x00\x0c\x02h2\x08http/1.1")])),
        ("supported-versions-13", client_hello_with([(0, b"\x00\x12\x00\x00\x0fwww.example.com"), (43, b"\x04\x03\x04\x03\x03")])),
        ("tls10-legacy", _tls_record(b"\x01" + (len(b"\x03\x01" + bytes(32) + b"\x00\x00\x04\x00\x2f\x00\x35\x01\x00")).to_bytes(3, "big") + b"\x03\x01" + bytes(32) + b"\x00\x00\x04\x00\x2f\x00\x35\x01\x00", b"\x03\x01")),
        ("weak-suites", client_hello_with([], ciphers=(0x0004, 0x002f, 0x0000, 0x0018))),
        ("ech", TLS_ECH_HELLO),
        ("ech-inner", client_hello_with([(0, b"\x00\x12\x00\x00\x0fwww.example.com"), (0xfe0d, b"\x01")])),
        ("ech-bad-kdf", client_hello_with([(0xfe0d, ech_outer(kdf=0x0009))])),
        ("alpn-binary", client_hello_with([(16, b"\x00\x04\x03\x00\xff\x01")])),
        ("sni-ip-literal", client_hello_with([(0, b"\x00\x0e\x00\x00\x0b192.0.2.1xx")])),
        ("sni-upper", client_hello_with([(0, b"\x00\x12\x00\x00\x0fWWW.Example.COM")])),
        ("duplicate-ext", client_hello_with([(16, b"\x00\x03\x02h2"), (16, b"\x00\x03\x02h2")])),
        ("bad-session-id", _tls_record(b"\x01\x00\x00\x2c" + b"\x03\x03" + bytes(32) + b"\x21" + bytes(5) + b"\x00\x02\x13\x01\x01\x00")),
        ("odd-ciphers", _tls_record(b"\x01\x00\x00\x29" + b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x03\x13\x01\x13" + b"\x01\x00")),
        ("no-null-compression", _tls_record(b"\x01\x00\x00\x28" + b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x01")),
        ("ssl3-record", client_hello_with([])[:1] + b"\x03\x00" + client_hello_with([])[3:]),
        ("not-handshake", b"\x17\x03\x03\x00\x05hello"),
        ("short-hello-length", _tls_record(b"\x01\x00\x00\x10" + bytes(16))),
        ("huge-record", b"\x16\x03\x03\xff\xff" + b"\x01"),
        ("sni-then-many-ext", client_hello_with([(0, b"\x00\x12\x00\x00\x0fwww.example.com")] + [(k, b"") for k in range(100, 150)])),
        ("server12-plain", _tls_record(_server_hello())),
        ("server12-ext", _tls_record(_server_hello(((0, b""), (5, b""), (23, b""), (35, b""), (65281, b"\0"), (11, b"\x03\x00\x01\x02"), (16, b"\x00\x03\x02h2"))))),
        ("server12-unknown-ext", _tls_record(_server_hello(((99, b"\x01"),)))),
        ("server12-bad-cipher", _tls_record(_server_hello(cipher=0x0004))),
        ("server13-keyshare", _tls_record(_server_hello(((43, b"\x03\x04"), (51, b"\x00\x1d\x00\x20" + bytes(32))), cipher=0x1301))),
        ("server13-psk", _tls_record(_server_hello(((43, b"\x03\x04"), (41, b"\x00\x01")), cipher=0x1302))),
        ("server13-bad-group", _tls_record(_server_hello(((43, b"\x03\x04"), (51, b"\x00\x63\x00\x04" + bytes(4))), cipher=0x1301))),
        ("hrr-cookie", _tls_record(_server_hello(((43, b"\x03\x04"), (44, b"\x00\x02ab")), cipher=0x1301, random_value=RETRY))),
        ("hrr-no-change", _tls_record(_server_hello(((43, b"\x03\x04"),), cipher=0x1301, random_value=RETRY))),
        ("server-compression", _tls_record(_server_hello(compression=1))),
        ("server-legacy-version", _tls_record(_server_hello(version=b"\x03\x01"))),
    ]
    cases = []
    for number, (name, data) in enumerate(hellos):
        base = "stream/tls-%02d-%s" % (number, name)
        for variant, chunks, end in (("whole", [data.hex()], "fin"), ("bytes", [data[i:i + 1].hex() for i in range(len(data))], "fin"),
                                     ("sevens", [data[i:i + 7].hex() for i in range(0, len(data), 7)], "fin"),
                                     ("half", [data[:max(1, len(data) // 2)].hex()], "Capture ended before initial message completed")):
            cases.append({"id": base + "/" + variant, "kind": "stream", "label": "tls", "chunks": chunks, "hint": None, "config": {}, "end": end})
    return cases


def _namelist(value):
    return len(value).to_bytes(4, "big") + value


def _kexinit(lists=None, first_follows=0, reserved=bytes(4), msg=20, padding=None):
    lists = lists or [b"curve25519-sha256,ecdh-sha2-nistp256", b"ssh-ed25519,rsa-sha2-512", b"aes128-ctr,aes256-gcm@openssh.com",
                      b"aes128-ctr", b"hmac-sha2-256,umac-128-etm@openssh.com", b"hmac-sha2-256", b"none,zlib@openssh.com", b"none", b"", b""]
    payload = bytes([msg]) + bytes(range(16)) + b"".join(_namelist(v) for v in lists) + bytes([first_follows]) + reserved
    if padding is None:
        padding = 8 - ((len(payload) + 5) % 8)
        padding = padding + 8 if padding < 4 else padding
    return (len(payload) + 1 + padding).to_bytes(4, "big") + bytes([padding]) + payload + bytes(padding)


def text_cases():
    """Text-route families (M5 batch 1): SSH banner and KEXINIT posture, SMTP with the STARTTLS watch, NATS JSON,
    IMAP server and client lines, POP3, FTP, IRC, SIP/RTSP headers, Telnet; identifications, ambiguities, budget and
    malformed outcomes, each as whole / 1-byte / 7-byte / truncated chunkings."""
    hello = client_hello_with([(0, b"\x00\x12\x00\x00\x0fwww.example.com")])   # deterministic (proxy_demo.client_hello is random)
    banner = b"SSH-2.0-OpenSSH_9.6\r\n"
    weak = [b"diffie-hellman-group1-sha1,curve25519-sha256", b"ssh-rsa,ssh-dss", b"aes128-cbc,arcfour,3des-cbc", b"none",
            b"hmac-md5,hmac-sha1-96", b"hmac-sha2-256-etm@openssh.com", b"none", b"none", b"", b""]
    chacha = [b"curve25519-sha256", b"ssh-ed25519", b"chacha20-poly1305@openssh.com", b"aes256-gcm@openssh.com", b"hmac-sha2-256", b"hmac-sha2-256", b"none", b"none", b"", b""]
    strict = [b"sntrup761x25519-sha512@openssh.com,kex-strict-c-v00@openssh.com", b"ssh-ed25519", b"aes256-gcm@openssh.com", b"aes256-gcm@openssh.com", b"hmac-sha2-256", b"hmac-sha2-256", b"none", b"none", b"", b""]
    sip = (b"OPTIONS sip:server.example SIP/2.0\r\nVia: SIP/2.0/TCP client.example;branch=z9hG4bKdemo\r\nMax-Forwards: 70\r\n"
           b"From: <sip:a@client.example>;tag=1\r\nTo: <sip:server.example>\r\nCall-ID: demo@client.example\r\nCSeq: 1 OPTIONS\r\n\r\n")
    sip_response = (b"SIP/2.0 200 OK\r\nVia: SIP/2.0/TCP client.example;branch=z9hG4bKdemo\r\nFrom: <sip:a@client.example>;tag=1\r\n"
                    b"To: <sip:server.example>;tag=2\r\nCall-ID: demo@client.example\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n")
    vectors = [
        ("ssh-banner", banner),
        ("ssh-banner-kexinit", banner + _kexinit()),
        ("ssh-banner-weak-kexinit", banner + _kexinit(weak)),
        ("ssh-banner-chacha", banner + _kexinit(chacha)),
        ("ssh-banner-strict", banner + _kexinit(strict)),
        ("ssh-199", b"SSH-1.99-Legacy_1.0 comment here\r\n"),
        ("ssh-bad-banner", b"SSH-3.0-Future\r\n"),
        ("ssh-long-banner", b"SSH-2.0-" + b"x" * 300 + b"\r\n"),
        ("ssh-bad-kexinit-msg", banner + _kexinit(msg=21)),
        ("ssh-bad-kexinit-length", banner + b"\x00\x00\x00\x05abcde"),
        ("ssh-kexinit-trailing", banner + _kexinit() + b"\x00\x00\x00\x0cmore"),
        ("smtp-ehlo-mail", b"EHLO client.example\r\nMAIL FROM:<a@b.example>\r\n"),
        ("smtp-ehlo-starttls-hello", b"EHLO client.example\r\nSTARTTLS\r\n" + hello),
        ("smtp-ehlo-noops-starttls", b"EHLO client.example\r\n" + b"NOOP\r\n" * 3 + b"STARTTLS\r\n" + hello),
        ("smtp-ehlo-many-noops", b"EHLO client.example\r\n" + b"NOOP\r\n" * 20 + b"STARTTLS\r\n" + hello),
        ("smtp-helo-literal", b"HELO [192.0.2.1]\r\n"),
        ("smtp-ehlo-ipv6", b"EHLO [IPv6:2001:db8::1]\r\nQUIT\r\n"),
        ("smtp-ehlo-bad-identity", b"EHLO not valid!\r\n"),
        ("smtp-ehlo-no-identity", b"EHLO\r\n"),
        ("smtp-unexpected-command", b"EHLO client.example\r\nFOO bar\r\n"),
        ("smtp-starttls-params", b"EHLO client.example\r\nSTARTTLS now\r\n" + hello),
        ("smtp-220-ambiguous", b"220 mail.example ESMTP ready\r\n"),
        ("nats-info", b'INFO {"server_id":"demo","version":"2.10.0","go":"go1.22","host":"127.0.0.1","port":4222,"max_payload":1048576,"proto":1}\r\n'),
        ("nats-connect", b'CONNECT {"verbose":false,"pedantic":false,"tls_required":false,"lang":"python","version":"1.0"}\r\n'),
        ("nats-info-missing", b'INFO {"server_id":"demo","version":"2.10.0"}\r\n'),
        ("nats-info-port-range", b'INFO {"server_id":"demo","version":"2.10.0","go":"go1.22","host":"h","port":70000,"max_payload":10}\r\n'),
        ("nats-duplicate-member", b'CONNECT {"verbose":false,"verbose":true,"pedantic":false,"tls_required":false,"lang":"go","version":"1"}\r\n'),
        ("nats-not-object", b'INFO [1,2,3]\r\n'),
        ("nats-bad-json", b'INFO {"server_id":\r\n'),
        ("nats-deep", b'INFO {"a":' + b"[" * 20 + b"]" * 20 + b'}\r\n'),
        ("nats-bool-wrong", b'CONNECT {"verbose":1,"pedantic":false,"tls_required":false,"lang":"go","version":"1"}\r\n'),
        ("nats-proto-level", b'INFO {"server_id":"demo","version":"2","go":"g","host":"h","port":1,"max_payload":1,"proto":7}\r\n'),
        ("nats-urls-wrong", b'INFO {"server_id":"demo","version":"2","go":"g","host":"h","port":1,"max_payload":1,"connect_urls":[1]}\r\n'),
        ("nats-big-int", b'INFO {"server_id":"demo","version":"2","go":"g","host":"h","port":1,"max_payload":123456789012345678901234}\r\n'),
        ("imap-greeting", b'* OK [CAPABILITY IMAP4rev1 IMAP4rev2 STARTTLS AUTH=PLAIN] Example server ready\r\n'),
        ("imap-capability", b'* CAPABILITY IMAP4rev1 IDLE\r\n'),
        ("imap-untagged-plain", b'* OK ready\r\n'),
        ("imap-bad-atom", b'* CAPABILITY IMAP4rev1 IDLE(x)\r\n'),
        ("imap-greeting-control", b'* OK [CAPABILITY IMAP4rev1] bad\x01text\r\n'),
        ("imap-login", b"a001 LOGIN user pass\r\n"),
        ("imap-capability-cmd", b"a001 CAPABILITY\r\n"),
        ("imap-starttls-hello", b"a001 STARTTLS\r\n" + hello),
        ("imap-login-no-args", b"a001 LOGIN\r\n"),
        ("imap-noop-args", b"a001 NOOP extra\r\n"),
        ("pop3-ok", b"+OK POP3 server ready\r\n"),
        ("pop3-err", b"-ERR no\r\n"),
        ("pop3-ok-bare", b"+OK\r\n"),
        ("pop3-ok-bad", b"+OKbad\x01\r\n"),
        ("pop3-capa", b"CAPA\r\n"),
        ("pop3-stls-hello", b"STLS\r\n" + hello),
        ("pop3-top", b"TOP 1 10\r\n"),
        ("pop3-top-bad", b"TOP one\r\n"),
        ("pop3-apop-bad", b"APOP alice\r\n"),
        ("ftp-feat", b"FEAT\r\n"),
        ("ftp-type", b"TYPE I\r\n"),
        ("ftp-type-bad", b"TYPE Z\r\n"),
        ("ftp-port", b"PORT 192,0,2,1,4,5\r\n"),
        ("ftp-port-bad", b"PORT nope\r\n"),
        ("ftp-cwd-missing", b"CWD\r\n"),
        ("ftp-auth-tls-hello", b"AUTH TLS\r\n" + hello),
        ("ftp-user-ambiguous", b"USER alice\r\n"),
        ("ftp-pass-ambiguous", b"PASS secret\r\n"),
        ("ftp-quit-arg", b"QUIT now\r\n"),
        ("ftp-user-empty", b"USER\r\n"),
        ("irc-nick", b"NICK alice\r\n"),
        ("irc-user", b"USER alice 0 * :Alice Example\r\n"),
        ("irc-cap-ls", b"CAP LS 302\r\n"),
        ("irc-cap-bad", b"CAP FOO\r\n"),
        ("irc-nick-bad", b"NICK 9alice\r\n"),
        ("irc-unprefixed-notice", b"NOTICE AUTH :*** Checking Ident\r\n"),
        ("irc-ping", b"PING :1760000000\r\n"),
        ("irc-server-notice", b":irc.example.org NOTICE * :*** Looking up your hostname...\r\n"),
        ("irc-server-welcome", b":irc.example.org 001 alice :Welcome to the Example IRC Network alice!alice@192.0.2.1\r\n"),
        ("irc-server-cap", b":irc.example.org CAP * LS :multi-prefix sasl\r\n"),
        ("irc-server-join", b":irc.example.org JOIN #chan\r\n"),
        ("irc-server-bad-numeric", b":irc.example.org 001 :no nick\r\n"),
        ("irc-server-unsupported", b":irc.example.org TOPIC #chan :x\r\n"),
        ("irc-prefix-bad", b":bad prefix! NOTICE * :x\r\n"),
        ("irc-long", b":irc.example.org NOTICE * :" + b"x" * 600 + b"\r\n"),
        ("sip-options", sip),
        ("sip-response", sip_response),
        ("sip-missing-headers", b"OPTIONS sip:server.example SIP/2.0\r\nVia: SIP/2.0/TCP client.example;branch=1\r\n\r\n"),
        ("sip-bad-cseq", sip.replace(b"CSeq: 1 OPTIONS", b"CSeq: 1 INVITE")),
        ("sip-bad-max-forwards", sip.replace(b"Max-Forwards: 70", b"Max-Forwards: 700")),
        ("sip-duplicate", sip.replace(b"To: <sip:server.example>\r\n", b"To: <sip:server.example>\r\nTo: <sip:b>\r\n")),
        ("sip-compact", sip.replace(b"Via:", b"v:").replace(b"From:", b"f:").replace(b"To:", b"t:").replace(b"Call-ID:", b"i:")),
        ("rtsp-options", b"OPTIONS rtsp://server.example/media RTSP/1.0\r\nCSeq: 1\r\n\r\n"),
        ("rtsp-response", b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n"),
        ("rtsp-no-cseq", b"OPTIONS rtsp://server.example/media RTSP/1.0\r\nSession: 1\r\n\r\n"),
        ("rtsp-6xx", b"RTSP/1.0 650 Weird\r\nCSeq: 1\r\n\r\n"),
        ("rtsp-bad-header", b"OPTIONS rtsp://server.example/media RTSP/1.0\r\nCSeq 1\r\n\r\n"),
        ("telnet", b"\xff\xfd\x18\xff\xfb\x01"),
        ("telnet-sub", b"\xff\xfa\x18\x01\xff\xf0\xff\xfd\x01"),
        ("telnet-data-first", b"\xff\xfd\x18login:"),
        ("telnet-bad-command", b"\xff\xf1\xff\x10"),
    ]
    cases = []
    for number, (name, data) in enumerate(vectors):
        base = "stream/text-%02d-%s" % (number, name)
        for variant, chunks, end in (("whole", [data.hex()], "fin"), ("bytes", [data[i:i + 1].hex() for i in range(len(data))], "fin"),
                                     ("sevens", [data[i:i + 7].hex() for i in range(0, len(data), 7)], "fin"),
                                     ("half", [data[:max(1, len(data) // 2)].hex()], "Capture ended before initial message completed")):
            cases.append({"id": base + "/" + variant, "kind": "stream", "label": name.split("-", 1)[0], "chunks": chunks, "hint": None, "config": {}, "end": end})
    cases.append({"id": "stream/text-options/smtp-header-budget", "kind": "stream", "label": "smtp",
                  "chunks": [(b"EHLO client.example\r\n" + b"NOOP\r\n" * 4 + b"STARTTLS\r\n").hex()], "hint": None, "config": {"max_headers": 2}, "end": "fin"})
    return cases


def _pg_startup(params, code=196608):
    body = struct.pack(">I", code) + b"".join(k + b"\x00" + v + b"\x00" for k, v in params) + b"\x00"
    return struct.pack(">I", len(body) + 4) + body


def _pg_server(kind, body):
    return kind + struct.pack(">I", len(body) + 4) + body


def _memcached(magic, command, key=b"", extras=b"", value=b"", status=0):
    body = extras + key + value
    return (bytes([magic, command]) + struct.pack(">HBBH", len(key), len(extras), 0, status) + struct.pack(">I", len(body))
            + bytes(12) + body)


def _fins(command, body, error=0):
    return b"FINS" + struct.pack(">III", len(body) + 8, command, error) + body


def _dsi(flags, command, payload=b"", code=b"\x00\x00\x00\x00"):
    return bytes([flags, command]) + b"\x00\x01" + code + struct.pack(">I", len(payload)) + bytes(4) + payload


def _zmtp(mechanism=b"NULL", server=0, minor=0):
    return b"\xff" + bytes(8) + b"\x7f" + bytes([3, minor]) + mechanism.ljust(20, b"\x00") + bytes([server]) + bytes(31)


def _bolt(*versions):
    slots = [bytes([0, span, minor, major]) for major, minor, span in versions]
    return b"\x60\x60\xb0\x17" + b"".join(slots + [bytes(4)] * (4 - len(slots)))


def framed_cases():
    """Framed binary TCP families and the two batch-2 line protocols (M5 batch 2): PostgreSQL startup, encryption
    requests and server messages, RFB, BitTorrent, memcached binary, FINS/TCP, AFP over DSI, ZMTP, Bolt, rsync and
    STOMP; identifications, malformed sizes, unsupported versions and budget outcomes, each as whole / 1-byte /
    7-byte / truncated chunkings."""
    startup = _pg_startup([(b"user", b"alice"), (b"database", b"demo")])
    fins_frame = bytes([0x80, 0, 2, 0, 1, 0, 0, 2, 0, 0x19, 0x01, 0x01, 0x82, 0, 0, 0, 0, 1])
    vectors = [
        ("postgresql-startup", startup),
        ("postgresql-ssl", struct.pack(">II", 8, 80877103)),
        ("postgresql-empty-startup", struct.pack(">II", 8, 196608)),
        ("postgresql-gss", struct.pack(">II", 8, 80877104)),
        ("postgresql-ssl-long", struct.pack(">II", 12, 80877103) + bytes(4)),
        ("postgresql-no-user", _pg_startup([(b"database", b"demo")])),
        ("postgresql-duplicate", _pg_startup([(b"user", b"a"), (b"user", b"b")])),
        ("postgresql-bad-version", _pg_startup([(b"user", b"a")], code=0x00040000)),
        ("postgresql-huge", struct.pack(">I", 1 << 20) + struct.pack(">I", 196608)),
        ("postgresql-auth-md5", _pg_server(b"R", struct.pack(">I", 5) + b"salt")),
        ("postgresql-auth-sasl", _pg_server(b"R", struct.pack(">I", 10) + b"SCRAM-SHA-256\x00\x00")),
        ("postgresql-auth-bad-salt", _pg_server(b"R", struct.pack(">I", 5) + b"sa")),
        ("postgresql-auth-unknown", _pg_server(b"R", struct.pack(">I", 99))),
        ("postgresql-error", _pg_server(b"E", b"SFATAL\x00C28P01\x00Mpassword authentication failed\x00\x00")),
        ("postgresql-error-no-state", _pg_server(b"E", b"SFATAL\x00Mno code\x00\x00")),
        ("postgresql-negotiate", _pg_server(b"v", struct.pack(">II", 196608, 1) + b"_pq_.opt\x00")),
        ("rfb-38", b"RFB 003.008\n"),
        ("rfb-33", b"RFB 003.003\n"),
        ("rfb-future", b"RFB 004.001\n"),
        ("bittorrent", b"\x13BitTorrent protocol" + bytes(8) + bytes(range(20)) + b"-XX0001-" + bytes(12)),
        ("bittorrent-bad", b"\x13BitTorrent protocoX" + bytes(48)),
        ("memcached-get", _memcached(0x80, 0, key=b"key")),
        ("memcached-set", _memcached(0x80, 1, key=b"key", extras=bytes(8), value=b"value")),
        ("memcached-noop", _memcached(0x80, 10)),
        ("memcached-bad-sizes", _memcached(0x80, 0, key=b"key", extras=bytes(4))),
        ("memcached-unknown-command", _memcached(0x80, 0x40, key=b"k")),
        ("memcached-response-get", _memcached(0x81, 0, extras=bytes(4), value=b"value")),
        ("memcached-response-miss", _memcached(0x81, 0, value=b"Not found", status=1)),
        ("memcached-response-bad-status", _memcached(0x81, 0, status=0x99)),
        ("fins-node-request", _fins(0, bytes(4))),
        ("fins-node-reply", _fins(1, bytes([0, 0, 0, 1, 0, 0, 0, 2]))),
        ("fins-frame", _fins(2, fins_frame)),
        ("fins-bad-node", _fins(0, b"\x00\x00\x01\x00")),
        ("fins-bad-command", _fins(7, bytes(4))),
        ("fins-bad-icf", _fins(2, bytes([0x81]) + fins_frame[1:])),
        ("afp-getstatus", _dsi(0, 3)),
        ("afp-opensession", _dsi(0, 4, b"\x01\x04\x00\x00\x04\x00")),
        ("afp-getstatus-reply", _dsi(1, 3, b"server-info")),
        ("afp-bad-option", _dsi(0, 4, b"\x05\x04\x00\x00\x04\x00")),
        ("afp-bad-command", _dsi(0, 8)),
        ("afp-getstatus-data", _dsi(0, 3, b"x")),
        ("zmtp-null", _zmtp()),
        ("zmtp-curve-server", _zmtp(b"CURVE", 1, 1)),
        ("zmtp-other", _zmtp(b"X-CUSTOM")),
        ("zmtp-lower", _zmtp(b"null")),
        ("zmtp-v2", b"\xff" + bytes(8) + b"\x7f\x01" + bytes(53)),
        ("bolt-handshake", _bolt((5, 4, 4), (4, 4, 0))),
        ("bolt-bad-version", _bolt((9, 0, 0))),
        ("bolt-gap", b"\x60\x60\xb0\x17" + bytes(4) + bytes([0, 0, 0, 4]) + bytes(8)),
        ("bolt-empty", _bolt()),
        ("rsync-31", b"@RSYNCD: 31.0\n"),
        ("rsync-32", b"@RSYNCD: 32.0 sha512 sha256 md5\n"),
        ("rsync-29", b"@RSYNCD: 29\n"),
        ("rsync-30-nosub", b"@RSYNCD: 30\n"),
        ("rsync-32-nodigest", b"@RSYNCD: 32.0\n"),
        ("rsync-duplicate", b"@RSYNCD: 32.0 md5 md5\n"),
        ("rsync-old", b"@RSYNCD: 26\n"),
        ("stomp-connect", b"CONNECT\naccept-version:1.1,1.2\nhost:broker.example\nheart-beat:0,1000\n\n\x00"),
        ("stomp-stomp", b"STOMP\r\naccept-version:1.2\r\nhost:broker\\cexample\r\n\r\n\x00"),
        ("stomp-connected", b"CONNECTED\nversion:1.2\n\n\x00"),
        ("stomp-no-host", b"CONNECT\naccept-version:1.2\n\n\x00"),
        ("stomp-body", b"CONNECT\naccept-version:1.2\nhost:b\n\nbody\x00"),
        ("stomp-bad-escape", b"STOMP\naccept-version:1.2\nhost:b\\t\n\n\x00"),
        ("stomp-bad-heartbeat", b"CONNECT\naccept-version:1.2\nhost:b\nheart-beat:1\n\n\x00"),
    ]
    cases = []
    for number, (name, data) in enumerate(vectors):
        base = "stream/framed-%02d-%s" % (number, name)
        for variant, chunks, end in (("whole", [data.hex()], "fin"), ("bytes", [data[i:i + 1].hex() for i in range(len(data))], "fin"),
                                     ("sevens", [data[i:i + 7].hex() for i in range(0, len(data), 7)], "fin"),
                                     ("half", [data[:max(1, len(data) // 2)].hex()], "Capture ended before initial message completed")):
            cases.append({"id": base + "/" + variant, "kind": "stream", "label": name.split("-", 1)[0], "chunks": chunks, "hint": None, "config": {}, "end": end})
    response = b"\x00\x00\x04\x05"
    for name, data in (("bolt-response", response), ("bolt-response-none", bytes(4)), ("bolt-response-bad", b"\x00\x00\x00\x09")):
        cases.append({"id": "stream/framed-hinted/" + name, "kind": "stream", "label": "bolt", "chunks": [data.hex()], "hint": "bolt", "config": {}, "end": "fin"})
    cases.append({"id": "stream/framed-options/stomp-header-budget", "kind": "stream", "label": "stomp",
                  "chunks": [b"CONNECT\naccept-version:1.2\nhost:b\na:1\nb:2\nc:3\n\n\x00".hex()], "hint": None, "config": {"max_headers": 2}, "end": "fin"})
    cases.append({"id": "stream/framed-options/postgresql-byte-budget", "kind": "stream", "label": "postgresql",
                  "chunks": [_pg_startup([(b"user", b"a" * 100)]).hex()], "hint": None, "config": {"max_bytes": 64}, "end": "fin"})
    return cases


class _CDR:
    """Minimal CDR writer with offsets relative to the whole GIOP message (body starts at 12)."""

    def __init__(self, little=False):
        self.order = "<" if little else ">"
        self.data = bytearray()

    def align(self, width):
        self.data.extend(bytes((-(12 + len(self.data))) % width))
        return self

    def uint(self, width, value):
        self.align(width)
        self.data.extend(struct.pack(self.order + {1: "B", 2: "H", 4: "I"}[width], value))
        return self

    def raw(self, value):
        self.data.extend(value)
        return self

    def seq(self, value):
        return self.uint(4, len(value)).raw(value)


def _giop(kind, body, little=False, flags=None):
    order = "<" if little else ">"
    return b"GIOP\x01\x02" + bytes([1 if little else 0 if flags is None else flags, kind]) + struct.pack(order + "I", len(body)) + bytes(body)


def _giop_request(operation=b"ping\x00", contexts=0, args=b"", little=False, response=3, target=0):
    w = _CDR(little).uint(4, 7).uint(1, response).raw(bytes(3)).uint(2, target).seq(b"key").seq(operation).uint(4, contexts)
    for _ in range(min(contexts, 4)):
        w.uint(4, 1).seq(b"ctx")
    if args:
        w.align(8).raw(args)
    return _giop(0, w.data, little)


def _x11_setup(name=b"MIT-MAGIC-COOKIE-1", data=bytes(16), little=False, major=11):
    order = "<" if little else ">"
    pad = lambda value: value + bytes((-len(value)) % 4)  # noqa: E731
    return (b"l" if little else b"B") + b"\x00" + struct.pack(order + "HHHH", major, 0, len(name), len(data)) + bytes(2) + pad(name) + pad(data)


def _x11_success(vendor=b"Example", formats=1, roots=1, keycodes=(8, 255)):
    fixed = bytes(16) + struct.pack(">HH", len(vendor), 65535) + bytes([roots, formats, 0, 0, 32, 32, keycodes[0], keycodes[1]]) + bytes(4)
    body = fixed + vendor + bytes((-len(vendor)) % 4) + bytes(8 * formats) + bytes(40 * roots)
    return b"\x01\x00\x00\x0b\x00\x00" + struct.pack(">H", len(body) // 4) + body


def _x11_failed(reason=b"No protocol specified"):
    padded = reason + bytes((-len(reason)) % 4)
    return bytes([0, len(reason)]) + b"\x00\x0b\x00\x00" + struct.pack(">H", len(padded) // 4) + padded


def _spice(body, major=2):
    return b"REDQ" + struct.pack("<III", major, 2, len(body)) + body


def _spice_link(channel_type=1, connection=0, common=1, channel=1):
    return _spice(struct.pack("<IBBIII", connection, channel_type, 0, common, channel, 18) + bytes(4 * (common + channel)))


def _spice_reply(error=0, common=1, channel=1, offset=178):
    return _spice(struct.pack("<I", error) + bytes(162) + struct.pack("<III", common, channel, offset) + bytes(4 * (common + channel)))


def desktop_cases():
    """GIOP 1.2 over the bounded CDR cursor, X11 connection setup (server reply hinted) and the SPICE link header
    (M5 batch 3); identifications, malformed sizes, unsupported versions and budget outcomes, each as whole / 1-byte /
    7-byte / truncated chunkings."""
    vectors = [
        ("giop-request", _giop_request()),
        ("giop-request-little", _giop_request(little=True)),
        ("giop-request-contexts-args", _giop_request(contexts=2, args=b"\x00\x00\x00\x01")),
        ("giop-locate-request", _giop(3, _CDR().uint(4, 9).uint(2, 0).seq(b"key").data)),
        ("giop-reply", _giop(1, _CDR().uint(4, 7).uint(4, 0).uint(4, 0).data)),
        ("giop-reply-exception", _giop(1, _CDR().uint(4, 7).uint(4, 2).uint(4, 0).align(8).raw(b"IDL:x").data)),
        ("giop-locate-reply", _giop(4, _CDR().uint(4, 9).uint(4, 1).data)),
        ("giop-locate-forward", _giop(4, _CDR().uint(4, 9).uint(4, 2).raw(b"ior-bytes").data)),
        ("giop-bad-magic", b"GIOX" + _giop_request()[4:]),
        ("giop-version-10", b"GIOP\x01\x00" + _giop_request()[6:]),
        ("giop-fragment", _giop_request()[:6] + b"\x02" + _giop_request()[7:]),
        ("giop-bad-operation", _giop_request(operation=b"9op\x00")),
        ("giop-string-nul", _giop_request(operation=b"pi\x00g\x00")),
        ("giop-many-contexts", _giop_request(contexts=500)),
        ("giop-truncated-contexts", _giop_request(contexts=40)),
        ("giop-profile-target", _giop_request(target=1)),
        ("giop-bad-response-flags", _giop_request(response=2)),
        ("giop-reply-status", _giop(1, _CDR().uint(4, 7).uint(4, 9).uint(4, 0).data)),
        ("giop-locate-trailing", _giop(3, _CDR().uint(4, 9).uint(2, 0).seq(b"key").raw(b"zz").data)),
        ("giop-short", _giop(0, bytes(8))),
        ("x11-setup", _x11_setup()),
        ("x11-setup-little", _x11_setup(little=True)),
        ("x11-setup-none", _x11_setup(name=b"", data=b"")),
        ("x11-setup-other", _x11_setup(name=b"CUSTOM-AUTH")),
        ("x11-setup-bad-name", _x11_setup(name=b"BAD\x01NAME")),
        ("x11-setup-data-no-name", _x11_setup(name=b"", data=bytes(8))),
        ("x11-setup-version", _x11_setup(major=10)),
        ("x11-setup-huge", _x11_setup(data=bytes(2048))),
        ("spice-link", _spice_link()),
        ("spice-link-display", _spice_link(channel_type=2, connection=5)),
        ("spice-link-no-connection", _spice_link(channel_type=2)),
        ("spice-reply", _spice_reply()),
        ("spice-reply-error", _spice_reply(error=7)),
        ("spice-reply-bad-error", _spice_reply(error=40)),
        ("spice-reply-three-caps", _spice_reply(common=3)),
        ("spice-reply-bad-offset", _spice_reply(offset=18)),
        ("spice-version", _spice_link()[:4] + struct.pack("<I", 1) + _spice_link()[8:]),
        ("spice-size", b"REDQ" + struct.pack("<IIII", 2, 2, 4, 0)),
    ]
    cases = []
    for number, (name, data) in enumerate(vectors):
        base = "stream/desktop-%02d-%s" % (number, name)
        for variant, chunks, end in (("whole", [data.hex()], "fin"), ("bytes", [data[i:i + 1].hex() for i in range(len(data))], "fin"),
                                     ("sevens", [data[i:i + 7].hex() for i in range(0, len(data), 7)], "fin"),
                                     ("half", [data[:max(1, len(data) // 2)].hex()], "Capture ended before initial message completed")):
            cases.append({"id": base + "/" + variant, "kind": "stream", "label": name.split("-", 1)[0], "chunks": chunks, "hint": None, "config": {}, "end": end})
    replies = (("x11-server-success", _x11_success()), ("x11-server-failed", _x11_failed()), ("x11-server-authenticate", b"\x02\x00\x00\x0b\x00\x00\x00\x02Auth\x00\x00\x00\x00"),
               ("x11-server-bad-keycodes", _x11_success(keycodes=(4, 255))), ("x11-server-no-screens", _x11_success(roots=0)),
               ("x11-server-short", b"\x01\x00\x00\x0b\x00\x00\x00\x02" + bytes(8)), ("x11-server-bad-reason", _x11_failed(b"bad\x07reason")),
               ("x11-server-status", b"\x05\x00\x00\x0b\x00\x00\x00\x00"))
    for name, data in replies:
        for variant, chunks in (("whole", [data.hex()]), ("sevens", [data[i:i + 7].hex() for i in range(0, len(data), 7)])):
            cases.append({"id": "stream/desktop-hinted/%s/%s" % (name, variant), "kind": "stream", "label": "x11", "chunks": chunks,
                          "hint": "x11-server", "config": {}, "end": "fin"})
    cases.append({"id": "stream/desktop-options/giop-context-budget", "kind": "stream", "label": "giop",
                  "chunks": [_giop_request(contexts=3).hex()], "hint": None, "config": {"max_headers": 2}, "end": "fin"})
    cases.append({"id": "stream/desktop-options/giop-key-budget", "kind": "stream", "label": "giop",
                  "chunks": [_giop_request(operation=b"operation_name_longer_than_sixteen\x00").hex()], "hint": None, "config": {"max_line": 16}, "end": "fin"})
    return cases


def _mysql_packet(payload, sequence=0):
    return struct.pack("<I", len(payload))[:3] + bytes([sequence]) + payload


def _mysql_server(version=b"8.0.36", caps_low=0xffff, caps_high=0xdfff, auth=21, plugin=b"caching_sha2_password", proto=10):
    return _mysql_packet(bytes([proto]) + version + b"\x00" + struct.pack("<I", 9) + bytes(range(1, 9)) + b"\x00"
                         + struct.pack("<HBHHB", caps_low, 0xff, 2, caps_high, auth) + bytes(10) + bytes(range(1, 13)) + b"\x00" + plugin + b"\x00")


def _mysql_response(caps=0x88208, user=b"alice", database=b"demo", plugin=b"caching_sha2_password", attrs=None, charset=0x21):
    body = struct.pack("<IIB", caps, 1 << 24, charset) + bytes(23) + user + b"\x00" + bytes([20]) + bytes(20)
    if caps & 0x8:
        body += database + b"\x00"
    if caps & 0x80000:
        body += plugin + b"\x00"
    if attrs is not None:
        block = b"".join(bytes([len(item)]) + item for item in attrs)
        body += bytes([len(block)]) + block
    return _mysql_packet(body, 1)


def _bson(elements):
    body = b"".join(bytes([kind]) + name + b"\x00" + value for kind, name, value in elements)
    return struct.pack("<i", len(body) + 5) + body + b"\x00"


def _bson_string(value):
    return struct.pack("<i", len(value) + 1) + value + b"\x00"


def _mongo(sections, response_to=0, flags=0, checksum=None):
    body = struct.pack("<I", flags) + sections
    size = 16 + len(body) + (4 if flags & 1 else 0)
    message = struct.pack("<iiii", size, 1, response_to, 2013) + body
    if flags & 1:
        message += struct.pack("<I", crc32c(message) if checksum is None else checksum)
    return message


def _tds(options, kind=0x12, status=0x01):
    table = b"".join(bytes([token]) + struct.pack(">HH", 0, len(value)) for token, value in options) + b"\xff"
    offset, entries, data = len(table), b"", b""
    for token, value in options:
        entries += bytes([token]) + struct.pack(">HH", offset + len(data), len(value))
        data += value
    payload = entries + b"\xff" + data
    return bytes([kind, status]) + struct.pack(">H", 8 + len(payload)) + b"\x00\x00\x01\x00" + payload


def _tns_connect(descriptor=b"(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=orcl)))", version=314, inline=True, order=b"\x01\x00"):
    offset = 58
    head = struct.pack(">HHHHHHH", version, 300, 0, 8192, 32767, 0x4f98, 0) + order + struct.pack(">HH", len(descriptor), offset)
    head += bytes(offset - 8 - len(head))
    body = head + (descriptor if inline else b"")
    return struct.pack(">H", 8 + len(body)) + b"\x00\x00\x01\x00\x00\x00" + body


def _tns(kind, body):
    return struct.pack(">H", 8 + len(body)) + b"\x00\x00" + bytes([kind]) + b"\x00\x00\x00" + body


def _cql(opcode, body=b"", version=0x04, flags=0):
    return bytes([version, flags]) + b"\x00\x01" + bytes([opcode]) + struct.pack(">I", len(body)) + body


def _cql_strings(*values):
    return b"".join(struct.pack(">H", len(value)) + value for value in values)


def _kafka(key, version, client=b"client", rest=b""):
    body = struct.pack(">hhi", key, version, 7) + (struct.pack(">h", -1) if client is None else struct.pack(">h", len(client)) + client) + rest
    return struct.pack(">I", len(body)) + body


def database_cases():
    """MySQL (hinted), MongoDB OP_MSG over bounded BSON (hinted), TDS PRELOGIN, Oracle Net TNS, Cassandra CQL v4 and
    Kafka request headers (M5 batch 4); identifications, malformed sizes, unsupported versions and budget outcomes,
    each as whole / 1-byte / 7-byte / truncated chunkings."""
    ping = _bson([(16, b"ping", struct.pack("<i", 1)), (2, b"$db", _bson_string(b"admin"))])
    version = struct.pack(">IH", 0x0f000000, 0)
    hinted = [
        ("mysql-server", _mysql_server()),
        ("mysql-server-v9", _mysql_server(proto=9)),
        ("mysql-server-bad-version", _mysql_server(version=b"8.0 36")),
        ("mysql-server-no-41", _mysql_server(caps_low=0x0000)),
        ("mysql-server-challenge", _mysql_server(auth=8)),
        ("mysql-server-plugin", _mysql_server(plugin=b"dialog")),
        ("mysql-response", _mysql_response()),
        ("mysql-response-attrs", _mysql_response(caps=0x188208, attrs=[b"_os", b"linux"])),
        ("mysql-response-ssl-flag", _mysql_response(caps=0x88a08)),
        ("mysql-response-after-frame", _mysql_response()[:-1] + b"\x00xx"),
        ("mysql-response-charset", _mysql_response(charset=0)),
        ("mysql-sslrequest", _mysql_packet(struct.pack("<IIB", 0x88a08, 1 << 24, 0x21) + bytes(23), 1)),
        ("mysql-sslrequest-no-ssl", _mysql_packet(struct.pack("<IIB", 0x88208, 1 << 24, 0x21) + bytes(23), 1)),
        ("mysql-short", _mysql_packet(bytes(20))),
        ("mongodb-ping", _mongo(b"\x00" + ping)),
        ("mongodb-reply", _mongo(b"\x00" + _bson([(1, b"ok", struct.pack("<d", 1.0))]), response_to=1)),
        ("mongodb-checksum", _mongo(b"\x00" + ping, flags=1)),
        ("mongodb-bad-checksum", _mongo(b"\x00" + ping, flags=1, checksum=1)),
        ("mongodb-sequence", _mongo(b"\x00" + _bson([(16, b"insert", struct.pack("<i", 1)), (2, b"$db", _bson_string(b"app"))])
                                    + b"\x01" + struct.pack("<i", 4 + 10 + len(_bson([]))) + b"documents\x00" + _bson([]))),
        ("mongodb-no-db", _mongo(b"\x00" + _bson([(16, b"ping", struct.pack("<i", 1))]))),
        ("mongodb-dollar-first", _mongo(b"\x00" + _bson([(2, b"$db", _bson_string(b"admin")), (16, b"ping", struct.pack("<i", 1))]))),
        ("mongodb-duplicate", _mongo(b"\x00" + _bson([(16, b"ping", struct.pack("<i", 1)), (16, b"ping", struct.pack("<i", 2))]))),
        ("mongodb-bad-bool", _mongo(b"\x00" + _bson([(8, b"ping", b"\x02"), (2, b"$db", _bson_string(b"a"))]))),
        ("mongodb-nested", _mongo(b"\x00" + _bson([(3, b"find", _bson([(4, b"a", _bson([(16, b"0", bytes(4)), (16, b"1", bytes(4))]))])),
                                                   (2, b"$db", _bson_string(b"a"))]))),
        ("mongodb-bad-array", _mongo(b"\x00" + _bson([(4, b"find", _bson([(16, b"1", bytes(4))])), (2, b"$db", _bson_string(b"a"))]))),
        ("mongodb-regex", _mongo(b"\x00" + _bson([(11, b"find", b"^a\x00im\x00"), (2, b"$db", _bson_string(b"a"))]))),
        ("mongodb-bad-regex", _mongo(b"\x00" + _bson([(11, b"find", b"^a\x00mi\x00"), (2, b"$db", _bson_string(b"a"))]))),
        ("mongodb-binary-uuid", _mongo(b"\x00" + _bson([(5, b"find", struct.pack("<i", 16) + b"\x04" + bytes(16)), (2, b"$db", _bson_string(b"a"))]))),
        ("mongodb-binary-bad-uuid", _mongo(b"\x00" + _bson([(5, b"find", struct.pack("<i", 8) + b"\x04" + bytes(8)), (2, b"$db", _bson_string(b"a"))]))),
        ("mongodb-unknown-type", _mongo(b"\x00" + _bson([(0x20, b"find", b""), (2, b"$db", _bson_string(b"a"))]))),
        ("mongodb-opcode", struct.pack("<iiii", 20, 1, 0, 2004) + bytes(4)),
        ("mongodb-flags", _mongo(b"\x00" + ping, flags=4)),
    ]
    vectors = [
        ("tds-prelogin", _tds([(0x00, version), (0x01, b"\x00"), (0x02, b"\x00"), (0x03, bytes(4)), (0x04, b"\x00")])),
        ("tds-prelogin-fedauth", _tds([(0x00, version), (0x01, b"\x03"), (0x06, b"\x01")])),
        ("tds-response", _tds([(0x00, version), (0x01, b"\x01"), (0x05, b"")], kind=0x04)),
        ("tds-bad-encryption", _tds([(0x00, version), (0x01, b"\x09")])),
        ("tds-no-version", _tds([(0x01, b"\x00"), (0x04, b"\x00"), (0x02, b"abc\x00")])),
        ("tds-repeated", _tds([(0x00, version), (0x01, b"\x00"), (0x01, b"\x00")])),
        ("tds-bad-mars", _tds([(0x00, version), (0x01, b"\x00"), (0x04, b"\x02")])),
        ("tds-instopt", _tds([(0x00, version), (0x01, b"\x00"), (0x02, b"abc")])),
        ("tds-status", _tds([(0x00, version), (0x01, b"\x00")], status=0x00)),
        ("tns-connect", _tns_connect()),
        ("tns-connect-deferred", _tns_connect(inline=False)),
        ("tns-connect-version", _tns_connect(version=0x0100)),
        ("tns-connect-order", _tns_connect(order=b"\x02\x02")),
        ("tns-connect-binary", _tns_connect(descriptor=b"(DESC\x01)")),
        ("tns-accept", _tns(2, struct.pack(">HHHH", 315, 0, 8192, 32767) + b"\x01\x00" + struct.pack(">HHHH", 0, 0, 0, 0))),
        ("tns-refuse", _tns(4, b"\x22\x00" + _cql_strings(b"(DESCRIPTION=(ERR=12514))"))),
        ("tns-refuse-length", _tns(4, b"\x22\x00\x00\x40(DESCRIPTION=(ERR=1))")),
        ("tns-resend", _tns(11, b"")),
        ("tns-checksum", b"\x00\x08\x00\x01\x0b\x00\x00\x00"),
        ("cql-startup", _cql(0x01, struct.pack(">H", 1) + _cql_strings(b"CQL_VERSION", b"3.0.0"))),
        ("cql-startup-compression", _cql(0x01, struct.pack(">H", 2) + _cql_strings(b"CQL_VERSION", b"3.0.0", b"COMPRESSION", b"lz4"))),
        ("cql-options", _cql(0x05)),
        ("cql-startup-no-version", _cql(0x01, struct.pack(">H", 1) + _cql_strings(b"COMPRESSION", b"lz4"))),
        ("cql-startup-trailing", _cql(0x01, struct.pack(">H", 1) + _cql_strings(b"CQL_VERSION", b"3.0.0") + b"x")),
        ("cql-ready", _cql(0x02, version=0x84)),
        ("cql-supported", _cql(0x06, struct.pack(">H", 1) + _cql_strings(b"CQL_VERSION") + struct.pack(">H", 1) + _cql_strings(b"3.4.5"), version=0x84)),
        ("cql-authenticate", _cql(0x03, _cql_strings(b"org.apache.cassandra.auth.PasswordAuthenticator"), version=0x84)),
        ("cql-error", _cql(0x00, struct.pack(">I", 0x100) + _cql_strings(b"Bad credentials"), version=0x84)),
        ("cql-v3", _cql(0x05, version=0x03)),
        ("cql-query", _cql(0x07, b"\x00\x00")),
        ("cql-ready-body", _cql(0x02, b"x", version=0x84)),
        ("kafka-apiversions", _kafka(18, 3, rest=b"\x00\x0dapache-kafka\x063.7.0\x00")),
        ("kafka-apiversions-v0", _kafka(18, 0)),
        ("kafka-metadata", _kafka(3, 9, client=None, rest=bytes(4))),
        ("kafka-null-client", _kafka(18, 2, client=None)),
        ("kafka-apiversions-bad-name", _kafka(18, 3, rest=b"\x00\x00")),
        ("kafka-client-binary", _kafka(18, 1, client=b"cl\x01ent")),
        ("kafka-client-length", _kafka(18, 1, client=b"c" * 300)),
        ("kafka-huge", struct.pack(">Ihhi", 100000, 18, 1, 7) + b"\x00\x00"),
    ]
    cases = []
    for group, entries, hint in (("database", vectors, False), ("database-hinted", hinted, True)):
        for number, (name, data) in enumerate(entries):
            base = "stream/%s-%02d-%s" % (group, number, name)
            family = name.split("-", 1)[0]
            for variant, chunks, end in (("whole", [data.hex()], "fin"), ("bytes", [data[i:i + 1].hex() for i in range(len(data))], "fin"),
                                         ("sevens", [data[i:i + 7].hex() for i in range(0, len(data), 7)], "fin"),
                                         ("half", [data[:max(1, len(data) // 2)].hex()], "Capture ended before initial message completed")):
                cases.append({"id": base + "/" + variant, "kind": "stream", "label": family, "chunks": chunks, "hint": family if hint else None,
                              "config": {}, "end": end})
    many = _bson([(16, b"f%d" % index, bytes(4)) for index in range(6)] + [(2, b"$db", _bson_string(b"a"))])
    deep = _bson([(16, b"x", bytes(4))])
    for _ in range(17):
        deep = _bson([(3, b"d", deep)])
    for name, data, config in (("mongodb-field-budget", _mongo(b"\x00" + many), {"max_headers": 4}),
                               ("mongodb-crc-budget", _mongo(b"\x00" + ping, flags=1), {"max_crc32c_bytes": 16}),
                               ("mongodb-depth", _mongo(b"\x00" + _bson([(16, b"find", bytes(4)), (3, b"q", deep), (2, b"$db", _bson_string(b"a"))])), {}),
                               ("mongodb-name-budget", _mongo(b"\x00" + _bson([(16, b"x" * 40, bytes(4)), (2, b"$db", _bson_string(b"a"))])), {"max_line": 16})):
        cases.append({"id": "stream/database-options/" + name, "kind": "stream", "label": "mongodb", "chunks": [data.hex()], "hint": "mongodb",
                      "config": config, "end": "fin"})
    attrs = [b"k%d" % index for index in range(34)]
    cases.append({"id": "stream/database-options/mysql-attribute-count", "kind": "stream", "label": "mysql",
                  "chunks": [_mysql_response(caps=0x188208, attrs=attrs).hex()], "hint": "mysql", "config": {}, "end": "fin"})
    return cases


def _modbus(function, pdu, unit=1):
    return struct.pack(">HHHB", 0x0102, 0, 2 + len(pdu), unit) + bytes([function]) + pdu


def _dnp3_crc(data):
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xa6bc if crc & 1 else crc >> 1
    return struct.pack("<H", (~crc) & 0xffff)


def _dnp3(user=b"\xc0\xc1\x01\x3c\x02\x06", control=0xc4, bad_block=False, bad_header=False):
    header = b"\x05\x64" + bytes([5 + len(user), control]) + struct.pack("<HH", 4, 3)
    frame = header + (b"\x00\x00" if bad_header else _dnp3_crc(header))
    for start in range(0, len(user), 16):
        block = user[start:start + 16]
        frame += block + (b"\x00\x00" if bad_block else _dnp3_crc(block))
    return frame


def _enip(command, body=b"", session=0, status=0, options=0):
    return struct.pack("<HHII", command, len(body), session, status) + bytes(8) + struct.pack("<I", options) + body


def _opcua(kind, body):
    return kind + struct.pack("<I", 8 + len(body)) + body


def _ua_string(value):
    return struct.pack("<i", -1) if value is None else struct.pack("<i", len(value)) + value


def _s7(rosctr, parameters, data=b"", error=b""):
    pdu = b"\x32" + bytes([rosctr]) + b"\x00\x00\x01\x00" + struct.pack(">HH", len(parameters), len(data)) + error + parameters + data
    return b"\x03\x00" + struct.pack(">H", 7 + len(pdu)) + b"\x02\xf0\x80" + pdu


def ics_cases():
    """Modbus/TCP, DNP3 link frames, EtherNet/IP encapsulation, IEC 60870-5-104 APCI, OPC UA connection messages and
    S7comm PDUs and IEC 104 S/I frames (hinted: the cotp-connect shift is not ported, and only U-format frames select
    IEC 104 automatically) (M5 batch 5); identifications, malformed sizes,
    unsupported codes and CRC outcomes, each as whole / 1-byte / 7-byte / truncated chunkings."""
    hello = struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + _ua_string(b"opc.tcp://plc.example:4840")
    setup = b"\xf0\x00" + struct.pack(">HHH", 1, 1, 480)
    vectors = [
        ("modbus-read", _modbus(3, struct.pack(">HH", 0, 10))),
        ("modbus-read-coils", _modbus(1, struct.pack(">HH", 0, 2000))),
        ("modbus-write-coil", _modbus(5, struct.pack(">HH", 1, 0xff00))),
        ("modbus-write-multiple", _modbus(16, struct.pack(">HHB", 0, 2, 4) + bytes(4))),
        ("modbus-response", _modbus(3, b"\x04" + bytes(4))),
        ("modbus-exception", _modbus(0x83, b"\x02")),
        ("modbus-exception-other", _modbus(0x83, b"\x07")),
        ("modbus-identification", _modbus(43, b"\x0e\x01\x00")),
        ("modbus-bad-quantity", _modbus(3, struct.pack(">HH", 0, 200))),
        ("modbus-bad-coil", _modbus(5, struct.pack(">HH", 1, 0x1234))),
        ("modbus-bad-count", _modbus(16, struct.pack(">HHB", 0, 2, 9) + bytes(4))),
        ("modbus-odd-registers", _modbus(3, b"\x05" + bytes(5))),
        ("modbus-private", _modbus(100, b"\x00")),
        ("modbus-exception-code", _modbus(0x83, b"\x09")),
        ("dnp3-read", _dnp3()),
        ("dnp3-long", _dnp3(user=bytes(range(40)))),
        ("dnp3-header-only", _dnp3(user=b"", control=0xc9)),
        ("dnp3-bad-header-crc", _dnp3(bad_header=True)),
        ("dnp3-bad-block-crc", _dnp3(bad_block=True)),
        ("dnp3-function", _dnp3(control=0xc6)),
        ("ethernet-register", _enip(0x65, b"\x01\x00\x00\x00")),
        ("ethernet-list-identity", _enip(0x63)),
        ("ethernet-send-rr", _enip(0x6f, bytes(6) + b"\x02\x00", session=0x11223344)),
        ("ethernet-register-version", _enip(0x65, b"\x02\x00\x00\x00")),
        ("ethernet-status", _enip(0x63, status=1)),
        ("ethernet-no-session", _enip(0x6f, bytes(8))),
        ("ethernet-list-body", _enip(0x04, b"xx")),
        ("iec-startdt", b"\x68\x04\x07\x00\x00\x00"),
        ("iec-two-functions", b"\x68\x04\x0f\x00\x00\x00"),
        ("opcua-hello", _opcua(b"HELF", hello)),
        ("opcua-ack", _opcua(b"ACKF", struct.pack("<IIIII", 0, 65536, 65536, 0, 0))),
        ("opcua-error", _opcua(b"ERRF", struct.pack("<I", 0x80010000) + _ua_string(b"Bad request"))),
        ("opcua-reverse", _opcua(b"RHEF", _ua_string(b"urn:server") + _ua_string(b"opc.tcp://plc.example:4840"))),
        ("opcua-small-buffer", _opcua(b"HELF", struct.pack("<IIIII", 0, 1024, 65536, 0, 0) + _ua_string(b"opc.tcp://x"))),
        ("opcua-scheme", _opcua(b"HELF", struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + _ua_string(b"http://x"))),
        ("opcua-null-url", _opcua(b"HELF", struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + _ua_string(None))),
        ("opcua-good-status", _opcua(b"ERRF", struct.pack("<I", 0) + _ua_string(b"x"))),
        ("opcua-trailing", _opcua(b"ACKF", struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + b"xx")),
        ("opcua-binary-reason", _opcua(b"ERRF", struct.pack("<I", 0x80010000) + _ua_string(b"bad\x01"))),
    ]
    hinted = [
        ("s7comm-setup", _s7(1, setup)),
        ("s7comm-setup-ack", _s7(3, setup, error=b"\x00\x00")),
        ("s7comm-read", _s7(1, b"\x04\x01\x12\x0a\x10\x02\x00\x01\x00\x01\x84\x00\x00\x00")),
        ("s7comm-userdata", _s7(7, b"\x00\x01\x12\x04\x11\x44\x01\x00", b"\x0a\x00\x00\x00")),
        ("s7comm-ack", _s7(2, b"", error=b"\x00\x00")),
        ("s7comm-bad-setup", _s7(1, b"\xf0\x00" + struct.pack(">HHH", 0, 1, 480))),
        ("s7comm-bad-pdu-size", _s7(1, b"\xf0\x00" + struct.pack(">HHH", 1, 1, 500))),
        ("s7comm-error-class", _s7(3, setup, error=b"\x90\x00")),
        ("s7comm-function", _s7(1, b"\x77")),
        ("s7comm-rosctr", _s7(5, b"\x04")),
        ("s7comm-protocol", _s7(1, setup)[:7] + b"\x72" + _s7(1, setup)[8:]),
        ("s7comm-cotp", b"\x03\x00\x00\x16\x11\xe0\x00" + bytes(15)),
        ("iec-supervisory", b"\x68\x04\x01\x00\x02\x00"),
        ("iec-information", b"\x68\x0e\x00\x00\x00\x00\x64\x01\x06\x00\x01\x00\x00\x00\x00\x14"),
        ("iec-short-i", b"\x68\x04\x00\x00\x00\x00"),
        ("iec-bad-s", b"\x68\x04\x01\x01\x00\x00"),
    ]
    cases = []
    for group, entries, hint in (("ics", vectors, False), ("ics-hinted", hinted, True)):
        for number, (name, data) in enumerate(entries):
            base = "stream/%s-%02d-%s" % (group, number, name)
            family = name.split("-", 1)[0]
            family = {"ethernet": "ethernet-ip", "iec": "iec-104"}.get(family, family)
            for variant, chunks, end in (("whole", [data.hex()], "fin"), ("bytes", [data[i:i + 1].hex() for i in range(len(data))], "fin"),
                                         ("sevens", [data[i:i + 7].hex() for i in range(0, len(data), 7)], "fin"),
                                         ("half", [data[:max(1, len(data) // 2)].hex()], "Capture ended before initial message completed")):
                cases.append({"id": base + "/" + variant, "kind": "stream", "label": family, "chunks": chunks, "hint": family if hint else None,
                              "config": {}, "end": end})
    cases.append({"id": "stream/ics-options/opcua-byte-budget", "kind": "stream", "label": "opcua",
                  "chunks": [_opcua(b"HELF", struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + _ua_string(b"opc.tcp://" + b"x" * 100)).hex()],
                  "hint": None, "config": {"max_bytes": 64}, "end": "fin"})
    return cases


def _mqtt_str(value):
    return struct.pack(">H", len(value)) + value


def _mqtt_connect(level=4, flags=0x02, client=b"sensor-1", properties=b"", will=b"", tail=b"", name=b"MQTT"):
    body = _mqtt_str(name) + bytes([level, flags]) + b"\x00\x3c"
    if level == 5:
        body += bytes([len(properties)]) + properties
    body += _mqtt_str(client) + will + tail
    return b"\x10" + bytes([len(body)]) + body


def _resp(*items):
    return b"*%d\r\n" % len(items) + b"".join(b"$%d\r\n%s\r\n" % (len(item), item) for item in items)


def _rpc_auth(flavor, body=b""):
    return struct.pack(">II", flavor, len(body)) + body


def _auth_sys(name=b"client", gids=2):
    padded = name + bytes((-len(name)) % 4)
    return struct.pack(">II", 1, len(name)) + padded + struct.pack(">III", 1000, 1000, gids) + bytes(4 * gids)


def _rpc_call(program=100003, version=3, procedure=0, credential=None, verifier=None, rpcvers=2):
    credential = _rpc_auth(0) if credential is None else credential
    verifier = _rpc_auth(0) if verifier is None else verifier
    return struct.pack(">IIIIII", 0x1234, 0, rpcvers, program, version, procedure) + credential + verifier


def _rpc_record(message, last=True):
    return struct.pack(">I", (0x80000000 if last else 0) | len(message)) + message


def _avp(code, value, flags=0x40, vendor=None):
    header = 12 if vendor is not None else 8
    body = struct.pack(">I", code) + bytes([flags | (0x80 if vendor is not None else 0)]) + struct.pack(">I", header + len(value))[1:]
    if vendor is not None:
        body += struct.pack(">I", vendor)
    return body + value + bytes((-len(value)) % 4)


def _diameter(avps, flags=0x80, command=257):
    body = b"".join(avps)
    return bytes([1]) + struct.pack(">I", 20 + len(body))[1:] + bytes([flags]) + struct.pack(">I", command)[1:] + bytes(4) + struct.pack(">II", 1, 2) + body


def messaging_cases():
    """MQTT CONNECT, RESP command arrays, AMQP protocol headers and Connection.Start, ONC RPC over TCP record marking and
    Diameter CER/CEA (M5 batch 6); identifications, malformed sizes, unsupported versions and budget outcomes, each as
    whole / 1-byte / 7-byte / truncated chunkings."""
    cer = [_avp(264, b"client.example.org"), _avp(296, b"example.org"), _avp(257, b"\x00\x01\xc0\x00\x02\x01"),
           _avp(266, struct.pack(">I", 0)), _avp(269, b"demo product")]
    table = struct.pack(">I", 4) + b"abcd"
    start = (b"\x00\x0a\x00\x0a\x00\x09" + table + struct.pack(">I", 5) + b"PLAIN" + struct.pack(">I", 5) + b"en_US")
    vectors = [
        ("mqtt-311", _mqtt_connect()),
        ("mqtt-5", _mqtt_connect(level=5, properties=b"\x11\x00\x00\x00\x3c\x21\x00\x10")),
        ("mqtt-will", _mqtt_connect(flags=0x0e, will=_mqtt_str(b"status/offline") + _mqtt_str(b"gone"))),
        ("mqtt-credentials", _mqtt_connect(flags=0xc2, tail=_mqtt_str(b"user") + _mqtt_str(b"secret"))),
        ("mqtt-5-will-utf8", _mqtt_connect(level=5, flags=0x06, will=b"\x02\x01\x01" + _mqtt_str(b"t") + _mqtt_str(b"\xff"))),
        ("mqtt-level", _mqtt_connect(level=3)),
        ("mqtt-name", _mqtt_connect(name=b"MQIsdp")),
        ("mqtt-flags", _mqtt_connect(flags=0x03)),
        ("mqtt-empty-client", _mqtt_connect(flags=0x00, client=b"")),
        ("mqtt-will-topic", _mqtt_connect(flags=0x06, will=_mqtt_str(b"a/#") + _mqtt_str(b"x"))),
        ("mqtt-duplicate-property", _mqtt_connect(level=5, properties=b"\x21\x00\x10\x21\x00\x10")),
        ("mqtt-auth-data", _mqtt_connect(level=5, properties=b"\x16\x00\x01x")),
        ("mqtt-extra", _mqtt_connect(tail=b"zz")),
        ("mqtt-password-only", _mqtt_connect(flags=0x42, tail=_mqtt_str(b"secret"))),
        ("resp-ping", _resp(b"PING")),
        ("resp-set", _resp(b"SET", b"key", b"value")),
        ("resp-empty-arg", _resp(b"ECHO", b"")),
        ("resp-bad-command", _resp(b"1NFO")),
        ("resp-empty", b"*0\r\n"),
        ("resp-bad-header", b"*1\r\n$x\r\nPING\r\n"),
        ("resp-bad-terminator", b"*1\r\n$4\r\nPINGxx"),
        ("resp-many", b"*5000\r\n"),
        ("resp-long-header", b"*" + b"1" * 30 + b"\r\n"),
        ("resp-leading-zeros", b"*0001\r\n$0004\r\nPING\r\n"),
        ("amqp-091", b"AMQP\x00\x00\x09\x01"),
        ("amqp-10", b"AMQP\x00\x01\x00\x00"),
        ("amqp-unknown", b"AMQP\x03\x01\x00\x00"),
        ("amqp-start", b"\x01\x00\x00" + struct.pack(">I", len(start)) + start + b"\xce"),
        ("amqp-start-end", b"\x01\x00\x00" + struct.pack(">I", len(start)) + start + b"\x00"),
        ("amqp-start-method", b"\x01\x00\x00" + struct.pack(">I", len(start)) + b"\x00\x0a\x00\x0b" + start[4:] + b"\xce"),
        ("amqp-start-locale", b"\x01\x00\x00" + struct.pack(">I", len(start)) + start[:-5] + b"en\x01US" + b"\xce"),
        ("onc-call", _rpc_record(_rpc_call())),
        ("onc-call-auth-sys", _rpc_record(_rpc_call(program=100005, version=3, credential=_rpc_auth(1, _auth_sys())))),
        ("onc-call-other", _rpc_record(_rpc_call(program=200100, version=1))),
        ("onc-call-args", _rpc_record(_rpc_call() + bytes(8))),
        ("onc-reply", _rpc_record(struct.pack(">III", 0x1234, 1, 0) + _rpc_auth(0) + struct.pack(">I", 0))),
        ("onc-reply-mismatch", _rpc_record(struct.pack(">III", 0x1234, 1, 0) + _rpc_auth(0) + struct.pack(">III", 2, 2, 3))),
        ("onc-denied", _rpc_record(struct.pack(">IIIII", 0x1234, 1, 1, 1, 5))),
        ("onc-denied-trailing", _rpc_record(struct.pack(">IIIII", 0x1234, 1, 1, 1, 5) + bytes(4))),
        ("onc-version", _rpc_record(_rpc_call(rpcvers=3))),
        ("onc-program-version", _rpc_record(_rpc_call(version=9))),
        ("onc-fragment", _rpc_record(_rpc_call(), last=False)),
        ("onc-bad-flavor", _rpc_record(_rpc_call(credential=_rpc_auth(9)))),
        ("onc-sys-verifier", _rpc_record(_rpc_call(verifier=_rpc_auth(1, _auth_sys())))),
        ("onc-sys-gids", _rpc_record(_rpc_call(credential=_rpc_auth(1, _auth_sys(gids=20))))),
        ("diameter-cer", _diameter(cer)),
        ("diameter-cea", _diameter(cer + [_avp(268, struct.pack(">I", 2001))], flags=0x00)),
        ("diameter-cea-failure", _diameter(cer + [_avp(268, struct.pack(">I", 5012))], flags=0x00)),
        ("diameter-vendor-avp", _diameter(cer + [_avp(1000, b"opaque", vendor=10415)])),
        ("diameter-missing", _diameter(cer[:3])),
        ("diameter-no-m-flag", _diameter([_avp(264, b"client.example.org", flags=0)] + cer[1:])),
        ("diameter-space", _diameter([_avp(264, b"client example")] + cer[1:])),
        ("diameter-repeated", _diameter(cer + [_avp(269, b"again")])),
        ("diameter-ipv6", _diameter(cer[:2] + [_avp(257, b"\x00\x02" + bytes(16))] + cer[3:])),
        ("diameter-bad-ip", _diameter(cer[:2] + [_avp(257, b"\x00\x01" + bytes(8))] + cer[3:])),
        ("diameter-result-range", _diameter(cer + [_avp(268, struct.pack(">I", 7000))], flags=0x00)),
        ("diameter-proxiable", _diameter(cer, flags=0xc0)),
        ("diameter-command", _diameter(cer, command=280)),
        ("diameter-cea-no-result", _diameter(cer, flags=0x00)),
    ]
    cases = []
    for number, (name, data) in enumerate(vectors):
        base = "stream/messaging-%02d-%s" % (number, name)
        family = {"onc": "onc-rpc"}.get(name.split("-", 1)[0], name.split("-", 1)[0])
        for variant, chunks, end in (("whole", [data.hex()], "fin"), ("bytes", [data[i:i + 1].hex() for i in range(len(data))], "fin"),
                                     ("sevens", [data[i:i + 7].hex() for i in range(0, len(data), 7)], "fin"),
                                     ("half", [data[:max(1, len(data) // 2)].hex()], "Capture ended before initial message completed")):
            cases.append({"id": base + "/" + variant, "kind": "stream", "label": family, "chunks": chunks, "hint": None, "config": {}, "end": end})
    for name, data, config in (("mqtt-byte-budget", _mqtt_connect(client=b"c" * 80), {"max_bytes": 64}),
                               ("resp-byte-budget", _resp(b"SET", b"k", b"v" * 100), {"max_bytes": 64}),
                               ("diameter-avp-budget", _diameter(cer), {"max_headers": 3})):
        cases.append({"id": "stream/messaging-options/" + name, "kind": "stream", "label": name.split("-", 1)[0], "chunks": [data.hex()],
                      "hint": None, "config": config, "end": "fin"})
    return cases


def _bgp_open(capabilities=b"\x01\x04\x00\x01\x00\x01\x41\x04\x00\x00\xfd\xe8", version=4, hold=180, kind=2, raw=None):
    parameters = raw if raw is not None else bytes([kind, len(capabilities)]) + capabilities
    body = bytes([version]) + struct.pack(">HH", 65001, hold) + bytes([192, 0, 2, 1]) + bytes([len(parameters)]) + parameters
    return b"\xff" * 16 + struct.pack(">H", 19 + len(body)) + b"\x01" + body


def _openvpn_tcp(opcode=7, session=b"\x11" * 8, hmac=0, tail=None):
    packet = bytes([opcode << 3]) + session
    if hmac:
        packet += bytes(hmac) + struct.pack(">II", 1, 1700000000)
    packet += b"\x00" + struct.pack(">I", 0) if tail is None else tail
    return struct.pack(">H", len(packet)) + packet


def _pptp(control=1, result=1, error=0, version=0x0100, framing=1, host=b"pptp-client", vendor=b"demo"):
    header = struct.pack(">HHIHH", 156, 1, 0x1a2b3c4d, control, 0)
    if control == 2:
        body = struct.pack(">HBBIIHH", version, result, error, framing, 1, 1, 1)
    else:
        body = struct.pack(">HHIIHH", version, 0, framing, 1, 1, 1)
    return header + body + host.ljust(64, b"\x00") + vendor.ljust(64, b"\x00")


def _fcgi(kind, body, request=1, padding=0, version=1):
    return struct.pack(">BBHHBB", version, kind, request, len(body), padding, 0) + body + bytes(padding)


def _fcgi_params(*pairs):
    out = b""
    for name, value in pairs:
        for item in (name, value):
            out += bytes([len(item)]) if len(item) < 128 else struct.pack(">I", 0x80000000 | len(item))
        out += name + value
    return out


def tunnel_cases():
    """BGP OPEN, OpenVPN over TCP, PPTP control connection and FastCGI (M5 batch 7); identifications, malformed
    sizes, unsupported versions and budget outcomes, each as whole / 1-byte / 7-byte / truncated chunkings."""
    begin = _fcgi(1, struct.pack(">HB", 1, 0) + bytes(5))
    params = _fcgi_params((b"SCRIPT_NAME", b"/index.php"), (b"REQUEST_METHOD", b"GET"))
    vectors = [
        ("bgp-open", _bgp_open()),
        ("bgp-open-no-caps", _bgp_open(raw=b"")),
        ("bgp-route-refresh", _bgp_open(capabilities=b"\x02\x00")),
        ("bgp-version", _bgp_open(version=3)),
        ("bgp-hold", _bgp_open(hold=2)),
        ("bgp-auth-param", _bgp_open(kind=1, capabilities=b"\x00")),
        ("bgp-bad-mp", _bgp_open(capabilities=b"\x01\x03\x00\x01\x00")),
        ("bgp-mp-reserved", _bgp_open(capabilities=b"\x01\x04\x00\x01\x05\x01")),
        ("bgp-marker", b"\xfe" + _bgp_open()[1:]),
        ("bgp-update", _bgp_open()[:18] + b"\x02" + _bgp_open()[19:]),
        ("openvpn-client", _openvpn_tcp()),
        ("openvpn-tls-auth", _openvpn_tcp(hmac=20)),
        ("openvpn-v3", _openvpn_tcp(opcode=10, tail=b"\x00" + struct.pack(">I", 0) + bytes(40))),
        ("openvpn-server", _openvpn_tcp(opcode=8, tail=b"\x01" + struct.pack(">I", 0) + b"\x22" * 8 + struct.pack(">I", 0))),
        ("openvpn-zero-session", _openvpn_tcp(session=bytes(8))),
        ("openvpn-data", _openvpn_tcp(opcode=9)),
        ("openvpn-layout", _openvpn_tcp(tail=b"\x03" + bytes(4))),
        ("openvpn-key-id", struct.pack(">H", 14) + bytes([7 << 3 | 1]) + b"\x11" * 8 + bytes(5)),
        ("pptp-sccrq", _pptp()),
        ("pptp-sccrp", _pptp(control=2)),
        ("pptp-sccrp-error", _pptp(control=2, result=2, error=1)),
        ("pptp-bad-version", _pptp(version=0x0200)),
        ("pptp-bad-result", _pptp(control=2, result=1, error=3)),
        ("pptp-framing", _pptp(framing=8)),
        ("pptp-host", _pptp(host=b"bad\x01host")),
        ("pptp-call", struct.pack(">HHIHH", 156, 1, 0x1a2b3c4d, 7, 0) + bytes(144)),
        ("fastcgi-request", begin + _fcgi(4, params) + _fcgi(4, b"")),
        ("fastcgi-split-params", begin + _fcgi(4, params[:9], padding=3) + _fcgi(4, params[9:]) + _fcgi(4, b"")),
        ("fastcgi-authorizer", _fcgi(1, struct.pack(">HB", 2, 1) + bytes(5)) + _fcgi(4, b"")),
        ("fastcgi-stdout", _fcgi(6, b"Content-Type: text/plain\r\n\r\nhi")),
        ("fastcgi-end", _fcgi(3, struct.pack(">IB", 0, 0) + bytes(3))),
        ("fastcgi-end-status", _fcgi(3, struct.pack(">IB", 0, 9) + bytes(3))),
        ("fastcgi-role", _fcgi(1, struct.pack(">HB", 7, 0) + bytes(5)) + _fcgi(4, b"")),
        ("fastcgi-management", _fcgi(9, b"", request=0)),
        ("fastcgi-interleaved", begin + _fcgi(5, b"x")),
        ("fastcgi-truncated-param", begin + _fcgi(4, b"\x05\x05abc") + _fcgi(4, b"")),
        ("fastcgi-long-length", begin + _fcgi(4, b"\x80\x00") + _fcgi(4, b"")),
        ("fastcgi-version", _fcgi(1, struct.pack(">HB", 1, 0) + bytes(5), version=2)),
    ]
    cases = []
    for number, (name, data) in enumerate(vectors):
        base = "stream/tunnel-%02d-%s" % (number, name)
        family = name.split("-", 1)[0]
        for variant, chunks, end in (("whole", [data.hex()], "fin"), ("bytes", [data[i:i + 1].hex() for i in range(len(data))], "fin"),
                                     ("sevens", [data[i:i + 7].hex() for i in range(0, len(data), 7)], "fin"),
                                     ("half", [data[:max(1, len(data) // 2)].hex()], "Capture ended before initial message completed")):
            cases.append({"id": base + "/" + variant, "kind": "stream", "label": family, "chunks": chunks, "hint": None, "config": {}, "end": end})
    many = begin + b"".join(_fcgi(4, _fcgi_params((b"K", b"V"))) for _ in range(6)) + _fcgi(4, b"")
    for name, data, config in (("fastcgi-record-budget", many, {"max_headers": 4}),
                               ("fastcgi-byte-budget", begin + _fcgi(4, _fcgi_params((b"QUERY", b"q" * 120))) + _fcgi(4, b""), {"max_bytes": 64}),
                               ("bgp-byte-budget", _bgp_open(capabilities=b"\x46\x00" * 30), {"max_bytes": 64})):
        cases.append({"id": "stream/tunnel-options/" + name, "kind": "stream", "label": name.split("-", 1)[0], "chunks": [data.hex()],
                      "hint": None, "config": config, "end": "fin"})
    return cases


_NDR = bytes.fromhex("045d888aeb1cc9119fe808002b104860") + struct.pack("<I", 2)
_NDR64 = bytes.fromhex("33057171babe37498319b5dbef9ccc36") + struct.pack("<I", 1)


def _dce(ptype, body, flags=3, auth=0, drep=b"\x10\x00\x00\x00"):
    return b"\x05\x00" + bytes([ptype, flags]) + drep + struct.pack("<HHI", 16 + len(body), auth, 2) + body


def _dce_bind(contexts, count=None):
    body = struct.pack("<HHI", 4280, 4280, 0) + bytes([len(contexts) if count is None else count]) + bytes(3)
    for number, (abstract, transfers) in enumerate(contexts):
        body += struct.pack("<HBB", number, len(transfers), 0) + abstract + struct.pack("<HH", 1, 0) + b"".join(transfers)
    return _dce(0x0b, body)


def _dce_ack(results, address=b"49664\x00"):
    body = struct.pack("<HHI", 4280, 4280, 0x1234) + struct.pack("<H", len(address)) + address
    body += bytes((-(16 + len(body))) % 4) + bytes([len(results)]) + bytes(3)
    for result, syntax in results:
        body += struct.pack("<HH", result, 0) + syntax
    return _dce(0x0c, body)


def _ws(first, second, rest=b""):
    return bytes([first, second]) + rest


def _xmpp(attributes, prolog=b"<?xml version='1.0'?>"):
    return prolog + b"<stream:stream" + attributes + b">"


def _syslog_line(message, octet=False):
    return (b"%d " % len(message) + message) if octet else message + b"\n"


def service_cases():
    """DCE/RPC bind/bind_ack/bind_nak, WebSocket frame headers (hinted; the HTTP upgrade shift reaches them too), XMPP
    stream headers and RFC 5424 syslog over RFC 6587 framing (M5 batch 8); syslog timestamps use 3- and 6-digit
    fractions only, because Python 3.9 and 3.11+ disagree on the others (see migration/STATUS.md)."""
    abstract = bytes.fromhex("78573412341256781234567890abcdef")
    client = b" xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='chat.example.org' version='1.0'"
    server = b" xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' id='c2s-1' from='chat.example.org' version='1.0'"
    header = b"<165>1 2026-11-08T10:00:00.123Z host.example app 1234 ID47 "
    vectors = [
        ("dcerpc-bind", _dce_bind([(abstract, [_NDR])])),
        ("dcerpc-bind-two", _dce_bind([(abstract, [_NDR, _NDR64]), (abstract, [_NDR64])])),
        ("dcerpc-bind-ack", _dce_ack([(0, _NDR), (2, bytes(20))])),
        ("dcerpc-bind-nak", _dce(0x0d, struct.pack("<HB", 4, 1) + b"\x05\x00")),
        ("dcerpc-bind-big-endian", b"\x05\x00\x0b\x03\x00\x00\x00\x00" + struct.pack(">HHI", 72, 0, 2) + struct.pack(">HHI", 4280, 4280, 0)
         + b"\x01\x00\x00\x00" + struct.pack(">HBB", 0, 1, 0) + abstract + struct.pack(">HH", 1, 0)
         + bytes.fromhex("8a885d041ceb11c99fe808002b104860") + struct.pack(">I", 2)),
        ("dcerpc-syntax", _dce_bind([(abstract, [bytes(range(20))])])),
        ("dcerpc-duplicate-syntax", _dce_bind([(abstract, [_NDR, _NDR])])),
        ("dcerpc-nil-abstract", _dce_bind([(bytes(16), [_NDR])])),
        ("dcerpc-count", _dce_bind([(abstract, [_NDR])], count=2)),
        ("dcerpc-auth", _dce(0x0b, bytes(56), auth=8)),
        ("dcerpc-fragment", _dce(0x0b, bytes(56), flags=1)),
        ("dcerpc-ack-result", _dce_ack([(5, _NDR)])),
        ("dcerpc-nak-version", _dce(0x0d, struct.pack("<HB", 4, 1) + b"\x04\x00")),
        ("xmpp-client", _xmpp(client)),
        ("xmpp-server", _xmpp(server, prolog=b"")),
        ("xmpp-double-quotes", _xmpp(client.replace(b"'", b'"'), prolog=b'<?xml version="1.0" encoding="UTF-8"?>\n')),
        ("xmpp-component", _xmpp(b" xmlns='jabber:component:accept' xmlns:stream='http://etherx.jabber.org/streams' to='comp.example.org'")),
        ("xmpp-ip-to", _xmpp(client.replace(b"chat.example.org", b"192.0.2.1"))),
        ("xmpp-namespace", _xmpp(client.replace(b"jabber:client", b"jabber:other"))),
        ("xmpp-streams-ns", _xmpp(client.replace(b"etherx", b"example"))),
        ("xmpp-duplicate", _xmpp(client + b" to='x.example'")),
        ("xmpp-self-closing", _xmpp(client + b"/")),
        ("xmpp-version", _xmpp(client.replace(b"'1.0'", b"'one'"))),
        ("xmpp-bad-host", _xmpp(client.replace(b"chat.example.org", b"bad_host!"))),
        ("xmpp-empty-id", _xmpp(server.replace(b"'c2s-1'", b"''"))),
        ("xmpp-prolog", _xmpp(client, prolog=b"<?xml version='2.0'?>")),
        ("xmpp-gt-in-quote", _xmpp(client + b" note='a>b'")),
        ("syslog-octet", _syslog_line(header + b"- hello", octet=True)),
        ("syslog-newline", _syslog_line(header + b"[exampleSDID@32473 iut=\"3\" eventSource=\"App\"] message")),
        ("syslog-crlf", header.replace(b".123Z", b".123456+02:00") + b"- x\r\n"),
        ("syslog-nil-time", _syslog_line(b"<34>1 - host app - - -")),
        ("syslog-escapes", _syslog_line(header + b"[id a=\"q\\\"b\\]c\\\\\"]")),
        ("syslog-priority", _syslog_line(header.replace(b"<165>", b"<192>") + b"-")),
        ("syslog-version", _syslog_line(header.replace(b">1 ", b">2 ") + b"-")),
        ("syslog-date", _syslog_line(header.replace(b"2026-11-08", b"2026-02-30") + b"-")),
        ("syslog-time-framing", _syslog_line(header.replace(b"T10:00:00", b" 10:00:00") + b"-")),
        ("syslog-field", _syslog_line(b"<34>1 - " + b"h" * 300 + b" app - - -")),
        ("syslog-duplicate-sd", _syslog_line(header + b"[a x=\"1\"][a y=\"2\"]")),
        ("syslog-bracket", _syslog_line(header + b"[a x=\"1]\"]")),
        ("syslog-unterminated", _syslog_line(header + b"[a x=\"1\"")),
        ("syslog-boundary", _syslog_line(header + b"[a]x")),
        ("syslog-utf8", _syslog_line(header + b"[a x=\"\xff\"]")),
        ("syslog-count-zero", b"012 <34>1 - h a - - -"),
        ("syslog-count-short", b"10 <34>1 - h"),
    ]
    hinted = [
        ("websocket-text", _ws(0x81, 0x85, b"\x01\x02\x03\x04")),
        ("websocket-binary-16", _ws(0x82, 0x7e, b"\x01\x00")),
        ("websocket-binary-64", _ws(0x82, 0x7f, struct.pack(">Q", 70000))),
        ("websocket-ping", _ws(0x89, 0x00)),
        ("websocket-rsv", _ws(0xc1, 0x05)),
        ("websocket-continuation", _ws(0x80, 0x05)),
        ("websocket-opcode", _ws(0x83, 0x05)),
        ("websocket-short-16", _ws(0x82, 0x7e, b"\x00\x10")),
        ("websocket-high-bit", _ws(0x82, 0x7f, struct.pack(">Q", 1 << 63))),
        ("websocket-fragmented-ping", _ws(0x09, 0x00)),
        ("websocket-long-close", _ws(0x88, 0x7e, b"\x00\x80")),
    ]
    cases = []
    for group, entries, hint in (("service", vectors, False), ("service-hinted", hinted, True)):
        for number, (name, data) in enumerate(entries):
            base = "stream/%s-%02d-%s" % (group, number, name)
            family = name.split("-", 1)[0]
            for variant, chunks, end in (("whole", [data.hex()], "fin"), ("bytes", [data[i:i + 1].hex() for i in range(len(data))], "fin"),
                                         ("sevens", [data[i:i + 7].hex() for i in range(0, len(data), 7)], "fin"),
                                         ("half", [data[:max(1, len(data) // 2)].hex()], "Capture ended before initial message completed")):
                cases.append({"id": base + "/" + variant, "kind": "stream", "label": family, "chunks": chunks, "hint": family if hint else None,
                              "config": {}, "end": end})
    many = b"".join(b" a%d='x'" % index for index in range(20))
    for name, data, config in (("xmpp-attribute-budget", _xmpp(client + many), {}),
                               ("xmpp-line-budget", _xmpp(client + b" note='" + b"n" * 200 + b"'"), {"max_line": 128}),
                               ("syslog-line-budget", _syslog_line(header + b"- " + b"m" * 200), {"max_line": 128}),
                               ("syslog-octet-budget", b"500 " + header, {"max_line": 128}),
                               ("dcerpc-context-budget", _dce_bind([(abstract, [_NDR])] * 3), {"max_headers": 2})):
        cases.append({"id": "stream/service-options/" + name, "kind": "stream", "label": name.split("-", 1)[0], "chunks": [data.hex()],
                      "hint": None, "config": config, "end": "fin"})
    return cases


def _pkt(body):
    return b"%04x" % (4 + len(body)) + body


def git_cases():
    """Native Git pkt-line requests (through the git/text discriminator) and the first server pkt-line (ref
    advertisement, version 2) (M5 batch 9); identifications, malformed framing, unsupported profiles and budgets,
    each as whole / 1-byte / 7-byte / truncated chunkings."""
    sha = b"0123456789abcdef0123456789abcdef01234567"
    vectors = [
        ("git-upload-pack", _pkt(b"git-upload-pack /project.git\x00host=git.example.org\x00")),
        ("git-receive-pack", _pkt(b"git-receive-pack /project.git\x00")),
        ("git-host-port", _pkt(b"git-upload-pack /p.git\x00host=git.example.org:9418\x00")),
        ("git-host-ipv4", _pkt(b"git-upload-pack /p.git\x00host=192.0.2.7\x00")),
        ("git-version-2", _pkt(b"git-upload-pack /p.git\x00host=git.example.org\x00\x00version=2\x00")),
        ("git-advertisement", _pkt(sha + b" HEAD\x00multi_ack thin-pack side-band\n")),
        ("git-advertisement-sha256", _pkt(sha + sha[:24] + b" refs/heads/main\x00agent=git/2.45\n")),
        ("git-server-v2", _pkt(b"version 2\n")),
        ("git-no-nul", _pkt(b"git-upload-pack /p.git")),
        ("git-command", _pkt(b"git-unknown /p.git\x00")),
        ("git-empty-path", _pkt(b"git-upload-pack \x00")),
        ("git-control-path", _pkt(b"git-upload-pack /p\x01.git\x00")),
        ("git-bad-host", _pkt(b"git-upload-pack /p.git\x00host=bad_host\x00")),
        ("git-bad-port", _pkt(b"git-upload-pack /p.git\x00host=git.example.org:70000\x00")),
        ("git-extra-separator", _pkt(b"git-upload-pack /p.git\x00host=git.example.org\x00version=2\x00")),
        ("git-version-3", _pkt(b"git-upload-pack /p.git\x00host=h.example\x00\x00version=3\x00")),
        ("git-duplicate-parameter", _pkt(b"git-upload-pack /p.git\x00host=h.example\x00\x00a=1\x00a=2\x00")),
        ("git-parameter", _pkt(b"git-upload-pack /p.git\x00host=h.example\x00\x00-bad\x00")),
        ("git-advertisement-lf", _pkt(sha + b" HEAD\x00caps")),
        ("git-advertisement-ref", _pkt(sha + b" tags/v1\x00caps\n")),
        ("git-advertisement-nul", _pkt(sha + b" HEAD\x00caps\x00more\n")),
        ("git-text-route", b"0032git-upload-pack /p.git\n"),
        ("git-uppercase-length", b"003Fgit-upload-pack /p.git\x00"),
    ]
    cases = []
    for number, (name, data) in enumerate(vectors):
        base = "stream/git-%02d-%s" % (number, name)
        for variant, chunks, end in (("whole", [data.hex()], "fin"), ("bytes", [data[i:i + 1].hex() for i in range(len(data))], "fin"),
                                     ("sevens", [data[i:i + 7].hex() for i in range(0, len(data), 7)], "fin"),
                                     ("half", [data[:max(1, len(data) // 2)].hex()], "Capture ended before initial message completed")):
            cases.append({"id": base + "/" + variant, "kind": "stream", "label": "git", "chunks": chunks, "hint": None, "config": {}, "end": end})
    for name, data, config, hint in (("git-hinted", _pkt(b"git-upload-pack /p.git\x00"), {}, "git"),
                                     ("git-field-budget", _pkt(b"git-upload-pack /p.git\x00host=h.example\x00\x00" + b"a\x00b\x00c\x00"), {"max_headers": 1}, None),
                                     ("git-line-budget", _pkt(b"git-upload-pack /" + b"p" * 40 + b"\x00"), {"max_line": 32}, None),
                                     ("git-discriminator-budget", b"0032git-upload-pack " + b"p" * 40, {"max_line": 32}, None)):
        cases.append({"id": "stream/git-options/" + name, "kind": "stream", "label": "git", "chunks": [data.hex()], "hint": hint, "config": config,
                      "end": "fin"})
    return cases


def _nb_name(text=b"FILESERVER"):
    padded = text.ljust(16, b" ")
    return b"\x20" + b"".join(bytes([0x41 + (byte >> 4), 0x41 + (byte & 15)]) for byte in padded) + b"\x00"


def _tacacs(kind, seq, body, flags=0x01, version=0xc1):
    return bytes([version, kind, seq, flags]) + struct.pack(">II", 0x1234, len(body)) + body


def _socks_client(methods=b"\x00", command=1, atyp=1, address=b"\xc0\x00\x02\x01", port=443):
    target = (bytes([len(address)]) + address) if atyp == 3 else address
    return b"\x05" + bytes([len(methods)]) + methods + bytes([5, command, 0, atyp]) + target + struct.pack(">H", port)


def session_cases_v():
    """NetBIOS session requests, TACACS+ packet headers and SOCKS5 exchanges (M5 batch 10); identifications,
    malformed framing, unsupported profiles, each as whole / 1-byte / 7-byte / truncated chunkings."""
    vectors = [
        ("netbios-request", b"\x81\x00\x00\x44" + _nb_name() + _nb_name(b"CLIENT")),
        ("netbios-length", b"\x81\x00\x00\x40" + bytes(64)),
        ("netbios-label", b"\x81\x00\x00\x44" + b"\x10" + _nb_name()[1:] + _nb_name()),
        ("netbios-encoding", b"\x81\x00\x00\x44" + _nb_name()[:5] + b"Z" + _nb_name()[6:] + _nb_name()),
        ("tacacs-start", _tacacs(1, 1, bytes([1, 15, 2, 1, 4, 3, 5, 0]) + b"user" + b"tty" + b"10.0.")),
        ("tacacs-encrypted", _tacacs(2, 1, bytes(20), flags=0x00)),
        ("tacacs-auth-reply", _tacacs(1, 2, bytes([1, 0]) + struct.pack(">HH", 3, 0) + b"msg")),
        ("tacacs-author-reply", _tacacs(2, 2, bytes([1, 1]) + struct.pack(">HH", 0, 0) + bytes([4]) + b"priv")),
        ("tacacs-acct-reply", _tacacs(3, 2, struct.pack(">HH", 2, 0) + bytes([1]) + b"ok")),
        ("tacacs-bad-start", _tacacs(1, 1, bytes([9, 15, 2, 1, 0, 0, 0, 0]))),
        ("tacacs-start-lengths", _tacacs(1, 1, bytes([1, 15, 2, 1, 9, 0, 0, 0]) + b"user")),
        ("tacacs-auth-status", _tacacs(1, 2, bytes([9, 0]) + struct.pack(">HH", 0, 0))),
        ("tacacs-author-args", _tacacs(2, 2, bytes([1, 9]) + struct.pack(">HH", 0, 0) + bytes([1]))),
        ("tacacs-seq", _tacacs(1, 3, bytes(8))),
        ("tacacs-version", _tacacs(1, 1, bytes(8), version=0xb1)),
        ("tacacs-flags", _tacacs(1, 1, bytes(8), flags=0x02)),
        ("socks5-connect-ipv4", _socks_client()),
        ("socks5-connect-domain", _socks_client(atyp=3, address=b"WWW.Example.org")),
        ("socks5-connect-ipv6", _socks_client(atyp=4, address=bytes.fromhex("20010db8000000000000000000000001"))),
        ("socks5-udp-mapped", _socks_client(command=3, atyp=4, address=bytes.fromhex("00000000000000000000ffffc0000201"))),
        ("socks5-two-methods", _socks_client(methods=b"\x00\x02")),
        ("socks5-server", b"\x05\x00\x05\x00\x00\x01\xc0\x00\x02\x01\x01\xbb"),
        ("socks5-server-userpass", b"\x05\x02\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"),
        ("socks5-server-refused", b"\x05\x00\x05\x05\x00\x03\x07host.ex\x00\x50"),
        ("socks5-auth-only", _socks_client(methods=b"\x02")),
        ("socks5-no-acceptable", _socks_client(methods=b"\xff\x00")),
        ("socks5-command", _socks_client(command=7)),
        ("socks5-domain-ip", _socks_client(atyp=3, address=b"192.0.2.1")),
        ("socks5-empty-domain", b"\x05\x01\x00\x05\x01\x00\x03\x00\x00\x50"),
        ("socks5-reply-code", b"\x05\x00\x05\x09\x00\x01" + bytes(6)),
    ]
    cases = []
    for number, (name, data) in enumerate(vectors):
        base = "stream/session-%02d-%s" % (number, name)
        family = {"netbios": "netbios-ss", "tacacs": "tacacs-plus"}.get(name.split("-", 1)[0], name.split("-", 1)[0])
        for variant, chunks, end in (("whole", [data.hex()], "fin"), ("bytes", [data[i:i + 1].hex() for i in range(len(data))], "fin"),
                                     ("sevens", [data[i:i + 7].hex() for i in range(0, len(data), 7)], "fin"),
                                     ("half", [data[:max(1, len(data) // 2)].hex()], "Capture ended before initial message completed")):
            cases.append({"id": base + "/" + variant, "kind": "stream", "label": family, "chunks": chunks, "hint": None, "config": {}, "end": end})
    long_domain = _socks_client(methods=bytes(range(0, 255)), atyp=3, address=b"a" * 63 + b"." + b"b" * 63 + b"." + b"c" * 63 + b"." + b"d" * 61)
    cases.append({"id": "stream/session-options/socks5-maximum", "kind": "stream", "label": "socks5", "chunks": [long_domain.hex()],
                  "hint": None, "config": {}, "end": "fin"})
    return cases


def udp_cases_1():
    """UDP validators of M5 batch 11 (syslog, ONC RPC, OpenVPN, WireGuard, BACnet): whole, truncated and hinted payloads."""
    rpc_call = struct.pack(">IIIIII", 0x77, 0, 2, 100000, 2, 3) + struct.pack(">IIII", 0, 0, 0, 0) + struct.pack(">IIII", 100003, 3, 17, 0)
    vectors = [
        ("syslog", b"<34>1 2026-11-08T10:00:00.123Z host app 1 ID - message", None),
        ("syslog", b"<34>1 2026-02-30T10:00:00Z host app 1 ID -", None),
        ("syslog", b"<34>1 - host app 1 ID [a b=\"c\"] text", "syslog"),
        ("onc-rpc", rpc_call, None),
        ("onc-rpc", struct.pack(">IIIIII", 0x77, 1, 0, 0, 0, 0) + struct.pack(">I", 7), None),
        ("onc-rpc", struct.pack(">IIIII", 0x77, 1, 1, 1, 20), None),
        ("onc-rpc", struct.pack(">IIIIII", 0x77, 0, 2, 100000, 9, 3) + bytes(16), None),
        ("openvpn", bytes([0x38]) + b"\x11" * 8 + b"\x00" + bytes(4), None),
        ("openvpn", bytes([0x38]) + b"\x11" * 8 + bytes(20) + struct.pack(">II", 1, 1) + b"\x00" + bytes(4), None),
        ("openvpn", bytes([0x40]) + b"\x11" * 8 + b"\x01" + bytes(4) + b"\x22" * 8 + bytes(4), None),
        ("openvpn", bytes([0x38]) + bytes(8) + b"\x00" + bytes(4), None),
        ("wireguard", b"\x01\x00\x00\x00\x01\x02\x03\x04" + bytes(140), None),
        ("wireguard", b"\x02\x00\x00\x00" + b"\x05" * 88, None),
        ("wireguard", b"\x03\x00\x00\x00" + b"\x06" * 60, None),
        ("wireguard", b"\x01\x00\x00\x00" + bytes(144), None),
        ("bacnet", b"\x81\x0a\x00\x0c\x01\x20\xff\xff\x00\xff\x10\x08", None),
        ("bacnet", b"\x81\x0b\x00\x08\x01\x00\x30\x00", None),
        ("bacnet", b"\x81\x00\x00\x06\x00\x00", None),
        ("bacnet", b"\x81\x0a\x00\x08\x02\x00\x10\x08", None),
        ("bacnet", b"\x81\x0a\x00\x07\x01\x00\xf0", None),
    ]
    cases = []
    for number, (label, data, hint) in enumerate(vectors):
        base = "datagram/udp1-%02d-%s" % (number, label)
        cases.append({"id": base + "/whole", "kind": "datagram", "label": label, "payload": data.hex(), "hint": hint, "config": {}})
        cases.append({"id": base + "/half", "kind": "datagram", "label": label, "payload": data[:max(1, len(data) // 2)].hex(), "hint": hint, "config": {}})
    return cases


def _l2tp(first=1, tunnel=0, session=0, extra=b"", flags=0xc802):
    avps = struct.pack(">HHHH", 0x8008, 0, 0, first) + extra
    body = struct.pack(">HHHH", tunnel, session, 0, 0) + avps
    return struct.pack(">HH", flags, 4 + len(body)) + body


def _lifx(kind=2, payload=b"", tagged=True, target=bytes(8)):
    word = 1024 | 0x1000 | (0x2000 if tagged else 0)
    header = struct.pack("<HHI", 36 + len(payload), word, 0x1234) + target + bytes(6) + b"\x01\x01" + bytes(8) + struct.pack("<HH", kind, 0)
    return header + payload


def _tuya(command=0x13, payload=b"\x01\x02\x03\x04", crc=None):
    import zlib
    body = b"\x00\x00\x55\xaa" + struct.pack(">III", 1, command, len(payload) + 8) + payload
    return body + struct.pack(">I", zlib.crc32(body) if crc is None else crc) + b"\x00\x00\xaa\x55"


def udp_cases_2():
    """UDP validators of M5 batch 12 (TFTP, NTP, L2TP, CoAP, RIP, RTCP, LIFX LAN, Tuya LAN, EtherNet/IP)."""
    ntp_client = bytes([0x23]) + bytes(47)
    ntp_server = bytes([0x24, 2]) + bytes(38) + b"\x01" * 8
    rip_entry = struct.pack(">HHIIII", 2, 0, 0xc0000200, 0, 0, 1)
    vectors = [
        ("tftp", b"\x00\x01boot.bin\x00octet\x00blksize\x001428\x00tsize\x000\x00", None),
        ("tftp", b"\x00\x02upload.txt\x00netascii\x00", None),
        ("tftp", b"\x00\x01f\x00binary\x00", None),
        ("tftp", b"\x00\x01f\x00octet\x00blksize\x004\x00", None),
        ("tftp", b"\x00\x01f\x00octet\x00tsize\x00100\x00", None),
        ("tftp", b"\x00\x06blksize\x001428\x00", None),
        ("tftp", b"\x00\x06color\x00red\x00", None),
        ("tftp", b"\x00\x05\x00\x01File not found\x00", "tftp"),
        ("tftp", b"\x00\x05\x00\x09bad\x00", "tftp"),
        ("ntp", ntp_client, "ntp"),
        ("ntp", ntp_server, "ntp"),
        ("ntp", bytes([0x24, 2]) + bytes(46), "ntp"),
        ("ntp", bytes([0x13]) + bytes(47), "ntp"),
        ("l2tp", _l2tp(), None),
        ("l2tp", _l2tp(first=2, tunnel=7), None),
        ("l2tp", _l2tp(first=2), None),
        ("l2tp", _l2tp(first=6), None),
        ("l2tp", _l2tp(flags=0x8802), None),
        ("coap", b"\x40\x01\x12\x34\xb4test", None),
        ("coap", b"\x52\x45\x12\x34\xab\xcd\xff\x01", None),
        ("coap", b"\x40\x01\x12\x34\xff", None),
        ("coap", b"\x40\x07\x12\x34\x01", None),
        ("coap", b"\x40\x00\x12\x34", "coap"),
        ("rip", struct.pack(">BBH", 2, 2, 0) + rip_entry, None),
        ("rip", struct.pack(">BBH", 1, 2, 0) + struct.pack(">HHIIII", 0, 0, 0, 0, 0, 16), None),
        ("rip", struct.pack(">BBH", 2, 2, 0) + b"\xff\xff\x00\x02" + b"password".ljust(16, b"\x00") + rip_entry, None),
        ("rip", struct.pack(">BBH", 2, 1, 0) + struct.pack(">HHIIII", 2, 7, 0xc0000200, 0, 0, 1), None),
        ("rip", struct.pack(">BBH", 2, 2, 0) + struct.pack(">HHIIII", 2, 0, 0xc0000200, 0, 0, 17), None),
        ("rtcp", bytes([0x80, 200]) + struct.pack(">H", 6) + bytes(24) + bytes([0x81, 202]) + struct.pack(">H", 1) + bytes(4), "rtcp"),
        ("rtcp", bytes([0x81, 201]) + struct.pack(">H", 7) + bytes(28), "rtcp"),
        ("rtcp", bytes([0x80, 202]) + struct.pack(">H", 1) + bytes(4), "rtcp"),
        ("rtcp", bytes([0x81, 200]) + struct.pack(">H", 6) + bytes(24), "rtcp"),
        ("lifx-lan", _lifx(), None),
        ("lifx-lan", _lifx(kind=3, payload=b"\x01\x7c\xdd\x00\x00", tagged=False, target=b"\xd0\x73\xd5\x01\x02\x03\x00\x00"), None),
        ("lifx-lan", _lifx(kind=999, payload=b"xyz"), None),
        ("lifx-lan", _lifx(kind=3, payload=b"\x01"), None),
        ("lifx-lan", _lifx(target=b"\x01" + bytes(7)), None),
        ("tuya-lan", _tuya(), None),
        ("tuya-lan", _tuya(command=0x77), None),
        ("tuya-lan", _tuya(crc=1), None),
        ("ethernet-ip", struct.pack("<HHII", 0x63, 0, 0, 0) + bytes(12), None),
        ("ethernet-ip", struct.pack("<HHII", 0x63, 0, 0, 0) + bytes(12) + b"xx", None),
    ]
    cases = []
    for number, (label, data, hint) in enumerate(vectors):
        base = "datagram/udp2-%02d-%s" % (number, label)
        cases.append({"id": base + "/whole", "kind": "datagram", "label": label, "payload": data.hex(), "hint": hint, "config": {}})
        cases.append({"id": base + "/half", "kind": "datagram", "label": label, "payload": data[:max(1, len(data) // 2)].hex(), "hint": hint, "config": {}})
    many = _l2tp(extra=b"".join(struct.pack(">HHH", 0x0006, 0, 9) for _ in range(6)))
    cases.append({"id": "datagram/udp2-options/l2tp-avp-budget", "kind": "datagram", "label": "l2tp", "payload": many.hex(), "hint": None,
                  "config": {"max_headers": 3}})
    return cases


def _stun(method_class=0x0001, attributes=b"", fingerprint=False):
    import zlib
    body = attributes
    length = len(body) + (8 if fingerprint else 0)
    message = struct.pack(">HH", method_class, length) + b"\x21\x12\xa4\x42" + bytes(range(12)) + body
    if fingerprint:
        message += struct.pack(">HHI", 0x8028, 4, (zlib.crc32(message) & 0xffffffff) ^ 0x5354554e)
    return message


def _dhcp(op=1, options=b"\x35\x01\x01\xff", flags=0):
    return bytes([op, 1, 6, 0]) + struct.pack(">IHH", 0x1234, 0, flags) + bytes(16) + bytes(16) + bytes(192) + b"\x63\x82\x53\x63" + options


def _radius(code, attributes):
    return bytes([code, 7]) + struct.pack(">H", 20 + len(attributes)) + bytes(16) + attributes


def udp_cases_3():
    """UDP validators of M5 batch 13 (NetFlow v5/v9, IPFIX, sFlow v5, STUN/TURN, DHCPv4, RADIUS)."""
    record = bytes(16) + struct.pack(">II", 10, 1500) + bytes(24)   # 48 bytes; offset 36 and 46..47 stay zero
    v5 = struct.pack(">HHIIIIBBH", 5, 1, 1, 2, 3, 4, 0, 0, 0) + record
    v9 = struct.pack(">HHIIII", 9, 1, 1, 2, 3, 4) + struct.pack(">HH", 0, 8) + bytes(4)
    ipfix_body = struct.pack(">HH", 2, 8) + bytes(4)
    ipfix = struct.pack(">HHIII", 10, 16 + len(ipfix_body), 1, 2, 3) + ipfix_body
    sflow = struct.pack(">IIIIIII", 5, 1, 0xc0000201, 0, 1, 2, 1) + struct.pack(">II", 1, 8) + bytes(8)
    xor_mapped = struct.pack(">HHBBH", 0x0020, 8, 0, 1, 0x1234) + bytes(4)
    vectors = [
        ("netflow", v5, None),
        ("netflow", v5[:24 + 16] + struct.pack(">II", 0, 1500) + v5[24 + 24:], None),
        ("netflow", v9, None),
        ("netflow", v9[:20] + struct.pack(">HH", 5, 8) + bytes(4), None),
        ("ipfix", ipfix, None),
        ("ipfix", ipfix[:16] + struct.pack(">HH", 1, 8) + bytes(4), None),
        ("sflow", sflow, None),
        ("sflow", sflow + b"xxxx", None),
        ("sflow", sflow[:28] + struct.pack(">II", 9, 8) + bytes(8), None),
        ("stun", _stun(), None),
        ("stun", _stun(0x0101, xor_mapped, fingerprint=True), None),
        ("stun", _stun(0x0003, struct.pack(">HHB", 0x0019, 4, 17) + bytes(3)), None),
        ("stun", _stun(0x0016, struct.pack(">HH", 0x0013, 4) + b"data"), None),
        ("stun", _stun(0x0006), None),
        ("stun", _stun(0x0101, struct.pack(">HHBBH", 0x0020, 8, 0, 3, 0x1234) + bytes(4)), None),
        ("stun", _stun(0x0001, struct.pack(">HH", 0x0008, 8) + bytes(8)), None),
        ("stun", _stun(0x0101, xor_mapped, fingerprint=True)[:-1] + b"\x00", None),
        ("dhcp", _dhcp(), None),
        ("dhcp", _dhcp(op=2, options=b"\x35\x01\x05\x01\x04\xff\xff\xff\x00\xff\x00\x00"), None),
        ("dhcp", _dhcp(op=2, options=b"\x35\x01\x01\xff"), None),
        ("dhcp", _dhcp(options=b"\x35\x01\x01"), None),
        ("dhcp", _dhcp(options=b"\x34\x01\x03\x35\x01\x01\xff"), None),
        ("dhcp", _dhcp(flags=0x0001), None),
        ("radius", _radius(1, bytes([1, 6]) + b"alice" [:4] + bytes([2, 18]) + bytes(16) + bytes([4, 6]) + bytes([192, 0, 2, 1])), "radius"),
        ("radius", _radius(2, bytes([6, 6, 0, 0, 0, 1]) + bytes([18, 5]) + b"ok!"), "radius"),
        ("radius", _radius(11, bytes([24, 6]) + b"st01"), "radius"),
        ("radius", _radius(11, bytes([18, 5]) + b"hi!"), "radius"),
        ("radius", _radius(1, bytes([1, 6]) + b"user" + bytes([4, 6]) + bytes(4)), "radius"),
        ("radius", _radius(1, bytes([2, 18]) + bytes(16) + bytes([3, 19]) + bytes(17) + bytes([4, 6]) + bytes(4)), "radius"),
        ("radius", _radius(3, bytes([6, 6]) + bytes(4)), "radius"),
    ]
    cases = []
    for number, (label, data, hint) in enumerate(vectors):
        base = "datagram/udp3-%02d-%s" % (number, label)
        cases.append({"id": base + "/whole", "kind": "datagram", "label": label, "payload": data.hex(), "hint": hint, "config": {}})
        cases.append({"id": base + "/half", "kind": "datagram", "label": label, "payload": data[:max(1, len(data) // 2)].hex(), "hint": hint, "config": {}})
    cases.append({"id": "datagram/udp3-options/radius-budget", "kind": "datagram", "label": "radius", "hint": "radius", "config": {"max_headers": 2},
                  "payload": _radius(1, bytes([1, 6]) + b"user" + bytes([2, 18]) + bytes(16) + bytes([4, 6]) + bytes(4)).hex()})
    return cases


def _tlv(tag, value):
    size = len(value)
    length = bytes([size]) if size < 128 else bytes([0x81, size]) if size < 256 else bytes([0x82]) + struct.pack(">H", size)
    return bytes([tag]) + length + value


def _int(value):
    return _tlv(2, value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big", signed=True))


def _snmp(version, pdu_tag, bindings, community=b"public", status=0, index=0):
    pdu = _tlv(pdu_tag, _int(7) + _int(status) + _int(index) + _tlv(0x30, bindings))
    return _tlv(0x30, _int(version) + _tlv(4, community) + pdu)


def _snmp3(flags=4, user=b"", engine=b"", auth=b"", priv=b"", scoped=None, model=3):
    header = _tlv(0x30, _int(1) + _int(65507) + _tlv(4, bytes([flags])) + _int(model))
    usm = _tlv(0x30, _tlv(4, engine) + _int(0) + _int(0) + _tlv(4, user) + _tlv(4, auth) + _tlv(4, priv))
    if scoped is None:
        scoped = _tlv(0x30, _tlv(4, b"") + _tlv(4, b"") + _tlv(0xa0, _int(1) + _int(0) + _int(0) + _tlv(0x30, b"")))
    return _tlv(0x30, _int(3) + header + _tlv(4, usm) + scoped)


def udp_cases_4():
    """UDP validators of M5 batch 14: SNMP v1/v2c/v3 over BER and the hinted RTP header."""
    sys_descr = _tlv(6, b"\x2b\x06\x01\x02\x01\x01\x01\x00")
    get_binding = _tlv(0x30, sys_descr + _tlv(5, b""))
    value_binding = _tlv(0x30, sys_descr + _tlv(4, b"Linux"))
    vectors = [
        ("snmp", _snmp(1, 0xa0, get_binding), None),
        ("snmp", _snmp(0, 0xa1, get_binding), None),
        ("snmp", _snmp(1, 0xa2, value_binding), None),
        ("snmp", _snmp(1, 0xa5, get_binding, status=0, index=10), None),
        ("snmp", _tlv(0x30, _int(0) + _tlv(4, b"public") + _tlv(0xa4, sys_descr + _tlv(0x40, bytes(4)) + _int(6) + _int(1) + _tlv(0x43, b"\x01") + _tlv(0x30, value_binding))), None),
        ("snmp", _snmp(1, 0xa0, value_binding), None),
        ("snmp", _snmp(1, 0xa0, get_binding, status=1), None),
        ("snmp", _snmp(2, 0xa0, get_binding), None),
        ("snmp", _snmp(0, 0xa5, get_binding), None),
        ("snmp", _snmp(1, 0xa0, _tlv(0x30, _tlv(6, b"\x2b\x80\x01") + _tlv(5, b""))), None),
        ("snmp", _snmp(1, 0xa2, _tlv(0x30, sys_descr + _tlv(0x40, b"\x01\x02"))), None),
        ("snmp", _snmp3(), None),
        ("snmp", _snmp3(flags=7, user=b"admin", engine=b"\x80\x00\x1f\x88", auth=bytes(12), priv=bytes(8), scoped=_tlv(4, bytes(32))), None),
        ("snmp", _snmp3(flags=5, user=b"admin", engine=b"\x80\x00\x1f\x88", auth=bytes(12)), None),
        ("snmp", _snmp3(flags=2), None),
        ("snmp", _snmp3(flags=5, user=b"admin", engine=b"e"), None),
        ("snmp", _snmp3(model=2, scoped=None), None),
        ("rtp", bytes([0x80, 0x60]) + struct.pack(">HII", 1, 1000, 0x1234) + bytes(160), "rtp"),
        ("rtp", bytes([0x91, 0x00]) + struct.pack(">HII", 1, 1000, 0x1234) + bytes(4) + struct.pack(">HH", 0xbede, 1) + bytes(4) + bytes(8), "rtp"),
        ("rtp", bytes([0xa0, 0x00]) + struct.pack(">HII", 1, 1000, 0x1234) + bytes(8) + b"\x00\x00\x03", "rtp"),
        ("rtp", bytes([0xa0, 0x00]) + struct.pack(">HII", 1, 1000, 0x1234) + bytes(3) + b"\x00", "rtp"),
        ("rtp", bytes([0x80, 0xc8]) + struct.pack(">HII", 1, 1000, 0x1234), "rtp"),
        ("rtp", bytes([0x40, 0x00]) + bytes(10), "rtp"),
    ]
    cases = []
    for number, (label, data, hint) in enumerate(vectors):
        base = "datagram/udp4-%02d-%s" % (number, label)
        cases.append({"id": base + "/whole", "kind": "datagram", "label": label, "payload": data.hex(), "hint": hint, "config": {}})
        cases.append({"id": base + "/half", "kind": "datagram", "label": label, "payload": data[:max(1, len(data) // 2)].hex(), "hint": hint, "config": {}})
    return cases


def udp_cases_5():
    """UDP validators of M5 batch 15: SSDP (HTTP header block) and SIP over UDP (text route plus Content-Length)."""
    sip = (b"OPTIONS sip:server.example SIP/2.0\r\nVia: SIP/2.0/UDP client.example;branch=z9hG4bKdemo\r\nMax-Forwards: 70\r\n"
           b"From: <sip:a@client.example>;tag=1\r\nTo: <sip:server.example>\r\nCall-ID: demo@client.example\r\nCSeq: 1 OPTIONS\r\n")
    vectors = [
        ("ssdp", b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n", None),
        ("ssdp", b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: upnp:rootdevice\r\nNTS: ssdp:alive\r\nUSN: uuid:1::upnp:rootdevice\r\n\r\n", None),
        ("ssdp", b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nST: upnp:rootdevice\r\nUSN: uuid:1::upnp:rootdevice\r\n\r\n", None),
        ("ssdp", b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: ssdp:all\r\n\r\n", None),
        ("ssdp", b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: upnp:rootdevice\r\n\r\n", None),
        ("ssdp", b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n\r\n", None),
        ("ssdp", b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST: a\r\n\r\ntrailing", None),
        ("ssdp", b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST: a\r\n", None),
        ("sip", sip + b"Content-Length: 0\r\n\r\n", None),
        ("sip", sip + b"Content-Length: 4\r\n\r\nbody", None),
        ("sip", sip + b"\r\n", None),
        ("sip", sip + b"Content-Length: 9\r\n\r\nbody", None),
        ("sip", b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP client.example;branch=z9hG4bKdemo\r\nFrom: <sip:a@client.example>;tag=1\r\n"
                b"To: <sip:server.example>;tag=2\r\nCall-ID: demo@client.example\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n", None),
        ("sip", sip, None),
        ("sip", b"OPTIONS sip:server.example SIP/2.0\r\nVia: SIP/2.0/UDP c;branch=1\r\n\r\n", "sip"),
    ]
    cases = []
    for number, (label, data, hint) in enumerate(vectors):
        base = "datagram/udp5-%02d-%s" % (number, label)
        cases.append({"id": base + "/whole", "kind": "datagram", "label": label, "payload": data.hex(), "hint": hint, "config": {}})
        cases.append({"id": base + "/half", "kind": "datagram", "label": label, "payload": data[:max(1, len(data) // 2)].hex(), "hint": hint, "config": {}})
    cases.append({"id": "datagram/udp5-options/ssdp-header-budget", "kind": "datagram", "label": "ssdp", "hint": None, "config": {"max_headers": 2},
                  "payload": vectors[0][1].hex()})
    return cases


def udp_cases_6():
    """UDP validator of M5 batch 16: TP-Link Smart Home (autokey JSON). The vectors pin the json.loads grammar the Go
    port must share: NaN/Infinity literals, number forms, escapes and surrogates, repeated keys, trailing data, the
    nesting budget and the 4300-digit integer limit."""
    from protocol_adapters.protocol_fixtures import kasa
    deep = lambda n: b'{"system":' + b'{"a":' * (n - 2) + b'{}' + b'}' * (n - 2) + b'}'
    vectors = [
        b'{"system":{"get_sysinfo":{}},"emeter":{"get_realtime":{}}}',
        b'{"system":{"get_sysinfo":{"alias":"placeholder","err_code":0}}}',
        b'{"smartlife.iot.common.emeter":{"get_realtime":{}},"time":{"get_time":null},"netif":{}}',
        b'  {"system" : { "a" : [ 1 , 2 ] } }  '[2:],
        b'{"system":1,"system":{}}',
        b'{"system":{},"system":1}',
        b'{"system":{},"emeter":{},"system":{}}',
        b'{"s\\u0079stem":{}}',
        b'{"s\\u0079stem":{},"system":{}}',
        b'{"system":{},"other_module":{}}',
        b'{"other_module":1,"system":{}}',
        b'{"system":[]}',
        b'{"system":null}',
        b'{"system":{"a":NaN,"b":-Infinity,"c":Infinity}}',
        b'{"system":{"a":Nan}}',
        b'{"system":{"a":-Inf}}',
        b'{"system":{"a":[1e5,-0,0.5,1E+2,-1.25e-3,0]}}',
        b'{"system":{"a":01}}',
        b'{"system":{"a":1.}}',
        b'{"system":{"a":1e}}',
        b'{"system":{"a":+1}}',
        b'{"system":{"a":.5}}',
        b'{"system":{"a":-}}',
        b'{"system":{"a":1,}}',
        b'{"system":{"a":[1,]}}',
        b'{"system":{}} x',
        b'{"system":{}}   ',
        b'{"system":{}}}',
        b'{"system":{}',
        deep(8),
        deep(9),
        b'{"system":{"a":"[[[[[[[[[[{{{{"}}',
        b'{"system":{"a":"\\"[[[[[[[[[[\\""}}',
        b'{"system":{"a":"\\n\\"\\/\\b\\f\\r\\t\\\\"}}',
        b'{"system":{"a":"\\x"}}',
        b'{"system":{"a":"\\u12"}}',
        b'{"system":{"a":"\\u12g4"}}',
        b'{"system":{"a":"\\ud83d\\ude00"}}',
        b'{"system":{"a":"\\ud800"}}',
        b'{"system":{"a":"\\ud800\\uZZZZ"}}',
        b'{"system":{"a":"\\ud800\\u0041"}}',
        b'{"system":{"a":' + b'1' * 4300 + b'}}',
        b'{"system":{"a":' + b'1' * 4301 + b'}}',
        b'{"system":{"a":-' + b'1' * 4301 + b'}}',
        b'{"system":{"a":' + b'1' * 4301 + b'.0}}',
        b'{"system":{"a":' + b'1' * 4301 + b'e1}}',
        b'{"system":{"a":"tab\there"}}',
        b'{"system":{"a":nul}}',
        b'{"system":{"a":tru}}',
        b"{\"system\":{'a':1}}",
        b'{"system" {}}',
        b'{"system":{"a":"unterminated}}',
        b'{"system":{"a":true,"b":false,"c":null,"d":""}}',
        b'{"":{}}xxx'[:8],
        b'{"a":1}',
        b'[{"system":{}}]',
    ]
    cases = []
    for number, text in enumerate(vectors):
        data = kasa(text)
        base = "datagram/udp6-%02d-tplink-smarthome" % number
        cases.append({"id": base + "/whole", "kind": "datagram", "label": "tplink-smarthome", "payload": data.hex(), "hint": None, "config": {}})
        cases.append({"id": base + "/half", "kind": "datagram", "label": "tplink-smarthome", "payload": data[:max(1, len(data) // 2)].hex(), "hint": None, "config": {}})
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
    cases.extend(udp_cases_1())
    cases.extend(udp_cases_2())
    cases.extend(udp_cases_3())
    cases.extend(udp_cases_4())
    cases.extend(udp_cases_5())
    cases.extend(udp_cases_6())
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
