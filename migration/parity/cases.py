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
