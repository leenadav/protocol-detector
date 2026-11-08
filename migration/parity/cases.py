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
    cases.extend(tls_cases())
    cases.extend(text_cases())
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
