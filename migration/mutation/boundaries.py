#!/usr/bin/env python3
"""Boundary cases for the Go TLS, QUIC and HTTP/1 parsers, answered by the Python reference (PRO-126).

The first gremlins run left most surviving mutants on comparison boundaries (`<` read as `<=`, `>` as `>=`) and
length arithmetic that no test exercised exactly. Each case here sits on one limit or one past it: TLS ClientHello
fixed fields, session ID, cipher and compression vectors and extensions; ServerHello session, compression and
extension budget; QUIC header connection IDs, Version Negotiation, token, Length, variable-length integers and the
Initial frame budgets; the HTTP/1 text route's line and header budgets, start-lines, Host authority,
framing headers and upgrade shifts. The expected outcome of every case comes from the reference (protocol_engine/parsers.py
parse_hello, tls_server.py parse_server_hello, quic.py quic_probe, varint, frames and quic, extended.py
TextParser), so each Go test
checks the boundary and the parity at once. Regenerate after a deliberate profile change:

    python3 -B migration/mutation/boundaries.py                     # writes the three boundary_test.go files and the lock
    python3 -B migration/mutation/boundaries.py --check-reference   # fails when a file is not what the reference gives
    python3 -B migration/mutation/boundaries.py --check             # fails when a file is not the one the lock pins

The generated files are golden files (PRO-401, Lee 2026-11-25: the Python reference is removed): their expected
outcomes are the reference's, frozen when they were written. migration/mutation/boundaries.lock.json pins each one by
SHA-256, and `--check` (make go-check-static) compares the files with the lock and imports nothing of the reference,
so a hand edit of a frozen expectation still fails. `--check-reference` re-renders them from the reference, as long
as it exists.

Standard library only (plus gofmt); Python 3.9 syntax.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
LOCK = ROOT / "migration/mutation/boundaries.lock.json"

# The reference's parsers: loaded by load_reference() when the files are rendered, never by --check. Until then the
# error classes are a placeholder exception that nothing raises, so every handler stays a valid exception handler.


class NotLoaded(Exception):
    """Stands in for the reference's error classes before load_reference()."""


BudgetError = ParseError = UnsupportedPrefix = NotLoaded
Config = ClientHelloInfo = parse_hello = None
AmbiguousPrefix = NotLoaded
MAX_CRYPTO = frames = quic = quic_probe = varint = TextParser = parse_server_hello = None


def load_reference():
    global Config, BudgetError, ClientHelloInfo, ParseError, UnsupportedPrefix, parse_hello
    global MAX_CRYPTO, frames, quic, quic_probe, varint, AmbiguousPrefix, TextParser, parse_server_hello
    from protocol_engine import Config  # noqa: F811
    from protocol_engine.parsers import BudgetError, ClientHelloInfo, ParseError, UnsupportedPrefix, parse_hello  # noqa: F811
    from protocol_engine.quic import MAX_CRYPTO, frames, quic, quic_probe, varint  # noqa: F811
    from protocol_engine.extended import AmbiguousPrefix, TextParser  # noqa: F811
    from protocol_engine.tls_server import parse_server_hello  # noqa: F811

V1 = b"\x00\x00\x00\x01"


def kind_of(error):
    if isinstance(error, BudgetError):
        return "budget"
    if isinstance(error, AmbiguousPrefix):
        return "ambiguous"
    if isinstance(error, UnsupportedPrefix):
        return "unsupported"
    return "malformed"


def outcome(call):
    """"kind: message" for a parser error, else "ok " and the value's description."""
    try:
        return "ok " + call()
    except ParseError as error:  # BudgetError and UnsupportedPrefix are ParseErrors
        return "{}: {}".format(kind_of(error), error)


def rows_of(evidence):
    """field=value of each evidence item (Evidence objects, or the (field, value, source, strength) tuples of
    parse_server_hello)."""
    pairs = ((e[0], e[1]) if isinstance(e, tuple) else (e.field, e.value) for e in evidence)
    return ",".join("{}={}".format(field, value) for field, value in pairs)


def vec(data, width):
    return len(data).to_bytes(width, "big") + data


# -- TLS ---------------------------------------------------------------------------------------------------------

def hello_body(version=b"\x03\x03", session=b"", ciphers=b"\x13\x01", compression=b"\x00", extensions=None, raw_tail=b""):
    body = version + bytes(32) + vec(session, 1) + vec(ciphers, 2) + vec(compression, 1)
    if extensions is not None:
        body += vec(b"".join(k.to_bytes(2, "big") + vec(v, 2) for k, v in extensions), 2)
    return body + raw_tail


def sni(name):
    return (0, vec(b"\x00" + vec(name, 2), 2))


def alpn(*names):
    return (16, vec(b"".join(vec(n, 1) for n in names), 2))


def server_body(session=b"", cipher=b"\x13\x01", compression=b"\x00", extensions=None, version=b"\x03\x03"):
    body = version + bytes(32) + vec(session, 1) + cipher + compression
    if extensions is not None:
        body += vec(b"".join(k.to_bytes(2, "big") + vec(v, 2) for k, v in extensions), 2)
    return body


def tls_cases():
    out = []

    def hello(name, body, collect=False):
        def call():
            # As the TLS stream and QUIC callers do: an `offered` list (which turns on the strict supported_versions
            # check), and a ClientHelloInfo when fingerprints or contexts are collected. DTLS refuses
            # supported_versions before it parses, so no reachable caller parses without `offered`.
            host, names = parse_hello(body, ClientHelloInfo() if collect else None, [])
            return "host={} alpn={}".format("-" if host is None else host, ",".join(names or ()))
        out.append(("hello-collect" if collect else "hello", name, body, 64, outcome(call)))

    def server(name, body, max_headers=64):
        def call():
            evidence, scope, reason = parse_server_hello(body, Config(max_headers=max_headers), 1 << 3, 0)
            return "{} | {} | {}".format(scope, reason, rows_of(evidence))
        out.append(("server", name, body, max_headers, outcome(call)))

    for collect in (False, True):
        tag = " (collected)" if collect else ""
        hello("one byte" + tag, b"\x03", collect)
        hello("version 3.0" + tag, hello_body(version=b"\x03\x00"), collect)
        hello("version 3.4" + tag, hello_body(version=b"\x03\x04"), collect)
        hello("version 3.1" + tag, hello_body(version=b"\x03\x01", extensions=[]), collect)
        hello("ends before the session length" + tag, b"\x03\x03" + bytes(32), collect)
        hello("session 32" + tag, hello_body(session=bytes(32), extensions=[]), collect)
        hello("session 33" + tag, hello_body(session=bytes(33), extensions=[]), collect)
        hello("session longer than the body" + tag, b"\x03\x03" + bytes(32) + b"\x05" + bytes(4), collect)
        hello("ends before the cipher length" + tag, b"\x03\x03" + bytes(32) + b"\x00\x00", collect)
        hello("cipher vector one past the body" + tag, b"\x03\x03" + bytes(32) + b"\x00\x00\x04" + bytes(3), collect)
        hello("odd cipher vector" + tag, hello_body(ciphers=b"\x13\x01\x13", extensions=[]), collect)
        hello("no compression byte" + tag, b"\x03\x03" + bytes(32) + b"\x00" + vec(b"\x13\x01", 2), collect)
        hello("compression vector one past the body" + tag, b"\x03\x03" + bytes(32) + b"\x00" + vec(b"\x13\x01", 2) + b"\x02\x00", collect)
        hello("no extension block" + tag, hello_body(), collect)
        hello("empty extension block" + tag, hello_body(extensions=[]), collect)
        hello("extension block one past the body" + tag, hello_body(raw_tail=b"\x00\x05\x00\x00\x00\x00"), collect)
        hello("trailing byte after extensions" + tag, hello_body(extensions=[], raw_tail=b"\x00"), collect)
        hello("server name" + tag, hello_body(extensions=[sni(b"www.example.com")]), collect)
        hello("server name 253 bytes" + tag, hello_body(extensions=[sni(b"a" * 63 + b"." + b"b" * 63 + b"." + b"c" * 63 + b"." + b"d" * 61)]), collect)
        hello("server name 254 bytes" + tag, hello_body(extensions=[sni(b"a" * 63 + b"." + b"b" * 63 + b"." + b"c" * 63 + b"." + b"d" * 62)]), collect)
        hello("server name list longer than the extension" + tag, hello_body(extensions=[(0, b"\x00\x09\x00\x00\x03abc")]), collect)
        hello("duplicate extension" + tag, hello_body(extensions=[(23, b""), (23, b"")]), collect)
        hello("alpn h2 and http/1.1" + tag, hello_body(extensions=[alpn(b"h2", b"http/1.1")]), collect)
        hello("alpn empty name" + tag, hello_body(extensions=[alpn(b"")]), collect)
        hello("alpn list one past the extension" + tag, hello_body(extensions=[(16, b"\x00\x04\x02h2")]), collect)
        hello("supported versions" + tag, hello_body(extensions=[(43, b"\x04\x03\x04\x03\x03")]), collect)
        hello("supported versions odd" + tag, hello_body(extensions=[(43, b"\x03\x03\x04\x03")]), collect)
        hello("64 extensions" + tag, hello_body(extensions=[(1000 + i, b"") for i in range(64)]), collect)
        hello("65 extensions" + tag, hello_body(extensions=[(1000 + i, b"") for i in range(65)]), collect)
    server("server session 32", server_body(session=bytes(32)))
    server("server session 33", server_body(session=bytes(33)))
    server("server version 3.2", server_body(version=b"\x03\x02"))
    server("server compression 1", server_body(compression=b"\x01"))
    server("server ends after compression", server_body())
    server("server truncated before compression", server_body()[:-1])
    server("server supported_versions 1.3", server_body(extensions=[(43, b"\x03\x04")]))
    server("server 64 extensions at budget 64", server_body(extensions=[(1000 + i, b"") for i in range(64)]))
    server("server 65 extensions at budget 64", server_body(extensions=[(1000 + i, b"") for i in range(65)]))
    server("server 3 extensions at budget 2", server_body(extensions=[(1000 + i, b"") for i in range(3)]), 2)
    server("server duplicate extension", server_body(extensions=[(43, b"\x03\x04"), (43, b"\x03\x04")]))
    server("server extension block one past the body", server_body() + b"\x00\x05\x00\x2b\x00\x02")
    server("server trailing byte after extensions", server_body(extensions=[]) + b"\x00")
    server("server tls 1.2 aes-gcm", server_body(cipher=b"\xc0\x2f", extensions=[(0xff01, b"\x00")]))
    server("server tls 1.2 static rsa", server_body(cipher=b"\x00\x2f", extensions=[(0xff01, b"\x00")]))
    return out


# -- QUIC --------------------------------------------------------------------------------------------------------

def quic_header(dcil=8, scil=0, version=V1, first=0xc3):
    return bytes([first]) + version + bytes([dcil]) + bytes(dcil) + bytes([scil]) + bytes(scil)


def v1(n):
    return bytes([n]) if n < 64 else bytes([0x40 | n >> 8, n & 0xff])


def quic_cases():
    out = []

    def probe(name, data):
        out.append(("probe", name, data, 64, outcome(lambda: str(quic_probe(data)).lower())))

    def validate(name, data, max_headers=64):
        def call():
            match = quic(data, Config(max_headers=max_headers))
            return "{} [{}] retracts={}".format(match.reason, rows_of(match.evidence), str(bool(match.retracts)).lower())
        out.append(("validate", name, data, max_headers, outcome(call)))

    def frame(name, plaintext, max_headers=64):
        call = lambda: ";".join("{}+{}".format(o, len(d)) for o, d in frames(plaintext, Config(max_headers=max_headers)))  # noqa: E731
        out.append(("frames", name, plaintext, max_headers, outcome(call)))

    def var(name, data):
        out.append(("varint", name, data, len(data), outcome(lambda: "{}@{}".format(*varint(data, 0, len(data))))))

    probe("probe six bytes", b"\xc3" + V1 + b"\x08")
    probe("probe seven bytes", b"\xc3" + V1 + b"\x08\x00")
    probe("probe version negotiation seven bytes", b"\xc0\x00\x00\x00\x00\x00\x00")
    validate("dcid 20 then nothing", quic_header(dcil=20)[:6 + 20])
    validate("dcid 21", quic_header(dcil=21) + bytes(30))
    validate("dcid 20 one byte short", quic_header(dcil=20)[:6 + 19])
    validate("scid 20 exactly at the end", quic_header(scil=20))
    validate("scid 21", quic_header(scil=21) + bytes(30))
    validate("scid 20 one byte short", quic_header(scil=20)[:-1])
    vn = quic_header(version=b"\x00\x00\x00\x00", first=0xc0, dcil=0)
    for n in (0, 3, 4, 5):
        validate("version negotiation rest {}".format(n), vn + bytes(n))
    validate("version negotiation 64 versions at budget 64", vn + bytes(4 * 64))
    validate("version negotiation 65 versions at budget 64", vn + bytes(4 * 65))
    validate("version negotiation 128 versions at budget 200", vn + bytes(4 * 128), 200)
    validate("version negotiation 129 versions at budget 200", vn + bytes(4 * 129), 200)
    base = quic_header()
    validate("token fills the datagram", base + v1(3) + bytes(3))
    validate("token one past the datagram", base + v1(4) + bytes(3))
    tail = base + v1(0)
    validate("length 16", tail + v1(16) + bytes(40))
    validate("length 17 fits exactly with 20 bytes after", tail + v1(20) + bytes(20))
    validate("length one past the datagram", tail + v1(21) + bytes(20))
    validate("length 17 but only 19 bytes after", tail + v1(17) + bytes(19))
    var("varint one byte", b"\x25")
    var("varint two bytes", b"\x40\x25")
    var("varint two bytes truncated", b"\x40")
    var("varint four bytes", b"\x80\x00\x01\x00")
    var("varint four bytes truncated", b"\x80\x00\x01")
    var("varint eight bytes", b"\xc0" + bytes(6) + b"\x01")
    var("varint empty", b"")
    frame("64 pings at budget 64", b"\x01" * 64)
    frame("65 pings at budget 64", b"\x01" * 65)
    frame("padding does not count", b"\x00" * 200 + b"\x01" * 64)
    frame("128 pings at budget 200", b"\x01" * 128, 200)
    frame("129 pings at budget 200", b"\x01" * 129, 200)
    frame("ack with 64 ranges", b"\x02\x00\x00" + v1(64) + b"\x00" + b"\x00\x00" * 64)
    frame("ack with 65 ranges", b"\x02\x00\x00" + v1(65) + b"\x00" + b"\x00\x00" * 65)
    frame("ack ecn counts", b"\x03\x00\x00\x00\x00\x00\x00\x00")
    frame("ack ecn counts truncated", b"\x03\x00\x00\x00\x00\x00\x00")
    frame("crypto at the assembly budget", b"\x06" + v1(MAX_CRYPTO - 1) + v1(1) + b"\x01")
    frame("crypto one past the assembly budget", b"\x06" + v1(MAX_CRYPTO) + v1(1) + b"\x01")
    frame("crypto exactly fills the packet", b"\x06\x00\x05" + bytes(5))
    frame("crypto one past the packet", b"\x06\x00\x06" + bytes(5))
    frame("crypto length truncated", b"\x06\x00")
    frame("close reason exactly fills the packet", b"\x1c\x00\x00\x03abc")
    frame("close reason one past the packet", b"\x1c\x00\x00\x04abc")
    frame("application close reason fills the packet", b"\x1d\x00\x02ab")
    frame("frame type 4 not permitted", b"\x04")
    return out


# -- HTTP/1 (text route) -----------------------------------------------------------------------------------------

def http_cases():
    out = []

    def text(name, data, max_line=8192, max_headers=64):
        def call():
            parser = TextParser(Config(max_line=max_line, max_headers=max_headers, max_bytes=65536))
            consumed = parser.feed(data)
            shift = "-" if parser.shift is None else "{}>{}".format(parser.shift[0], parser.shift[1] or "-")
            return "consumed={} done={} family={} name={} host={} shift={} | {} | {}".format(
                consumed, str(bool(parser.done)).lower(), parser.family, parser.protocol_name or "-",
                "-" if parser.host is None else parser.host, shift, parser.reason, rows_of(parser.extra_evidence))
        # The Go case struct has one limit column: text cases pack it as max_line * 1000 + max_headers.
        out.append(("text", name, data, max_line * 1000 + max_headers, outcome(call)))

    def request(*headers, start=b"GET / HTTP/1.1", host=b"Host: example.com"):
        lines = [start] + ([host] if host is not None else []) + list(headers)
        return b"".join(line + b"\r\n" for line in lines) + b"\r\n"

    text("get with host", request())
    text("start-line only", b"GET / HTTP/1.1\r\n")
    text("partial line", b"GET / HTTP/1.1")
    text("line exactly at the budget", b"GET /" + b"a" * 9 + b" HTTP/1.1\r\n", max_line=25)
    text("line one past the budget", b"GET /" + b"a" * 10 + b" HTTP/1.1\r\n", max_line=25)
    text("unterminated line past the budget", b"GET /" + b"a" * 40, max_line=25)
    text("bare LF", b"GET / HTTP/1.1\n")
    text("http/1.0 without host", request(start=b"GET / HTTP/1.0", host=None))
    text("http/1.1 without host", request(host=None))
    text("duplicate host", request(b"Host: example.com"))
    text("empty host", request(host=b"Host:"))
    text("host with port 65535", request(host=b"Host: example.com:65535"))
    text("host with port 65536", request(host=b"Host: example.com:65536"))
    text("host with port 0", request(host=b"Host: example.com:0"))
    text("host with six-digit port", request(host=b"Host: example.com:000080"))
    text("host with empty port", request(host=b"Host: example.com:"))
    text("host ipv4 literal", request(host=b"Host: 192.0.2.1:8080"))
    text("host ipv6 literal", request(host=b"Host: [2001:db8::1]:443"))
    text("host ipv6 port 65536", request(host=b"Host: [2001:db8::1]:65536"))
    text("host ipv6 bad suffix", request(host=b"Host: [2001:db8::1]x"))
    text("host upper case", request(host=b"Host: WWW.Example.COM"))
    text("headers exactly at the budget", request(*[b"X-%d: v" % i for i in range(3)]), max_headers=4)
    text("headers one past the budget", request(*[b"X-%d: v" % i for i in range(4)]), max_headers=4)
    text("invalid header name", request(b"Bad Name: v"))
    text("header without colon", request(b"NoColon"))
    text("control byte in header", request(b"X-A: a\x01b"))
    text("tab in header", request(b"X-A: a\tb"))
    text("delete byte in header", request(b"X-A: a\x7fb"))
    text("content-length 20 digits", request(b"Content-Length: " + b"1" * 20))
    text("content-length 21 digits", request(b"Content-Length: " + b"1" * 21))
    text("duplicate content-length", request(b"Content-Length: 1", b"Content-Length: 1"))
    text("chunked", request(b"Transfer-Encoding: chunked"))
    text("chunked and content-length", request(b"Transfer-Encoding: chunked", b"Content-Length: 3"))
    text("gzip transfer-encoding", request(b"Transfer-Encoding: gzip"))
    text("content type and accept", request(b"Content-Type: application/json", b"Accept: application/dns-message"))
    text("authorization schemes", request(b"Authorization: Basic abc", b"Proxy-Authorization: Bearer x"))
    text("response 200", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    text("response 599", b"HTTP/1.1 599 Odd\r\n\r\n")
    text("response 600", b"HTTP/1.1 600 Odd\r\n\r\n")
    text("response challenge list", b"HTTP/1.1 401 No\r\nWWW-Authenticate: Basic realm=x, Bearer\r\n\r\n")
    text("unsupported start-line", b"GET / HTTP/2.0\r\n\r\n")
    text("extension method", request(start=b"PURGE / HTTP/1.1"))
    text("connect authority form", request(start=b"CONNECT example.com:443 HTTP/1.1", host=b"Host: example.com:443"))
    text("connect origin form", request(start=b"CONNECT / HTTP/1.1"))
    key, accept = b"Sec-WebSocket-Key: " + b"A" * 22 + b"==", b"Sec-WebSocket-Accept: " + b"A" * 27 + b"="
    text("websocket upgrade", request(b"Upgrade: websocket", b"Connection: Upgrade", key, b"Sec-WebSocket-Version: 13"))
    text("websocket upgrade without connection", request(b"Upgrade: websocket", key, b"Sec-WebSocket-Version: 13"))
    text("websocket upgrade version 12", request(b"Upgrade: websocket", b"Connection: Upgrade", key, b"Sec-WebSocket-Version: 12"))
    text("websocket upgrade on post", request(b"Upgrade: websocket", b"Connection: keep-alive, Upgrade", key,
                                              b"Sec-WebSocket-Version: 13", start=b"POST / HTTP/1.1"))
    text("websocket nonce one short", request(b"Sec-WebSocket-Key: " + b"A" * 21 + b"=="))
    text("upgrade with a body", request(b"Upgrade: websocket", b"Connection: Upgrade", b"Content-Length: 4"))
    text("h2c upgrade", request(b"Upgrade: h2c", b"Connection: Upgrade, HTTP2-Settings", b"HTTP2-Settings: AAMAAABkAAQAAP__"))
    text("h2c upgrade without settings", request(b"Upgrade: h2c", b"Connection: Upgrade"))
    text("upgrade other", request(b"Upgrade: foo/1", b"Connection: Upgrade"))
    text("upgrade eight protocols", request(b"Upgrade: " + b", ".join([b"a"] * 8), b"Connection: Upgrade"))
    text("upgrade nine protocols", request(b"Upgrade: " + b", ".join([b"a"] * 9), b"Connection: Upgrade"))
    text("duplicate upgrade", request(b"Upgrade: h2c", b"Upgrade: h2c"))
    text("101 websocket", b"HTTP/1.1 101 Switching\r\nUpgrade: websocket\r\n" + accept + b"\r\n\r\n")
    text("101 websocket without accept", b"HTTP/1.1 101 Switching\r\nUpgrade: websocket\r\n\r\n")
    text("101 h2c", b"HTTP/1.1 101 Switching\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n")
    text("101 h2c without connection", b"HTTP/1.1 101 Switching\r\nUpgrade: h2c\r\n\r\n")
    text("ssh banner", b"SSH-2.0-OpenSSH_9.6\r\n")
    text("ssh banner 1.99", b"SSH-1.99-x\r\n")
    text("ssh banner 1.5", b"SSH-1.5-x\r\n")
    text("smtp ehlo", b"EHLO mail.example.com\r\n")
    text("smtp ehlo address literal", b"EHLO [192.0.2.1]\r\n")
    text("smtp helo without domain", b"HELO\r\n")
    text("ehlo as an http method", b"EHLO / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    text("leading bare LF", b"\nGET / HTTP/1.1\r\n")
    text("content type parameters only", request(b"Content-Type: ;charset=utf-8"))
    text("content type with parameters", request(b"Content-Type: text/html; charset=utf-8"))
    text("accept list led by a comma", request(b"Accept: ,application/dns-message"))
    text("accept dns after another type", request(b"Accept: application/dns-message, */*"))
    text("authorization led by a comma", request(b"Authorization: ,Basic"))
    text("authorization scheme then comma", request(b"Authorization: Negotiate,x"))
    text("repeated authorization scheme", request(b"Authorization: Basic a", b"Proxy-Authorization: Basic b"))
    for challenge in (b"realm=x", b"Basic realm=x, Digest nonce=1", b"Negotiate", b"=x", b", ,Bearer", b"Basic, NTLM"):
        text("challenge " + challenge.decode(), b"HTTP/1.1 401 No\r\nWWW-Authenticate: " + challenge + b"\r\n\r\n")
    text("ssh banner 253 bytes", b"SSH-2.0-" + b"a" * 245 + b"\r\n")
    text("ssh banner 254 bytes", b"SSH-2.0-" + b"a" * 246 + b"\r\n")
    # No valid identity is this long: at 510 bytes the identity check answers, at 511 the length limit does.
    text("smtp ehlo 510 bytes", b"EHLO " + b"a" * 505 + b"\r\n")
    text("smtp ehlo 511 bytes", b"EHLO " + b"a" * 506 + b"\r\n")
    text("smtp ehlo then starttls", b"EHLO mail.example.com\r\nSTARTTLS\r\n")
    text("smtp ehlo ipv6 literal", b"EHLO [IPv6:2001:db8::1]\r\n")
    text("smtp ehlo bad literal", b"EHLO [192.0.2.300]\r\n")
    info = b'INFO {"server_id":"x","version":"2.10.0","go":"go1.22","host":"0.0.0.0","port":%d,"max_payload":1048576}\r\n'
    text("nats info port 65535", info % 65535)
    text("nats info port 65536", info % 65536)
    text("nats info port 0", info % 0)
    text("nats connect", b'CONNECT {"verbose":false,"pedantic":false,"tls_required":false,"lang":"go","version":"1.0"}\r\n')
    text("nats info not json", b"INFO {x\r\n")
    text("imap capability", b"* OK [CAPABILITY IMAP4rev1 STARTTLS] ready\r\n")
    text("imap untagged without capability", b"* OK ready\r\n")
    text("ftp or smtp 220 greeting", b"220 mail.example.com ESMTP\r\n")
    text("pop3 ok", b"+OK POP3 ready\r\n")
    text("pop3 err", b"-ERR no\r\n")
    text("imap tagged starttls", b"a1 STARTTLS\r\n")
    text("imap tagged capability", b"a1 CAPABILITY\r\n")
    text("irc nick", b"NICK guest\r\n")
    text("irc server notice", b"NOTICE * :*** Looking up your hostname\r\n")
    text("rtsp options", b"OPTIONS rtsp://192.0.2.1/x RTSP/1.0\r\nCSeq: 1\r\n\r\n")
    text("sip options", b"OPTIONS sip:a@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1\r\n\r\n")
    text("unknown text", b"hello there\r\n")
    return out


# -- Go test files -----------------------------------------------------------------------------------------------

QUIC_DISPATCH = """		switch c.fn {
		case "probe":
			got = fmt.Sprintf("ok %t", Probe(data))
		case "varint":
			if value, pos, err := varint(data, 0, len(data)); err != nil {
				got = errOutcome(err)
			} else {
				got = fmt.Sprintf("ok %d@%d", value, pos)
			}
		case "frames":
			if fragments, err := frames(data, c.maxHeaders); err != nil {
				got = errOutcome(err)
			} else {
				parts := make([]string, 0, len(fragments))
				for _, f := range fragments {
					parts = append(parts, fmt.Sprintf("%d+%d", f.Offset, len(f.Data)))
				}
				got = "ok " + strings.Join(parts, ";")
			}
		case "validate":
			opts := Options{MaxHeaders: c.maxHeaders, MaxBytes: 65536, Decrypt: true}
			if m, err := Validate(data, opts, nil, "", nil); err != nil {
				got = errOutcome(err)
			} else {
				rows := make([]string, 0, len(m.Evidence))
				for _, r := range m.Evidence {
					rows = append(rows, r.Field+"="+r.Value)
				}
				got = fmt.Sprintf("ok %s [%s] retracts=%t", m.Reason, strings.Join(rows, ","), m.Retracts)
			}
		}"""

TLS_DISPATCH = """		switch c.fn {
		case "hello", "hello-collect":
			if f, err := parseHello(data, c.fn == "hello-collect"); err != nil {
				got = errOutcome(err)
			} else {
				host := "-"
				if f.hasHost {
					host = f.hostname
				}
				got = fmt.Sprintf("ok host=%s alpn=%s", host, strings.Join(f.alpn, ","))
			}
		case "server":
			if rows, scope, reason, err := parseServerHello(data, Options{MaxHeaders: c.maxHeaders}, 1<<3, 0); err != nil {
				got = errOutcome(err)
			} else {
				parts := make([]string, 0, len(rows))
				for _, r := range rows {
					parts = append(parts, r.Field+"="+r.Value)
				}
				got = fmt.Sprintf("ok %s | %s | %s", scope, reason, strings.Join(parts, ","))
			}
		}"""

HTTP_DISPATCH = """		switch c.fn {
		case "text": // maxHeaders packs MaxLine*1000 + MaxHeaders
			p, err := New(Options{MaxLine: c.maxHeaders / 1000, MaxHeaders: c.maxHeaders % 1000, MaxBytes: 65536})
			if err != nil {
				t.Fatal(err)
			}
			if consumed, err := p.Feed(data); err != nil {
				got = errOutcome(err)
			} else {
				r := p.Result()
				name, host, shift := r.ProtocolName, "-", "-"
				if p.mode != "http" && p.mode != "" {
					name = p.protocolName2
				}
				if name == "" {
					name = "-"
				}
				if r.HasHost {
					host = r.Host
				}
				if r.Shift != nil {
					expected := r.Shift.Expected
					if expected == "" {
						expected = "-"
					}
					shift = r.Shift.Boundary + ">" + expected
				}
				rows := make([]string, 0, len(r.Extra))
				for _, row := range r.Extra {
					rows = append(rows, row.Field+"="+row.Value)
				}
				got = fmt.Sprintf("ok consumed=%d done=%t family=%s name=%s host=%s shift=%s | %s | %s", consumed, p.Done(),
					p.ResolvedFamily(), name, host, shift, r.Reason, strings.Join(rows, ","))
			}
		}"""

PACKAGES = (("quicx", "go/internal/protocols/quicx/boundary_test.go", quic_cases, QUIC_DISPATCH),
            ("tlsx", "go/internal/protocols/tlsx/boundary_test.go", tls_cases, TLS_DISPATCH),
            ("textroute", "go/internal/protocols/textroute/boundary_test.go", http_cases, HTTP_DISPATCH))


def go_string(text):
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render(package, cases, dispatch):
    lines = ["// Code generated by migration/mutation/boundaries.py from the Python reference. DO NOT EDIT.",
             "// Regenerate with `python3 -B migration/mutation/boundaries.py`.", "",
             "package " + package, "",
             'import (\n\t"encoding/hex"\n\t"fmt"\n\t"strings"\n\t"testing"\n\n\t"github.com/leenadav/protocol-detector/go/internal/parsing"\n)', "",
             "// boundaryCases sit exactly on, or one past, each limit the first gremlins run found untested (PRO-126); want",
             "// is the Python reference's outcome for the same bytes.",
             "var boundaryCases = []struct {\n\tfn, name, hex string\n\tmaxHeaders     int\n\twant           string\n}{"]
    for fn, name, data, max_headers, want in cases():
        lines.append("\t{{{}, {}, {}, {}, {}}},".format(go_string(fn), go_string(name), go_string(data.hex()), max_headers, go_string(want)))
    lines += ["}", "", """func errOutcome(err error) string {
	if e, ok := err.(*parsing.Error); ok {
		return e.Kind + ": " + e.Message
	}
	return "error: " + err.Error()
}

// TestBoundariesMatchTheReference: every case gives the reference's outcome (error kind and message, or the result).
func TestBoundariesMatchTheReference(t *testing.T) {
	for _, c := range boundaryCases {
		data, err := hex.DecodeString(c.hex)
		if err != nil {
			t.Fatal(err)
		}
		var got string
""" + dispatch + """
		if got != c.want {
			t.Errorf("%s %q:\\n  got  %s\\n  want %s", c.fn, c.name, got, c.want)
		}
	}
}
"""]
    return subprocess.run(["gofmt"], input="\n".join(lines), capture_output=True, text=True, check=True).stdout  # noqa: S603,S607


def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def check_lock():
    """The files against the lock: (problems, files checked). Imports nothing of the reference."""
    try:
        lock = json.loads(LOCK.read_text(encoding="utf-8"))["files"]
    except (OSError, ValueError, KeyError) as error:
        return ["{}: {}".format(LOCK.relative_to(ROOT), error)], 0
    problems = []
    expected = {relative for _, relative, _, _ in PACKAGES}
    if set(lock) != expected:
        problems.append("the lock names {} but the generated files are {}".format(sorted(lock), sorted(expected)))
    for relative in sorted(expected & set(lock)):
        path = ROOT / relative
        if not path.is_file():
            problems.append("{} is missing".format(relative))
        elif digest(path.read_text(encoding="utf-8")) != lock[relative]["sha256"]:
            problems.append("{} is not the generated file the lock pins (hand-edited?): regenerate it".format(relative))
    return problems, len(expected & set(lock))


def self_test():
    assert digest("a") == hashlib.sha256(b"a").hexdigest()
    problems, checked = check_lock()
    assert checked == len(PACKAGES), "every generated file is pinned"
    print("boundaries self-test: ok ({} pinned files)".format(checked))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="compare the files with the lock (no reference needed)")
    parser.add_argument("--check-reference", action="store_true", help="re-render the files from the reference and compare")
    args = parser.parse_args(argv)
    if args.check:
        problems, checked = check_lock()
        for problem in problems:
            print("boundaries: " + problem)
        print("boundaries: " + ("ok ({} generated files match {})".format(checked, LOCK.relative_to(ROOT)) if not problems else "STALE"))
        return 1 if problems else 0
    load_reference()
    stale, lock = [], {}
    for package, relative, cases, dispatch in PACKAGES:
        path, text = ROOT / relative, render(package, cases, dispatch)
        lock[relative] = {"sha256": digest(text), "cases": len(cases())}
        if args.check_reference:
            if not path.is_file() or path.read_text(encoding="utf-8") != text:
                stale.append(relative)
        else:
            path.write_text(text, encoding="utf-8")
            print("boundaries: wrote {} cases to {}".format(len(cases()), relative))
    if args.check_reference:
        problems, _ = check_lock()
        print("boundaries: " + ("ok" if not stale and not problems else "STALE, regenerate: " + ", ".join(stale + problems)))
        return 1 if stale or problems else 0
    LOCK.write_text(json.dumps({"comment": "SHA-256 of each file migration/mutation/boundaries.py generates (PRO-401)",
                                "files": lock}, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print("boundaries: wrote {}".format(LOCK.relative_to(ROOT)))
    return 0

if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        sys.exit(self_test())
    sys.exit(main())
