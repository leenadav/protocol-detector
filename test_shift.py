"""v0.28: application shift at structural boundaries.

A message that announces a protocol change (HTTP CONNECT, Upgrade, STARTTLS,
PostgreSQL/MySQL SSLRequest, RDP security negotiation) ends the carrier's
inspection exactly at the boundary. Bytes after it are inspected by a fresh
inner phase sharing the remaining budget. The carrier identification is
published first and never removed: a shifted phase that identifies replaces
the observation with a "shifted" event carrying shift/shift_from evidence; one
that fails leaves the carrier identified with shifted_payload context.
"""
import contextlib
import io
import json
import random
import tempfile
import unittest
from pathlib import Path

from protocol_engine import Config, Inspector
from protocol_engine.appid import classify, session_verdict, verdict_fields
from protocol_fixtures import (CONNECT_REQUEST, CONNECT_RESPONSE, FTP_AUTH_TLS, H2C_UPGRADE, IMAP_STARTTLS, MYSQL, MYSQL_SSL_REQUEST,
                               POP3_STLS, POSTGRESQL_SSL, RDP, RDP_CONFIRM, SMTP_STARTTLS, WEBSOCKET_101, WEBSOCKET_ACCEPT, WEBSOCKET_FRAME,
                               WEBSOCKET_KEY, WEBSOCKET_SERVER_FRAME, WEBSOCKET_UPGRADE)
from proxy_demo import client_hello
from test_services import rdp

HELLO = client_hello()
H2_PREFACE_SETTINGS = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"


def run(data, hint=None, **kwargs):
    inspector = Inspector(protocol_hint=hint, **kwargs)
    events = inspector.feed(data)
    return inspector, events


def fields(observation, *names):
    return {e.field: e.value for e in observation.evidence if e.field in names}


SHIFTS = (
    # data, hint, carrier protocol/encryption, boundary, inner protocol, inner encryption
    (CONNECT_REQUEST + HELLO, None, "http/1.1", "http-connect", None, "tls"),
    (WEBSOCKET_UPGRADE + WEBSOCKET_FRAME, None, "http/1.1", "websocket-upgrade", "websocket", None),
    (WEBSOCKET_101 + WEBSOCKET_SERVER_FRAME, None, "http/1.1", "websocket-upgrade", "websocket", None),
    (H2C_UPGRADE + H2_PREFACE_SETTINGS, None, "http/1.1", "h2c-upgrade", "http/2", None),
    (SMTP_STARTTLS + HELLO, None, "smtp", "starttls", None, "tls"),
    (IMAP_STARTTLS + HELLO, None, "imap", "starttls", None, "tls"),
    (POP3_STLS + HELLO, None, "pop3", "starttls", None, "tls"),
    (FTP_AUTH_TLS + HELLO, None, "ftp", "auth-tls", None, "tls"),
    (POSTGRESQL_SSL + HELLO, None, "postgresql", "postgresql-sslrequest", None, "tls"),
    (MYSQL_SSL_REQUEST + HELLO, "mysql", "mysql", "mysql-sslrequest", None, "tls"),
    (RDP + HELLO, None, "rdp", "rdp-negotiation", None, "tls"),
    (RDP_CONFIRM + HELLO, None, "rdp", "rdp-negotiation", None, "tls"),
)


class ShiftMechanismTests(unittest.TestCase):
    def test_every_boundary_publishes_carrier_then_shifted_phase(self):
        for data, hint, carrier, boundary, protocol, encryption in SHIFTS:
            inspector, events = run(data, hint)
            self.assertEqual([e.kind for e in events], ["updated", "shifted"], boundary)
            first, final = events[0].observation, events[1].observation
            self.assertEqual((first.status, first.application_protocol), ("identified", carrier), boundary)
            self.assertNotIn("shift", fields(first, "shift"))
            self.assertEqual((final.status, final.application_protocol, final.encryption), ("identified", protocol, encryption), boundary)
            self.assertEqual(fields(final, "shift", "shift_from"), {"shift": boundary, "shift_from": carrier}, boundary)
            self.assertTrue(final.reason.startswith("After " + boundary))
            self.assertLessEqual(inspector.metrics.bytes_inspected, len(data))
            self.assertEqual(inspector.metrics.candidates_selected, 1)
            self.assertTrue(inspector._terminal)
            self.assertEqual(inspector.feed(b"more" * 100), ())

    def test_all_split_points_and_fragments_agree(self):
        rng = random.Random(2028)
        for data, hint, _, boundary, _, _ in SHIFTS:
            whole = run(data, hint)[0]
            for split in range(len(data) + 1):
                inspector = Inspector(protocol_hint=hint)
                kinds = [e.kind for e in inspector.feed(data[:split])] + [e.kind for e in inspector.feed(data[split:])]
                self.assertEqual(inspector.observation, whole.observation, (boundary, split))
                self.assertEqual(kinds, ["updated", "shifted"], (boundary, split))
                self.assertEqual(inspector.metrics.bytes_inspected, whole.metrics.bytes_inspected, (boundary, split))
            for _ in range(60):
                changed = bytearray(data)
                changed[rng.randrange(len(changed))] = rng.randrange(256)
                one, three = Inspector(protocol_hint=hint), Inspector(protocol_hint=hint)
                one.feed(bytes(changed))
                for pos in range(0, len(changed), 3):
                    three.feed(bytes(changed[pos:pos + 3]))
                one.end()
                three.end()
                self.assertEqual(one.observation, three.observation, bytes(changed))
                self.assertIn(one.observation.status, ("identified", "unknown", "malformed", "incomplete", "budget_exhausted"))
                self.assertLessEqual(three.metrics.bytes_inspected, len(changed))

    def test_failed_or_missing_shifted_phase_keeps_the_carrier(self):
        garbage = run(CONNECT_REQUEST + b"\xff" * 40)[0].observation
        self.assertEqual((garbage.status, garbage.application_protocol), ("identified", "http/1.1"))
        self.assertEqual(fields(garbage, "shift", "shifted_payload"), {"shift": "http-connect", "shifted_payload": "unknown"})
        self.assertEqual(classify(garbage, "tcp", 8080).app, "http-proxy")
        pending, events = run(CONNECT_REQUEST)
        self.assertEqual([e.kind for e in events], ["updated"])
        self.assertFalse(pending._terminal)
        ended = pending.end("EOF")
        self.assertEqual([e.kind for e in ended], ["shifted"])
        self.assertEqual(fields(pending.observation, "shifted_payload"), {"shifted_payload": "incomplete"})
        self.assertEqual(pending.observation.status, "identified")
        malformed = run(SMTP_STARTTLS + b"\x16\x03\x01\x00\x05abcde")[0].observation
        self.assertEqual((malformed.status, malformed.application_protocol), ("identified", "smtp"))
        self.assertEqual(fields(malformed, "shifted_payload")["shifted_payload"], "malformed")
        # A hint-restricted shifted phase (TLS expected) does not accept another protocol.
        http_after = run(POSTGRESQL_SSL + b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")[0].observation
        self.assertEqual(http_after.application_protocol, "postgresql")
        self.assertIn(fields(http_after, "shifted_payload")["shifted_payload"], ("unknown", "malformed"))

    def test_budgets_cover_both_phases(self):
        inspector = Inspector(Config(max_bytes=len(CONNECT_REQUEST) + 40))
        inspector.feed(CONNECT_REQUEST + HELLO)
        self.assertEqual(inspector.observation.application_protocol, "http/1.1")
        self.assertEqual(fields(inspector.observation, "shifted_payload"), {"shifted_payload": "budget_exhausted"})
        self.assertLessEqual(inspector.metrics.bytes_inspected, len(CONNECT_REQUEST) + 40)
        inspector = Inspector(Config(max_bytes=len(CONNECT_REQUEST) + 200))
        inspector.feed(CONNECT_REQUEST + HELLO)
        self.assertEqual(fields(inspector.observation, "shifted_payload"), {"shifted_payload": "budget_exhausted"})
        self.assertLessEqual(inspector.metrics.bytes_inspected, len(CONNECT_REQUEST) + 200)
        self.assertTrue(inspector._terminal)
        updates = Inspector(Config(max_updates=2))
        updates.feed(CONNECT_REQUEST)
        updates.feed(HELLO[:10])
        self.assertEqual(updates.observation.application_protocol, "http/1.1")
        updates.feed(HELLO[10:20])
        self.assertEqual(updates.observation.status, "budget_exhausted")

    def test_invalidate_and_decrypted_boundaries(self):
        inspector = run(CONNECT_REQUEST + HELLO[:50])[0]
        self.assertFalse(inspector._terminal)
        self.assertEqual(inspector.invalidate("conflict")[0].kind, "invalidated")
        self.assertEqual(inspector.feed(HELLO[50:]), ())
        self.assertEqual(inspector.observation.status, "invalidated")
        shifted = run(CONNECT_REQUEST + HELLO)[0]
        self.assertEqual(shifted.observation.encryption, "tls")
        events = shifted.feed_decrypted(b"GET / HTTP/1.1\r\nHost: inner.example\r\n\r\n")
        self.assertEqual(events[0].kind, "refined")
        self.assertEqual((shifted.observation.encryption, shifted.observation.application_protocol), ("tls", "http/1.1"))


class BoundaryProfileTests(unittest.TestCase):
    def test_connect_requires_authority_form_and_marks_http_proxy(self):
        request = run(CONNECT_REQUEST)[0].observation
        self.assertEqual((request.scope, fields(request, "http_method")), ("tunnel_request", {"http_method": "CONNECT"}))
        self.assertEqual(classify(request, "tcp", 3128).app, "http-proxy")
        self.assertEqual(classify(request, "tcp", 3128).port_usage, "standard")
        plain = run(b"CONNECT / HTTP/1.1\r\nHost: a\r\n\r\n" + HELLO)[0].observation
        self.assertEqual((plain.application_protocol, fields(plain, "shift")), ("http/1.1", {}))
        self.assertEqual(classify(plain, "tcp", 80).app, "web-browsing")
        ipv6 = run(b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n" + HELLO)[0].observation
        self.assertEqual(ipv6.encryption, "tls")

    def test_websocket_upgrade_rules_and_frame_profile(self):
        for data in (WEBSOCKET_UPGRADE.replace(b"Connection: Upgrade\r\n", b""), WEBSOCKET_UPGRADE.replace(b"GET", b"POST"),
                     WEBSOCKET_UPGRADE.replace(b"Sec-WebSocket-Version: 13", b"Sec-WebSocket-Version: 8"),
                     WEBSOCKET_UPGRADE.replace(b"Sec-WebSocket-Key: " + WEBSOCKET_KEY + b"\r\n", b""),
                     WEBSOCKET_101.replace(b"Sec-WebSocket-Accept: " + WEBSOCKET_ACCEPT + b"\r\n", b"")):
            self.assertEqual(run(data)[0].observation.status, "malformed", data)
        with_body = run(WEBSOCKET_UPGRADE.replace(b"\r\n\r\n", b"\r\nContent-Length: 2\r\n\r\n") + b"ab" + WEBSOCKET_FRAME)[0].observation
        self.assertEqual((with_body.application_protocol, fields(with_body, "shift")), ("http/1.1", {}))
        other = run(b"GET / HTTP/1.1\r\nHost: a\r\nUpgrade: tls/1.2\r\nConnection: Upgrade\r\n\r\n")[0].observation
        self.assertEqual((other.application_protocol, fields(other, "http_upgrade", "shift")), ("http/1.1", {"http_upgrade": "other"}))
        self.assertEqual(run(WEBSOCKET_FRAME, "websocket")[0].observation.application_protocol, "websocket")
        self.assertNotEqual(run(WEBSOCKET_FRAME)[0].observation.status, "identified")  # never selected from a bare prefix
        long16 = b"\x82\xfe\x01\x00" + bytes(4)
        long64 = b"\x82\xff" + (70000).to_bytes(8, "big") + bytes(4)
        for data in (long16, long64, b"\x88\x80" + bytes(4), b"\x8a\x00"):
            self.assertEqual(run(data, "websocket")[0].observation.application_protocol, "websocket", data)
        for data in (b"\x80\x85" + bytes(4), b"\x83\x85" + bytes(4), b"\xc1\x85" + bytes(4), b"\x82\xfe\x00\x7d" + bytes(4),
                     b"\x82\xff" + (65535).to_bytes(8, "big") + bytes(4), b"\x82\xff" + (1 << 63).to_bytes(8, "big") + bytes(4),
                     b"\x08\x80" + bytes(4), b"\x88\xfe\x01\x00" + bytes(4)):
            self.assertNotEqual(run(data, "websocket")[0].observation.status, "identified", data)
        self.assertEqual(run(WEBSOCKET_FRAME[:5], "websocket")[0].observation.status, "detecting")
        verdict = classify(run(WEBSOCKET_UPGRADE + WEBSOCKET_FRAME)[0].observation, "tcp", 80)
        self.assertEqual((verdict.app, verdict.shifted_from, verdict.port_usage), ("websocket", "web-browsing", "standard"))
        self.assertIn("web-browsing", verdict.implicitly_uses)
        h2c_response = run(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n" + bytes(9))[0].observation
        self.assertEqual((h2c_response.application_protocol, fields(h2c_response, "shift", "http_upgrade")), ("http/1.1", {"http_upgrade": "h2c"}))

    def test_smtp_watches_for_starttls_within_bounds(self):
        mail = run(b"EHLO client.example\r\nMAIL FROM:<a@b>\r\n" + HELLO)[0]
        self.assertEqual((mail.observation.application_protocol, fields(mail.observation, "shift")), ("smtp", {}))
        self.assertTrue(mail._terminal)
        noops = run(b"EHLO client.example\r\n" + b"NOOP\r\n" * 20 + b"STARTTLS\r\n" + HELLO)[0].observation
        self.assertEqual((noops.application_protocol, fields(noops, "shift")), ("smtp", {}))
        few = run(b"EHLO client.example\r\n" + b"NOOP\r\n" * 3 + b"STARTTLS\r\n" + HELLO)[0].observation
        self.assertEqual(few.encryption, "tls")
        self.assertEqual(run(b"EHLO client.example\r\nSTARTTLS now\r\n" + HELLO)[0].observation.application_protocol, "smtp")
        self.assertEqual(run(b"EHLO client.example\r\n\x00\x01\x02\r\n")[0].observation.status, "identified")
        self.assertEqual(run(b"EHLO client.example\r\n")[0].end(), ())
        for data, carrier in ((b"a1 starttls\r\n" + HELLO, "imap"), (b"stls\r\n" + HELLO, "pop3"), (b"AUTH SSL\r\n" + HELLO, "ftp"), (b"auth tls-c\r\n" + HELLO, "ftp")):
            final = run(data)[0].observation
            self.assertEqual((final.encryption, fields(final, "shift_from")["shift_from"]), ("tls", carrier), data)
        self.assertEqual(run(b"AUTH PLAIN\r\n")[0].observation.status, "unknown")  # still FTP/POP3 ambiguous
        self.assertEqual(run(b"a1 STARTTLS x\r\n")[0].observation.status, "malformed")

    def test_database_and_rdp_negotiations(self):
        gss = run(POSTGRESQL_SSL[:4] + (80877104).to_bytes(4, "big") + HELLO)[0].observation
        self.assertEqual((gss.application_protocol, fields(gss, "shift")), ("postgresql", {}))
        self.assertEqual(run(MYSQL, "mysql")[0].observation.application_protocol, "mysql")
        bad_caps = MYSQL_SSL_REQUEST[:4] + (0x00000205).to_bytes(4, "little") + MYSQL_SSL_REQUEST[8:]
        self.assertEqual(run(bad_caps, "mysql")[0].observation.status, "malformed")
        self.assertEqual(run(MYSQL_SSL_REQUEST[:12] + b"\x00" + MYSQL_SSL_REQUEST[13:], "mysql")[0].observation.status, "malformed")
        self.assertEqual(run(MYSQL_SSL_REQUEST[:20] + b"\x01" + MYSQL_SSL_REQUEST[21:], "mysql")[0].observation.status, "malformed")
        mariadb = run(MYSQL_SSL_REQUEST[:32] + b"\x08\x00\x00\x00" + HELLO, "mysql")[0].observation
        self.assertEqual(mariadb.encryption, "tls")
        self.assertEqual(run(MYSQL_SSL_REQUEST)[0].observation.status, "unknown")  # mysql stays hint-only
        standard = run(rdp(security=0) + HELLO)[0].observation
        self.assertEqual((standard.application_protocol, fields(standard, "shift")), ("rdp", {}))
        confirm_rdp = run(RDP_CONFIRM[:15] + bytes(4))[0].observation
        self.assertEqual((confirm_rdp.application_protocol, confirm_rdp.scope, fields(confirm_rdp, "shift")), ("rdp", "negotiation_response", {}))
        failure = run(RDP_CONFIRM[:11] + b"\x03\x00\x08\x00\x02\x00\x00\x00")[0].observation
        self.assertEqual((failure.application_protocol, fields(failure, "rdp_negotiation")), ("rdp", {"rdp_negotiation": "failure"}))
        for data in (RDP_CONFIRM[:15] + b"\x03\x00\x00\x00", RDP_CONFIRM[:11] + b"\x03\x00\x08\x00\x09\x00\x00\x00",
                     RDP_CONFIRM[:6] + b"\x00\x00" + RDP_CONFIRM[8:], RDP_CONFIRM[:12] + b"\x20" + RDP_CONFIRM[13:]):
            self.assertEqual(run(data)[0].observation.status, "malformed", data)
        self.assertEqual(run(RDP_CONFIRM[:11])[0].observation.status, "detecting")
        self.assertEqual(run(b"\x03\x00\x00\x0b\x06\xd0\x12\x34\x00\x00\x00")[0].observation.status, "unknown")


class VerdictTests(unittest.TestCase):
    def test_session_verdicts_name_the_shifted_application(self):
        client = run(CONNECT_REQUEST + HELLO)[0].observation
        server = run(CONNECT_RESPONSE)[0].observation
        verdict = session_verdict(client, server, "tcp", 8080, 700, 40, True, None)
        self.assertEqual((verdict.app, verdict.shifted_from, verdict.client_protocol, verdict.server_protocol, verdict.encryption),
                         ("ssl", "http-proxy", "tls", "http/1.1", "tls"))
        self.assertIn("http-proxy", verdict.implicitly_uses)
        self.assertEqual(verdict_fields(verdict)["shifted_from"], "http-proxy")
        smtp = session_verdict(run(SMTP_STARTTLS + HELLO)[0].observation, None, "tcp", 587, 600, 0, True, None)
        self.assertEqual((smtp.app, smtp.shifted_from, smtp.port_usage), ("ssl", "smtp", "standard"))  # carrier's standard port
        rdp_both = session_verdict(run(RDP + HELLO)[0].observation, run(RDP_CONFIRM + HELLO)[0].observation, "tcp", 3389, 600, 600, True, None)
        self.assertEqual((rdp_both.app, rdp_both.shifted_from, rdp_both.port_usage), ("ssl", "rdp", "standard"))
        self.assertEqual(session_verdict(run(SMTP_STARTTLS + HELLO)[0].observation, None, "tcp", 8443, 600, 0, True, None).port_usage, "nonstandard")
        websocket = session_verdict(run(WEBSOCKET_UPGRADE + WEBSOCKET_FRAME)[0].observation, run(WEBSOCKET_101 + WEBSOCKET_SERVER_FRAME)[0].observation,
                                    "tcp", 80, 200, 150, True, None)
        self.assertEqual((websocket.app, websocket.shifted_from), ("websocket", "web-browsing"))
        no_shift = session_verdict(run(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")[0].observation, None, "tcp", 80, 30, 0, True, None)
        self.assertIsNone(no_shift.shifted_from)
        self.assertIsNone(verdict_fields(no_shift)["shifted_from"])


class PipelineTests(unittest.TestCase):
    def test_offline_analysis_emits_shifted_events_and_session_records(self):
        from analyze_pcap import analyze
        from make_sample_pcap import A, B, frame, pcap_bytes
        request_end, response_end = 1000 + len(CONNECT_REQUEST), 9000 + len(CONNECT_RESPONSE)
        frames = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18), frame(A, B, 1000, 9000, 24, CONNECT_REQUEST),
                  frame(B, A, 9000, request_end, 24, CONNECT_RESPONSE), frame(A, B, request_end, response_end, 24, HELLO)]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "connect.pcap"
            path.write_bytes(pcap_bytes(frames))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                analyze(path, json_output=True, events_only=True, sessions=True)
        rows = [json.loads(line) for line in output.getvalue().splitlines()]
        kinds = [row["events"][0]["kind"] for row in rows if "classification" in row]
        self.assertEqual(kinds, ["updated", "updated", "shifted"])
        shifted = [row["classification"] for row in rows if "classification" in row][-1]
        self.assertEqual((shifted["status"], shifted["encryption"]), ("identified", "tls"))
        self.assertEqual({e["field"]: e["value"] for e in shifted["evidence"] if e["field"] in ("shift", "shift_from")},
                         {"shift": "http-connect", "shift_from": "http/1.1"})
        session = [row for row in rows if row.get("type") == "session"][0]
        self.assertEqual((session["app"], session["shifted_from"], session["implicitly_uses"], session["port_usage"], session["server_protocol"]),
                         ("ssl", "http-proxy", ["http-proxy"], "standard", "http/1.1"))
        self.assertNotIn("hostname", session)  # session records carry no hostname unless --hostnames


if __name__ == "__main__":
    unittest.main()
