"""v0.61: database transport protection (TDS session encryption, MySQL TLS and cleartext plugin, PostgreSQL startup)."""
import unittest

from protocol_engine import Config, Inspector
from protocol_engine.appid import classify, session_verdict
from protocol_engine.risks import RISKS
from protocol_fixtures import (MYSQL, MYSQL_HANDSHAKE_RESPONSE, MYSQL_SSL_REQUEST, POSTGRESQL, POSTGRESQL_SSL, SNI_PUBLIC, TDS_PRELOGIN,
                               TDS_PRELOGIN_RESPONSE, client_hello_with, mysql_handshake_response, tds_prelogin)

DB_RISKS = ("database-encryption-unavailable", "database-session-unencrypted", "cleartext-credential-protocol")


def observe(data, hint=None):
    inspector = Inspector(Config(), protocol_hint=hint)
    inspector.feed(data)
    return inspector.observation


def field(observation, name):
    return [e.value for e in observation.evidence if e.field == name]


def db_risks(observation, port):
    return tuple(name for name in classify(observation, "tcp", port).risks if name in DB_RISKS)


def tds_response(encryption):
    return tds_prelogin(((0x00, bytes.fromhex("100007d00000")), (0x01, bytes([encryption]))), kind=0x04)


def mysql_greeting(tls):
    # Flip CLIENT_SSL (0x0800) in the lower capability word of the MYSQL fixture greeting.
    data = bytearray(MYSQL)
    pos = data.index(b"\0", 5) + 1 + 13
    flags = int.from_bytes(data[pos:pos + 2], "little")
    data[pos:pos + 2] = ((flags | 0x800) if tls else (flags & ~0x800)).to_bytes(2, "little")
    return bytes(data)


class DatabaseTransportTests(unittest.TestCase):
    def test_tds_session_encryption_follows_the_response(self):
        # MS-TDS 2.2.6.5: the response value is the server's resolution of both offers.
        for value, label, risks in ((0, "login-only", ("database-session-unencrypted",)), (1, "full", ()),
                                    (2, "none", ("database-encryption-unavailable", "database-session-unencrypted")), (3, "full", ())):
            observation = observe(tds_response(value))
            self.assertEqual((observation.status, field(observation, "tds_session_encryption")), ("identified", [label]), value)
            self.assertEqual(db_risks(observation, 1433), risks, value)
        self.assertEqual(field(observe(TDS_PRELOGIN_RESPONSE), "tds_session_encryption"), ["full"])
        for value in (0, 1, 2, 3):                                     # a client's offer decides nothing
            request = observe(tds_prelogin(((0x00, bytes(6)), (0x01, bytes([value])))))
            self.assertEqual((field(request, "tds_session_encryption"), db_risks(request, 1433)), ([], ()), value)
        verdict = session_verdict(observe(TDS_PRELOGIN), observe(tds_response(0)), "tcp", 1433, 94, 49, True, None)
        self.assertEqual(verdict.risks, ("database-session-unencrypted",))

    def test_mysql_greeting_and_handshake_response(self):
        self.assertEqual(db_risks(observe(mysql_greeting(True), "mysql"), 3306), ())
        self.assertEqual(db_risks(observe(mysql_greeting(False), "mysql"), 3306), ("database-encryption-unavailable",))
        self.assertEqual(db_risks(observe(MYSQL_HANDSHAKE_RESPONSE, "mysql"), 3306), ("database-session-unencrypted",))
        self.assertEqual(db_risks(observe(mysql_handshake_response(plugin=b"mysql_clear_password"), "mysql"), 3306),
                         ("cleartext-credential-protocol", "database-session-unencrypted"))
        ssl_request = observe(MYSQL_SSL_REQUEST, "mysql")
        self.assertEqual((field(ssl_request, "mysql_client_ssl"), db_risks(ssl_request, 3306)), (["requested"], ()))

    def test_postgresql_startup_in_the_clear(self):
        startup = observe(POSTGRESQL)
        self.assertEqual((startup.status, field(startup, "postgresql_message")), ("identified", ["startup"]))
        self.assertIn("database-session-unencrypted", classify(startup, "tcp", 5432).risks)
        request = observe(POSTGRESQL_SSL)
        self.assertEqual((field(request, "postgresql_message"), "database-session-unencrypted" in classify(request, "tcp", 5432).risks), ([], False))
        for name in DB_RISKS:
            self.assertIn(name, RISKS)

    def test_decrypted_bytes_are_not_seen_in_the_clear(self):
        # Self-review of v0.61: a handshake the host decrypted out of TLS was protected on the wire, so the
        # "seen in the clear" rules apply to wire rows only. The capability rows keep their meaning.
        hello = client_hello_with(((0, SNI_PUBLIC), (43, b"\x02\x03\x04")))
        clear = mysql_handshake_response(plugin=b"mysql_clear_password")
        for data, hint, port in ((MYSQL_HANDSHAKE_RESPONSE, "mysql", 3306), (clear, "mysql", 3306), (POSTGRESQL, "postgresql", 5432)):
            inner = Inspector(Config(), source="decrypted", protocol_hint=hint)
            inner.feed(data)
            self.assertNotIn("database-session-unencrypted", classify(inner.observation, "tcp", port).risks, hint)
            outer = Inspector(Config())
            outer.feed(hello)
            outer.feed_decrypted(data)
            self.assertNotIn("database-session-unencrypted", classify(outer.observation, "tcp", port).risks, hint)
        decrypted = Inspector(Config(), source="decrypted", protocol_hint="mysql")
        decrypted.feed(clear)
        self.assertEqual(classify(decrypted.observation, "tcp", 3306).risks, ())    # no cleartext password either
        tds = Inspector(Config(), source="decrypted")
        tds.feed(tds_response(2))
        self.assertIn("database-encryption-unavailable", classify(tds.observation, "tcp", 1433).risks)   # an assertion, not visibility

    def test_split_points(self):
        for data, hint, name in ((tds_response(0), None, "tds_session_encryption"), (POSTGRESQL, None, "postgresql_message")):
            reference = field(observe(data, hint), name)
            for split in range(1, len(data)):
                inspector = Inspector(Config(), protocol_hint=hint)
                inspector.feed(data[:split])
                inspector.feed(data[split:])
                self.assertEqual(field(inspector.observation, name), reference, split)


if __name__ == "__main__":
    unittest.main()
