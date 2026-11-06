"""v0.45: PostgreSQL server messages, LDAP BindResponse, CQL responses and the MySQL HandshakeResponse41."""
import random
import unittest

from protocol_engine import Config, Inspector
from protocol_engine.appid import classify, session_verdict
from protocol_engine.dispatch import select
from protocol_fixtures import (CQL, CQL_AUTHENTICATE, CQL_ERROR, CQL_READY, CQL_SUPPORTED, LDAP, LDAP_BIND_INVALID, LDAP_BIND_RESPONSE, MYSQL,
                               MYSQL_HANDSHAKE_RESPONSE, POSTGRESQL, POSTGRESQL_AUTH_MD5, POSTGRESQL_AUTH_OK, POSTGRESQL_AUTH_SASL,
                               POSTGRESQL_ERROR, POSTGRESQL_NEGOTIATE, _ber, cql_response, cql_string, ldap_bind_response,
                               mysql_handshake_response, pg_server)

LEAKS = ("placeholder", "SCRAM", "libmysql", "80090308", "snappy", "PasswordAuthenticator")


def stream(data, hint=None, config=None):
    inspector = Inspector(config, protocol_hint=hint)
    inspector.feed(data)
    return inspector


def fields(observation, prefix):
    return {e.field: e.value for e in observation.evidence if e.field.startswith(prefix)}


class DatabaseReplyTests(unittest.TestCase):
    def assert_identified(self, data, protocol, scope, hint=None, **expected):
        observation = stream(data, hint).observation
        self.assertEqual((observation.status, observation.application_protocol, observation.scope), ("identified", protocol, scope), observation)
        found = {e.field: e.value for e in observation.evidence}
        for key, value in expected.items():
            self.assertEqual(found.get(key), value, (key, found))
        text = repr(observation)
        for leak in LEAKS:
            self.assertNotIn(leak, text)
        return observation

    def assert_rejected(self, data, hint=None):
        observation = stream(data, hint).observation
        self.assertNotEqual(observation.status, "identified", (data[:16].hex(), observation.reason))

    def test_postgresql_server_messages(self):
        self.assert_identified(POSTGRESQL_AUTH_MD5, "postgresql", "negotiation_response", postgresql_message="authentication", postgresql_auth="md5-password")
        self.assert_identified(POSTGRESQL_AUTH_SASL, "postgresql", "negotiation_response", postgresql_auth="sasl")
        self.assert_identified(POSTGRESQL_AUTH_OK, "postgresql", "negotiation_response", postgresql_auth="ok")
        self.assert_identified(POSTGRESQL_ERROR, "postgresql", "negotiation_response", postgresql_message="error", postgresql_error_class="28")
        self.assert_identified(POSTGRESQL_NEGOTIATE, "postgresql", "negotiation_response", postgresql_message="negotiate-version")
        self.assert_identified(POSTGRESQL, "postgresql", "initial_message")
        for method, label in ((3, "cleartext-password"), (7, "gss"), (9, "sspi")):
            self.assert_identified(pg_server(b"R", method.to_bytes(4, "big")), "postgresql", "negotiation_response", postgresql_auth=label)
        for method in (8, 11, 12):
            self.assert_identified(pg_server(b"R", method.to_bytes(4, "big") + b"opaque"), "postgresql", "negotiation_response")
        self.assert_identified(pg_server(b"v", bytes(8)), "postgresql", "negotiation_response")
        client, server = stream(POSTGRESQL).observation, stream(POSTGRESQL_AUTH_MD5).observation
        verdict = session_verdict(client, server, "tcp", 5432, 36, 13, True, None)
        self.assertEqual((verdict.app, verdict.port_usage, verdict.server_protocol), ("postgresql", "standard", "postgresql"))
        rejected = [
            pg_server(b"R", (4).to_bytes(4, "big")),                                    # crypt() method is obsolete and outside the profile
            pg_server(b"R", (13).to_bytes(4, "big")),                                   # unknown method
            pg_server(b"R", (0).to_bytes(4, "big") + b"x"),                             # ok with data
            pg_server(b"R", (5).to_bytes(4, "big") + b"abc"),                           # three-byte salt
            pg_server(b"R", (10).to_bytes(4, "big") + b"SCRAM-SHA-256\x00"),           # list without the empty terminator
            pg_server(b"R", (10).to_bytes(4, "big") + b"scram\x00\x00"),               # lower-case mechanism
            pg_server(b"R", (8).to_bytes(4, "big")),                                    # continuation without data
            pg_server(b"R", b""),                                                       # no method
            pg_server(b"E", b"SFATAL\x00"),                                             # fields without the empty terminator
            pg_server(b"E", b"SNOTICE\x00C28P01\x00\x00"),                              # severity outside error levels
            pg_server(b"E", b"SFATAL\x00C28P\x00\x00"),                                 # SQLSTATE of four characters
            pg_server(b"E", b"SFATAL\x00SFATAL\x00C28P01\x00\x00"),                     # repeated field
            pg_server(b"E", b"\x00"),                                                   # empty error
            pg_server(b"v", (0).to_bytes(4, "big") + (1).to_bytes(4, "big")),            # option count without options
            pg_server(b"v", (0).to_bytes(4, "big") + (0).to_bytes(4, "big") + b"x\x00"),  # options without count
            b"R\x00\x00\x00\x07\x00\x00\x00",                                           # length below the fixed fields
            b"R\x00\x00\x00\x09\x00\x00\x00\x00\x00",                                   # length beyond the fields with ok
        ]
        for data in rejected:
            self.assert_rejected(data)
            self.assert_rejected(data, hint="postgresql")
        for data in (POSTGRESQL_AUTH_SASL, POSTGRESQL_ERROR):
            whole = stream(data).observation
            for split in range(1, len(data)):
                inspector = Inspector()
                inspector.feed(data[:split])
                inspector.feed(data[split:])
                self.assertEqual(inspector.observation, whole, split)
        for text in (b"EHLO client.example.com\r\n", b"RFB 003.008\n", b"version 1\r\n", b"E\x00\x01\x00"):
            self.assertNotEqual(stream(text).observation.application_protocol, "postgresql", text)
        self.assertEqual(stream(b"EHLO client.example.com\r\n").observation.application_protocol, "smtp")
        self.assertEqual(stream(b"RFB 003.008\n").observation.application_protocol, "rfb")

    def test_ldap_bind_response(self):
        self.assert_identified(LDAP_BIND_RESPONSE, "ldap", "negotiation_response", ldap_result="success")
        self.assert_identified(LDAP_BIND_INVALID, "ldap", "negotiation_response", ldap_result="invalid-credentials")
        self.assert_identified(LDAP, "ldap/3", "initial_message")
        self.assert_identified(ldap_bind_response(14, extra=_ber(0x87, bytes(16))), "ldap", "negotiation_response", ldap_result="sasl-bind-in-progress")
        self.assert_identified(ldap_bind_response(10, extra=_ber(0xa3, _ber(4, b"ldap://placeholder/"))), "ldap", "negotiation_response", ldap_result="other")
        verdict = session_verdict(stream(LDAP).observation, stream(LDAP_BIND_INVALID).observation, "tcp", 389, 14, 44, True, None)
        self.assertEqual((verdict.app, verdict.client_protocol, verdict.server_protocol), ("ldap", "ldap/3", "ldap"))
        rejected = [
            ldap_bind_response(124),                                                    # result code beyond RFC 4511
            _ber(0x30, _ber(2, b"\x01") + _ber(0x61, _ber(2, b"\x00") + _ber(4, b"") + _ber(4, b""))),   # INTEGER instead of ENUMERATED
            _ber(0x30, _ber(2, b"\x01") + _ber(0x61, _ber(0x0a, b"\x00") + _ber(4, b""))),                # diagnostic missing
            ldap_bind_response(0, extra=_ber(0xa3, _ber(4, b""))),                                       # empty referral
            ldap_bind_response(0, extra=_ber(0x87, b"") + _ber(0x87, b"")),                              # two credential fields
            ldap_bind_response(0, extra=b"\x00"),                                                          # trailing byte
            ldap_bind_response(0, diagnostic=b"\xff\xfe"),                                                  # invalid UTF-8
            _ber(0x30, _ber(2, b"\x01") + _ber(0x61, _ber(0x0a, b"\x00") + _ber(4, b"") + _ber(4, b"")) + _ber(0xa0, b"")),   # controls
            ldap_bind_response(0, message_id=b"\x00"),                                                      # message id zero
        ]
        for data in rejected:
            self.assert_rejected(data)
            self.assert_rejected(data, hint="ldap")

    def test_cql_responses(self):
        self.assert_identified(CQL_READY, "cql/4", "negotiation_response", cql_response="ready")
        self.assert_identified(CQL_AUTHENTICATE, "cql/4", "negotiation_response", cql_response="authenticate")
        self.assert_identified(CQL_SUPPORTED, "cql/4", "negotiation_response", cql_response="supported")
        self.assert_identified(CQL_ERROR, "cql/4", "negotiation_response", cql_response="error")
        self.assert_identified(CQL, "cql/4", "protocol_header")
        verdict = session_verdict(stream(CQL).observation, stream(CQL_READY).observation, "tcp", 9042, 31, 9, True, None)
        self.assertEqual((verdict.app, verdict.risks), ("cql", ("cleartext-credential-protocol",)))
        rejected = [
            cql_response(0x01, b""),                                                    # STARTUP is a request opcode
            cql_response(0x02, b"\x00"),                                                # READY with a body
            cql_response(0x00, (1).to_bytes(4, "big")),                                 # ERROR without a message
            cql_response(0x00, (1).to_bytes(4, "big") + cql_string(b"\x01")),           # non-printable message
            cql_response(0x03, cql_string(b"a") + b"\x00"),                             # AUTHENTICATE with a tail
            cql_response(0x06, (0).to_bytes(2, "big")),                                 # empty multimap
            cql_response(0x06, (1).to_bytes(2, "big") + cql_string(b"K") + (1).to_bytes(2, "big")),   # truncated values
            cql_response(0x06, (1).to_bytes(2, "big") + cql_string(b"K") + (65).to_bytes(2, "big") + cql_string(b"v") * 65),  # value budget
            cql_response(0x02, b"", flags=0x10),                                        # reserved flag
            b"\x84" + CQL[1:],                                                          # request opcode under the response version
        ]
        for data in rejected:
            self.assert_rejected(data)
        self.assertEqual(select(CQL_READY[:9]), "cql")
        self.assertEqual(stream(cql_response(0x02, b"", stream=0xffff)).observation.application_protocol, "cql/4")

    def test_mysql_handshake_response(self):
        self.assert_identified(MYSQL_HANDSHAKE_RESPONSE, "mysql", "authentication_request", hint="mysql", mysql_auth_plugin="caching_sha2_password",
                               mysql_client_ssl="not-requested")
        self.assert_identified(MYSQL, "mysql", "protocol_header", hint="mysql")
        for plugin, label in ((b"mysql_native_password", "mysql_native_password"), (b"mysql_clear_password", "cleartext"), (b"other_plugin", "other")):
            self.assert_identified(mysql_handshake_response(plugin=plugin), "mysql", "authentication_request", hint="mysql", mysql_auth_plugin=label)
        self.assert_identified(mysql_handshake_response(capabilities=0x0a20f), "mysql", "authentication_request", hint="mysql", mysql_auth_plugin="none")  # secure connection, no plugin
        self.assert_identified(mysql_handshake_response(capabilities=0x200, auth=b"abcdefgh"), "mysql", "authentication_request", hint="mysql")  # NUL-terminated legacy auth
        self.assert_identified(mysql_handshake_response(capabilities=0x3fa20f | 0x4000000, zstd=3), "mysql", "authentication_request", hint="mysql")
        self.assert_identified(mysql_handshake_response(capabilities=0x0fa20f), "mysql", "authentication_request", hint="mysql")   # no attributes, one-byte auth length
        self.assert_identified(mysql_handshake_response(attrs=((b"k", b"v"),) * 16), "mysql", "authentication_request", hint="mysql")
        verdict = session_verdict(stream(MYSQL_HANDSHAKE_RESPONSE, "mysql").observation, stream(MYSQL, "mysql").observation, "tcp", 3306, 117, 83, True, None)
        self.assertEqual((verdict.app, verdict.port_usage), ("mysql", "standard"))
        self.assertEqual(classify(stream(mysql_handshake_response(plugin=b"mysql_clear_password"), "mysql").observation, "tcp", 3306).risks, ())
        rejected = [
            mysql_handshake_response(capabilities=0x0fa00f),                            # CLIENT_PROTOCOL_41 missing
            mysql_handshake_response(capabilities=0x3faa0f),                            # CLIENT_SSL without an SSLRequest
            mysql_handshake_response(user=b"u" * 129),                                  # user too long
            mysql_handshake_response()[:-1],                                            # truncated plugin terminator
            (len(MYSQL_HANDSHAKE_RESPONSE) - 3).to_bytes(3, "little") + MYSQL_HANDSHAKE_RESPONSE[3:] + b"\x00",   # trailing byte inside the packet length
            mysql_handshake_response(database=b"d" * 65),                               # database too long
            mysql_handshake_response(attrs=((b"k", b"v"),) * 33),                       # attribute budget (16 pairs of two)
            mysql_handshake_response(capabilities=0x3fa20f | 0x800),                    # CLIENT_SSL with attributes
            MYSQL_HANDSHAKE_RESPONSE[:4] + MYSQL_HANDSHAKE_RESPONSE[4:12] + b"\x00" + MYSQL_HANDSHAKE_RESPONSE[13:],   # charset zero
            MYSQL_HANDSHAKE_RESPONSE[:4] + MYSQL_HANDSHAKE_RESPONSE[4:20] + b"\x01" + MYSQL_HANDSHAKE_RESPONSE[21:],   # reserved byte set
        ]
        for data in rejected:
            self.assert_rejected(data, hint="mysql")
        self.assertNotEqual(stream(MYSQL_HANDSHAKE_RESPONSE).observation.application_protocol, "mysql")   # still hint-only
        whole = stream(MYSQL_HANDSHAKE_RESPONSE, "mysql").observation
        for split in range(1, len(MYSQL_HANDSHAKE_RESPONSE), 5):
            inspector = Inspector(protocol_hint="mysql")
            inspector.feed(MYSQL_HANDSHAKE_RESPONSE[:split])
            inspector.feed(MYSQL_HANDSHAKE_RESPONSE[split:])
            self.assertEqual(inspector.observation, whole, split)

    def test_mutations_never_raise_or_leak(self):
        generator = random.Random(45)
        for base, hint in ((POSTGRESQL_AUTH_SASL, None), (POSTGRESQL_ERROR, None), (LDAP_BIND_INVALID, None), (CQL_SUPPORTED, None), (CQL_ERROR, None),
                           (MYSQL_HANDSHAKE_RESPONSE, "mysql")):
            for _ in range(250):
                data = bytearray(base)
                data[generator.randrange(len(data))] = generator.randrange(256)
                inspector = stream(bytes(data), hint, Config(max_bytes=4096))
                self.assertIn(inspector.observation.status, ("identified", "unknown", "malformed", "detecting", "budget_exhausted"))
                text = repr(inspector.observation)
                for leak in LEAKS:
                    self.assertNotIn(leak, text)


if __name__ == "__main__":
    unittest.main()
