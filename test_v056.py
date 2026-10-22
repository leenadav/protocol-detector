"""v0.56: authentication mechanism evidence (SMB session setup, LDAP bind, HTTP Authorization) and the NTLM/basic risks."""
import random
import unittest

from protocol_engine import Config, Inspector
from protocol_engine.appid import classify, session_verdict
from protocol_engine.gss import classify_token
from protocol_engine.media import auth_scheme_class
from protocol_engine.parsers import BudgetError, ParseError
from protocol_fixtures import (HTTP_BASIC_AUTH, HTTP_NTLM_CHALLENGE, LDAP, OID_KRB5, OID_NEGOEX, OID_NTLMSSP, SMB1, SMB1_RESPONSE, SMB1_SESSION_CHALLENGE,
                               SMB1_SESSION_GUEST, SMB1_SESSION_LEGACY, SMB1_SESSION_NTLM, SMB2, SMB2_RESPONSE, SMB2_SESSION_CHALLENGE, SMB2_SESSION_GUEST,
                               SMB2_SESSION_KRB5, SMB2_SESSION_NTLM, SMB2_SESSION_OK, SMB311, SPNEGO_ACCEPT, SPNEGO_KRB5_INIT, SPNEGO_MECHS_ONLY,
                               SPNEGO_NTLM_AUTHENTICATE, SPNEGO_NTLM_CHALLENGE, SPNEGO_NTLM_INIT, H2_PREFACE, H2_SETTINGS, der, hpack_literal, krb5_ap_req,
                               ntlmssp, smb1_session_setup, smb1_session_setup_legacy, smb1_session_setup_response, smb2_session_setup, spnego_init, spnego_resp)


def stream(data, hint=None, **kwargs):
    inspector = Inspector(protocol_hint=hint, **kwargs)
    events = inspector.feed(data)
    events += inspector.end()
    return inspector.observation, [e.kind for e in events]


def fields(observation, *names):
    found = {}
    for e in observation.evidence:
        if e.field in names:
            found.setdefault(e.field, []).append(e.value)
    return {k: (v[0] if len(v) == 1 else v) for k, v in found.items()}


def ldap_bind(auth):
    bind = b"\x02\x01\x03" + b"\x04\x00" + auth
    message = b"\x02\x01\x01" + b"\x60" + bytes((len(bind),)) + bind
    return b"\x30" + bytes((len(message),)) + message


def sasl(mechanism, credentials=None):
    body = b"\x04" + bytes((len(mechanism),)) + mechanism
    if credentials is not None:
        body += b"\x04" + (bytes((len(credentials),)) if len(credentials) < 128 else b"\x82" + len(credentials).to_bytes(2, "big")) + credentials
    return b"\xa3" + (bytes((len(body),)) if len(body) < 128 else b"\x82" + len(body).to_bytes(2, "big")) + body


class TokenClassifierTests(unittest.TestCase):
    def test_known_layouts(self):
        self.assertEqual(classify_token(SPNEGO_NTLM_INIT)[:3], ("spnego-init", "ntlm", "negotiate"))
        self.assertEqual(classify_token(SPNEGO_NTLM_CHALLENGE), ("spnego-response", "ntlm", "challenge", "accept-incomplete"))
        self.assertEqual(classify_token(SPNEGO_NTLM_AUTHENTICATE), ("spnego-response", "ntlm", "authenticate", "accept-incomplete"))
        self.assertEqual(classify_token(SPNEGO_ACCEPT), ("spnego-response", "spnego-other", None, "accept-completed"))
        self.assertEqual(classify_token(SPNEGO_KRB5_INIT)[:3], ("spnego-init", "kerberos", None))
        self.assertEqual(classify_token(SPNEGO_MECHS_ONLY)[:3], ("spnego-init", "kerberos", None))     # preferred (first) mechanism
        self.assertEqual(classify_token(spnego_init(mechs=(OID_NEGOEX, OID_NTLMSSP)))[:2], ("spnego-init", "negoex"))
        self.assertEqual(classify_token(krb5_ap_req())[:2], ("kerberos", "kerberos"))
        self.assertEqual(classify_token(ntlmssp(3, 120))[:3], ("ntlmssp", "ntlm", "authenticate"))
        other = der(0x60, der(0x06, b"\x2b\x06\x01\x05\x05\x0e") + b"\x00")
        self.assertEqual(classify_token(other)[:2], ("gss-other", "other"))
        self.assertEqual(classify_token(spnego_resp(2, None, None)).state, "reject")

    def test_rules_and_bounds(self):
        malformed = (b"", b"\x30\x00", ntlmssp(4), ntlmssp(1)[:11], der(0x60, der(0x06, OID_KRB5) + b"\x09\x00"),
                     der(0x60, der(0x06, b"\x2b\x06\x01\x05\x05\x02") + der(0xa1, b"")),                     # NegTokenResp inside the initial token
                     spnego_init(mechs=()), spnego_resp(5, None, None), spnego_resp(None if False else 1, None, None)[:-1],
                     der(0xa1, der(0x30, b"")),                                                               # empty NegTokenResp
                     spnego_init(token=ntlmssp(1)) + b"\x00",                                               # trailing byte
                     der(0x60, der(0x06, b"\x2b\x06\x01\x05\x05\x02") + der(0xa0, der(0x30, der(0xa2, der(0x04, b"x")) + der(0xa0, der(0x30, der(0x06, OID_KRB5)))))))   # field order
        for blob in malformed:
            with self.assertRaises(ParseError, msg=blob.hex()):
                classify_token(blob)
        with self.assertRaises(BudgetError):
            classify_token(spnego_init(mechs=(OID_KRB5,) * 9))
        with self.assertRaises(BudgetError):
            classify_token(b"\x60" + b"\x82\x10\x00" + bytes(4096))
        self.assertNotIn("alice", repr(classify_token(spnego_init(token=ntlmssp(3, 200)))))

    def test_auth_scheme_class(self):
        self.assertEqual([auth_scheme_class(v) for v in (b"Basic YWxpY2U6czNjcmV0", b"bearer tok", b"Digest realm=x", b"Negotiate", b"NTLM TlRMTVNT", b"Negotiate, NTLM", b"Foo", b"")],
                         ["basic", "bearer", "digest", "negotiate", "ntlm", "negotiate", "other", "empty"])


class SMBSessionSetupTests(unittest.TestCase):
    def test_smb2_mechanisms_after_negotiate(self):
        cases = ((SMB2 + SMB2_SESSION_NTLM, {"smb_message": "session-setup-request", "gss_mechanism": "ntlm", "ntlm_message": "negotiate"}, ("ntlm-authentication",)),
                 (SMB311 + SMB2_SESSION_KRB5, {"smb_message": "session-setup-request", "gss_mechanism": "kerberos"}, ()),
                 (SMB2_RESPONSE + SMB2_SESSION_CHALLENGE, {"smb_message": "session-setup-response", "smb_session": "continuing", "gss_mechanism": "ntlm", "ntlm_message": "challenge"}, ("ntlm-authentication",)),
                 (SMB2_RESPONSE + SMB2_SESSION_GUEST, {"smb_message": "session-setup-response", "smb_session": "guest", "gss_mechanism": "spnego-other"}, ("smb-guest-or-anonymous-session",)),
                 (SMB2_RESPONSE + SMB2_SESSION_OK, {"smb_message": "session-setup-response", "smb_session": "authenticated", "gss_mechanism": "spnego-other"}, ()))
        for data, expected, risks in cases:
            observation, kinds = stream(data)
            self.assertEqual((observation.status, observation.application_protocol, kinds), ("identified", "smb2", ["updated", "refined"]), data[:8].hex())
            self.assertEqual(fields(observation, *expected), expected)
            verdict = classify(observation, "tcp", 445)
            self.assertEqual(verdict.app, "smb")
            for risk in risks:
                self.assertIn(risk, verdict.risks)
            self.assertIn("smb_signing", fields(observation, "smb_signing"))
        alone, kinds = stream(SMB2)
        self.assertEqual((kinds, fields(alone, "smb_signing", "smb_message")), (["updated"], {"smb_signing": "enabled"}))
        self.assertNotIn("ntlm-authentication", classify(alone, "tcp", 445).risks)
        self.assertEqual(fields(stream(SMB311)[0], "smb_signing"), {"smb_signing": "enabled"})

    def test_smb2_session_setup_rules(self):
        # Another command, a compounded frame or a foreign frame after NEGOTIATE ends the watch and keeps the identification.
        other = bytearray(SMB2_SESSION_NTLM)
        other[4 + 12] = 3                                                     # TREE_CONNECT
        for extra in (bytes(other), b"\x00\x00\x00\x40" + b"\xfdSMB" + bytes(60), b"GET / HTTP/1.1\r\n\r\n"):
            observation, kinds = stream(SMB2 + extra)
            self.assertEqual((observation.application_protocol, kinds, fields(observation, "smb_message")), ("smb2", ["updated"], {}), extra[:8].hex())
        malformed = (smb2_session_setup(SPNEGO_NTLM_INIT, security_mode=4), smb2_session_setup(b""), smb2_session_setup(SPNEGO_NTLM_INIT, status=1),
                     smb2_session_setup(SPNEGO_ACCEPT, response=True, flags=8), smb2_session_setup(SPNEGO_ACCEPT, response=True, status=0xC000006D),
                     smb2_session_setup(b"\x30\x00"), SMB2_SESSION_NTLM[:4 + 78] + (len(SPNEGO_NTLM_INIT) + 1).to_bytes(2, "little") + SMB2_SESSION_NTLM[4 + 80:])   # buffer length past the frame
        for extra in malformed:
            observation, kinds = stream(SMB2 + extra)
            self.assertEqual((observation.application_protocol, fields(observation, "gss_mechanism")), ("smb2", {}), extra[:16].hex())
        # Split points and mutations of the two-frame stream stay bounded and never leak the token.
        data = SMB2 + SMB2_SESSION_NTLM
        whole = stream(data)[0]
        for split in range(1, len(data)):
            inspector = Inspector()
            inspector.feed(data[:split])
            inspector.feed(data[split:])
            inspector.end()
            self.assertEqual(inspector.observation, whole, split)
        rng = random.Random(56)
        for _ in range(80):
            changed = bytearray(data)
            changed[rng.randrange(len(changed))] = rng.randrange(256)
            observation = stream(bytes(changed))[0]
            self.assertIn(observation.status, ("identified", "unknown", "malformed", "incomplete", "budget_exhausted"))
            self.assertNotIn("NTLMSSP", repr(observation))
        tight = Inspector(Config(max_bytes=len(SMB2) + 40))
        tight.feed(data)
        self.assertEqual((tight.observation.application_protocol, fields(tight.observation, "gss_mechanism")), ("smb2", {}))

    def test_smb1_session_setup(self):
        cases = ((SMB1 + SMB1_SESSION_NTLM, {"smb1_message": ["negotiate-request", "session-setup-request"], "gss_mechanism": "ntlm", "ntlm_message": "negotiate"}, ("ntlm-authentication", "obsolete-protocol")),
                 (SMB1 + SMB1_SESSION_LEGACY, {"gss_mechanism": "ntlm-response"}, ("ntlm-authentication",)),
                 (SMB1_RESPONSE + SMB1_SESSION_CHALLENGE, {"smb1_message": ["negotiate-response", "session-setup-response"], "smb_session": "continuing", "ntlm_message": "challenge"}, ("ntlm-authentication",)),
                 (SMB1_RESPONSE + SMB1_SESSION_GUEST, {"smb_session": "guest"}, ("smb-guest-or-anonymous-session",)))
        for data, expected, risks in cases:
            observation, kinds = stream(data)
            self.assertEqual((observation.status, observation.application_protocol, kinds), ("identified", "smb1", ["updated", "refined"]), data[:8].hex())
            self.assertEqual(fields(observation, *expected), expected)
            verdict = classify(observation, "tcp", 445)
            for risk in risks:
                self.assertIn(risk, verdict.risks)
            self.assertNotIn("alice", repr(observation))
            self.assertNotIn("WORKGROUP", repr(observation))
        self.assertEqual(fields(stream(SMB1 + smb1_session_setup_legacy(0, 0))[0], "gss_mechanism"), {"gss_mechanism": "none"})
        for extra in (smb1_session_setup_legacy(25, 24), smb1_session_setup(b""), smb1_session_setup_response(action=4), SMB1_SESSION_NTLM[:-3]):
            observation, kinds = stream(SMB1 + extra)
            self.assertEqual((observation.application_protocol, fields(observation, "gss_mechanism", "smb_session")), ("smb1", {}), extra[:9].hex())
        tree = bytearray(SMB1_SESSION_NTLM)
        tree[4 + 4] = 0x75
        self.assertEqual(stream(SMB1 + bytes(tree))[1], ["updated"])


class LDAPBindTests(unittest.TestCase):
    def test_bind_mechanism_labels_and_risk(self):
        simple = stream(LDAP)[0]
        self.assertEqual(fields(simple, "ldap_bind"), {"ldap_bind": "simple"})
        self.assertIn("cleartext-credential-protocol", classify(simple, "tcp", 389).risks)
        for mechanism, label, clear in ((b"GSSAPI", "sasl-gssapi", False), (b"PLAIN", "sasl-plain", True), (b"DIGEST-MD5", "sasl-digest-md5", False),
                                        (b"EXTERNAL", "sasl-external", False), (b"CRAM-MD5", "sasl-cram-md5", False), (b"SCRAM-SHA-256", "sasl-scram", False),
                                        (b"NTLM", "sasl-ntlm", False), (b"X-CUSTOM", "sasl-other", True)):
            observation = stream(ldap_bind(sasl(mechanism, b"creds")))[0]
            self.assertEqual((observation.application_protocol, fields(observation, "ldap_bind")), ("ldap/3", {"ldap_bind": label}), mechanism)
            self.assertEqual("cleartext-credential-protocol" in classify(observation, "tcp", 389).risks, clear, mechanism)
            self.assertNotIn("creds", repr(observation))
        spnego = stream(ldap_bind(sasl(b"GSS-SPNEGO", SPNEGO_NTLM_INIT)))[0]
        self.assertEqual(fields(spnego, "ldap_bind", "gss_mechanism", "ntlm_message"), {"ldap_bind": "sasl-gss-spnego", "gss_mechanism": "ntlm", "ntlm_message": "negotiate"})
        risks = classify(spnego, "tcp", 389).risks
        self.assertIn("ntlm-authentication", risks)
        self.assertNotIn("cleartext-credential-protocol", risks)
        kerberos = stream(ldap_bind(sasl(b"GSS-SPNEGO", SPNEGO_KRB5_INIT)))[0]
        self.assertEqual(fields(kerberos, "gss_mechanism"), {"gss_mechanism": "kerberos"})
        self.assertEqual(stream(ldap_bind(sasl(b"GSS-SPNEGO", b"\x30\x00")))[0].status, "malformed")
        self.assertEqual(fields(stream(ldap_bind(sasl(b"GSS-SPNEGO")))[0], "ldap_bind", "gss_mechanism"), {"ldap_bind": "sasl-gss-spnego"})


class HTTPAuthTests(unittest.TestCase):
    def test_http1_schemes_and_risks(self):
        request = stream(HTTP_BASIC_AUTH)[0]
        self.assertEqual(fields(request, "http_auth_scheme"), {"http_auth_scheme": "basic"})
        self.assertNotIn("YWxpY2U6czNjcmV0", repr(request))
        self.assertIn("http-basic-authentication", classify(request, "tcp", 80).risks)
        challenge = stream(HTTP_NTLM_CHALLENGE)[0]
        self.assertEqual(fields(challenge, "http_auth_challenge"), {"http_auth_challenge": ["negotiate", "ntlm"]})
        self.assertIn("ntlm-authentication", classify(challenge, "tcp", 80).risks)
        bearer = stream(b"GET / HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer abc.def\r\nProxy-Authorization: Basic x\r\n\r\n")[0]
        self.assertEqual(fields(bearer, "http_auth_scheme"), {"http_auth_scheme": "bearer"})        # the first credential header only
        self.assertNotIn("abc.def", repr(bearer))
        self.assertEqual(classify(bearer, "tcp", 80).risks, ("cleartext-credential-protocol",))
        ntlm = stream(b"GET / HTTP/1.1\r\nHost: h\r\nAuthorization: NTLM TlRMTVNTUAAB\r\n\r\n")[0]
        self.assertIn("ntlm-authentication", classify(ntlm, "tcp", 80).risks)
        # The session verdict carries the risks of both directions once.
        verdict = session_verdict(request, challenge, "tcp", 80, 200, 150, True, None)
        self.assertEqual(verdict.risks.count("ntlm-authentication"), 1)
        self.assertIn("http-basic-authentication", verdict.risks)

    def test_http2_schemes(self):
        block = (hpack_literal(b":method", b"GET") + hpack_literal(b":scheme", b"https") + hpack_literal(b":path", b"/") + hpack_literal(b":authority", b"h.example")
                 + hpack_literal(b"authorization", b"Negotiate YIIB") + hpack_literal(b"www-authenticate", b"NTLM") + hpack_literal(b"proxy-authenticate", b"Basic realm=x"))
        headers = len(block).to_bytes(3, "big") + b"\x01\x05" + (1).to_bytes(4, "big") + block
        observation = stream(H2_PREFACE + H2_SETTINGS + headers)[0]
        self.assertEqual((observation.application_protocol, fields(observation, "http2_auth_scheme", "http2_auth_challenge")),
                         ("http/2", {"http2_auth_scheme": "negotiate", "http2_auth_challenge": ["ntlm", "basic"]}))
        self.assertNotIn("YIIB", repr(observation))
        self.assertIn("ntlm-authentication", classify(observation, "tcp", 443).risks)


if __name__ == "__main__":
    unittest.main()
