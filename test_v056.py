"""v0.56: authentication mechanism evidence (SMB session setup, LDAP bind, HTTP Authorization) and the NTLM/basic risks."""
import random
import unittest

from protocol_engine import Config, DatagramInspector, Inspector
from protocol_engine.appid import classify, session_verdict
from protocol_engine.gss import classify_token
from protocol_engine.media import MAX_AUTH_ELEMENTS, auth_scheme_class, challenge_scheme_classes
from protocol_engine.parsers import BudgetError, ParseError
from protocol_fixtures import (HTTP_BASIC_AUTH, HTTP_NTLM_CHALLENGE, LDAP, OID_KRB5, OID_MS_KRB5, SMB311_RESPONSE, _ber, _krb_principal, krb_error,
                               krb5_ap_rep_message, krb5_ap_req_message, krb5_encrypted, krb5_gss, krb5_tgt_req_message, OID_NEGOEX, OID_NTLMSSP, SMB1, SMB1_RESPONSE, SMB1_SESSION_CHALLENGE,
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
    return der(0x30, b"\x02\x01\x01" + der(0x60, bind))      # long-form lengths once a real Kerberos envelope is carried


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
        self.assertEqual(fields(bearer, "http_auth_scheme"), {"http_auth_scheme": ["bearer", "basic"]})   # every credential header (round 1)
        self.assertNotIn("abc.def", repr(bearer))
        self.assertEqual(classify(bearer, "tcp", 80).risks, ("cleartext-credential-protocol", "http-basic-authentication"))
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


def krb5_token(tok_id=b"\x01\x00", tag=0x6e, body=None, trailing=b"", oid=OID_KRB5):
    """A GSS Kerberos token. Without `body` the message is a valid envelope for `tag`; with it, `tag` frames raw bytes."""
    if body is None and tag is not None:
        message = {0x6e: krb5_ap_req_message(), 0x6f: krb5_ap_rep_message(), 0x7e: krb_error(), 0x30: krb5_tgt_req_message()}[tag]
    else:
        message = der(tag, body) if tag is not None else b""
    return krb5_gss(message + trailing, tok_id, oid)


def smb2_frame_with(frame, header_flags=None, signature=None, body_flags=None):
    """Patch an SMB2 frame (4-byte direct-TCP prefix included): header Flags, Signature, request Flags byte."""
    data = bytearray(frame)
    if header_flags is not None:
        data[4 + 16:4 + 20] = header_flags.to_bytes(4, "little")
    if signature is not None:
        data[4 + 48:4 + 64] = signature
    if body_flags is not None:
        data[4 + 66] = body_flags
    return bytes(data)


class ReviewRound1Tests(unittest.TestCase):
    """Repairs for the v0.56 round-1 review findings (Kerberos TOK_ID, SMB2 header flags, repeated HTTP auth)."""

    def test_kerberos_tokens_share_one_validator(self):
        valid = [(krb5_token(), "AP-REQ"), (krb5_token(b"\x02\x00", 0x6f), "AP-REP"), (krb5_token(b"\x03\x00", 0x7e), "KRB-ERROR"),
                 (krb5_token(b"\x04\x00", 0x30), "TGT-REQ"), (krb5_token(oid=OID_MS_KRB5), "MS-KRB5")]
        invalid = [(krb5_token(b"\x05\x00"), "unknown TOK_ID"), (krb5_token(b"", None), "missing TOK_ID"),
                   (krb5_token(b"\x01", None), "truncated TOK_ID"), (krb5_token(b"\x01\x00", None), "TOK_ID without a message"),
                   (krb5_token(b"\x01\x00", 0x6f), "AP-REQ TOK_ID framing an AP-REP"), (krb5_token(b"\x02\x00", 0x6e), "AP-REP TOK_ID framing an AP-REQ"),
                   (krb5_token(trailing=b"\x00"), "trailing byte after the message"),
                   (der(0x60, der(0x06, OID_KRB5) + b"\x01\x00" + b"\x6e\x20" + bytes(4)), "message overruns the token"),
                   (krb5_token(body=bytes(16)), "AP-REQ tag around arbitrary bytes")]
        for token, name in valid:
            self.assertEqual(classify_token(token).mechanism, "kerberos", name)
            self.assertEqual(classify_token(spnego_init(mechs=(OID_KRB5,), token=token)).mechanism, "kerberos", name)
            self.assertEqual(classify_token(spnego_resp(0, OID_KRB5, token)).mechanism, "kerberos", name)
        for token, name in invalid:
            for carried in (token, spnego_init(mechs=(OID_KRB5,), token=token), spnego_init(mechs=(OID_NTLMSSP,), token=token),
                            spnego_resp(1, OID_KRB5, token), spnego_resp(1, None, token)):
                with self.assertRaises(ParseError, msg=name):
                    classify_token(carried)
        # A malformed Kerberos mechToken never yields positive evidence on the carriers.
        bad = spnego_init(mechs=(OID_KRB5,), token=krb5_token(b"\x09\x09"))
        observation, kinds = stream(SMB2 + smb2_session_setup(bad))
        self.assertEqual((observation.application_protocol, fields(observation, "gss_mechanism", "smb_message")), ("smb2", {}))
        self.assertNotIn("refined", kinds)
        bind = stream(ldap_bind(sasl(b"GSS-SPNEGO", bad)))[0]
        self.assertEqual((bind.status, fields(bind, "gss_mechanism")), ("malformed", {}))
        # Mechanism lists without a token are offers and keep their label.
        self.assertEqual(classify_token(spnego_init(mechs=(OID_KRB5,))).mechanism, "kerberos")

    def test_smb2_session_setup_header_flags(self):
        request, final, challenge = SMB2_SESSION_NTLM, SMB2_SESSION_OK, SMB2_SESSION_CHALLENGE
        signature = bytes(range(1, 17))

        def session(frame, negotiate=SMB2):
            observation = stream(negotiate + frame)[0]
            return observation.application_protocol, fields(observation, "smb_message").get("smb_message")
        accepted = [
            (request, "session-setup-request", "plain request"),
            (smb2_frame_with(final, header_flags=0x09, signature=signature), "session-setup-response", "signed final response"),
            (challenge, "session-setup-response", "unsigned more-processing response"),
        ]
        for frame, expected, name in accepted:
            negotiate = SMB2_RESPONSE if expected.endswith("response") else SMB2
            self.assertEqual(session(frame, negotiate), ("smb2", expected), name)
        rejected = [
            (smb2_frame_with(request, header_flags=0x08, signature=signature), SMB2, "signed request without binding"),
            (smb2_frame_with(request, header_flags=0x20), SMB2, "priority value on a request (dialect unknown, round 2)"),
            (smb2_frame_with(request, header_flags=0x08, signature=signature, body_flags=1), SMB2, "signed binding request (dialect unknown, round 2)"),
            (smb2_frame_with(challenge, header_flags=0x09, signature=signature), SMB2_RESPONSE, "signed more-processing response"),
            (smb2_frame_with(request, signature=signature), SMB2, "unsigned request with signature bytes"),
            (smb2_frame_with(final, signature=signature), SMB2_RESPONSE, "unsigned response with signature bytes"),
            (smb2_frame_with(request, header_flags=0x02), SMB2, "async request"),
            (smb2_frame_with(final, header_flags=0x03), SMB2_RESPONSE, "async response"),
            (smb2_frame_with(request, header_flags=0x04), SMB2, "related operation"),
            (smb2_frame_with(request, header_flags=0x10000000), SMB2, "DFS operation"),
            (smb2_frame_with(request, header_flags=0x20000000), SMB2, "replay operation"),
            (smb2_frame_with(final, header_flags=0x21), SMB2_RESPONSE, "priority value on a response"),
            (smb2_frame_with(request, header_flags=0x80), SMB2, "reserved flag bit"),
        ]
        for frame, negotiate, name in rejected:
            self.assertEqual(session(frame, negotiate), ("smb2", None), name)

    def test_repeated_and_listed_http_authentication(self):
        self.assertEqual(challenge_scheme_classes(b"Negotiate, NTLM"), ("negotiate", "ntlm"))
        self.assertEqual(challenge_scheme_classes(b'Bearer realm="a, Basic", error="x", Basic realm="b"'), ("bearer", "basic"))
        self.assertEqual(challenge_scheme_classes(b'Digest realm="x", qop="auth,auth-int", nonce="n", NTLM'), ("digest", "ntlm"))
        self.assertEqual(challenge_scheme_classes(b"Negotiate oYIB==, NTLM"), ("negotiate", "ntlm"))
        self.assertEqual(challenge_scheme_classes(b'realm="x", Basic'), ("other", "basic"))
        self.assertEqual(challenge_scheme_classes(b" , ,"), ("empty",))
        self.assertEqual(challenge_scheme_classes(b'"unterminated, NTLM'), ("other",))
        self.assertEqual(challenge_scheme_classes(b"x, " * MAX_AUTH_ELEMENTS + b"NTLM"), ("other",))      # bounded list walk
        self.assertEqual(challenge_scheme_classes(b"x, " * (MAX_AUTH_ELEMENTS - 1) + b"NTLM"), ("other", "ntlm"))
        listed = stream(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer, NTLM\r\nContent-Length: 0\r\n\r\n")[0]
        self.assertEqual(fields(listed, "http_auth_challenge"), {"http_auth_challenge": ["bearer", "ntlm"]})
        self.assertIn("ntlm-authentication", classify(listed, "tcp", 80).risks)
        repeated = stream(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Digest realm=\"p\"\r\n"
                          b"Proxy-Authenticate: Kerberos\r\nProxy-Authenticate: Basic realm=\"p\", NTLM\r\nContent-Length: 0\r\n\r\n")[0]
        self.assertEqual(fields(repeated, "http_auth_challenge"), {"http_auth_challenge": ["digest", "other", "basic", "ntlm"]})
        later = stream(b"GET / HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer abc\r\nAuthorization: NTLM TlRMTVNTUAAB\r\n\r\n")[0]
        self.assertEqual(fields(later, "http_auth_scheme"), {"http_auth_scheme": ["bearer", "ntlm"]})
        self.assertIn("ntlm-authentication", classify(later, "tcp", 80).risks)
        for text in (repr(listed), repr(repeated), repr(later)):
            self.assertNotIn("TlRMTVNTUAAB", text)
            self.assertNotIn('realm=', text)
        block = (hpack_literal(b":method", b"GET") + hpack_literal(b":scheme", b"https") + hpack_literal(b":path", b"/") + hpack_literal(b":authority", b"h.example")
                 + hpack_literal(b"authorization", b"Bearer x") + hpack_literal(b"proxy-authorization", b"Basic eDp5")
                 + hpack_literal(b"www-authenticate", b"Negotiate, NTLM"))
        headers = len(block).to_bytes(3, "big") + b"\x01\x05" + (1).to_bytes(4, "big") + block
        h2 = stream(H2_PREFACE + H2_SETTINGS + headers)[0]
        self.assertEqual(fields(h2, "http2_auth_scheme", "http2_auth_challenge"),
                         {"http2_auth_scheme": ["bearer", "basic"], "http2_auth_challenge": ["negotiate", "ntlm"]})
        self.assertEqual(classify(h2, "tcp", 80).risks.count("ntlm-authentication"), 1)
        self.assertNotIn("eDp5", repr(h2))


class ReviewRound2Tests(unittest.TestCase):
    """Repairs for the v0.56 round-2 findings: Kerberos message envelopes, dialect-dependent SMB2 flags."""

    def test_kerberos_message_envelopes(self):
        ap_req_fields = lambda **parts: krb5_ap_req_message(fields=b"".join(
            parts.get(name, default) for name, default in (
                ("pvno", _ber(0xa0, _ber(2, b"\x05"))), ("msg_type", _ber(0xa1, _ber(2, b"\x0e"))),
                ("options", _ber(0xa2, _ber(3, b"\x00\x20\x00\x00\x00"))),
                ("ticket", _ber(0xa3, _ber(0x61, _ber(0x30, _ber(0xa0, _ber(2, b"\x05")) + _ber(0xa1, _ber(0x1b, b"EXAMPLE.ORG"))
                                                         + _ber(0xa2, _krb_principal(b"cifs")) + _ber(0xa3, krb5_encrypted()))))),
                ("authenticator", _ber(0xa4, krb5_encrypted(kvno=False))))))
        valid = [(krb5_gss(krb5_ap_req_message()), "AP-REQ"), (krb5_gss(ap_req_fields()), "AP-REQ from parts"),
                 (krb5_gss(krb5_ap_rep_message(), b"\x02\x00"), "AP-REP"), (krb5_gss(krb_error(), b"\x03\x00"), "KRB-ERROR"),
                 (krb5_gss(krb5_tgt_req_message(), b"\x04\x00"), "TGT-REQ"), (krb5_gss(krb5_tgt_req_message(False, False), b"\x04\x00"), "bare TGT-REQ")]
        bad_ticket = lambda inner: _ber(0xa3, _ber(0x61, _ber(0x30, inner)))
        invalid = [
            (krb5_gss(b"\x6e\x00"), "empty AP-REQ"), (krb5_gss(b"\x6f\x00", b"\x02\x00"), "empty AP-REP"),
            (krb5_gss(b"\x7e\x00", b"\x03\x00"), "empty KRB-ERROR"), (krb5_gss(b"\x30\x00", b"\x04\x00"), "empty TGT-REQ"),
            (krb5_gss(_ber(0x6e, _ber(0x30, b""))), "AP-REQ with an empty SEQUENCE"),
            (krb5_gss(ap_req_fields(pvno=_ber(0xa0, _ber(2, b"\x04")))), "pvno 4"),
            (krb5_gss(ap_req_fields(msg_type=_ber(0xa1, _ber(2, b"\x0f")))), "AP-REQ carrying msg-type 15"),
            (krb5_gss(ap_req_fields(authenticator=b"")), "AP-REQ without authenticator"),
            (krb5_gss(ap_req_fields(ticket=b"")), "AP-REQ without ticket"),
            (krb5_gss(ap_req_fields(options=_ber(0xa2, _ber(3, b"\x00\x20\x00\x00")))), "ap-options shorter than 32 bits"),
            (krb5_gss(ap_req_fields(options=_ber(0xa2, _ber(3, b"\x08\x20\x00\x00\x00")))), "ap-options with 8 unused bits"),
            (krb5_gss(ap_req_fields(ticket=_ber(0xa3, _ber(0x62, _ber(0x30, b"\x00"))))), "ticket not APPLICATION 1"),
            (krb5_gss(ap_req_fields(ticket=bad_ticket(_ber(0xa0, _ber(2, b"\x04")) + _ber(0xa1, _ber(0x1b, b"R")) + _ber(0xa2, _krb_principal(b"s"))
                                                      + _ber(0xa3, krb5_encrypted())))), "tkt-vno 4"),
            (krb5_gss(ap_req_fields(ticket=bad_ticket(_ber(0xa0, _ber(2, b"\x05")) + _ber(0xa1, _ber(0x1b, b"")) + _ber(0xa2, _krb_principal(b"s"))
                                                      + _ber(0xa3, krb5_encrypted())))), "empty realm"),
            (krb5_gss(ap_req_fields(ticket=bad_ticket(_ber(0xa0, _ber(2, b"\x05")) + _ber(0xa1, _ber(0x1b, b"R"))
                                                      + _ber(0xa2, _ber(0x30, _ber(0xa0, _ber(2, b"\x01")) + _ber(0xa1, _ber(0x30, _ber(0x1b, b"a") * 9))))
                                                      + _ber(0xa3, krb5_encrypted())))), "principal beyond 8 components"),
            (krb5_gss(ap_req_fields(ticket=bad_ticket(_ber(0xa0, _ber(2, b"\x05")) + _ber(0xa1, _ber(0x1b, b"R"))
                                                      + _ber(0xa2, _ber(0x30, _ber(0xa0, _ber(2, b"\x01")) + _ber(0xa1, _ber(0x30, b""))))
                                                      + _ber(0xa3, krb5_encrypted())))), "principal without components"),
            (krb5_gss(ap_req_fields(authenticator=_ber(0xa4, _ber(0x30, _ber(0xa0, _ber(2, b"\x12")) + _ber(0xa2, _ber(4, b"")))))), "empty cipher"),
            (krb5_gss(ap_req_fields(authenticator=_ber(0xa4, _ber(0x30, _ber(0xa2, _ber(4, b"x")))))), "EncryptedData without etype"),
            (krb5_gss(ap_req_fields(authenticator=_ber(0xa4, _ber(0x30, _ber(0xa0, _ber(2, bytes(5))) + _ber(0xa2, _ber(4, b"x")))))), "etype wider than Int32"),
            (krb5_gss(ap_req_fields(options=_ber(0xa3, _ber(3, b"\x00" * 5)), ticket=_ber(0xa2, krb5_encrypted()))), "fields out of order"),
            (krb5_gss(_ber(0x6e, _ber(0x30, _ber(0xa0, _ber(2, b"\x05")) + _ber(0xa1, _ber(2, b"\x0e"))) + b"\x00")), "byte after the SEQUENCE"),
            (krb5_gss(krb5_ap_rep_message()[:2] + b"\x31" + krb5_ap_rep_message()[3:], b"\x02\x00"), "AP-REP body not a SEQUENCE"),
            (krb5_gss(_ber(0x30, _ber(0xa0, _ber(2, b"\x05")) + _ber(0xa1, _ber(2, b"\x11"))), b"\x04\x00"), "TGT-REQ msg-type 17"),
            (krb5_gss(krb_error(fields=_ber(0xa0, _ber(2, b"\x05")) + _ber(0xa1, _ber(2, b"\x1e"))), b"\x03\x00"), "KRB-ERROR without stime"),
        ]
        for token, name in valid:
            for carried in (token, spnego_init(mechs=(OID_KRB5,), token=token), spnego_resp(0, OID_KRB5, token)):
                self.assertEqual(classify_token(carried).mechanism, "kerberos", name)
        for token, name in invalid:
            for carried in (token, spnego_init(mechs=(OID_KRB5,), token=token), spnego_resp(1, OID_KRB5, token)):
                with self.assertRaises(ParseError, msg=name):
                    classify_token(carried)
        observation = stream(SMB2 + smb2_session_setup(spnego_init(mechs=(OID_KRB5,), token=krb5_gss(b"\x6e\x00"))))[0]
        self.assertEqual(fields(observation, "gss_mechanism", "smb_message"), {})
        self.assertEqual(fields(stream(SMB2 + SMB2_SESSION_KRB5)[0], "gss_mechanism"), {"gss_mechanism": "kerberos"})
        self.assertNotIn("EXAMPLE.ORG", repr(stream(SMB2 + SMB2_SESSION_KRB5)[0]))

    def test_dialect_dependent_flags_end_the_watch(self):
        signature = bytes(range(1, 17))
        for negotiate in (SMB2, SMB311):
            for frame, name in ((smb2_frame_with(SMB2_SESSION_NTLM, header_flags=0x10), "priority 1"),
                                (smb2_frame_with(SMB2_SESSION_NTLM, header_flags=0x70), "priority 7"),
                                (smb2_frame_with(SMB2_SESSION_NTLM, header_flags=0x08, signature=signature, body_flags=1), "signed binding request")):
                observation = stream(negotiate + frame)[0]
                self.assertEqual((observation.application_protocol, fields(observation, "smb_message")), ("smb2", {}), name)
            self.assertEqual(fields(stream(negotiate + SMB2_SESSION_NTLM)[0], "smb_message"), {"smb_message": "session-setup-request"})
        for negotiate in (SMB2_RESPONSE, SMB311_RESPONSE):
            final = stream(negotiate + smb2_frame_with(SMB2_SESSION_OK, header_flags=0x09, signature=signature))[0]
            self.assertEqual(fields(final, "smb_message", "smb_session"), {"smb_message": "session-setup-response", "smb_session": "authenticated"})


def krb_error_with(susec=b"\x01", cusec=None):
    """KRB-ERROR fields with chosen microsecond INTEGER contents (susec required, cusec optional)."""
    stamp = _ber(0x18, b"20260101120000Z")
    return krb_error(fields=_ber(0xa0, _ber(2, b"\x05")) + _ber(0xa1, _ber(2, b"\x1e"))
                     + ((_ber(0xa2, stamp) + _ber(0xa3, _ber(2, cusec))) if cusec is not None else b"")
                     + _ber(0xa4, stamp) + _ber(0xa5, _ber(2, susec)) + _ber(0xa6, _ber(2, b"\x19"))
                     + _ber(0xa9, _ber(0x1b, b"EXAMPLE.ORG")) + _ber(0xaa, _krb_principal(b"krbtgt")))


class ReviewRound3Tests(unittest.TestCase):
    """Repairs for the v0.56 round-3 findings, carried into the v0.57 round-1 request."""

    def carriers(self, token):
        return (token, spnego_init(mechs=(OID_KRB5,), token=token), spnego_resp(1, OID_KRB5, token))

    def test_kerberos_flags_bit_string(self):
        def ap_req(options):
            fields = (_ber(0xa0, _ber(2, b"\x05")) + _ber(0xa1, _ber(2, b"\x0e")) + _ber(0xa2, _ber(3, options))
                      + _ber(0xa3, _ber(0x61, _ber(0x30, _ber(0xa0, _ber(2, b"\x05")) + _ber(0xa1, _ber(0x1b, b"EXAMPLE.ORG"))
                                                   + _ber(0xa2, _krb_principal(b"cifs")) + _ber(0xa3, krb5_encrypted()))))
                      + _ber(0xa4, krb5_encrypted(kvno=False)))
            return krb5_gss(krb5_ap_req_message(fields=fields))
        accepted = [b"\x00\x20\x00\x00\x00", b"\x00" * 5, b"\x00\x20\x00\x00\x00\x00"]
        accepted += [bytes((unused,)) + b"\x20\x00\x00\x00\x00" for unused in range(1, 8)]          # 40 - unused >= 32, zero padding
        rejected = [bytes((unused,)) + b"\x20\x00\x00\x00" for unused in range(1, 8)]                # fewer than 32 significant bits
        rejected += [b"\x07\x00\x00\x00\x01",                                                       # the reviewer's trigger: 25 bits, padding set
                     b"\x01\x20\x00\x00\x00\x01", b"\x03\x20\x00\x00\x00\x04",                    # nonzero padding bits
                     b"\x00\x20\x00\x00", b"\x00", b"\x01", b"", b"\x08" + bytes(5)]
        for options in accepted:
            for carried in self.carriers(ap_req(options)):
                self.assertEqual(classify_token(carried).mechanism, "kerberos", options.hex())
        for options in rejected:
            for carried in self.carriers(ap_req(options)):
                with self.assertRaises(ParseError, msg=options.hex()):
                    classify_token(carried)

    def test_kerberos_error_microseconds_range(self):
        accepted = [b"\x00", b"\x01", b"\x0f\x42\x3f"]                         # 0, 1, 999999
        rejected = [b"\x0f\x42\x40", b"\x7f\xff\xff", b"\xff", b"\x80\x00", b"", b"\x00\x00\x00\x01"]   # 1000000, max, negatives, empty, 4 octets
        for usec in accepted:
            for message in (krb_error_with(susec=usec), krb_error_with(cusec=usec)):
                for carried in self.carriers(krb5_gss(message, b"\x03\x00")):
                    self.assertEqual(classify_token(carried).mechanism, "kerberos", usec.hex())
                self.assertEqual(DatagramInspector().inspect(message).status, "identified", usec.hex())
                self.assertEqual(stream(len(message).to_bytes(4, "big") + message)[0].status, "identified", usec.hex())
        for usec in rejected:
            for message in (krb_error_with(susec=usec), krb_error_with(cusec=usec)):
                for carried in self.carriers(krb5_gss(message, b"\x03\x00")):
                    with self.assertRaises(ParseError, msg=usec.hex()):
                        classify_token(carried)
                self.assertNotEqual(DatagramInspector().inspect(message).status, "identified", usec.hex())
                self.assertNotEqual(stream(len(message).to_bytes(4, "big") + message)[0].status, "identified", usec.hex())


if __name__ == "__main__":
    unittest.main()
