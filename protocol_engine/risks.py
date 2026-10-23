"""Flow risks derived from structural evidence, in the spirit of nDPI flow risks.

A risk is a named, documented condition over a session verdict and the two
directional observations. Risks are advisory flags for policy and triage; they
are never used to identify an application, and none of them inspects payload
beyond what the parsers already validated. RISKS.md documents every entry.
"""
from types import MappingProxyType

from .ssh_posture import RISK_EXEMPT as _SSH_RISK_EXEMPT
from .tls_server import NO_FORWARD_SECRECY
from .x509 import WEAK_SIGNATURES, validity, weak_key

RISKS = MappingProxyType({
    "nonstandard-port": ("medium", "Identified application on a port outside its catalog ports (application-default violation)"),
    "cleartext-credential-protocol": ("medium", "Protocol that carries credentials in cleartext was observed without encryption"),
    "obsolete-protocol": ("high", "Protocol version or family that is deprecated and known to be unsafe (SMB1, Telnet, SSH 1.99, TLS < 1.2 selected, RDP standard security)"),
    "tls-legacy-version-offer": ("medium", "ClientHello offers no version above TLS 1.1"),
    "tls-missing-sni": ("low", "ClientHello without a server_name extension"),
    "unknown-high-entropy-payload": ("medium", "No profile matched and the payload prefix looks encrypted, compressed or random"),
    "malformed-protocol": ("medium", "A supported protocol was selected but the message violated its profile"),
    "dns-suspicious-query-name": ("medium", "DNS query name with very long or high-entropy labels (tunnelling or algorithmically generated names)"),
    "http-proxy-tunnel": ("low", "HTTP CONNECT tunnel; the carried application is only visible through the shifted phase"),
    "desktop-or-file-sharing-session": ("low", "Remote desktop or file-sharing application"),
    "tls-self-issued-certificate": ("medium", "TLS 1.2 server leaf certificate whose issuer equals its subject (self-signed or a root presented as the leaf); unauthenticated"),
    "tls-weak-certificate-key": ("high", "TLS 1.2 server leaf certificate public key below RSA 2048 or a named curve below 256 bits"),
    "tls-weak-certificate-signature": ("high", "TLS 1.2 server leaf certificate signed with MD5 or SHA-1"),
    "tls-certificate-lifetime-excessive": ("low", "TLS 1.2 server leaf certificate valid for more than 398 days"),
    "dns-error-response": ("low", "DNS response with rcode servfail, nxdomain or refused"),
    "modbus-exception-response": ("low", "Modbus/TCP exception response (illegal function, address or value, device failure or gateway error)"),
    "radius-access-reject": ("low", "RADIUS Access-Reject answering an Access-Request"),
    "kerberos-error-response": ("low", "KRB-ERROR other than KDC_ERR_PREAUTH_REQUIRED (the normal pre-authentication step)"),
    "tls-encrypted-client-hello": ("low", "ClientHello carries an outer encrypted_client_hello extension: the visible server_name is the client-facing public name and the real name is encrypted"),
    "ntlm-authentication": ("medium", "NTLM authentication offered or performed (SMB session setup, LDAP bind, HTTP Negotiate/NTLM): relay and legacy hash exposure"),
    "http-basic-authentication": ("medium", "HTTP Basic credentials sent without encryption in the session"),
    "smb-guest-or-anonymous-session": ("low", "SMB session established as guest or anonymous (null session)"),
    "tls-no-forward-secrecy": ("medium", "Server selected a key exchange without forward secrecy: static RSA or static ECDH (TLS 1.2, DTLS 1.2) or psk_ke resumption (TLS 1.3)"),
    "tls-ca-certificate-as-leaf": ("medium", "TLS 1.2 server leaf certificate asserts basicConstraints cA TRUE (a CA certificate presented as the end entity)"),
    "tls-certificate-not-for-server-auth": ("medium", "TLS 1.2 server leaf certificate restricts its extended key usage to purposes other than serverAuth"),
    "tls-certificate-without-san": ("low", "TLS 1.2 server v3 leaf certificate without a subjectAltName extension (subject-CN-only names are rejected by current clients)"),
    "smb-signing-not-required": ("medium", "SMB2/3 server NEGOTIATE response enables but does not require signing: sessions can be relayed or tampered with unless the client requires signing"),
    "smb-encryption-unavailable": ("low", "SMB2/3 server NEGOTIATE response selects a dialect or cipher without SMB encryption (2.0.2/2.1, no encryption capability, or no common cipher)"),
    "ssh-weak-algorithm-offered": ("medium", "SSH KEXINIT offers a weak algorithm class: SHA-1 key exchange, DSA host keys, RC4, 3DES or 64-bit block ciphers, CBC mode, MD5 or truncated MACs, or no MAC"),
    "ssh-none-cipher-offered": ("high", "SSH KEXINIT offers the none cipher (no encryption)"),
    "ssh-terrapin-exposed": ("medium", "SSH KEXINIT offers ChaCha20-Poly1305 or an encrypt-then-MAC MAC with a CBC-mode cipher without the strict key exchange marker (Terrapin, CVE-2023-48795)"),
    "rdp-nla-not-negotiated": ("medium", "RDP server Connection Confirm selects standard RDP security or TLS without CredSSP: no network level authentication, so the logon happens inside the session"),
    "database-encryption-unavailable": ("medium", "Database server cannot encrypt the session: MySQL greeting without CLIENT_SSL, or a TDS PRELOGIN response that does not support encryption (the login is protected only by TDS's reversible password obfuscation)"),
    "database-session-unencrypted": ("medium", "Database session proceeds without transport encryption: a MySQL HandshakeResponse41 or PostgreSQL StartupMessage seen in the clear, or a TDS PRELOGIN response that encrypts only the login packet or nothing"),
    "snmpv3-unauthenticated": ("medium", "SNMPv3 message at noAuthNoPriv other than an engine-discovery request or a Report: operations and values are neither authenticated nor encrypted"),
    "snmpv3-no-privacy": ("low", "SNMPv3 message at authNoPriv other than a Report: authenticated, but the scoped PDU (OIDs and values) travels in cleartext"),
    "tls-certificate-outside-validity": ("medium", "TLS 1.2 server leaf certificate expired or not yet valid at the capture time (evaluated only when the host supplies a capture clock)"),
})
MAX_CERTIFICATE_LIFETIME_DAYS = 398   # CA/Browser Forum baseline since September 2020

_SHARING = frozenset(("rdp", "vnc", "smb", "ftp", "bittorrent", "rsync", "tftp"))
_LEGACY_TLS = frozenset(("1.0", "1.1", "SSL 3.0"))


_FIELDS = frozenset(("ssh_version", "selected_tls_version", "rdp_security_flags", "rdp_selected_protocol",
                     "tls_offered_max_version", "dns_query_shape", "payload_class", "tls_certificate_self_issued",
                     "tls_certificate_key", "tls_certificate_signature", "tls_certificate_lifetime_days", "tls_ech", "dns_rcode", "kerberos_error", "radius_code", "modbus_pdu", "zmtp_mechanism", "rip_authentication", "gss_mechanism", "ldap_bind", "smb_session",
                     "http_auth_scheme", "http_auth_challenge", "http2_auth_scheme", "http2_auth_challenge",
                     "selected_key_exchange", "tls_certificate_ca", "tls_certificate_eku", "tls_certificate_san",
                     "tls_certificate_not_before", "tls_certificate_not_after", "ssh_weak_algorithm", "ssh_terrapin",
                     "smb_signing", "smb_encryption", "rdp_selected_security",
                     "mysql_tls_supported", "mysql_client_ssl", "mysql_auth_plugin", "tds_session_encryption", "postgresql_message",
                     "snmp_security_level", "snmp_usm_discovery", "snmp_pdu"))
_OBSOLETE_PROTOCOLS = frozenset(("smb1", "telnet"))
# Protocol versions whose credentials never travel in cleartext even though the
# application family lists `cleartext-credentials` for its older versions.
_PROTECTED_VERSIONS = frozenset(("snmp/3",))
_NO_RISKS = ()
_APP_RISKS = {}


def _application_risks(verdict):
    """Risks fixed by the application name and encryption; cached per (app, encrypted)."""
    key = (verdict.app, verdict.encryption is None)
    cached = _APP_RISKS.get(key)
    if cached is None:
        cached = []
        if verdict.app not in ("incomplete", "insufficient-data", "not-applicable"):
            if key[1] and "cleartext-credentials" in verdict.characteristics:
                cached.append("cleartext-credential-protocol")
            if verdict.app in _SHARING:
                cached.append("desktop-or-file-sharing-session")
            if verdict.app == "http-proxy":
                cached.append("http-proxy-tunnel")
        cached = _APP_RISKS[key] = tuple(cached)
    return cached


def flow_risks(verdict, client, server, at=None):
    """Sorted tuple of risk names for a verdict and its directional observations.

    The per-application part is cached; the per-observation part is one pass over
    the evidence rows that carry the fields risks read. The common case
    (nothing to flag) returns the shared empty tuple without allocating. `at` is
    the capture time in POSIX seconds supplied by the host (the engine has no
    clock); without it certificate validity is never evaluated.
    """
    found = list(_application_risks(verdict))
    if verdict.port_usage == "nonstandard":
        found.append("nonstandard-port")
    if verdict.shifted_from == "http-proxy" and "http-proxy-tunnel" not in found:
        found.append("http-proxy-tunnel")
    for obs in (client, server):
        if obs is None:
            continue
        status = obs.status
        if status == "malformed":
            found.append("malformed-protocol")
            continue
        if status == "identified":
            if obs.application_protocol in _OBSOLETE_PROTOCOLS:
                found.append("obsolete-protocol")
            elif obs.application_protocol in _PROTECTED_VERSIONS and "cleartext-credential-protocol" in found:
                # SNMPv3 keys are never on the wire (USM authenticates with HMAC
                # parameters and encrypts the scoped PDU); only v1/v2c community
                # strings are a cleartext credential.
                found.remove("cleartext-credential-protocol")
        elif status != "unknown":
            continue
        window = {}
        for evidence in obs.evidence:
            field = evidence.field
            if field not in _FIELDS:
                continue
            value = evidence.value
            if field == "tls_offered_max_version":
                if value in _LEGACY_TLS:
                    found.append("tls-legacy-version-offer")
                if obs.hostname is None:
                    found.append("tls-missing-sni")
            elif field == "payload_class":
                if value == "high-entropy" and status == "unknown":
                    found.append("unknown-high-entropy-payload")
            elif field == "dns_query_shape":
                if value == "suspicious":
                    found.append("dns-suspicious-query-name")
            elif field == "tls_certificate_self_issued":
                if value == "yes":
                    found.append("tls-self-issued-certificate")
            elif field == "tls_certificate_key":
                if weak_key(value):
                    found.append("tls-weak-certificate-key")
            elif field == "tls_certificate_signature":
                if value in WEAK_SIGNATURES:
                    found.append("tls-weak-certificate-signature")
            elif field == "modbus_pdu":
                if value == "exception":
                    found.append("modbus-exception-response")
            elif field == "radius_code":
                if value == "access-reject":
                    found.append("radius-access-reject")
            elif field == "kerberos_error":
                if value != "25":
                    found.append("kerberos-error-response")
            elif field == "dns_rcode":
                if value in ("servfail", "nxdomain", "refused"):
                    found.append("dns-error-response")
            elif field == "tls_ech":
                if value == "outer":
                    found.append("tls-encrypted-client-hello")
            elif field == "rip_authentication":
                if value != "simple-password" and "cleartext-credential-protocol" in found:
                    found.remove("cleartext-credential-protocol")   # only the v2 simple password travels in the clear
            elif field == "gss_mechanism":
                if value in ("ntlm", "ntlm-response", "lm-response") and "ntlm-authentication" not in found:
                    found.append("ntlm-authentication")
            elif field in ("http_auth_scheme", "http_auth_challenge", "http2_auth_scheme", "http2_auth_challenge"):
                if value == "ntlm" and "ntlm-authentication" not in found:
                    found.append("ntlm-authentication")
                if value == "basic" and field.endswith("scheme") and verdict.encryption is None and "http-basic-authentication" not in found:
                    found.append("http-basic-authentication")
            elif field == "ldap_bind":
                # Only a simple bind or SASL PLAIN carries the password; GSSAPI, SPNEGO, DIGEST, CRAM, SCRAM, NTLM
                # and EXTERNAL authenticate without placing it on the wire (v0.56).
                if value not in ("simple", "sasl-plain", "sasl-other") and "cleartext-credential-protocol" in found:
                    found.remove("cleartext-credential-protocol")
            elif field == "smb_session":
                if value in ("guest", "anonymous") and "smb-guest-or-anonymous-session" not in found:
                    found.append("smb-guest-or-anonymous-session")
            elif field == "zmtp_mechanism":
                # Only the PLAIN mechanism sends a username and password in the clear; NULL has no
                # credentials and CURVE/GSSAPI authenticate cryptographically.
                if value != "plain" and "cleartext-credential-protocol" in found:
                    found.remove("cleartext-credential-protocol")
            elif field == "smb_signing":
                # Only the server's NEGOTIATE response decides; a client's "enabled" is not a weakness on its own.
                if value == "enabled" and evidence.source.endswith("negotiate_response"):
                    found.append("smb-signing-not-required")
            elif field == "smb_encryption":
                if value in ("unavailable", "not-supported"):
                    found.append("smb-encryption-unavailable")
            elif field == "ssh_weak_algorithm":
                if value == "cipher-none":
                    found.append("ssh-none-cipher-offered")
                if value not in _SSH_RISK_EXEMPT:
                    found.append("ssh-weak-algorithm-offered")
            elif field == "ssh_terrapin":
                if value == "exposed":
                    found.append("ssh-terrapin-exposed")
            elif field == "rdp_selected_security":
                # Only the server's selection decides; RDSTLS and AAD authenticate before the session as well (v0.60).
                if value in ("standard-rdp", "tls"):
                    found.append("rdp-nla-not-negotiated")
            elif field == "mysql_tls_supported":
                if value == "false":
                    found.append("database-encryption-unavailable")
            elif field == "mysql_client_ssl":
                # A HandshakeResponse41 is only visible when no SSLRequest started TLS before it (v0.61).
                if value == "not-requested":
                    found.append("database-session-unencrypted")
            elif field == "mysql_auth_plugin":
                # mysql_clear_password puts the password itself in this cleartext HandshakeResponse41.
                if value == "cleartext" and "cleartext-credential-protocol" not in found:
                    found.append("cleartext-credential-protocol")
            elif field == "tds_session_encryption":
                if value == "none":
                    found.append("database-encryption-unavailable")
                if value in ("none", "login-only"):
                    found.append("database-session-unencrypted")
            elif field == "postgresql_message":
                if value == "startup":
                    found.append("database-session-unencrypted")
            elif field == "selected_key_exchange":
                if value in NO_FORWARD_SECRECY:
                    found.append("tls-no-forward-secrecy")
            elif field == "tls_certificate_ca":
                if value == "yes":
                    found.append("tls-ca-certificate-as-leaf")
            elif field == "tls_certificate_eku":
                if value == "other":
                    found.append("tls-certificate-not-for-server-auth")
            elif field == "tls_certificate_san":
                if value == "absent":
                    found.append("tls-certificate-without-san")
            elif field in ("tls_certificate_not_before", "tls_certificate_not_after", "snmp_security_level", "snmp_usm_discovery", "snmp_pdu"):
                window[field] = value
            elif field == "tls_certificate_lifetime_days":
                if value.isdigit() and int(value) > MAX_CERTIFICATE_LIFETIME_DAYS:
                    found.append("tls-certificate-lifetime-excessive")
            elif (field == "ssh_version" and value == "1.99") or (field == "selected_tls_version" and value in _LEGACY_TLS) \
                    or (field in ("rdp_security_flags", "rdp_selected_protocol") and value == "0"):
                if "obsolete-protocol" not in found:
                    found.append("obsolete-protocol")
        if window:
            if ("tls_certificate_not_before" in window or "tls_certificate_not_after" in window) and \
                    validity(window.get("tls_certificate_not_before"), window.get("tls_certificate_not_after"), at) in ("expired", "not-yet-valid"):
                found.append("tls-certificate-outside-validity")
            level = window.get("snmp_security_level")
            # Discovery requests and Reports (RFC 3414 4, 3.1.1) are sent below the session's level by design (v0.62).
            if level is not None and window.get("snmp_pdu") != "report" and "snmp_usm_discovery" not in window:
                if level == "no-auth-no-priv":
                    found.append("snmpv3-unauthenticated")
                elif level == "auth-no-priv":
                    found.append("snmpv3-no-privacy")
    if not found:
        return _NO_RISKS
    return tuple(sorted(set(found)))


def risk_severity(name):
    return RISKS[name][0]
