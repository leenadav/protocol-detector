"""Flow risks derived from structural evidence, in the spirit of nDPI flow risks.

A risk is a named, documented condition over a session verdict and the two
directional observations. Risks are advisory flags for policy and triage; they
are never used to identify an application, and none of them inspects payload
beyond what the parsers already validated. RISKS.md documents every entry.
"""
from types import MappingProxyType

from .x509 import WEAK_SIGNATURES, weak_key

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
})
MAX_CERTIFICATE_LIFETIME_DAYS = 398   # CA/Browser Forum baseline since September 2020

_SHARING = frozenset(("rdp", "vnc", "smb", "ftp", "bittorrent", "rsync", "tftp"))
_LEGACY_TLS = frozenset(("1.0", "1.1", "SSL 3.0"))


_FIELDS = frozenset(("ssh_version", "selected_tls_version", "rdp_security_flags", "rdp_selected_protocol",
                     "tls_offered_max_version", "dns_query_shape", "payload_class", "tls_certificate_self_issued",
                     "tls_certificate_key", "tls_certificate_signature", "tls_certificate_lifetime_days", "tls_ech", "dns_rcode", "kerberos_error", "radius_code", "modbus_pdu", "zmtp_mechanism", "rip_authentication", "ldap_extended"))
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


def flow_risks(verdict, client, server):
    """Sorted tuple of risk names for a verdict and its directional observations.

    The per-application part is cached; the per-observation part is one pass over
    the evidence rows that carry the seven fields risks read. The common case
    (nothing to flag) returns the shared empty tuple without allocating.
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
            elif field == "ldap_extended":
                # A StartTLS exchange carries no credentials; the bind that follows travels inside TLS (v0.54).
                if value == "starttls" and "cleartext-credential-protocol" in found:
                    found.remove("cleartext-credential-protocol")
            elif field == "zmtp_mechanism":
                # Only the PLAIN mechanism sends a username and password in the clear; NULL has no
                # credentials and CURVE/GSSAPI authenticate cryptographically.
                if value != "plain" and "cleartext-credential-protocol" in found:
                    found.remove("cleartext-credential-protocol")
            elif field == "tls_certificate_lifetime_days":
                if value.isdigit() and int(value) > MAX_CERTIFICATE_LIFETIME_DAYS:
                    found.append("tls-certificate-lifetime-excessive")
            elif (field == "ssh_version" and value == "1.99") or (field == "selected_tls_version" and value in _LEGACY_TLS) \
                    or (field in ("rdp_security_flags", "rdp_selected_protocol") and value == "0"):
                if "obsolete-protocol" not in found:
                    found.append("obsolete-protocol")
    if not found:
        return _NO_RISKS
    return tuple(sorted(set(found)))


def risk_severity(name):
    return RISKS[name][0]
