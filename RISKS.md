# Flow risks and unknown-traffic heuristics (v0.29)

Flow risks are advisory names attached to every session verdict and live
classification event (`risks`). They follow the idea of nDPI flow risks: a
documented condition over evidence the parsers already validated, useful for
policy and triage. A risk never identifies an application, never changes the
engine status, and never reads payload beyond the bounded initial message.
Heuristics (off by default, `Config(heuristics=True)`, CLI `--heuristics`) add
shape evidence for payload no profile matched and for DNS query names; their
evidence strength is `heuristic` and their thresholds are listed here.

## Risk table

| Risk | Severity | Condition (all structural unless marked heuristic) |
|---|---|---|
| `nonstandard-port` | medium | Identified application with `port_usage=nonstandard` (catalog ports, carrier ports after a shift count as standard) |
| `cleartext-credential-protocol` | medium | Identified application whose catalog characteristics include `cleartext-credentials` and no encryption in the session (FTP, POP3, IMAP, SMTP, Telnet, HTTP, SNMPv1/v2c, ...). A STARTTLS/AUTH TLS shift to `ssl` clears it; an identified `snmp/3` message (v0.38) is exempt because USM never places the key on the wire | ZeroMQ (ZMTP) counts only with the PLAIN mechanism; NULL carries no credentials and CURVE/GSSAPI authenticate cryptographically (v0.51). RIP counts only with v2 simple-password authentication; unauthenticated and MD5-authenticated datagrams do not (v0.53). An LDAP StartTLS request alone is not exempt: the risk clears only once the correlated shift to `ssl` is established, since the client continues in plaintext after a refusal (v0.54, review round 1). An LDAP bind clears it when `ldap_bind` names a mechanism that never places the password on the wire (SASL GSSAPI, GSS-SPNEGO, DIGEST-MD5, CRAM-MD5, SCRAM, NTLM, EXTERNAL); simple binds, SASL PLAIN and unknown mechanisms keep it (v0.56). A MySQL HandshakeResponse41 naming `mysql_clear_password` (`mysql_auth_plugin=cleartext`) raises it, since that plugin sends the password in the message itself (v0.61); only on wire bytes, never on a handshake a host decrypted.
| `obsolete-protocol` | high | SMB1 negotiate; Telnet; SSH banner `1.99`; a ServerHello selecting TLS 1.1 or lower (`selected_tls_version`); RDP request offering only standard RDP security (`rdp_security_flags=0`) or a Connection Confirm selecting it (`rdp_selected_protocol=0`) |
| `tls-legacy-version-offer` | medium | ClientHello whose highest offered version is TLS 1.1 or lower: `supported_versions` when present (GREASE/unknown values skipped, legacy field ignored per RFC 8446 4.2.1), else the legacy field. Evidence `tls_offered_max_version` |
| `tls-missing-sni` | low | ClientHello (evidence `tls_offered_max_version` present) without `server_name` |
| `unknown-high-entropy-payload` | medium | `unknown-tcp`/`unknown-udp` whose profiled prefix has `payload_class=high-entropy` (heuristic, requires heuristics on) |
| `malformed-protocol` | medium | A direction ended `malformed`: a profile was selected and the message violated it |
| `dns-suspicious-query-name` | medium | DNS query with `dns_query_shape=suspicious` (heuristic, requires heuristics on) |
| `http-proxy-tunnel` | low | `http-proxy` verdict (CONNECT) or an application shifted from it |
| `desktop-or-file-sharing-session` | low | Application in rdp, vnc, smb, ftp, bittorrent, rsync, tftp |
| `tls-self-issued-certificate` | medium | With `--certificates` (v0.39): the leaf certificate after a TLS 1.2 ServerHello has an issuer equal to its subject (`tls_certificate_self_issued=yes`). Self-signed in practice; the signature itself is not verified |
| `tls-weak-certificate-key` | high | Leaf public key below RSA 2048 bits or a named curve below 256 bits (`tls_certificate_key`, e.g. `rsa-1024`). `ec-other` and `other` never flag |
| `tls-weak-certificate-signature` | high | Leaf signed with `md5-rsa`, `sha1-rsa` or `ecdsa-sha1` (`tls_certificate_signature`) |
| `modbus-exception-response` | low | Modbus/TCP exception response (`modbus_pdu=exception`, v0.47); the exception code is reported as `modbus_exception` |
| `radius-access-reject` | low | RADIUS Access-Reject (hinted family, evidence `radius_code`, v0.46); the request's authenticator is never checked |
| `kerberos-error-response` | low | KRB-ERROR (UDP or TCP, evidence `kerberos_error`, v0.44) with an error code other than 25 (KDC_ERR_PREAUTH_REQUIRED, which every initial AS exchange produces); bad passwords (24), unknown principals (6), expired or revoked principals and clock skew all land here |
| `dns-error-response` | low | DNS response (UDP or TCP, evidence `dns_rcode`, v0.43) with rcode `servfail`, `nxdomain` or `refused`; a single flow signal for resolution failures, not a judgement about the name |
| `tls-encrypted-client-hello` | low | ClientHello (TLS or QUIC) with an outer `encrypted_client_hello` extension (`tls_ech=outer`, v0.42): the `server_name` and any hostname mapping refer to the client-facing public name; the real server name is encrypted and the inner offer is not visible. An inner-type extension or a GREASE-shaped one that fails structure never flags |
| `tls-certificate-lifetime-excessive` | low | Leaf validity longer than 398 days (`tls_certificate_lifetime_days`), the CA/Browser Forum baseline since September 2020 |
| `ntlm-authentication` | medium | NTLM offered or performed (v0.56): `gss_mechanism` of `ntlm`, `ntlm-response` or `lm-response` on an SMB2/SMB1 session setup or an LDAP GSS-SPNEGO bind, or an HTTP/1 or HTTP/2 `Authorization`/`WWW-Authenticate` scheme `ntlm` (`http_auth_scheme`, `http_auth_challenge`, `http2_*`). Relay and legacy hash exposure; Kerberos and NEGOEX never flag |
| `http-basic-authentication` | medium | HTTP/1 or HTTP/2 request with an `Authorization` or `Proxy-Authorization` header whose scheme is `basic` (any occurrence, not only the first) in a session without encryption (v0.56); the credential bytes are never read |
| `smb-guest-or-anonymous-session` | low | SMB2 SESSION_SETUP response with the guest or null-session flag, or an SMB1 SESSION_SETUP_ANDX response with the guest action bit (`smb_session`, v0.56) |
| `smb-signing-not-required` | medium | SMB2/3 NEGOTIATE response (v0.59) with `smb_signing=enabled`: the server signs only when the client insists, so sessions can be relayed (with NTLM) or tampered with. A client request's `enabled` never raises it |
| `database-encryption-unavailable` | medium | The database server cannot encrypt the session (v0.61): a MySQL greeting without CLIENT_SSL (`mysql_tls_supported=false`), or a TDS PRELOGIN response with ENCRYPT_NOT_SUP (`tds_session_encryption=none`; the LOGIN7 password is then protected only by TDS's reversible obfuscation) |
| `database-session-unencrypted` | medium | The database session proceeds without transport encryption (v0.61): a MySQL HandshakeResponse41 (`mysql_client_ssl=not-requested`) or PostgreSQL StartupMessage (`postgresql_message=startup`) seen in the clear, or a TDS PRELOGIN response encrypting only the login packet (`login-only`) or nothing (`none`). Offers (TDS request, MySQL SSLRequest, PostgreSQL SSLRequest/GSSENCRequest) never raise it, and the two "seen in the clear" cases count only for wire bytes: a handshake a host decrypted out of TLS (`feed_decrypted`, `Inspector(source="decrypted")`) was protected |
| `snmpv3-unauthenticated` | medium | SNMPv3 message at noAuthNoPriv (`snmp_security_level`, v0.62): operations and values are neither authenticated nor encrypted. An engine-discovery request (`snmp_usm_discovery=request`) and a Report PDU never raise it (RFC 3414 sends both below the session's level) |
| `snmpv3-no-privacy` | low | SNMPv3 message at authNoPriv other than a Report (v0.62): authenticated, but OIDs and values travel in cleartext |
| `kerberos-weak-etype-offered` | low | Kerberos AS-REQ or TGS-REQ (v0.63) whose `etype` list includes RC4-HMAC, single DES or 3DES (`kerberos_etype_offered` of `rc4`, `des`, `des3`; deprecated by RFC 6649 and RFC 8429). Common for compatibility; an offer, not the KDC's choice |
| `kerberos-weak-etype-selected` | high | Kerberos AS-REP or TGS-REP (v0.63) whose reply `enc-part` or ticket is encrypted with RC4-HMAC, DES or 3DES (`kerberos_reply_etype`, `kerberos_ticket_etype`): the key is exposed to offline cracking; an RC4 service ticket in a TGS-REP is the Kerberoasting case |
| `rdp-nla-not-negotiated` | medium | RDP Connection Confirm (v0.60) with `rdp_selected_security` `standard-rdp` or `tls`: no network level authentication (CredSSP), so the logon screen and its attack surface are reachable before authentication. Offers and negotiation failures never raise it |
| `smb-encryption-unavailable` | low | SMB2/3 NEGOTIATE response (v0.59) whose selected dialect cannot encrypt (`smb_encryption=unavailable`: 2.0.2, 2.1) or does not offer it (`not-supported`: 3.0/3.0.2 without the encryption capability, 3.1.1 without a common cipher) |
| `ssh-weak-algorithm-offered` | medium | An SSH KEXINIT (v0.58) offers a weak class (`ssh_weak_algorithm`): SHA-1 key exchange, DSA host keys, RC4, 3DES or 64-bit block ciphers, CBC mode, MD5 or truncated MACs, or no MAC. `hostkey-rsa-sha1` (ssh-rsa) is reported but does not raise the risk alone; `cipher-none` raises its own risk. An offer, not the negotiated choice |
| `ssh-none-cipher-offered` | high | An SSH KEXINIT offers the `none` cipher in either direction (v0.58) |
| `ssh-terrapin-exposed` | medium | An SSH KEXINIT offers ChaCha20-Poly1305, or an encrypt-then-MAC MAC with a CBC or 64-bit-block cipher in the same direction, without a strict key exchange marker (`ssh_terrapin=exposed`, CVE-2023-48795, v0.58) |
| `tls-no-forward-secrecy` | medium | ServerHello key exchange without forward secrecy (`selected_key_exchange`, v0.57): `static-rsa` (TLS_RSA_*), `static-ecdh` (TLS_ECDH_* suites keyed by the certificate) in TLS 1.2 or DTLS 1.2, or `psk` (TLS 1.3 `pre_shared_key` without `key_share`). The selection is the server's assertion; completion is unverified |
| `tls-ca-certificate-as-leaf` | medium | With `--certificates` (v0.57): the leaf's basicConstraints asserts cA TRUE (`tls_certificate_ca=yes`), a CA certificate presented as the end entity |
| `tls-certificate-not-for-server-auth` | medium | The leaf's extendedKeyUsage lists neither id-kp-serverAuth nor anyExtendedKeyUsage (`tls_certificate_eku=other`, v0.57). An absent extension never flags |
| `tls-certificate-without-san` | low | v3 leaf without subjectAltName (`tls_certificate_san=absent`, v0.57); current clients ignore the subject common name. v1/v2 leaves carry no `san` label and never flag |
| `tls-certificate-outside-validity` | medium | The leaf's validity window (calendar days, `tls_certificate_not_before`/`_not_after`) does not contain the capture time the host supplied (v0.57): the session's first packet offline, the event's packet live. Boundary days count as inside; capture clocks before 2000-01-01 count as unset and never flag; without a capture time (`classify` without `at`) the risk is never evaluated |

Severities are editorial defaults for policy authoring (`protocol_engine.risks.RISKS`).
`protocol_engine.risks.flow_risks(verdict, client, server, at=None)` is one pass over
each direction's evidence (about 1-2 µs) and returns a sorted tuple.

## Unknown-payload heuristics

With heuristics on, a stream whose prefix no family selects (dispatch says
unknown) collects up to `heuristic_bytes` (default 512, 16..65536) before the
`unknown` observation is published (or the stream ends); a datagram is profiled
as a whole, bounded by the same limit. The profile is one pass with a 256-entry
histogram:

| Evidence | Meaning |
|---|---|
| `payload_bytes_profiled` | bytes used (<= heuristic_bytes) |
| `payload_entropy` | Shannon entropy, bits per byte, 0.00..8.00 |
| `payload_printable` | fraction of bytes in 0x09, 0x0a, 0x0d, 0x20..0x7e |
| `payload_class` | `insufficient` (< 8 bytes); `text` (printable >= 0.95); `high-entropy` (>= 64 bytes and entropy >= 0.90 x log2(min(size, 256)), the maximum a sample of that size can reach); `sparse-binary` (>= 30% zero bytes); else `binary` |

Encrypted, compressed and random data are indistinguishable at this level:
`high-entropy` means "no plaintext structure", not "a tunnel". With heuristics
on, an unknown stream's observation is published later (after up to
heuristic_bytes instead of at the first undispatchable bytes); custom
unknown-payload signatures use the larger of `signature_bytes` and
`heuristic_bytes`. No payload byte, hash or sample is emitted.

## DNS query-name shape

With heuristics on, every validated DNS message gains `dns_query_labels`,
`dns_query_longest_label`, `dns_label_entropy` (highest byte entropy among
labels of 16+ bytes, lower-cased) and `dns_query_shape`: `suspicious` when a
label is 40+ bytes, the name is 150+ bytes, or a label of 16+ bytes has
entropy >= 4.0 bits per byte; otherwise `ordinary`. The query name itself is
not emitted (it remains available only as a signature context when contexts
are retained). Long encoded labels (tunnelling), algorithmically generated
names and legitimate content-hash labels all trigger it; it is a triage hint.

## Not implemented

Certificate validation (signature, chain, name match, revocation; expiry is
judged only against the capture time a host supplies, never a wall clock),
TLS 1.3 certificates (encrypted), cipher-strength grading beyond forward
secrecy and AEAD versus CBC, HTTP header anomaly
scoring, port scan or probing detection, periodicity/beaconing analysis, byte
distribution learning, and any risk that needs more than the initial message.
