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
| `cleartext-credential-protocol` | medium | Identified application whose catalog characteristics include `cleartext-credentials` and no encryption in the session (FTP, POP3, IMAP, SMTP, Telnet, HTTP, SNMPv1/v2c, ...). A STARTTLS/AUTH TLS shift to `ssl` clears it; an identified `snmp/3` message (v0.38) is exempt because USM never places the key on the wire | ZeroMQ (ZMTP) counts only with the PLAIN mechanism; NULL carries no credentials and CURVE/GSSAPI authenticate cryptographically (v0.51). RIP counts only with v2 simple-password authentication; unauthenticated and MD5-authenticated datagrams do not (v0.53). An LDAP StartTLS request alone is not exempt: the risk clears only once the correlated shift to `ssl` is established, since the client continues in plaintext after a refusal (v0.54, review round 1).
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

Severities are editorial defaults for policy authoring (`protocol_engine.risks.RISKS`).
`protocol_engine.risks.flow_risks(verdict, client, server)` is one pass over
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

Certificate validation (signature, chain, name match, revocation, expiry
against a clock: the engine has no clock and emits only the lifetime), TLS 1.3
certificates (encrypted), TLS cipher-strength assessment, HTTP header anomaly
scoring, port scan or probing detection, periodicity/beaconing analysis, byte
distribution learning, and any risk that needs more than the initial message.
