# Session summary: v0.38 to v0.52 and what the product does today

Branch `claude/appid-engine` (origin `leenadav/protocol-detector`), head
a2f8e90, version 0.52.0. Every milestone below shipped with tests, fixtures,
documentation (PROTOCOLS, APPID, RISKS, README, REVIEW-SCOPE,
SECURITY-REQUIREMENTS, START-HERE in Hebrew), a regenerated coverage matrix
where fixtures changed, a benchmark record where a hot path changed, and the
full gate set green: unit/fuzz/property tests on Python 3.11 and 3.13, ruff,
compileall, policy lint, coverage-matrix check, security-requirements check,
and the whole-engine behaviour diff against the parent commit. CI (ci,
codeql) was green on every pushed commit checked (v0.48 through v0.50 at the
last look; v0.51 and v0.52 were queued).

## What changed in this session

| Version | Change |
|---|---|
| v0.38 | SNMPv3 message profile: global header, msgFlags rules, USM parameters bounded and never emitted, plaintext or encrypted scoped PDU. |
| v0.39 | TLS 1.2 server Certificate watch (`Config(certificates=True)`): bounded DER walk of the leaf (`x509.py`), evidence `tls_certificate_*` (version, self-issued, key, signature, lifetime), risks for self-issued, weak key, weak signature and excessive lifetime; `certificate` object in session records and schemas. |
| v0.40 | MSSQL TDS PRELOGIN/response and Oracle Net (TNS) CONNECT/ACCEPT/REFUSE/RESEND families. |
| v0.41 | OPC UA Hello/Acknowledge/Error/ReverseHello; SOCKS5 server direction (method selection, reply). |
| v0.42 | Encrypted ClientHello awareness: `tls_ech` outer/inner structure on TLS and QUIC ClientHellos, risk `tls-encrypted-client-hello`. |
| v0.43 | SNMP Response, Set, Trap (v1 and v2), Inform PDUs; DNS result codes with the `dns-error-response` risk; precomputed DNS evidence rows (benchmark V043). |
| v0.44 | SMB2 NEGOTIATE responses (dialect, signing, 3.1.1 contexts), Kerberos AS/TGS replies and KRB-ERROR (risk `kerberos-error-response`), DCE/RPC bind_ack/bind_nak. |
| v0.45 | PostgreSQL server messages (authentication, error class), LDAP BindResponse, CQL responses, MySQL HandshakeResponse41 (auth plugin, SSL not requested). |
| v0.46 | DTLS HelloVerifyRequest/ServerHello, RADIUS Accept/Reject/Challenge (risk `radius-access-reject`), OpenVPN server hard reset, IKEv2 SA_INIT response. |
| v0.47 | Modbus normal and exception responses (risk `modbus-exception-response`), GIOP Reply/LocateReply, TACACS+ reply, SMB1 NEGOTIATE response, AMQP Connection.Start. |
| v0.48 | Generated direction coverage matrix (`tools/coverage_matrix.py`) embedded in PROTOCOLS.md and gated in CI and `make check`. |
| v0.49 | Direction evidence for DHCP, NTP, MongoDB, WireGuard; TFTP OACK/ERROR, L2TP and PPTP replies, memcached binary responses, git ref advertisement, FastCGI application records. |
| v0.50 | RFC 7541 HPACK decoder (`hpack.py`, nibble-table Huffman) and the first HTTP/2 HEADERS block on both sides: method, scheme, `:authority` host, extended-CONNECT protocol, content-type class, server status; `grpc` application; six `http2-*` signature contexts; `h2_pseudo_order` fingerprint; server side of prior-knowledge HTTP/2 expected from the client preface (`Inspector.expect`); shifted phases that continue are merged correctly. |
| v0.51 | ONC RPC v2 (TCP records and UDP; AUTH_NONE/AUTH_SYS validated; `portmapper`, `nfs`, `sun-rpc`), Diameter CER/CEA, ZeroMQ ZMTP 3.x greeting, Neo4j Bolt handshake; HTTP/1 `http_method`, `http_content_type` and `http_accept` evidence; `dns-over-https`. |
| v0.52 | XMPP stream header in both directions (domain as hostname), syslog over TCP (RFC 6587 octet counting and non-transparent framing), App-ID `webdav`, `ipp`, `ocsp`, `soap` from HTTP methods and content classes. |
| v0.53 | X11 connection setup (hinted server reply), SPICE link messages and replies, AFP session opening over DSI, Omron FINS/TCP, RIP v1/v2 and hinted RTCP. |
| v0.54 | LDAP ExtendedRequest/ExtendedResponse with the `ldap-starttls` shift (named server success; client and unnamed-success directions opened by message-id correlation in the analyzer, with retained bytes replayed from the reassembly buffer and the replay's events delivered to live output on their own direction); IRC family (client registration and `:`-prefixed server lines, four-parameter USER ambiguous with FTP); TURN methods and attributes over STUN (`turn`); `dns_query_type` with NetBIOS NB/NBSTAT (`netbios-ns`); RPC over HTTP methods (`ms-rpc-over-http`). |
| v0.55 | Name services on the DNS layout: `mdns` (markers: `.local`, QU/cache-flush bits, several questions, announcements; profile reported), `netbios-ns` as a family (query, registration, release, WACK, refresh and responses), hint-only `llmnr`; the DNS-layout candidate rule admits the rarer layouts only under a plausibility check. |
| v0.56 | Authentication mechanism evidence: `gss.py` SPNEGO/GSS/NTLMSSP token classifier; SMB2/SMB1 session-setup watch after NEGOTIATE (`gss_mechanism`, `ntlm_message`, `smb_session`, request-side `smb_signing`); LDAP `ldap_bind` labels; HTTP/1 and HTTP/2 `Authorization`/`WWW-Authenticate` scheme classes; risks `ntlm-authentication`, `http-basic-authentication`, `smb-guest-or-anonymous-session`. |
| v0.57 | TLS posture: ServerHello `selected_key_exchange` (ecdhe, dhe, static-ecdh, static-rsa, psk) and `selected_cipher_mode` (aead, cbc) for TLS 1.2/1.3 and DTLS 1.2; leaf `tls_certificate_ca`, `tls_certificate_eku`, `tls_certificate_san`, day-granular `not_before`/`not_after`; validity judged at the capture time the host supplies; risks `tls-no-forward-secrecy`, `tls-ca-certificate-as-leaf`, `tls-certificate-not-for-server-auth`, `tls-certificate-without-san`, `tls-certificate-outside-validity`. |

Numbers moved from 59 families / 60 applications / about 420 tests at the
start of the session to 75 families (68 automatic), 87 catalog applications,
19 flow risks, 31 signature contexts, 50 security requirements mapped to
tests, 18 threat-model rows, and 546 tests. The coverage matrix proves both
sides (or a symmetric shape) for 63 of the 75 families; the remaining server
sides are listed in PROTOCOLS.md with the structural reason each is out of
reach.

## What the application does

Passive, dependency-free (Python 3.9+) application identification for IPv4
TCP and UDP traffic, in the vocabulary of a next-generation firewall App-ID:

- **Structural protocol profiles.** 75 families, each a documented
  initial-message profile with explicit exclusions: web (HTTP/1.x, HTTP/2 with
  HPACK, WebSocket, QUIC with Initial decryption, TLS and DTLS handshakes,
  SOCKS5), mail and messaging (SMTP, POP3, IMAP, XMPP, MQTT, AMQP, STOMP,
  NATS, Kafka, ZeroMQ, RTSP, SIP, RTP), remote access and tunnels (SSH, Telnet,
  RDP, VNC, OpenVPN, WireGuard, IKEv2, L2TP, PPTP), directory and
  authentication (LDAP, Kerberos, RADIUS, TACACS+, Diameter, DCE/RPC, ONC RPC
  with NFS and portmapper), file and storage (SMB1/2/3, FTP, TFTP, rsync, git,
  BitTorrent, NetBIOS), databases (MySQL, PostgreSQL, MongoDB, Cassandra CQL,
  Redis RESP, memcached, MSSQL TDS, Oracle TNS, Neo4j Bolt), industrial
  (Modbus, DNP3, BACnet, EtherNet/IP, IEC 104, S7comm over ISO-TSAP, OPC UA),
  infrastructure (DNS, DHCP, NTP, SNMP v1/v2c/v3, syslog UDP and TCP, NetFlow,
  IPFIX, sFlow, STUN, SSDP, CoAP, BGP, FastCGI, GIOP). Hints select candidates
  but never establish identity; every length, count and depth is checked
  against a budget.
- **Both directions and session verdicts.** Client and server messages are
  recognised separately, merged into one verdict with `port_usage`
  (application-default), `implicitly_uses`, `depends_on`, category, risk and
  characteristics; ambiguous text directions are correlated; application
  shifts (CONNECT tunnels, WebSocket and h2c upgrades, STARTTLS, SSLRequest,
  RDP negotiation) are followed into the new phase.
- **Application refinement without payload leakage.** Hostnames from SNI,
  Host, `:authority` and XMPP stream addresses (asserted, mappable by
  `RuleIndex`); content classes name gRPC, DNS over HTTPS, IPP, OCSP, SOAP and
  WebDAV; custom signatures over 31 bounded contexts; configured host
  mappings. Evidence is a closed vocabulary with provenance and strength
  (structural, asserted, offered, derived, context); credentials, keys, paths,
  cookies, identities and message bodies are never emitted.
- **Fingerprints and risks.** JA3, JA4, JA3S, JA4S, HASSH, Akamai-style HTTP/2
  SETTINGS and pseudo-header order; 19 documented flow risks (cleartext
  credentials, obsolete protocols, weak or self-issued certificates, ECH,
  error responses, suspicious DNS names, non-standard ports, high-entropy
  unknown payloads) and a policy engine (`POLICY.md`) that turns verdicts and
  risks into allow/alert/block decisions.
- **Inputs and outputs.** Offline PCAP and pcapng analysis with TCP
  reassembly (overlap conflicts invalidate), live capture from tcpdump or
  stdin, readable and JSON Lines output validated by published schemas
  (session records, live events, offline rows), a single `protodetect` CLI
  (analyze, live, protocols, apps, risks, demo, policy, signatures, schema).
- **Engineering guarantees.** Zero runtime dependencies, byte/count/depth
  budgets on every parser, seeded fuzzing and mutation tests per family, a
  per-commit whole-engine behaviour diff, security requirements each mapped
  to executable tests, a threat model, and an SSDLC CI (ruff, bandit, CodeQL,
  gitleaks, SBOM, pinned actions, nightly fuzz, release workflow).

## Deliberate limits (unchanged)

Initial-message inspection, not a full session validator; IPv4 only; no
decryption beyond QUIC Initial protection and host-supplied `feed_decrypted`
plaintext; no port-based inference; no proprietary signature corpus or cloud
lookup; benchmarks measure local CPU work, not gateway latency.
