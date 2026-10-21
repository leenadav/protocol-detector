# Protocol detector v0.38

A standalone Python 3.9+ protocol classification engine and passive observation
tool. **70 protocol families**, with explicit profiles rather than claims of full
protocol/session validation. No Python runtime dependencies. Live capture uses
an installed `tcpdump`; ordinary demos and tests require no capture privileges.
We are staying in Python. This release does not integrate with or modify an SWG.

Start with [START-HERE.md](START-HERE.md) for Hebrew instructions.

## Capabilities at v0.30

| Area | What exists | Where to read |
|---|---|---|
| Protocol profiles | 85 families (76 automatic, 9 hint-only or shift-only), each a bounded initial-message structural profile with documented exclusions; TCP reassembly and UDP datagrams, IPv4 only, from live tcpdump, classic PCAP or pcapng | [PROTOCOLS.md](PROTOCOLS.md) |
| Application verdicts | App-ID style vocabulary: 99 catalog applications with category, technology, risk, characteristics, ports and dependencies; session outcomes (`unknown-tcp`, `incomplete`, ...); bidirectional correlation of ambiguous text; `port_usage` (application-default) | [APPID.md](APPID.md) |
| Application shift | CONNECT, WebSocket/h2c upgrade, STARTTLS/STLS/AUTH TLS, PostgreSQL/MySQL SSLRequest, RDP negotiation: the phase after the boundary is inspected and the carrier is kept as `shifted_from` | PROTOCOLS.md (v0.28) |
| Custom signatures | JSON rules over bounded parser contexts (host, SNI, ALPN, banner, query name, payload prefix) with a safe regex subset | [SIGNATURES.md](SIGNATURES.md) |
| Fingerprints | JA3/JA4/JA3S/JA4S/HASSH/HTTP2 SETTINGS, opt-in, derived evidence only | [FINGERPRINTS.md](FINGERPRINTS.md) |
| QUIC | v1/v2 client Initial recognition with protection removal (public keys) and ClientHello recovery; HTTP/3 ALPN as an offer | PROTOCOLS.md (v0.25) |
| Heuristics and risks | Opt-in entropy/printable profile of unknown payload and DNS name shape; ten documented flow risks on every verdict | [RISKS.md](RISKS.md) |
| Policy | Ordered allow/deny/alert rules over verdicts with application-default and dependency lint; labels only, no enforcement | [POLICY.md](POLICY.md) |
| Tools | `protodetect.py` (analyze, live, protocols, apps, risks, demo, policy, signatures, schema, version); `analyze_pcap.py`, `live_capture.py`; JSON output schemas | this file, [OUTPUT.md](OUTPUT.md) |
| Engineering | Zero runtime dependencies, Python 3.9+, byte/count/depth budgets everywhere, 587 tests, seeded fuzzing, per-commit behaviour diff, SSDLC CI (ruff, bandit, CodeQL, gitleaks, actionlint, pip-audit, SBOM, pinned actions, documentation-number gate), threat model and security requirements mapped to tests | [SSDLC.md](SSDLC.md), [CONTRIBUTING.md](CONTRIBUTING.md), [THREAT-MODEL.md](THREAT-MODEL.md), [SECURITY-REQUIREMENTS.md](SECURITY-REQUIREMENTS.md), [ARCHITECTURE.md](ARCHITECTURE.md) |

What it is not: a TLS-terminating proxy, a full TCP stack, an IPv6 or
non-TCP/UDP classifier, a certificate validator, a signature corpus for named
web applications, or a product-identity oracle. Every verdict is as strong as
the structural evidence beneath it and says so in its `reasons`.

## Run

```bash
cd ~/protocol-detector
make test
make demo
make protocols
make interfaces
make live INTERFACE=en0 DURATION=60
# One entry point for every tool (v0.30); subcommands forward to the scripts below:
python3 -B protodetect.py analyze sample-expanded.pcap --sessions --policy policy-example.json
python3 -B protodetect.py live --interface en0 --duration 60 --json --heuristics
python3 -B protodetect.py policy lint policy-example.json --strict
python3 -B protodetect.py protocols      # also: apps, risks, demo, version
```

Live output is one short line per identification, plus periodic/final counters.
No payloads, request paths, communities or credentials are printed or saved.
The default capture is non-promiscuous. It observes copies and does not forward,
block or decrypt traffic. Use an explicit interface; Linux commonly uses `eth0`
or another configured name. Create new connections after capture starts.

```bash
# Real local socket traffic, narrowly filtered loopback capture (IPv4 only):
make live-smoke
# Exercise the same live parser with deterministic synthetic PCAP, no privileges:
make replay-live
# Machine-readable live results with a narrower capture filter:
python3 -B live_capture.py -i en0 --filter 'tcp port 443' --duration 30 --json
```

`live_smoke.py` deliberately creates only local test traffic and verifies HTTP,
TLS client/server hellos and retry, BGP, SMB2/3, DNS, SNMP, TFTP, STOMP, NATS, IMAP, RDP, FastCGI, rsync, Git, GIOP DCE/RPC, DTLS and IKEv2 detections,
including server-direction handshakes. Separate modes also check MySQL, MongoDB
and RADIUS with explicit candidates. It is opt-in, outside
`make test`. `sample-expanded.pcap` is generated synthetic data with reordered
TCP segments and UDP messages on arbitrary ports.

If capture permission is denied, grant permission to the capture helper according
to your OS setup. The `--stdin` mode accepts a classic PCAP pipe from a separately
privileged tcpdump; keep Python unprivileged. See START-HERE for a Mac command.

## New in v0.55 — Name services on the DNS layout

Multicast DNS (`.local` names, QU and cache-flush bits, probes, known-answer
queries and announcements) and the NetBIOS name service (queries,
registrations, releases, refreshes, WACK and responses) become their own UDP
families, told from unicast DNS by structure; LLMNR joins as a hint-only
family because its bytes equal a unicast DNS query. The DNS-layout candidate
rule admits the rarer layouts only under a plausibility check so RIP and DTLS
bytes never compete. 85 families, 76 automatic, 99 applications, 587 tests.

## New in v0.54 — LDAP StartTLS, IRC, TURN, NetBIOS name service and RPC over HTTP

LDAP ExtendedRequest/ExtendedResponse with the `ldap-starttls` shift (a named
server success shifts by itself; the client direction and an unnamed success
are opened by the analyzer only for a success with the same message id); a
new IRC family (client registration lines and `:`-prefixed server lines,
nothing but the message class emitted; four-parameter USER stays ambiguous
with FTP); TURN methods and attributes over STUN framing (`turn`
application); `dns_query_type` evidence with NetBIOS NB/NBSTAT detection
(`netbios-ns`); the RPC_CONNECT/RPC_IN_DATA/RPC_OUT_DATA methods
(`ms-rpc-over-http`). 82 families, 74 automatic, 97 applications, 579 tests.

## New in v0.53 — Remote desktop, storage, ICS and routing greetings

Six new families: X11 connection setup (and the server reply with a hint),
SPICE link messages and replies, AFP session opening over DSI, Omron FINS/TCP
node address exchange and frames, RIP v1/v2 datagrams (simple-password
authentication is the only cleartext-credential case) and hinted RTCP
compound packets. 81 families, 73 automatic, 93 applications, 558 tests.

## New in v0.52 — XMPP, syslog over TCP and HTTP-carried applications

The XMPP stream header is validated in both directions (client, server and
component streams; the `to`/`from` domain becomes an asserted hostname),
syslog gains RFC 6587 TCP framing (octet counting and non-transparent) on top
of the RFC 5424 profile, and App-ID names `webdav` (WebDAV methods on HTTP/1.x
and HTTP/2), `ipp`, `ocsp` and `soap` from the request or response content
class. 75 families, 68 automatic, 87 applications, 546 tests.

## New in v0.51 — ONC RPC, Diameter, ZeroMQ, Neo4j and DNS over HTTPS

Four new families: ONC RPC v2 over TCP records and UDP (calls with validated
AUTH_NONE/AUTH_SYS structures and program labels, accepted and denied replies;
App-ID `portmapper`, `nfs`, `sun-rpc`), Diameter capabilities exchange
(CER/CEA with every AVP header and the mandatory AVPs checked, result class
reported), the ZMTP 3.x greeting (mechanism and bind side; PLAIN is the only
cleartext-credential case) and the Neo4j Bolt handshake (server reply with a
hint). HTTP/1.x requests report the method and the content-type class like
HTTP/2, and `dns-over-https` is named from an `application/dns-message`
content or accept header on either HTTP version. 74 families, 67 automatic,
82 applications, 538 tests.

## New in v0.50 — HPACK-decoded HTTP/2 HEADERS and gRPC

HTTP/2 inspection continues past the initial SETTINGS: the first HEADERS block
(with CONTINUATION, padding and priority) is decoded with a bounded RFC 7541
HPACK decoder and validated against RFC 9113's header rules. The engine emits
method, scheme, `:authority` host, extended-CONNECT protocol, content-type
class and the server's status code as closed labels, never header values.
`grpc` joins the catalog (POST with an `application/grpc` content type), HTTP/2
CONNECT maps to `http-proxy`, WebSocket over extended CONNECT to `websocket`,
and configured host mappings and six new `http2-*` signature contexts apply to
HTTP/2. The offline analyzer expects the server side of a prior-knowledge
HTTP/2 connection once the client preface identified it. 513 tests.

## New in v0.49 — Direction evidence and the last structural replies

DHCP, NTP, MongoDB and WireGuard now report which side they saw; TFTP OACK and
ERROR, L2TP and PPTP replies, memcached binary responses, the git server's ref
advertisement and FastCGI application records are validated. The coverage
matrix now shows 58 of 70 families proven on both sides or symmetric; the eight
remaining server sides are documented with the structural reason each is left
out. 484 tests.

## New in v0.48 — Generated direction coverage matrix

`tools/coverage_matrix.py` classifies every fixture and records, per family,
which side of the exchange the engine is proven to identify and every evidence
field it emits; PROTOCOLS.md carries the generated table and CI fails when the
table drifts from the fixtures. The table lists the server sides still open
by name. 476 tests.

## New in v0.47 — ICS and legacy server replies

Modbus normal and exception responses (new low risk `modbus-exception-response`),
GIOP Reply and LocateReply (status reported), the TACACS+ server packet, the SMB1
NEGOTIATE response (three dialect layouts) and the AMQP broker Connection.Start
frame are validated, closing the server side for the remaining TCP families that
had only a client profile. 474 tests.

## New in v0.46 — Datagram server replies

The DTLS server flight (HelloVerifyRequest, ServerHello), RADIUS Access-Accept,
Reject and Challenge (hinted, per-code attribute rules, new low risk
`radius-access-reject`), the OpenVPN server hard reset and the IKEv2
IKE_SA_INIT response (single selected proposal, CERTREQ) are validated, so UDP
flows carry server evidence into their verdicts. 468 tests.

## New in v0.45 — Database and directory server replies

PostgreSQL authentication requests, error responses and version negotiation
(method and SQLSTATE class reported, salts and messages never emitted), the
LDAP BindResponse (result code), Cassandra response frames (ERROR, READY,
AUTHENTICATE, SUPPORTED) and the MySQL client HandshakeResponse41 (plugin
reported, user and database never emitted) are validated, so both directions
of these database sessions carry structural evidence. 463 tests.

## New in v0.44 — Server replies for SMB2, Kerberos and DCE/RPC

The server side of three more families is validated: the SMB2 NEGOTIATE
response (selected dialect, signing mode, 3.1.1 contexts; evidence
`smb_dialect`, `smb_signing`), Kerberos AS-REP, TGS-REP and KRB-ERROR on UDP and
TCP (evidence `kerberos_message`, `kerberos_error`; principals and tickets never
emitted) and DCE/RPC Bind_ack/Bind_nak (evidence `dcerpc_pdu`,
`accepted_transfer_syntax`). The new low risk `kerberos-error-response` marks
KDC errors other than the routine pre-authentication-required step. 458 tests.

## New in v0.43 — Responses, traps and DNS result codes

SNMP now validates every standard PDU kind in v1, v2c and v3: Set, Response,
Inform, SNMPv2-Trap and the v1 Trap-PDU join the read requests, with each
binding's value checked against its SMI type and never emitted; evidence
`snmp_pdu` names the kind. DNS reports `dns_message` and, for responses,
`dns_rcode`; queries carrying answers or a response code are rejected. The
new risk `dns-error-response` marks servfail, nxdomain and refused answers, so
the server side of UDP flows now contributes evidence to the session verdict.
454 tests; BENCHMARK-V043.md records the cost check against v0.39.

## New in v0.42 — Encrypted ClientHello awareness

A TLS or QUIC ClientHello carrying the `encrypted_client_hello` extension is
validated structurally (HPKE suite, config id, enc and payload vectors) and
reported as `tls_ech=outer` or `inner`; the ciphertext is never read. With an
outer extension the visible SNI is the client-facing public name, so the new
low-severity risk `tls-encrypted-client-hello` marks sessions whose real server
name is hidden from passive inspection. 450 tests.

## New in v0.41 — OPC UA and the SOCKS5 server side

`opcua` validates the OPC UA TCP connection messages Hello, Acknowledge,
Error and ReverseHello (size, buffer minimums, bounded printable `opc.tcp://`
URLs and reasons, exact field coverage) and reports the message kind and
protocol version; URLs and reasons are never emitted. The SOCKS5 family now
identifies the server direction too: method selection plus the complete
reply, reported as `socks_method` and `socks_reply`, so both sides of a SOCKS
session carry the `socks` verdict. 70 families, 63 automatic, 74
applications, 447 tests.

## New in v0.40 — MSSQL and Oracle negotiation packets

Two enterprise database families: `tds` validates the MSSQL PRELOGIN packet
and its response (option table, mandatory VERSION/ENCRYPTION, fixed option
lengths) and reports the offered encryption, MARS and federated-authentication
settings; `tns` validates Oracle Net CONNECT, ACCEPT, REFUSE and RESEND
packets (header checksums, version range, connect data placement, printable
descriptor) and reports the version and whether the descriptor is inline or
deferred. Instance names, connect descriptors, thread and trace identifiers
are never emitted. Catalog applications `mssql-db` (tcp/1433) and `oracle`
(tcp/1521). 69 families, 62 automatic, 73 applications, 442 tests.

## New in v0.39 — TLS 1.2 certificate structure

`--certificates` (`Config(certificates=True)`) keeps the TLS parser after a
TLS 1.2 ServerHello and walks the first certificate of the Certificate message
as bounded DER: chain shape, X.509 version, issuer-equals-subject, public key
family and size, signature algorithm family and validity lifetime. Session
records carry a `certificate` object with those labels; names, serials, keys
and signature bytes are never emitted, and nothing is verified. Four flow
risks follow (self-issued, weak key, weak signature, lifetime over 398 days).
Any deviation ends the watch and keeps the ServerHello identification. About
80 µs per TLS 1.2 server flight (BENCHMARK-V039.md). 436 tests pass.

## New in v0.38 — SNMPv3

The SNMP profile covers version 3: the global header (flags rules, size and
model bounds), USM security parameters within RFC 3414 limits, and a plaintext
Get/GetNext/GetBulk/Report scoped PDU or an encrypted one. Reported as
`snmp/3` with `snmp_security`, `snmp_scoped_pdu` and `snmp_flags` evidence;
users, engine ids, keys and values are never emitted. 429 tests pass.

## New in v0.37 — behaviour diff against the previous commit

`tools/compare_engine.py BASELINE_TREE` feeds every stream and datagram
fixture, every truncation, a 3-byte fragmentation and seeded mutations through
the working tree and another checkout, and reports per family where the
terminal observation differs. CI runs it against the parent commit on every
push and uploads `behaviour-diff.md`, so a change that alters what the engine
says about an input is visible even when the suite stays green. 425 tests.

## New in v0.36 — server frames after an h2c upgrade

A `101 Switching Protocols` with `Upgrade: h2c` now shifts the server
direction to a preface-less HTTP/2 parser (`http2-server`, reachable only
through the shift or an explicit candidate): the server's initial SETTINGS
frame is validated with the client rules and no client fingerprint is derived.
Both directions of an h2c upgrade therefore end as `http/2` shifted from
`http/1.1`. 424 tests pass.

## New in v0.35 — faster ClientHello parsing, same errors

The TLS ClientHello walk (the engine's hottest parser) now uses index
arithmetic instead of per-field helper calls: a ClientHello inspection drops
from about 73 to 55 µs. Every bound raises the same error as before; a
differential tool (`tools/compare_client_hello.py`) replays every truncation
and thousands of seeded mutations against another source tree and reports zero
differences in result or exception against v0.34. BENCHMARK-V035.md.

## New in v0.34 — published output schemas

Every JSON line the tools emit now conforms to a JSON Schema in `schemas/`
(`session`, `live-event`, `offline-row`), validated in the test suite under
every option that changes the output shape and checkable in the field with
`protodetect schema NAME --validate FILE` or `tools/schema_check.py` (a
dependency-free draft-07 subset validator). Objects are closed
(`additionalProperties: false`), enumerations are listed, and the contract is
documented in [OUTPUT.md](OUTPUT.md). 424 tests pass.

## New in v0.33 — both sides of a CONNECT tunnel

The Analyzer correlates the two directions of an HTTP CONNECT: once the client
request and the server's 2xx are both identified, the server direction is
reopened as the tunnel (`Inspector.open_shift`, evidence source `wire:peer`)
and its later bytes are inspected, so the TLS ServerHello inside the tunnel
yields `selected_tls_version`, server fingerprints and risks, and
`server_protocol` becomes `tls`. Other answers or plain requests open nothing;
a failed tunnel phase keeps the HTTP identification. HTTP responses now carry
`http_status` evidence. 421 tests pass; BENCHMARK-V033.md.

## New in v0.32 — S7comm after the ISO-TSAP connection

The ISO-TSAP profile now validates the server's X.224 Connection Confirm as
well as the client's request, and both announce a `cotp-connect` shift: the
next message in each direction is inspected as **S7comm** (new family; header,
ROSCTR, public function codes, setup-communication fields; addresses and values
never decoded). The TPKT route tells RDP confirms (RDP_NEG_RSP/FAILURE) from
ISO-TSAP confirms structurally. Verdicts name `s7comm` (business-systems/
ics-protocol, tcp/102) with `shifted_from=iso-tsap`. Coverage: 67 families,
74 catalog applications; 418 tests pass. BENCHMARK-V032.md.

## New in v0.31 — pcapng input

Offline analysis (`analyze_pcap.py`, `protodetect analyze`) and live replay
(`live_capture.py --stdin`) accept **pcapng** captures as well as classic
PCAP: Section Header, Interface Description, Enhanced and Simple Packet Blocks
with options, several interfaces and several sections; statistics, name
resolution, decryption-secrets and custom blocks are skipped. Every block
length is checked against its trailer and a 1 MiB + 64 KiB bound before any
byte is read, and a failure closes the decoder as before. The offline reader
now streams through the same decoder as the live path, so raw IPv4, Linux
cooked and loopback captures work offline too. IPv6 and non-TCP/UDP packets
remain counted as unsupported. 415 tests pass; BENCHMARK-V031.md.

## New in v0.30 — policy evaluation and one command line

A JSON **policy** (POLICY.md) is evaluated on every session verdict: ordered
rules match applications (names, aliases or session outcomes), categories,
technologies, risk scores, characteristics, flow risks, port usage, transports
and server ports, encryption and the carrier after an application shift;
`application_default` rules match only on an application's standard ports, as
in application-aware firewalls. The first match decides `allow`, `deny` or
`alert`, else the policy default; decisions and the reasons behind them appear
in session records, live events and summaries. `Policy.lint` warns about
allowed applications whose implicitly-used or depended-on applications the
policy denies, and about rules that can never match. The engine enforces
nothing; the label is for the host. `protodetect.py` is the single entry
point (`analyze`, `live`, `protocols`, `apps`, `risks`, `demo`, `policy
lint|test`, `signatures lint`, `version`) and forwards to the existing scripts.
This closes the App-ID roadmap (ROADMAP-APPID.md): 66 families, 70 catalog
applications, 10 flow risks, 410 tests. BENCHMARK-V030.md.

## New in v0.29 — unknown-traffic heuristics and flow risks

Every verdict now carries **flow risks**, advisory names in the spirit of nDPI
(`nonstandard-port`, `cleartext-credential-protocol`, `obsolete-protocol` for
SMB1/Telnet/SSH 1.99/TLS < 1.2/RDP standard security, `tls-legacy-version-offer`,
`tls-missing-sni`, `malformed-protocol`, `http-proxy-tunnel`,
`desktop-or-file-sharing-session`, and with heuristics on
`unknown-high-entropy-payload` and `dns-suspicious-query-name`). They appear in
session records, classification events and live summaries. With
`--heuristics` (`Config(heuristics=True)`, off by default) an unknown payload
prefix is profiled (entropy, printable ratio, class) within `heuristic_bytes`
and DNS query names gain shape evidence; the status stays `unknown`, nothing is
identified by a heuristic, and no payload byte is emitted. TLS ClientHellos
now always record the highest offered version and SSH banners their version.
See [RISKS.md](RISKS.md) for every risk, threshold and limit. 402 tests pass;
BENCHMARK-V029.md.

## New in v0.28 — application shift at structural boundaries

A message that announces a protocol change now ends the carrier's inspection
exactly at the boundary, and the bytes after it are inspected as a new phase:
HTTP `CONNECT` (tunnel contents, usually TLS; verdict `ssl` shifted from
`http-proxy`), `Upgrade: websocket` requests and `101` responses (new
**WebSocket** frame-header family), `Upgrade: h2c`, SMTP `STARTTLS` (watched
after EHLO), IMAP `STARTTLS`, POP3 `STLS`, FTP `AUTH TLS`, PostgreSQL and MySQL
`SSLRequest`, and RDP security negotiation (the server Connection Confirm is now
parsed too). The carrier identification is published first and never removed;
a shifted phase that identifies is published as a `shifted` event with
`shift`/`shift_from` evidence, one that fails leaves `shifted_payload` context.
Session verdicts carry `shifted_from`, add the carrier to `implicitly_uses` and
accept the carrier's standard port (ssl after STARTTLS on 587 is `standard`).
Both phases share one byte budget. Coverage is **66 families, 60 automatic**,
70 catalog applications (`http-proxy`, `websocket` added); 391 tests pass. See
PROTOCOLS.md (v0.28 section), APPID.md and BENCHMARK-V028.md.

## New in v0.27 — 23 more decoders and greeting/command correlation

Coverage grows from 41 to **65 families, 60 automatic** (381 tests). New TCP
profiles: FTP, POP3 (client and server), IMAP tagged client commands, Telnet
negotiation, SMB1 negotiate, NetBIOS session request, Kerberos AS/TGS requests
(also UDP), TACACS+, OpenVPN over TCP, PPTP, Modbus/TCP, DNP3 (CRC-verified),
ISO-TSAP (RFC 1006/X.224), EtherNet/IP (also UDP), IEC 60870-5-104, Kafka and
Cassandra CQL v4. New UDP profiles: WireGuard and OpenVPN (reported as
`encryption`), L2TPv2, SSDP, NetFlow v5/v9, IPFIX, sFlow v5, BACnet/IP, and RTP
with an explicit hint only. Text lines shared by several protocols (`220`
greetings, `USER`/`PASS`/`QUIT` …) are no longer guessed: the direction reports
`unknown` with an `ambiguous_candidates` context, and the session verdict
intersects both directions (`220` + `USER` becomes `ftp` with status
`correlated`). The application catalog has 68 entries. v0.26 (IP-level
protocols) was dropped; the engine stays an application-layer classifier over
TCP/UDP. See PROTOCOLS.md (v0.27 section) and BENCHMARK-V027.md.

## New in v0.25 — QUIC Initial recognition with ClientHello recovery

QUIC v1 and v2 client Initial packets are recognized structurally, and their
protection is removed with the public Initial keys (version salt plus
Destination Connection ID; pure-Python AES-128-GCM, HKDF-SHA256 and header
protection, all verified against FIPS-197, NIST GCM and RFC 9001/9369 vectors).
The CRYPTO stream is assembled, within one datagram or across Initials through
a bounded host-owned assembler, and validated as a TLS ClientHello, giving SNI,
ALPN (`h3` stays an offer) and JA4 with protocol `q`. Version Negotiation is
recognized too. Server Initials, later packets and HTTP/3 framing stay opaque;
decryption is about 2 ms per Initial and can be turned off with
`Config(quic_decrypt=False)`. The RFC 9001 Appendix A client Initial is the
fixture and decrypts to `example.com`. Coverage is **41 families, 37 automatic**;
359 tests pass. See PROTOCOLS.md (QUIC profile) and BENCHMARK-V025.md.

## New in v0.24 — handshake fingerprints and post-identification refinement

`--fingerprints` (`Config(fingerprints=True)`) derives **JA4** and **JA3** from
TLS ClientHello, **JA4** (`d`) from DTLS ClientHello, **JA4S**/**JA3S** from TLS
ServerHello, **HASSH** from the SSH client KEXINIT and an Akamai-style
**HTTP/2 SETTINGS** string. They are `derived` evidence: implementation-family
indicators, never identities. The TLS 1.3 server fixture reproduces the JA4S
specification example `t130200_1301_a56c5b993250`.

SSH shows a new engine mechanism: the banner identifies immediately
(`updated`), then the parser stays attached for exactly one bounded KEXINIT
packet and publishes a `refined` event with `hassh`. A malformed packet, the
budget or EOF ends the continuation without touching the identification.
Session records carry `fingerprints`; live events carry `fingerprints` and
`event` (`updated`/`refined`). `benchmark_ab.py` is a new stable A/B harness
(min over alternating runs) replacing the noise-prone paired percentiles on
shared hosts. 349 tests pass. See [FINGERPRINTS.md](FINGERPRINTS.md) and
BENCHMARK-V024.md.

## New in v0.23 — custom application signatures

Operators can now name applications with **custom signatures**: JSON rules
whose conditions apply to named contexts that a completed structural profile
exposed (`http-req-host-header`, `http-req-user-agent-header`, `http-req-uri-path`,
`ssl-req-chello-sni`, `ssl-req-alpn`, `ssl-req-client-hello-ext-type`,
`ssh-req-banner`, `dns-req-query-name`, `socks-req-target`, …) or to the first
bytes of a stream/datagram that no profile accepted (`unknown-req-tcp-payload`,
`unknown-req-udp-payload`, with length contexts). Operators: `pattern-match`,
`equal-to`, `less-than`, `greater-than`, `negate`, nested `and`/`or`.

Patterns are compiled once and must carry a literal run (7 bytes for raw
payload contexts, 3 for parsed fields), may not nest quantifiers or use
backreferences/lookaround, and run only after a plain substring prefilter; the
unknown-payload buffer is bounded by `Config.signature_bytes` (2000). Contexts
are retained only with `Config(retain_contexts=True)` and never leave the
engine. A match reports the signature name as `application` with evidence
strength `configured_signature`; verdicts use the signature's own category and
risk and name the carrier in `base_app`.

```bash
python3 -B analyze_pcap.py capture.pcap --sessions --signatures signatures-example.json
python3 -B live_capture.py -i eth0 --signatures signatures-example.json
```

See [SIGNATURES.md](SIGNATURES.md) for the file format, every context, the
pattern rules and the evaluation semantics. 339 tests pass; BENCHMARK-V023.md
records context-retention and signature-evaluation costs.

## New in v0.22 — App-ID style verdicts, application catalog and session records

Every connection and UDP flow now receives one **session verdict** in the
vocabulary of application-aware firewalls: a catalog application
(`web-browsing`, `ssl`, `ssh`, `dns`, `smb`, …, or a configured mapping) or a
session outcome (`unknown-tcp`, `unknown-udp`, `insufficient-data`,
`incomplete`, `not-applicable`). The verdict merges both directions, prefers the
client, records a disagreeing server identification, and never upgrades the
structural evidence beneath it. A 44-entry **application catalog** supplies
category, subcategory, technology, risk 1..5, characteristics, standard/secure
ports, implicit-use/dependency links and vendor aliases; `port_usage` reports
application-default violations (`nonstandard`). Session records
(`{"type": "session"}`) carry packets, per-direction payload bytes, start/end,
end reason and the verdict fields; hostnames stay out unless `--hostnames`.
Classification events gain `app`; live summaries gain `apps`.

```bash
python3 -B analyze_pcap.py sample-expanded.pcap --events-only --sessions
python3 -B live_capture.py --stdin --duration 0 < sample.pcap   # SESSION lines appear live
make apps                                                       # print the catalog
```

See [APPID.md](APPID.md) for the exact vocabulary, merge rules and limits.

The repository now also carries an SSDLC pipeline: [SSDLC.md](SSDLC.md) (phases
and gates), [THREAT-MODEL.md](THREAT-MODEL.md) (STRIDE table tied to tests),
[SECURITY-REQUIREMENTS.md](SECURITY-REQUIREMENTS.md) (each requirement names
its test; CI fails on a dangling reference), [SECURITY.md](SECURITY.md)
(reporting policy) and `.github/workflows` (test matrix 3.9/3.11/3.13, ruff,
bandit, CodeQL, gitleaks, SBOM, SHA-pinned actions, hash-pinned dev tools,
nightly fuzzing, attested releases). `make check` runs the local gates.
324 tests pass; BENCHMARK-V022.md records the per-event cost of the verdict layer.
Risk scores and characteristics are editorial policy defaults, not measurements.

## New in v0.21 — IKEv2 negotiation and bounded UDP ambiguity

IKEv2 IKE_SA_INIT requests now have structural recognition, including optional
non-ESP framing. The validator checks proposal/transform nesting, supported
AES-CBC/GCM and HMAC-SHA offers, MODP key widths, nonce size and consistency with
the offers. It identifies the plaintext negotiation protocol; it does not claim
an established IPsec tunnel, encryption, authentication or application identity.

Arbitrary initiator SPI bytes can resemble another UDP protocol. One fixed-position
IKE probe supplements existing candidates, bounded to three validators. Dual
CoAP/IKE or DHCP/IKE interpretations return unknown; a competing work-budget
failure prevents a positive result. There is no registry scan.

Coverage is **40 families,36 automatic**;309 tests pass. A delayed TLS review
finding was independently reproduced and fixed: EC point formats now require an
ECC cipher suite in TLS1.2 ServerHello. `ike_decoder_check.py` optionally verifies
synthetic framing with tcpdump offline. No real IKE peer interoperability claim.
See PROTOCOLS.md and BENCHMARK-V021.md for exact coverage, exclusions and CPU costs.

## New in v0.20 — DTLS over UDP

DTLS1.2 ClientHello now has automatic recognition with exact record, epoch,
handshake, cookie and vector framing. The profile accepts one complete hello per
record/datagram, checks extension counts and reuses SNI/ALPN syntax validation.
It emits `encryption="dtls"`, with no inferred inner application protocol.
Client version, hostname and ALPN remain unauthenticated offers/assertions.

Coverage is **39 families,35 automatic**;294 tests pass. Fragmented handshakes,
coalesced records/messages, encrypted epochs and supported_versions negotiation
are explicitly unsupported. The UDP inspector retains no association state.
`python3 -B dtls_interop.py` verifies an installed TLS client's initial hello and
cookie retry against a synthetic IPv4 loopback responder. It never completes or
authenticates the handshake. Exact profile and CPU results are in PROTOCOLS.md
and BENCHMARK-V020.md. Offline and live readable output both identify the layer.

## New in v0.19 — TLS server hello and retry profiles

TLS recognition now includes ServerHello for TLS 1.2/1.3 and TLS 1.3
HelloRetryRequest. Server-selected version/cipher/group and TLS1.2 ALPN are
reported as unauthenticated assertions. They never set the inner application
protocol, hostname or product mapping. TLS1.3 ALPN is encrypted and is not inferred.
Cross-record assembly, byte budgets and terminal parser release remain shared
with ClientHello. Exact cipher/group/extension limits are in PROTOCOLS.md.

283 tests pass. Optional `python3 -B tls_server_interop.py` checks locally generated
MemoryBIO handshakes without network sockets. Reports cover LibreSSL TLS1.2 and
OpenSSL TLS1.2/1.3 plus retry, validated by the Python3.9 engine; secp256r1 is
explicitly configured. Hybrid/post-quantum groups remain unsupported. Coverage
remains **38 families,34 automatic**: this expands an existing protocol family.

## New in v0.18 — DCE/RPC bind validation

Connection-oriented DCE/RPC 5.0 Bind now has a bounded automatic profile for
unfragmented, unauthenticated presentation offers. Both byte orders are supported,
with NDR 2.0 and NDR64 1.0 transfer identifiers; no RPC interface/product identity
or successful negotiation is inferred. Two-byte dispatch distinguishes RPC from
SOCKS5 without parser fan-out. The 05 00 prefix now waits for an RPC header;
explicit socks5 hints still reject a zero-method greeting immediately.
Coverage is **38 families, 34 automatic**; 270 tests pass. See PROTOCOLS.md and
BENCHMARK-V018.md for profile limits, validation and CPU measurements.

## New in v0.17 — GIOP and bounded CDR parsing

GIOP 1.2 Request/LocateRequest now have automatic structural recognition for
unfragmented KeyAddr messages in either byte order. A bounded CDR cursor checks
alignment, string/sequence lengths and service-context framing. Argument values,
object keys and context payloads remain opaque and are never exposed as identity.
Coverage is **37 families, 33 automatic**; 261 tests pass. HTTP methods starting
with GIOP remain HTTP. See PROTOCOLS.md for exact exclusions and BENCHMARK-V017.md
for measured CPU costs. No production latency or complete CORBA coverage claim.

## New in v0.16 — native Git and bounded ambiguity routing

The engine now validates native Git service requests, including optional virtual
host and version offers, without using ports or publishing repository paths.
Coverage is **36 families, 32 automatic**. Git-over-SSH/HTTPS and packfiles are not
inferred from this initial request. The version offer does not prove negotiation.

A private Git/text route distinguishes NUL-framed Git requests from HTTP extension
methods with the same ASCII prefix. It buffers one bounded field, selects one
parser, replays that field once and delegates; there is no registry scan or
parallel parser fan-out. Explicit `git` hints still run strict Git validation.

252 unit tests pass. `python3 -B git_interop.py` is an opt-in local-only check using
an installed Git client with user/system configuration disabled. The updated
loopback smoke check includes Git. See BENCHMARK-V016.md for measured costs,
including the added cost for an intentionally ambiguous HTTP method.

## New in v0.15 — consistent leading-payload coordinates

Compact FIN comparisons now normalize every leading segment end, including ends
before zero. A harmless payload wholly before the retained origin no longer
retracts a completed direction after FIN. A crossing payload extending past FIN
still invalidates, and pre-origin FINs remain rejected. An independent absolute
coordinate oracle checks 1,680 combinations plus live event regressions; 241 tests
pass. BENCHMARK-V015.md records current CPU measurements and limitations.

## New in v0.14 — pre-origin FIN boundaries

A compact-mode FIN ending before the retained stream origin is now rejected,
with an explicit directional retraction. It cannot become a huge future boundary
that permits later data. A FIN ending exactly at the origin closes an empty
direction; a payload crossing the origin still validates its retained tail.
Five regression tests cover wraparound, prior identifications and boundaries;
239 tests pass. BENCHMARK-V014.md records verification and synthetic CPU costs.
Multiple TCP sequence epochs remain outside this initial-prefix observer.

## New in v0.13 — visible TCP control retractions

Rejected FIN/SYN-ACK/URG/ACK state now publishes a directional `invalidated`
event before releasing tracking. Offline `--events-only` consumers therefore
receive the retraction of a previously identified stream. Live output uses the
same structured event and counts it once. Normal RST/timeout/EOF retirement still
preserves completed initial-message observations. Four new parameterized tests
exercise eight rejection sequences, both directions and offline/live output;
234 tests pass. See BENCHMARK-V013.md for paired CPU measurements and limitations.

## New in v0.12 — review corrections

All three initial GitHub review findings were reproduced and corrected. Prefix
reassembly checks a segment's retained tail even when it starts before the window,
including sequence wrap and FIN. Offline PCAP analysis preserves original wire
length, emits an explicit capture-gap retraction on truncated records, discards
active tracking, and requires new handshakes. Physical PCAP failure retracts all
observations from that capture and exits with an error. Reserved IPv4 flags are
rejected consistently by offline and live decoders.

The legacy `read_pcap` tuple API now raises on captured/original length mismatch;
use `read_pcap_records` for explicit metadata. CaptureRecord remains importable
from capture_stream and is defined in packets. Coverage stays 35 families, 31
automatic; its verification passed 230 tests. See BENCHMARK-V012.md for verification and CPU costs.

## New in v0.11

Reassembly now bulk-compares fully retained retransmissions, bulk-copies new
ranges and searches for the next gap without a Python byte loop. Mixed overlaps
are checked before any write; conflicts still invalidate classification. No new
protocol profiles in this milestone. 218 tests pass; see BENCHMARK-V011.md for
measured improvements and the first-byte conflict tradeoff.

## New in v0.10

RADIUS Access-Request is available through `--udp-hint radius`, with a bounded
PAP/CHAP/State attribute profile. There are **35 families, 31 automatic**; RADIUS,
NTP, MySQL and MongoDB require explicit candidate selection. RADIUS packet length,
TLV boundaries, known widths, singleton counts and required attributes are checked.
Authenticator/HMAC values and credentials are not verified or output. EAP and
responses are outside scope. A test demonstrates bytes valid as both RADIUS and
DNS, so structural validity alone cannot establish sender intent. RADIUS is not
added to automatic candidate competition; a hinted-only profile may overlap an
automatically supported structure. Exact coverage is in PROTOCOLS.md.

```bash
python3 -B live_capture.py --stdin --duration 0 --udp-hint radius < sample-radius.pcap
python3 -B analyze_pcap.py sample-radius.pcap --udp-hint radius --events-only
```

Incomplete stream inspections now finish explicitly on contiguous FIN, idle expiry,
observed RST, capture EOF or capture stop. A FIN beyond a gap waits for missing
bytes; half-close affects its own direction only. Final capture summaries release
all tracked connections. These boundaries are observations, not full endpoint TCP
validation. Existing initial identifications survive normal retirement; capture
loss still invalidates observations. `incomplete` counts directions, including
empty reverse directions, and does not mean the identified protocol was invalid.
Use `--all-events` to see the specific reason; normal summaries include the count.

The inspection byte budget now matches the Analyzer reassembly prefix limit
(64..65536 bytes), so a full prefix cannot remain detecting forever. Callback/clock
reference cycles were removed. FIN checks use the highest retained byte offset
instead of scanning the entire reassembly bitmap. 209 tests cover lifecycle ordering, mutation,
resource limits, independent RFC RADIUS examples and all prior protocol profiles.
See BENCHMARK-V010.md for engine and separately compared capture-adapter CPU costs.

## Previous v0.9 milestone

Automatic **FastCGI** and **rsync daemon** profiles bring coverage to 34 families,
31 with automatic profiles. MySQL, MongoDB and NTP still require explicit hints.
FastCGI requires a valid BEGIN_REQUEST and a complete, structurally validated
PARAMS stream for the same request. Its values can cross records and TCP chunks;
record/parameter counts and aggregate wire bytes are bounded. No CGI variable is
promoted to HTTP or application identity. Rsync validates the full bounded daemon
greeting, including version/subprotocol and digest-offer syntax. Neither profile
validates authentication or the whole session. See [PROTOCOLS.md](PROTOCOLS.md).

Redirected PCAP input now terminates correctly at EOF on macOS; regular files
also avoid epoll's unsupported-descriptor path on Linux. Reads remain bounded
and respect packet/time limits between batches. Pipes retain readiness-based I/O.

181 tests pass. The expanded synthetic PCAP contains 96 packets / 30 detections;
real IPv4 loopback smoke covers 13 families / 15 detections. These are synthetic
validation checks, not production accuracy measurements. See
[BENCHMARK-V09.md](BENCHMARK-V09.md) for the v0.8 comparison and new-path costs.

## Previous v0.8 milestone

MySQL modern server handshakes and MongoDB uncompressed OP_MSG are now supported
with **explicit candidate selection**. There are 32 families: 29 have automatic
profiles; MySQL, MongoDB and NTP require a hint. Hints restrict which parser runs
and are recorded as caller context. The bytes must still pass validation. They
are not port-derived identifications. `supported_protocols()` exposes
`requires_hint` for families without automatic selection.

Database length prefixes collide with unrelated protocol prefixes, so this
release leaves automatic routing unchanged. MySQL checks the full modern V10
handshake for three authentication plugins; MongoDB checks sections, BSON and
optional CRC-32C. Neither validates authentication or database command semantics.
Exact bounds and unsupported formats are in [PROTOCOLS.md](PROTOCOLS.md).

```bash
# Synthetic files; exercise reassembly and readable output without privileges:
python3 -B live_capture.py --stdin --duration 0 --tcp-hint mysql < sample-mysql.pcap
python3 -B live_capture.py --stdin --duration 0 --tcp-hint mongodb < sample-mongodb.pcap
# The older offline analyzer also accepts the candidate:
python3 -B analyze_pcap.py sample-mysql.pcap --tcp-hint mysql --events-only
```

`--tcp-hint` applies to both TCP directions and all selected connections; narrow
live capture filters accordingly. Unsupported directions/phases remain unclassified.
Readable output marks candidate-based results; JSON retains `candidate_hint`.
The explicit API is `Inspector(protocol_hint="mysql")` or `"mongodb"`.

Python CRC-32C has a separate **4096-byte default budget**, including the message
header but excluding the checksum field. Larger checksummed MongoDB messages stop
from their fixed 20-byte header with `budget_exhausted`, before body accumulation.
`Config(max_crc32c_bytes=...)` and `--crc32c-byte-limit` configure it; zero rejects
checksummed messages, never silently skips verification. Raising it increases CPU
cost. Unchecksummed messages still obey the overall byte/structure limits.

165 tests pass, including published BSON/CRC vectors and malformed inputs.
`make live-smoke` now also verifies MySQL and MongoDB, including a checksummed
MongoDB message, using synthetic IPv4 loopback traffic. Performance details and
cost of explicitly raising the CRC budget: [BENCHMARK-V08.md](BENCHMARK-V08.md).

## New in v0.7

Four additional families: STOMP handshake frames, NATS typed INFO/CONNECT JSON,
IMAP server revision capabilities and RDP connection negotiation. Each profile
requires complete framing and validates relevant fields. No port inference,
credential output, authentication claims or promotion of security offers to TLS.
See [PROTOCOLS.md](PROTOCOLS.md) for exact coverage and exclusions.

STOMP has incremental LF/CRLF framing with required NUL termination. NATS and
IMAP reuse first-line framing; JSON has depth, structure, number and UTF-8 limits.
RDP reuses bounded binary framing. HTTP extension methods remain valid even
when named CONNECT, STOMP or INFO. Terminal inspection still releases parser
state. No per-packet registry scan was added. The legacy display derives new
families from the catalog once at import; live capture bypasses that display.

The expanded synthetic PCAP now contains 88 packets / 28 identifications.
147 tests pass. The opt-in IPv4 loopback check covers 11 families over real OS
sockets and capture; payloads are synthetic, not independently labeled traffic.
[BENCHMARK-V07.md](BENCHMARK-V07.md) records measured local CPU costs and limits.

## Changed in v0.6.1

IPv6 packet decoding is removed for the current IPv4-only product scope. Every
owned tcpdump capture combines the requested BPF filter with `ip`, so custom
filters cannot enable IPv6. PCAP stdin still rejects IPv6 packets; dedicated IPv6
link type 229 is unsupported. Loopback smoke verification creates IPv4 traffic only.
Application-field syntax (such as an IPv6 literal in an HTTP Host or SOCKS target)
remains valid when carried inside an IPv4 connection; this does not enable IPv6 transport.

Functional verification: [live-smoke-v061.json](live-smoke-v061.json).
The v0.6 benchmark and smoke report remain historical; their adapter measurements
and IPv6 coverage do not describe the v0.6.1 capture decoder. No new latency claim
is made for this removal.

## New in v0.6

- Live tcpdump input and arbitrary-chunk PCAP stream parsing; no intermediate file.
- IPv4 TCP/UDP on Ethernet/VLAN, BSD loopback, raw IP and Linux SLL/SLL2.
- BGPv4 OPEN and SMB2/3 NEGOTIATE (including 3.1.1 context framing).
- SNMPv1/v2c read requests and TFTP initial requests/options.
- NTPv3/v4 base header validation **requires an explicit candidate hint**; no
  automatic match from its weak header. It is not authenticated NTP/NTS.
- Bounded live connection/prefix storage, amortized expiry, time/count stop limits,
  truncation handling, subprocess cleanup and capture loss statistics.
- Compact adapter mode avoids the old per-update list of protocol results.
  Later bytes outside the initial inspection window do not invalidate a valid
  initial classification; conflicting retained-prefix overlaps still do.

[PROTOCOLS.md](PROTOCOLS.md) lists exact profiles, exclusions and primary sources.

## Stream API

```python
from protocol_engine import Inspector, Config

inspector = Inspector(Config(max_bytes=65536))
events = inspector.feed(new_ordered_bytes)
events = inspector.end()
```

One Inspector per direction, starting at byte zero. Feed only new ordered,
deduplicated bytes. Parsers retain incremental state; at most one stream parser
is selected through bounded prefix dispatch. Terminal initial identification
bypasses further parsing. It is not full-session content inspection.

Optional `Inspector(protocol_hint="dns")` restricts a candidate but still requires
structural validation. DNS/TCP length prefixes >=512 need this hint because their
prefixes may collide with other families. `feed_decrypted()` remains available for
trusted plaintext supplied by a caller; the engine itself does not decrypt TLS.
No additional proxy integration was implemented in v0.6.

## Datagram API

```python
from protocol_engine import DatagramInspector

udp = DatagramInspector()
result = udp.inspect(one_complete_udp_payload)
result = udp.inspect(ntp_payload, protocol_hint="ntp")
```

Each call validates one complete message independently. No concatenation, permanent
UDP bypass or product identity inference. At most two preselected validators are
run, not a registry scan. Ambiguous valid interpretations remain unknown; an
unresolved competing budget cannot be treated as a unique match. Hints are reported
as caller context, not proof of identity.

## Results and scope

Transport, TLS envelope, application protocol, configured application mapping,
hostname and ALPN offers are separate. Structural evidence is not authentication.
Scopes describe the portion examined: initial_message, initial_headers,
protocol_header, negotiation_request or datagram. SMB dialect offers do not imply
that SMB encryption is established. NTP results with a hint remain weak evidence.

Statuses: detecting, identified, unknown, malformed, budget_exhausted, incomplete,
invalidated. Malformed is relative to the selected supported profile.

## Verification

209 tests cover fragmented input, every split point for stream fixtures, EOF,
malformed fields, protocol ambiguity, hints, seeded mutation/noise, parser release,
TCP reordering/conflicts, IPv6 rejection/link framing, capture pipes, loss reporting, idle
stop deadlines, process cleanup and bounded reassembly allocation/release.
These do not substitute for accuracy measurements on independently labeled
production traffic. [BENCHMARK-V010.md](BENCHMARK-V010.md) reports same-run v0.9/v0.10
comparisons and separate packet-to-event adapter CPU costs. Capturing, scheduling,
output I/O, concurrent load and end-to-end network latency are not in those timings.

## Files

| File | Responsibility |
|---|---|
| protocol_engine/ | Pure incremental TCP and complete UDP recognition |
| protocol_engine/appid.py, applications.py | Session verdicts and the application catalog ([APPID.md](APPID.md)) |
| protocol_engine/signatures.py | Custom signature compilation and evaluation ([SIGNATURES.md](SIGNATURES.md)) |
| protocol_engine/fingerprints.py | JA3/JA4/JA3S/JA4S/HASSH/HTTP2 digests ([FINGERPRINTS.md](FINGERPRINTS.md)) |
| protocol_engine/quic.py, aes.py | QUIC Initial parsing, protection removal, CRYPTO assembly; AES-GCM/HKDF primitives |
| live_capture.py | Bounded live loop, readable/JSON events and capture diagnostics |
| capture_stream.py | Incremental PCAP framing |
| link_packets.py | Link/IPv4 decoding |
| sessions.py, analyze_pcap.py | Bounded prefix reassembly and observer lifecycle |
| live_smoke.py | Opt-in real loopback verification |
| protocol_fixtures.py, protocol_demo.py | Synthetic protocol examples |
| benchmark_v08.py | Current comparison and adapter measurements |

## Current limits

Live TCP needs SYN and SYN-ACK. No attaching midway through a connection, complete
TCP endpoint validation, IP fragment reassembly, TLS decryption, HTTP/3 framing, PCAPNG
or Apple PKTAP. IPv6 traffic is unsupported and rejected. Checksums are not verified. Initial classification does not inspect
later requests, tunnel transitions or all payloads.

Defaults: 128 connections and a 64KiB prefix per direction. Raw prefix/presence
buffers can total 32MiB, plus Python/parser/capture overhead. Slow output can cause
capture drops. Final loss counters are shown; unavailable counters do not imply
zero loss. Exit 2 indicates reported drops or truncated captures, exit 1 an error.
The older offline `analyze_pcap.py` reader remains Ethernet/IPv4-only; `--stdin`
uses the new IPv4-only decoder for supported link types.

[ARCHITECTURE.md](ARCHITECTURE.md) describes exact contracts and remaining gaps.
Earlier benchmarks and teaching files are historical, not the current hot path.
