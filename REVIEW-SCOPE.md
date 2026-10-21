# Review scope: protocol detector v0.54

Python3.9-compatible IPv4 passive classification: 82 families, 74 automatic.
PROTOCOLS.md defines exact initial-message profiles and exclusions. APPID.md
defines the verdict vocabulary and the application catalog; RISKS.md the flow
risks and heuristic thresholds; POLICY.md the policy file and decisions.

New focus (v0.54): `protocol_engine/binary.py` LDAP ExtendedRequest and
ExtendedResponse (OID grammar, the StartTLS no-value rule, result walk shared
with BindResponse, the shift only on a named success, the private message id
in `parser.correlation`) and the analyzer's `_correlate_ldap` (client and
unnamed-server phases opened only for a success with the same message id,
nothing on a refusal) together with `Stream.open_shift` in sessions.py and
`Inspector.boundary`/`replay` in engine.py (bytes skipped while terminal are
replayed once into a peer-opened phase, never counted twice; the CONNECT
correlation now uses the same path); `protocol_engine/irc.py` (prefix grammar, parameter
counts, the 512-byte limit in `LineParser.feed` for the `:` route and the
hint only, four-parameter USER ambiguous with FTP, `PASS` only with the hint); `protocol_engine/wire.py` STUN class/method consistency and
the TURN attribute sizes, `dns_query_type_class` (lowercase expanded names,
32-byte A..P label, SRV versus NBSTAT); `appid.py` refinements (`turn`,
`netbios-ns`, `ms-rpc-over-http`); the new `:` route in dispatch.py. Trace:
extended values, nicknames, hosts, realms, nonces and names never reach
evidence; the shift never fires on a refused or unnamed response; every
attribute size against its message. 578 tests pass.

Previous focus (v0.53): `protocol_engine/desktop.py` (X11 setup lengths and
padding, the hinted reply's byte-order inference and size arithmetic, SPICE
message/reply discrimination by the caps offset), `protocol_engine/afp.py`
(DSI header rules, option walk, status reply bound), `protocol_engine/fins.py`
(length per command, ICF/GCT/address ranges), `protocol_engine/rip.py` (entry
arithmetic, authentication entries and trailer, whole-table request, RTCP
packet lengths) and the new routes in dispatch.py (`B`/`l` + NUL, `FINS`,
`REDQ`, the DSI header before the Kafka probe) and datagram.py (RIP words).
Trace: cookies, vendor strings, public keys, passwords and report contents
never reach evidence; every size against its container; that text routes for
`B...`, `l...` and `F...` are unchanged. 561 tests passed at v0.53.

Previous focus (v0.52): `protocol_engine/xmpp.py` (declaration regex, tag
boundary, attribute regex and the 16/1023 bounds, namespace and id rules,
hostname from to/from only), `SyslogStreamParser` in syslog.py (octet count
digits and bounds, LF framing, reuse of the UDP validator), the `<` and
digit-space-`<` routes in dispatch.py, `host_source` on parsers in
engine.py, and the WebDAV/ipp/ocsp/soap refinements in media.py and appid.py.
Trace: no stream id, JID, language or message content in evidence or
reasons; that every digit-first text route (SMTP/FTP replies, RESP, git) is
unchanged; the budget on a declaration without a stream tag. 546 tests pass.

Previous focus (v0.51): `protocol_engine/rpc.py` (opaque_auth bounds, AUTH_SYS
length arithmetic, reply status tables, the trailing-bytes rule, the 0x80
memcached/RPC split in dispatch and the UDP candidate words),
`protocol_engine/diameter.py` (AVP walk: header, padding, vendor flag,
once-only codes, mandatory set, Result-Code ranges), `protocol_engine/greetings.py`
(ZMTP mechanism and filler rules, Bolt version space and the hint-only
response), the HTTP/1 `http_method`/`http_content_type`/`http_accept`
evidence in parsers.py and `_web_application`/`_RPC_APPLICATIONS` in appid.py.
Trace: no machine name, uid, identity, realm, product name, header value or
argument byte in evidence or reasons; every size against its container; that
the new first-byte routes (0x60, 0x80, 0xff, 0x01) leave memcached, telnet,
BGP, FastCGI, AMQP and HTTP text untouched. 538 tests pass.

Previous focus (v0.50): `protocol_engine/hpack.py` (integer limit, Huffman table
construction and padding rule, dynamic table accounting and eviction, the
three budgets) and the HTTP/2 continuation in extended.py (`_frames`,
`_frame_header`, `_frame_complete`, `_headers`, `_request`, `_response`,
`_authority_host`, `content_type_class`), plus `Inspector.expect` and
`_correlate_http2` in analyze_pcap.py and the `_forward`/`end` merge of a
continuing shifted phase. Trace: every frame length against `max_bytes`, the
CONTINUATION and preamble counts, HPACK indices against both tables, that a
ParseError anywhere leaves the SETTINGS identification intact with no header
evidence, that no path, user agent, cookie, authority port or header value
reaches evidence or reasons, and that the gRPC/http-proxy/websocket refinement
needs the structural method plus the asserted field. 513 tests pass.

Previous focus (v0.49): `_tftp_server` (network.py), the L2TP/PPTP reply rules
(vpn.py), `MemcachedParser._response_size` with the 0x81 netbios/memcached
split, `GitParser._advertisement` with `_git_first_ref` and the 24-byte hex
wait in dispatch, the FastCGI application-record path, and the new direction
evidence on DHCP, NTP and MongoDB. Trace: every size rule against the
specification, no value, key, refname, capability or record content in
evidence; the netbios fixed-length discriminator; the mutation and split tests.

Previous focus (v0.48): tools/coverage_matrix.py and the generated table in
PROTOCOLS.md. Trace: the side attribution rules (scopes, evidence predicates,
declared server fixtures, symmetric and one-way sets) against the fixtures
they describe, the `--check` gate in CI and `make check`, and that the
evidence column is the complete set of fields a record may carry per family.

Previous focus (v0.47): `ModbusParser._response`/`_exception` with the widened
probe (function | 0x80), `GIOPParser._reply`, `TACACSParser._reply` (per-type
length arithmetic on unencrypted bodies), `SMB1Parser._response` (three word
counts, challenge length rule) and the AMQP frame mode with its eleven-byte
dispatch discriminator. Trace: exception codes and statuses as closed labels
only; no challenge, domain, server message, property or argument bytes in
evidence; echo-shaped Modbus responses deliberately left as requests. 474
tests pass.

Previous focus (v0.46): `dtls._server_flight` (translation to the TLS 1.2
ServerHello profile, dropped TLS labels and fingerprints), `radius._response`
(per-code attribute sets, repeatable Reply-Message/EAP/Class, State on a
Challenge), the OpenVPN server reset layout (ack array arithmetic, remote
session id) and the IKEv2 responder header/SA rules (`_header_at`,
`_sa(single=True)`, CERTREQ and capability notifications). Trace: no cookie,
authenticator, reply text, session id or key bytes in evidence; the responder
SPI rule; both directions in a UDP flow verdict. 468 tests pass.

Previous focus (v0.45): `PostgreSQLParser._server` (binary.py: length arithmetic
with the type byte, SASL list and error field walks, SQLSTATE class),
`LDAPParser._bind_response`, `CQLParser._response` with `_cql_string`,
`MySQLParser._handshake_response` (capability-driven field layout, one-byte
length-encoded profile, attribute block arithmetic) and the dispatch waits for
`R`/`E`/`v` followed by NUL bytes. Trace: no salt, mechanism, message, DN,
diagnostic, option value, user, database or attribute in evidence or reasons;
text protocols starting with E/R/v unchanged. 463 tests pass.

Previous focus (v0.44): `SMB2Parser._response`/`_contexts` (network.py), the
rewritten `_kerberos_body` with `_kerberos_fields` (windows.py: three field
layouts, strictly increasing tags, GeneralizedTime and error-code bounds,
dispatch and probe tags 11/13/30) and `DCERPCParser._bind_ack`/`_bind_nak`
(secondary address bounds and alignment, result list arithmetic, nil syntax on
rejection, nak version list with the optional signature tail). Trace: no
token, principal, realm, ticket, address or association group in evidence or
reasons; every split point; the kerberos-error-response rule. 458 tests pass.

Previous focus (v0.43): `_snmp_pdu`/`_snmp_bindings` in network.py (per-kind
status rules, the v1 Trap-PDU layout, the SMI value tag and length table,
version-specific PDU sets for v1, v2c and v3), `dns_message_evidence` and the
stricter query rule in wire.py, and the DatagramMatch returns that now carry
evidence for every SNMP and DNS result. Trace: no value, OID, community,
agent address or name in evidence or reasons; the 128-binding budget on every
kind; test_network and test_snmpv3 expectations changed only where response
and Set PDUs became accepted. 454 tests pass.

Previous focus (v0.42): `ech_type` in parsers.py and its two callers (TLSParser
through the `offered` list, quic.py). Trace: every ECH field bound against the
extension, exact fill, the inner type carrying no fields, the malformed path
(the whole ClientHello becomes malformed exactly as for other extensions), the
evidence strength (`offered`) and sources, the risk only for `outer`, DTLS
untouched, JA4 unchanged in method. 450 tests pass.

Previous focus (v0.41): opcua.py and the rewritten buffer-based `Socks5Parser` in
extended.py with its two roles. Trace: the OPC UA route ahead of the text,
AMQP and RFB prefixes (prefixes of the four magics now wait for byte 4 or 8;
anything else falls through unchanged), every string length against the
message and the 4096 bound, exact message coverage, no URL/URI/reason in
evidence; for SOCKS5 the role decision (`05 00` server, `05 02` by byte 4,
everything else client), the 519-byte buffer cap, the six-byte `05 00`
dispatch rule versus DCE/RPC, identical client evidence and contexts to the
previous parser, and the bound address never emitted. 447 tests pass.

Previous focus (v0.40): enterprise_db.py (`TDSParser`, `TNSParser`, `tns_probe`)
and the two dispatch changes. Trace: the type-4 TDS response versus a
compressed CQL request (bytes 7 and 8 zero), the TNS header test placed ahead
of Modbus/PostgreSQL/Kafka/DNS in the leading-0x00 block, every option data
region inside the packet with nothing after the last datum, the deferred
versus inline connect descriptor, printable-descriptor checks on REFUSE, no
instance name, descriptor, thread or trace bytes in evidence or reasons; the
new catalog entries and `_PROTOCOL_NAMES` mapping. 442 tests pass.

Previous focus (v0.39): `CertificateWatch` in tls_server.py and the DER walk in
x509.py behind `Config(certificates=True)`. Trace: the watch starts only after
a TLS 1.2 ServerHello (never 1.3 or a retry); record/handshake framing and the
shared `max_bytes` budget (the watch may never consume past it, also when the
leaf arrives in one chunk); every `_element` bound before every slice; name,
extension and serial budgets; time parsing; the issuer/subject comparison on
DER bytes; closed value sets for key and signature labels; no name, serial,
key or signature byte in evidence, reasons, records or events; every rejection
leaving the ServerHello identification intact; the four risks in risks.py and
RISKS.md; the `certificate` object in the three schemas. 436 tests pass.
BENCHMARK-V039.md.

Previous focus (v0.38): `_snmpv3` and the shared `_snmp_pdu` in network.py.
Trace: every BER field bounded by its enclosing length, flag combinations,
USM length limits, the privacy/plaintext choice, Report bindings accepting one
value TLV, binding budget, no secret in evidence or reason. 429 tests pass.

Previous focus (v0.36-v0.37): HTTP2ServerParser behind the 101 h2c shift
(no preface, no fingerprint, shift-only registration) and
tools/compare_engine.py with its CI job (baseline package loading without
polluting the working tree's imports, comparison keys, report rendering,
report-only exit code). Trace: that the self-comparison is empty, that the
report lists the h2c and ISO-TSAP changes when run against older trees, and
that the CI job cannot fail a build on its own.

Previous focus (v0.35): the rewritten `parse_hello` in parsers.py (fixed-field
offsets, extension walk, extension-count budget only with info, trailing-byte
check order) and tools/compare_client_hello.py. Trace: every bound before
every slice; identical ParseError messages; the differential run against the
previous tree (12,640 cases, zero differences); unchanged behaviour for DTLS
and QUIC callers of parse_hello. 424 tests pass. BENCHMARK-V035.md.

Previous focus (v0.34): schemas/*.schema.json (closed objects, enumerations
matching the engine's statuses, kinds, strengths, port usage and policy
actions), tools/schema_check.py (type semantics for bool/int/number, oneOf
counting, local refs, error paths), test_schema.py coverage of option
combinations. Trace: any emitted key missing from a schema; nullable fields;
the `datagram` event kind on UDP rows; optional fields that depend on flags
(fingerprints, hostname, policy, boundary). 424 tests pass.

Previous focus (v0.33): Inspector.open_shift (preconditions, budget, peer
provenance, no immediate event), Analyzer._correlate_connect (evidence-only
decision, both capture orders, counter), http_status evidence on responses.
Trace: a reopened terminal Inspector receiving bytes through SessionManager,
end()/invalidate() on the reopened phase, no retraction of the HTTP
identification, verdict server_protocol/risks after the tunnel ServerHello.
421 tests pass. BENCHMARK-V033.md.

Previous focus (v0.32): protocol_engine/s7.py (TPKT/COTP data header, S7 header
and parameter rules, setup-communication bounds), the COTP confirm branch and
shift in ics.py, the TPKT confirm routing (RDP negotiation response versus
ISO-TSAP). Trace: PDU length arithmetic for job versus ack headers, function
code gate, carrier kept on failure, split-point and mutation equivalence,
verdict shifted_from and catalog alias move (s7comm is now an application,
iso-tsap keeps cotp). 418 tests pass. BENCHMARK-V032.md.

Previous focus (v0.31): capture_stream.PcapStreamDecoder pcapng path (format
detection, block length/alignment/trailer checks, section byte order and
interface reset, if_tsresol bounds, EPB/SPB length rules, option walk,
skipped block types, failure closing the decoder), packets.read_pcap_records
now streaming through the decoder, analyze_pcap decoding by link type.
Trace: every slice preceded by a bound check; MAX_BLOCK versus snapshot and
options; 64-bit timestamp arithmetic; behaviour of a capture cut between
blocks (complete by definition); interface count and option count limits;
equivalence of classic and pcapng results. 415 tests pass. BENCHMARK-V031.md.

Previous focus (v0.30): protocol_engine/policy.py (loading, Rule.matches,
Policy.evaluate, dependency_warnings, lint), its use in analyze_pcap.Analyzer
._record and live_capture (classification events, summaries), and
protodetect.py. Trace: every validation path (types, bounds, unknown names,
alias resolution, port specs), first-match ordering, application-default
semantics for standard/unknown/nonstandard port usage and the second-pass
explanation, shifted_from and encryption "none" matching, outcome names in
apps, synthetic verdicts in dependency warnings, evaluation cost with large
rule sets, policy files as untrusted operator input (no execution, bounded
size), decisions never altering verdicts, and the CLI's argument forwarding
(REMAINDER) and exit codes. 410 tests pass. BENCHMARK-V030.md.

Previous focus (v0.29): protocol_engine/heuristics.py, risks.py, the generalized
unknown-payload buffer in engine.py (`_unknown_limit`), `DatagramInspector._unknown`
and `dns_with_contexts`/`dns_name_shape` in datagram.py, `offered_max_version`
and the `offered` out-parameter of `parse_hello` in parsers.py, `ssh_version`
evidence, `session_verdict` wrapping in appid.py, and the risks plumbing in
live_capture.py/analyze_pcap.py. Trace: heuristics never change a status or
verdict name; buffer bound = max(signature_bytes, heuristic_bytes) and byte
accounting under it; event timing change for unknown streams when heuristics
are on; the entropy normalization (0.90 x log2(min(size,256))) and class order;
DNS shape thresholds and that no label text leaves the engine; TLS version
precedence (supported_versions over legacy, GREASE skipped) and its use in
`tls-legacy-version-offer`; the RDP/SSH/SMB1/Telnet obsolete rules; risk
evaluation cost (single pass) and the `_replace` on a NamedTuple with default
fields; JSON shape of `risks` in session records, classification events and
summaries. 402 tests pass. BENCHMARK-V029.md.

Previous focus (v0.28): the application-shift state machine in engine.py
(`_begin_shift`, `_forward`, `_shift_result`, `_merge_shift`, `_continue`) and
the boundary detection in parsers.py (`_shift_boundary`), extended.py
(`_consume_smtp`, IMAP/POP3/FTP shifts), binary.py, database.py, remote.py
(RDP confirm), ics.py (TPKT route) and upgrade.py (WebSocket). Trace: byte
accounting across both phases against max_bytes (inner budget = remaining,
< 64 ends the shift), update budget, parser_calls; publish-before-shift
ordering and the "shifted" event kind; carrier evidence kept in a merged
observation (hostname/application only when the inner has none) and never a
downgrade of the carrier; the LineParser continuation returning at the
identifying line so a same-chunk STARTTLS error cannot make EHLO malformed;
SMTP watch bounds (512-byte lines, known verbs, NOOP count); CONNECT
authority-form regex and the no-shift fallback; Upgrade/Connection/Sec-WebSocket
header rules, body exclusion, 101 handling, h2c server frames excluded;
WebSocket frame-header bounds (RSV, opcodes, minimal lengths, control frames);
MySQL SSLRequest capability/reserved checks within the hint-only family; RDP CC
DST-REF/class/selected-protocol checks and failure codes; `shifted_from`
derivation in appid (http-connect -> http-proxy), implicitly_uses and carrier
port acceptance; invalidate/end/feed_decrypted interplay with a pending shift.
391 tests pass. BENCHMARK-V028.md.

Previous focus (v0.27): 23 decoders in protocol_engine/session_text.py, windows.py,
vpn.py, telemetry.py, ics.py, datainfra.py, their dispatch routes
(dispatch.py 0x00/0x01, 0x03 TPKT, 0x04/0x63.., 0x68, 0xff blocks) and UDP
candidate probes (datagram.py). Trace: every length/count field against the
frame or datagram before body access; min(max_headers, N) bounds on dialects,
padata, AVPs, flowsets, sets, samples; DNP3 CRC coverage and the 255-byte
frame bound; Kerberos BER definite-length handling and field ordering; TPKT
child selection (RDP cookie / negotiation / bare request vs. COTP); Kafka
8-byte selection and fragmentation equivalence; Telnet byte-at-a-time state
and the 64-byte bound; the `AmbiguousPrefix` route (shared 220/USER/PASS/QUIT
lines, `* OK` without capabilities) producing terminal `unknown` with
`ambiguous_candidates` context only, and `session_verdict` correlation
requiring both directions with an intersection of exactly one family (never a
hint or port); WireGuard/OpenVPN reported as encryption without tunnel claims;
no emission of dialects, NetBIOS names, principals, realms, host/vendor names,
client ids, LOCATION/USN strings. 381 tests pass. BENCHMARK-V027.md.

Previous focus (v0.25): QUIC (protocol_engine/quic.py, aes.py). Trace: long-header
bounds (CID lengths, token, Length varint vs datagram, coalesced trailing bytes),
probe placement ahead of DTLS and IKE competition, key derivation against the
RFC 9001/9369 vectors, header protection sample offset and reserved-bit check,
GCM tag failure and frame-type violations mapping to unverified (never
malformed/unknown), frame budgets, CRYPTO assembly (gaps, overlaps, offset
budget), QuicAssembler LRU and per-entry bounds, capture-gap clearing, no
connection-ID or token emission, signature contexts under the tls family,
CPU cost per Initial and the host's rate-limiting responsibility.
359 tests pass. BENCHMARK-V025.md.

Previous focus (v0.24): fingerprints (protocol_engine/fingerprints.py) and the
post-identification continuation in engine.py. Trace: GREASE filtering and
JA4 field rules (version from supported_versions, SNI flag, counts capped at
99, ALPN two-character code including non-alphanumeric cases, sorted vs
original order, SNI/ALPN exclusion in JA4_c, signature-algorithm suffix),
JA4S example vector, JA3/JA3S/HASSH definitions, DTLS version, HTTP/2
SETTINGS order; continuation accounting of consumed bytes, failure/budget/EOF
behaviour never downgrading an identification, KexInit bounds (35000, padding,
name-list ASCII and size, trailer), parser release after refinement, event
kinds updated/refined and live counters. 349 tests pass. BENCHMARK-V024.md.

Previous focus (v0.23): custom signatures (protocol_engine/signatures.py), context
retention in parsers.py/extended.py/binary.py/wire.py, the unknown-payload
buffering state in engine.py and unknown-udp evaluation in datagram.py. Trace:
pattern safety (nested quantifiers, backreferences, lookaround, repeat counts,
Latin-1, anchor length), prefilter correctness with case_insensitive, absent
contexts under negate, buffer accounting against max_bytes/signature_bytes,
eager evaluation vs. negated unknown-payload conditions, EOF evaluation of an
unresolved prefix, hint isolation, retention off by default and never emitted,
signature precedence over RuleIndex, verdict metadata via SignatureSet.
339 tests pass. Benchmarks: BENCHMARK-V023.md.

Previous focus (v0.22): the App-ID verdict layer (protocol_engine/appid.py, applications.py)
and the session ledger in analyze_pcap.Analyzer. Trace: verdict precedence
(identified > unknown/malformed/budget > invalidated > insufficient-data >
incomplete), client preference and server disagreement reporting, custom
mappings inheriting their carrier, port_usage with ranges/dynamic/secure ports,
per-direction byte accounting including retransmissions, SYN-only sessions,
record emission ordering relative to retirement/retraction events, UDP flow
table bounds and expiry, capture-gap clearing, hostname opt-in. Catalog risk
and characteristics are editorial defaults; review them as policy metadata,
not as detection claims. 324 tests pass. Benchmarks: BENCHMARK-V022.md.


Python3.9-compatible IPv4 passive classification:40 families,36 automatic.
PROTOCOLS.md defines exact initial-message profiles and exclusions.

New focus: IKEv2 IKE_SA_INIT initiator requests. Trace fixed native/non-ESP header
positions, complete payload chaining, bounded proposals/transforms, AES attributes,
CBC/AEAD integrity rules and KE/nonce consistency with offered algorithms. All
payload/proposal/transform work shares one128-capped budget. No crypto, peer
identity, successful negotiation or established IPsec tunnel is claimed.

An arbitrary IKE initiator SPI can collide with another UDP profile. One fixed
IKE probe adds a candidate to existing routes, never steals the first match.
Maximum three validators. Actual dual CoAP/IKE and DHCP/IKE messages must return
unknown; a competing exhausted budget blocks identification. No registry scan.

Delayed review4319051025 fromv0.19 was independently reproduced onv0.20 and fixed:
TLS1.2 RSA-only cipher0x002f now rejects EC point-format extension11. Every TCP
and TLS-record split rejects; all supported ECC suites still accept the extension.
Thev0.20 review reported no major issues; this older finding is explicitly retained.

309 installed tests pass. IKE includes all supported algorithm combinations,
truncations, count/length/attribute/marker/cookie negatives,3,000 mutations and
three-candidate tests. Independent tcpdump dissection agrees on both synthetic
IKE fixtures, but no real IKE peer handshake was tested. LibreSSL TLS1.2 MemoryBIO
still passes. Synthetic actual IPv4 loopback capture:186 packets,24 identifications,
18 families,zero reported kernel drops.

BENCHMARK-V021.md: five paired subprocess rounds; new IKE p50 about15us including
packet decode/events. Existing UDP differences -0.7%..+1.4% and TCP -1.7%..+2.2%
include host noise. Different semantics are reported separately. No production
latency or detection-accuracy guarantee. Prior feature/fix history stays in scope.

No proxy integration, IPv6, native rewrite or external/user traffic. Only source,
synthetic fixtures and verification reports uploaded; backups/development notes,
credentials, old source copies and replay logs excluded. Existing sample-expanded
PCAP preserved; generator can produce a new fixture with current coverage.
