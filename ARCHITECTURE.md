# Stream/datagram engine v0.36 — engine and observation contracts

## Ownership

The SWG owns transport, TLS, packet forwarding, policy, lifecycle, timeouts, rate
limits, backpressure and aggregate memory budgets. The library consumes already
reassembled stream deltas or complete UDP payloads, and performs no network I/O.
No threads or locks are created. One owner per Inspector/DatagramInspector;
immutable Config and RuleIndex may be shared. The offline PCAP adapter is not a
production network stack.

No target hardware, throughput, latency budget, implementation runtime or labeled
traffic corpus has been supplied. This reference implementation makes resource
bounds and semantics testable. Native implementation and production capacity
claims require deployment-specific evidence.

## Stream lifecycle

An Inspector accepts only new ordered, deduplicated bytes from stream offset zero.
Its parser cursor survives feed calls. Prefix dispatch holds at most 23 bytes
while waiting for a discriminator; it resolves within 24 bytes. The first-byte
table bypasses irrelevant family branches. One parsing pipeline is selected, never
a loop across registered parsers. Registry and capability catalog are immutable
and built once. The catalog is not accessed in the hot path.

Shared text framing preserves HTTP extension-method collisions (PRI, EHLO, AMQP,
RFB, *digits, methods starting with 0). SIP/RTSP are selected only from a complete
versioned start-line. After selection, an unbound callback handles later headers
without repeating family dispatch or creating a self-reference cycle. Binary
FrameParser reads a small fixed header, checks the advertised length, accumulates
one bounded message and validates it once. DNS/STUN reuse complete-message
validators on both transports. RESP skips bulk argument bodies without retention.

STOMP command-plus-newline routing distinguishes it from HTTP CONNECT/STOMP
methods; unrelated C*/S* prefixes leave that branch early. Its parser accepts
LF/CRLF, validates UTF-8 and escape rules, and requires the terminal NUL after
an empty handshake body. NATS validates JSON only after a complete INFO/CONNECT
line. Preflight depth <=16, <=128 configured/capped members and bounded structure
precede JSON decoding; numeric conversions and decoded Unicode are constrained.
IMAP requires explicit revision capability syntax. RDP requires full TPKT/X.224
and negotiation structure; TPKT alone is insufficient. These offer/header scopes
do not validate authentication, successful negotiation or subsequent application data.

FastCGI uses an eight-byte candidate discriminator disjoint from the current DNS
profile: its zero reserved byte prevents DNS QDCOUNT=1. The selected incremental
parser checks BEGIN_REQUEST and one complete PARAMS stream, matching request IDs,
counting records and checking aggregate advertised wire size before accumulation.
Parameter encodings span arbitrary records; validation runs once at PARAMS EOF.
Padding is skipped, not retained. Binary parameter values never become host/app
identity. Rsync routes directly from @ to a bounded full greeting parser; no HTTP
method token contains @. Its version and digest metadata are offers only.

MySQL and MongoDB are explicit-candidate parsers. Neither changes automatic
prefix routing. Hints are emitted as caller context in successful TCP observations;
they do not establish identity. Capture CLI selection applies to both directions,
and must be scoped by the operator. The immutable catalog exposes requires_hint.
An Analyzer shares one immutable inspection Config across its stream inspectors.

MongoDB framing uses a 20-byte header. Before growing the body buffer it validates
the opcode, mandatory flags, reply-only constraints and CRC input budget. Default
max_crc32c_bytes=4096 bounds the Python checksum path independently of max_bytes;
zero refuses checksummed messages. CRC uses shared slicing-by-eight tables with
explicit little-endian unpacking, and is verified against RFC test vectors.
No constant wall-clock latency is implied by a byte budget. The capture/offline
CLI exposes --crc32c-byte-limit. Raising it is an explicit CPU-cost tradeoff.
BSON is traversed without materializing user documents, with depth <=16, total
fields <=min(max_headers,128), documents <=128, cstrings <=min(max_line,1024).
Nested duplicate keys are conservatively rejected; arrays require consecutive
indices. Binary inner formats remain opaque. No JavaScript/regex is executed.
Metadata and frame buffers are released at terminal inspection.

A terminal identified/unknown/malformed/budget/incomplete/invalidated state releases
parser buffers and bypasses further initial-protocol work. This is not a policy
allow decision and not a full-session security inspection. end() finalizes an
unfinished scope. invalidate() clears classification and inner state after loss
of upstream byte integrity. Events carry a local revision and no retained history.

The host must create new inspection contexts at trusted boundaries for subsequent
requests, CONNECT tunnels, STARTTLS, PostgreSQL encryption upgrades or other phase
transitions. Do not search arbitrary content for signatures to guess a new boundary.

## Plaintext provenance

feed_decrypted accepts plaintext only after wire TLS identification. The SWG must
supply it from its own TLS stack and at plaintext stream offset zero. The library
does not decrypt, authenticate handshakes or validate certificates. TLS encryption
and offered ALPN are retained when plaintext refines the application protocol.
Offered ALPN is never promoted to a selected/observed application protocol.
Changed inner HTTP Host attribution replaces an outer SNI mapping; a bad inner
scope clears application attribution. Wire parser hints are not inherited inside
TLS. Hosts can also use a separate Inspector(source="decrypted", protocol_hint=...)
when managing their own layering and phase boundaries.

## Datagram lifecycle and uncertainty

DatagramInspector.inspect takes exactly one complete UDP payload. It validates
each call independently, retaining only aggregate metrics; it does not hold input
between messages and has no permanent session bypass. There is no stream EOF or
fragmentation concept in this API. A host must reject incomplete packet captures
or reassemble IP fragments before invoking it.

Header probes preselect at most three candidates (two existing routes plus IKE). Full validators must pass within
the datagram boundary; lengths cannot silently consume another datagram. If both
DNS and CoAP structures validate, return unknown. If a competing candidate exhausts
its budget, do not identify the surviving interpretation as unique. A candidate
hint restricts validation but supplies no identity evidence. Tiny/empty CoAP messages
are only recognized with a CoAP hint because their standalone structure is weak.

The API emits Observation values, not state-change events. The PCAP adapter wraps
each UDP result as a datagram event with an analyzer-local UDP revision. Those
revisions are not comparable with per-direction TCP revisions. No UDP flow cache,
handshake correlation, transaction matching or spoofing resistance is supplied.

## Evidence and scope

Transport, encryption, application_protocol, application, hostname, offered_alpn,
status, evidence and scope are distinct. Scope can be initial_message,
initial_headers, protocol_header, negotiation_request or datagram. Read the exact
profile in PROTOCOLS.md; none asserts full bidirectional session validation.

Structural evidence means implemented framing/field checks passed. Asserted
hostnames and SOCKS destinations come from peers. Exact application rules are
configured mappings, not authenticated product identities. Rule lookup is a hash
lookup on canonical (source, hostname), with no suffix/wildcard fallback or rule
scan. IP literals are not application rule identities. No proprietary application
signature corpus, behavior/ML classifier, cloud lookup or global attribution cache
is included. Hidden ECH names cannot be recovered.

A PostgreSQL SSL/GSS request is a negotiation_request with no encryption label.
AMQP/RFB only validate protocol_header. SIP/RTSP on TCP stop at initial_headers;
bodies and later dialogues are not inspected. UDP SIP additionally checks body
length against Content-Length when present. Unknown RDATA/attribute/option
semantics are explicitly unverified where their framing is accepted.

## Resource budgets

Defaults: 64 KiB inspected bytes, 4096 nonempty stream updates, 8192 bytes per text
line and 128 HTTP/control headers. TLS+decrypted scopes have independent budgets,
so together they can inspect twice the configured byte limit. Parser buffers are
released on terminal results. RuleIndex defaults to at most 100,000 rules and is
compiled outside packet processing.

Additional bounds: 24 bytes prefix lookahead; 128 DNS questions/records total and
max_bytes name-processing steps; 255-byte expanded DNS names and backward pointers
to previously parsed name boundaries; 128 STUN attributes; 128 DHCP non-pad options;
128 CoAP options; 128 Syslog elements/parameters; 128 MQTT properties per block;
128 PostgreSQL parameters; RESP 1024 arguments, 24-byte numeric headers and a
128-byte command token. Binary frame sizes are rejected before body allocation.
These are bounded inspection profiles, not complete protocol implementations.

UDP uses max_bytes per datagram and its protocol work bounds. max_updates is a
stream fragmentation limit, not a lifetime cap on DatagramInspector calls; the
host must apply packet rate/connection limits. Stream bytes_inspected counts
consumed bytes on success and conservatively charges submitted bytes on parser
errors. UDP bytes_inspected counts selected datagram bytes once, even if two
validators run; parser_calls exposes those extra validations. Datagram metrics do
not themselves emit events. Metrics are diagnostic counters, not wall-clock limits.

## Verification and production gap

Tests include split/EOF cases, bytewise parsing, prefix collisions, bounds,
malformed fields, privacy of emitted evidence, plaintext provenance, reassembly,
realistic synthetic PCAP, packet lengths, ambiguity and deterministic mutations.
Callback lifecycle tests disable cyclic GC to verify parsers release immediately.
One published STUN test vector was also manually checked. Local benchmarks compare
identical fixtures against the preserved v0.4 snapshot and retain source hashes,
per-round medians and p50/p95/p99. Small deltas are not deployment guarantees.

Production readiness still requires independently labeled real replay corpora,
false-positive/false-negative evaluation, sustained/concurrent load, memory and
GC/tail-latency measurements, explicit policy behavior for every status, upgrades
and transaction semantics, remaining parsers, and independent security review.

## Passive live adapter (v0.6.1)

`live_capture.py` launches tcpdump with argv (no shell), non-promiscuous capture,
packet-buffered PCAP output, immediate capture mode and explicit interface/filter.
The Python process does not request root or alter network routes. It accepts a
PCAP pipe from a separately privileged capture helper with `--stdin` when needed.
No payload capture files or raw payload logs are produced.

`PcapStreamDecoder` incrementally parses global/record headers and payloads across
arbitrary read boundaries; 64KiB maximum feed chunk, 1MiB maximum advertised
snapshot length. Invalid lengths fail the stream. A record retaining fewer bytes
than its original length is skipped and clears all active TCP state, with a gap
notification. Previously emitted labels for active connections must be retracted.

`link_packets.py` supports IPv4 TCP/UDP over Ethernet (two VLAN tags), BSD
NULL/LOOP, raw IPv4, and Linux SLL/SLL2. IPv6 decoding has been removed. All
owned capture commands apply `ip and (<requested BPF>)`, including custom filters.
IPv6 frames received through stdin are rejected and counted as unsupported;
a dedicated IPv6 PCAP link type (229) fails at the global header. IPv4 fragments
are rejected. Checksums are not verified; host capture can precede checksum offload.
Application protocol syntax can still contain IPv6 address literals inside an
IPv4 stream. This is field validation, not IPv6 network/transport support.
PCAPNG and Apple PKTAP remain unsupported. Legacy `analyze_pcap.py` retains its
Ethernet/IPv4 reader for compatibility; use the live stdin path for other supported IPv4 link types.

Live observation reuses bounded prefix reassembly with compact mode (no per-update
legacy protocol result list). One-second amortized idle sweeps avoid per-packet
whole-table scans. Wall-clock monotonic arrival time, not PCAP timestamps, drives
live expiry. At most 128 connections by default, configurable up to 1024; each
connection allocates two directions * (byte buffer + presence buffer). At 64KiB
this is 32MiB by default, excluding Python objects, parser buffers and pipe buffers.
The pending SYN table shares the same connection cap; excess new flows are counted.

Prefix-only mode ignores bytes beyond the inspection window, continues checking
conflicts within the retained prefix, and handles FIN beyond the window without
retracting a valid initial-message identification. This is explicitly not full
TCP validation. SYN/SYN-ACK must be observed. Existing connections, TCP Fast Open,
urgent data and unsupported transports are not reconstructed. Missing segments
remain gaps until expiry; no speculative parsing across gaps. FIN/RST and sequence
handling remain a bounded observer approximation, not an endpoint TCP stack.

The selector loop drains stdout/stderr without unbounded queues, respects idle
duration limits, handles Ctrl-C and shuts down/drains the owned capture process.
Slow output consumers can cause capture loss; final tcpdump counters are exposed.
Reported drops emit a capture-wide gap notice and exit 2; truncated records also
exit 2. Errors exit 1. Exit 0 alone does not prove loss-free capture: statistics
may be unavailable for external stdin streams. Classification is provisional with
respect to capture loss until final statistics arrive. No payload history is kept.

The live adapter is a standalone Python observation/test tool. There is no new SWG
integration, packet forwarding, blocking policy or TLS decryption in this release.

## Regular-file PCAP input

run_capture detects a regular input file once via fstat when no owned capture
process is present. It reads at most 65536 bytes per batch without registering
that descriptor with a selector: kqueue may not signal EOF and epoll rejects
regular files. The next zero-byte read finalizes the PCAP decoder. Truncated EOF
remains an error; packet/duration limits are checked between batches. This finite
file mode does not tail future appends. A local filesystem read can itself block;
there is no hard real-time deadline during a disk read. Pipe/device capture retains
nonblocking readiness handling and process cleanup. Caller-owned files stay open
and their original blocking flags remain unchanged.

## v0.10 observation retirement and byte budgets

Inspector.end(reason=...) accepts a bounded caller reason and propagates it into
an unfinished plaintext child. Default end() remains compatible. SessionManager
finish_direction ends an inspector but retains its prefix bytes for subsequent
overlap validation. Analyzer calls it only once all bytes up to an observed FIN
inside the retained window are contiguous. Out-of-order FIN waits; half-close
leaves the other direction active. Retransmissions do not duplicate terminal
events; conflicting overlap still invalidates, including after FIN finalization.
No FIN/RST receive-window, ACK validation or TIME-WAIT endpoint emulation is added.
TCP reference: [RFC9293 section 3.4](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.4).

Analyzer's Config.max_bytes equals its byte_limit (64..65536). Reaching a full
prefix while still detecting therefore emits budget_exhausted, not an artificial
FIN/EOF. Standalone SessionManager keeps its existing smaller-window API; its
caller remains responsible for inspection/lifecycle policy.

Analyzer.drop/expire/finish end unfinished directions with explicit tracking,
timeout, RST or capture reasons, then release state. Optional on_retire(source,
destination,event) is synchronous and streams at most two terminal events per
connection; no unbounded event queue. Packet-driven FIN events remain in
last_events and use that packet's timestamp. CaptureMonitor retirement records
have timestamp=null and boundary=observation_retired because no packet caused
that observation. They are visible with --all-events, and counted even when hidden.
Offline JSON emits stream_end records separately from frame records. Empty reverse
directions count as incomplete. Repeated finish is idempotent; normal retirement
does not retract already completed initial classifications.

A successful capture EOF/stop finalizes pending directions and releases all
connections before final summary (active_connections=0). Capture errors/loss first
invalidate and discard state; they do not produce fabricated clean EOF events.
Idle expiry uses observation time; none of these local boundaries proves that
the remote TCP endpoint closed. Direct Analyzer callers should invoke finish when
ending observation. Weak owner references in the clock/capture callback avoid
reference cycles and release buffers without requiring cyclic GC.

RADIUS adds only an explicit UDP validator registry entry, leaving automatic
selection bounded by two existing candidates. Attribute iteration is bounded by
packet bytes and count; no secrets, HMAC work, external calls or value attribution.

FIN validation uses Stream.highest_end, the exclusive end of the highest retained
payload byte. In-order appends assign it; reordered/duplicate writes take max;
bytes ignored beyond the prefix window do not move it. A FIN before retained data
is rejected by one integer comparison instead of scanning present[end:] across
up to 65536 bytes. The metadata is checked against the presence bitmap in tests,
including gaps, retransmissions, clipping and ignored later data.

## v0.12 review corrections

Compact prefix mode trims bytes preceding the known stream origin before checking
retained overlaps; strict mode continues to reject out-of-window payloads. FIN
positions crossing the origin are normalized consistently. This protects retained
bytes, not arbitrary multiple wraps of a long-lived TCP sequence epoch.

Offline read_pcap_records retains timestamp, captured bytes, original wire length
and Ethernet link type in CaptureRecord. The old read_pcap tuple interface rejects
truncated captures rather than silently losing metadata. The live decoder imports
the same record class. On captured length < original length, offline output emits
a capture_gap with active_connections scope, discards every active connection and
requires fresh handshakes; this conservatively includes truncation of link padding.
Physical record/header errors emit all_observations_this_capture invalidation and
raise CaptureError without a clean EOF finalization. Consumers must apply these
retractions to prior labels. Offline/live IPv4 decoders reject reserved bit 0x8000
as well as fragmentation, allowing only an optional DF bit.


## v0.13: control rejection events

Analyzer.reject publishes Inspector.invalidate for the rejected packet's direction
before drop releases both directions. The triggering packet's last_events and
last_classification therefore carry the retraction, just as retained-overlap
errors already do. Offline events-only output cannot suppress that event; live
monitoring counts and emits it once through the ordinary event path. The reverse
direction uses normal retirement: an unfinished observation ends incomplete,
while a completed independent initial observation remains historical evidence.
No endpoint receive-window validation or connection-wide application inference
is implied. RST, timeout and capture EOF are observation retirement, not protocol
contradictions; they keep their existing completed-observation semantics.

The reject helper is only called on exceptional control paths and retains no
queue. Its allocation/work is bounded by one inspector retraction plus the
existing two-direction drop. Tests cover eight concrete rejection sequences in
compact/strict Analyzer and default/all-events live/offline outputs.


## v0.14: FIN before the retained origin

For compact mode, a segment offset in the upper half of the 32-bit sequence
space is treated as a possible leading segment. If its payload reaches the
origin, end is normalized by subtracting 2**32 as in v0.12. If it does not reach
the origin and carries FIN, Analyzer rejects it with a directional event rather
than storing a huge positive FIN boundary. This also conservatively rejects
ambiguous FIN positions at or above the half-range boundary; tracking multiple
sequence epochs or endpoint receive windows remains unsupported. Payload wholly
before the origin without FIN is still ignored. A FIN normalized to zero ends
an empty direction; later data is rejected against that zero boundary.

The extra FIN test executes only in the already exceptional upper-half-offset
branch. No additional scan or retained data is introduced. Strict mode keeps
its existing bounded-window rejection. Reference: RFC9293 section 3.4 sequence
arithmetic; this observer's conservative ambiguity policy is not an endpoint TCP
implementation.


## v0.15: one coordinate system for leading payload and FIN

Compact upper-half offsets now normalize end by subtracting 2**32 regardless
of whether payload reaches zero. This aligns the FIN comparison with Stream's
existing prefix clipping: wholly pre-origin non-FIN payload has a negative/zero
end and cannot be mistaken for data beyond a previously observed positive FIN.
A negative FIN remains rejected; a crossing end beyond FIN remains rejected.
No extra loops, allocations or retained state are added. Sequence epochs beyond
the unambiguous origin-relative range remain unsupported as documented in v0.14.
The regression oracle uses absolute integer offsets and independently computes
FIN consistency, retained byte positions and highest retained end before wire
sequence encoding. It checks 1,680 combinations over three origins, five FIN
boundaries, payload lengths/positions and FIN/non-FIN flags.


## v0.16: bounded structural ambiguity routes

Dispatch detects a lowercase four-hex length followed by git- using at most8
bytes, then chooses the private git_text factory. Other families still resolve
within the existing24-byte lookahead. PARSERS remains the immutable public hint
registry; FACTORIES adds private automatic routes without exposing them as hints.
GitTextParser scans only new bytes up to max_line for the earliest NUL/LF,
buffers at most that one field, then replays it once into one chosen parser.
After selection it delegates directly. No competing parsers run concurrently.
This preserves HTTP extension methods such as0033git-upload-pack; a git hint
always uses GitParser and cannot identify HTTP. The final family comes from the
selected parser, as with existing shared text routing. Metrics charge new bytes
once across both prefix and field replay, and stop at the initial message boundary.

GitParser reuses FrameParser for bounded advertised length, validates the complete
service-request profile and releases its buffer. Parameter count/width and path
limits are checked before unbounded allocations; the largest frame is capped by
both protocol and configured budgets. Version evidence is an offer. No Git path,
virtual host or opaque extra is promoted to application identity. Single-message
terminal bypass and retained TCP overlap checking remain unchanged.

## v0.17: bounded CDR and GIOP

CDRCursor works against a complete bounded frame and absolute message offsets,
so alignment includes the 12-byte common header. Lengths are checked before
slicing; count preflight and a 128-context cap bound iteration. No recursive
CDR/TypeCode or context decoding. GIOP shares FrameParser and releases retained
bytes on terminal outcomes. A G-prefix discriminator waits at most five bytes;
ordinary GET diverges at byte two and HTTP extension-method compatibility remains.

## v0.18: DCE/RPC versus SOCKS5

Byte 05 waits for one further byte. A zero selects RPC (minor version 0), while
nonzero selects SOCKS5 (method count). No speculative parallel parsing. RPC reuses
FrameParser, bounds a complete frame before allocation, and preflights list lengths
before traversal. At most128 contexts each offer at most2 transfer syntaxes.
UUID wire constants are built at import, not per packet. Only known transfer
names are emitted as offers; no opaque interface or connection identifiers leak.

## v0.19: directional TLS server hello evidence

TLSParser shares record/handshake assembly for type1 and type2. A record-version
bitmask costs constant space. Server-only semantic parsing is loaded on demand,
so ordinary dispatch does not change. Server extension count is capped before
reading another entry. The complete message is byte-bounded; buffers are released
on terminal outcomes. ClientHello output semantics are unchanged.

Server evidence is returned through the existing extra_evidence mechanism with
explicit asserted provenance. No server name is invented from an acknowledgement,
and selected ALPN is never promoted to an inner application protocol or placed
in client offers. Retry is a distinct scope. There is no cross-direction client
correlation or full TLS session validation. New module constraints are explicit
in PROTOCOLS.md rather than treating arbitrary extension payloads as validated.


## Layered UDP results (v0.20)

Validators may return an internal immutable DatagramMatch carrying encryption,
optional application protocol and asserted metadata. Existing plaintext validators
retain their lightweight protocol/reason tuple. The inspector normalizes only the
single winning result, after the same ambiguity/budget rules. Public Observation
is unchanged. DTLS populates encryption and client assertions, never an inner
protocol or application mapping. Offline text now falls back to encryption like
live text already did; JSON keeps the existing Observation schema.

DTLS prefix dispatch is constant-size and disjoint from existing complete UDP
profiles. It precedes deeper DHCP-cookie probing, so opaque cookie contents cannot
steal the route. A single record/hello must fill the complete datagram; fragment
and coalescing support is intentionally excluded. Extension count is checked
before reuse of the TLS ClientHello field validator, with at most128 entries and
16KiB plaintext record size. No input survives inspect(), even on a rejection.


## Fixed-position IKE ambiguity route (v0.21)

Unlike a fixed prefix signature, the initial IKE SPI may contain arbitrary bytes.
After existing UDP probing, a bounded IKE header probe adds one candidate; it does
not override a possible CoAP/DHCP interpretation. It checks native position0 or
position4 after the non-ESP marker and first gates on the smallest supported
message size352. At most three validators run, independent of registry size.
Single/dual matches and competing budget failures use existing uncertainty rules.
The IKE parser has one aggregate128-capped structural work budget and never
materializes algorithm combinations. No cryptography or association cache.

TLS1.2 server extension11 now checks its ECC-cipher context before reading point
formats. This adds no work when that extension is absent, preserving the existing
ClientHello path and server-extension bounds.


## App-ID verdict layer and session ledger (v0.22)

`appid.classify`/`session_verdict` read at most two Observations and perform a
constant number of dictionary lookups into an immutable catalog validated once at
import; they never scan the catalog, touch bytes or run parsers. Precedence:
identified (client first, server disagreement recorded) > unmatched payload
(`unknown-*`) > invalidated (`not-applicable`) > payload without completion
(`insufficient-data`) > `incomplete`. Configured mappings become custom
applications that inherit their carrier's attributes and implicitly use it.

Analyzer keeps per-connection counters (packets, payload bytes per endpoint,
start) in the existing `tracked` state and emits one session record from
`drop()`, after directional retirement events, so ordering is: retraction or
end events, then the session verdict. `retiring` exposes the dropping state to
`on_retire` consumers for byte-aware direction verdicts. SYN-only states produce
`incomplete` with `no_handshake`. UDP flows live in a separate table bounded by
`max_udp_flows` (default: connection limit) with the same idle timeout and
amortized sweep; the first identified datagram labels the flow, otherwise the
latest outcome. Capture gaps clear both tables without fabricating records.
Session records contain counts and verdict metadata only; hostnames are opt-in.


## Custom signatures (v0.23)

`SignatureSet` is compiled once and immutable; signatures are indexed by the
parser family whose contexts they reference, so evaluation touches only that
family's list (`wants(family)` is one dictionary lookup in the hot path).
Pattern compilation walks the regex parse tree: it rejects nested quantifiers,
backreferences, lookaround and repeat counts above 4096, extracts the longest
literal run and requires 7 bytes (raw contexts) or 3 bytes (fields). At runtime
the anchor is searched with `bytes.find` before `re.search`, so a signature set
costs one substring scan per signature on a miss. Inputs are bounded by the
parser budgets (header block 4096, User-Agent 1024, ClientHello 16 KiB) or by
`Config.signature_bytes`.

Inspector evaluates signatures in `_identified()` before the `RuleIndex` lookup;
contexts live on the parser and are released with it. For an unknown prefix the
Inspector enters a buffering state instead of finishing: bytes are charged to
the byte budget, signatures are evaluated after each update (a match is
terminal with `scope=signature_match`), and the stream becomes `unknown` when
the buffer is full or at `end()`. An unresolved dispatch prefix is evaluated once
at `end()`. `invalidate()` drops the buffer. DatagramInspector evaluates
unknown-udp signatures when no candidate exists or every candidate reported
`unknown`, never when a hint was given. Contexts are never copied into
Observation, events or adapter output; only the signature name is.

Verdicts: `appid._application` resolves a signature name through the supplied
`SignatureSet` to use its own category/risk/characteristics and `parent`
carrier; without the set the name inherits its carrier like a configured
mapping. Unknown-payload matches are carried by `unknown-tcp`/`unknown-udp`.


## Post-identification continuation and fingerprints (v0.24)

`Inspector.feed` gains a continuation state. When a parser completes with
`continues = True`, the Inspector publishes the identification (`updated`),
keeps the parser, and feeds it the remainder of the current chunk and later
chunks, charging only consumed bytes. When the parser clears `continues`, the
Inspector finishes with a `refined` event whose evidence appends the parser's
`fingerprints` tuples (field, value, provenance) at strength `derived`. A
ParseError during continuation, reaching `max_bytes`, `end()` or `invalidate()`
finish or retract without changing status; a continuation can only add
evidence. Terminal release semantics are unchanged once the continuation ends.

The same continuation carries the v0.39 certificate watch: with
`Config(certificates=True)` a TLS 1.2 ServerHello sets `continues` and hands
`tls_server.CertificateWatch` the bytes left in its record plus the remaining
`max_bytes` budget. The watch reads handshake records until the first entry of
the Certificate message is complete, calls `x509.leaf_profile` (a bounded DER
walk that returns closed-set labels only) and appends the result to
`extra_evidence`, so the `refined` observation carries `tls_certificate_*`
rows at strength `asserted` (chain shape `structural`). Any ParseError or
BudgetError ends the watch with the identification intact.

TLSParser fills `ClientHelloInfo` when contexts or fingerprints are configured
and computes JA4/JA3 at completion; `tls_server.parse_server_hello` appends
JA4S/JA3S for completed ServerHello profiles (not for retries); `dtls()` passes
the DTLS legacy version so JA4 reports `d2`; `HTTP2Parser` keeps the ordered
SETTINGS pairs for the Akamai-style string; `LineParser` delegates to a bounded
`KexInit` reader after an SSH banner. All digests are over already validated
structural fields; GREASE values are removed where the definition requires.
`fingerprints.py` has no parsing of its own.

`benchmark_ab.py` compares two trees by minimum per-flow time over alternating
interpreter runs with the constructor subtracted; it exists because percentile
comparisons across shuffled subprocess rounds were shown to swing by ±30% on
unchanged code on the shared development host (BENCHMARK-V023.md).


## QUIC Initial processing (v0.25)

`quic_probe` is a constant-size first check in DatagramInspector (long header,
fixed bit, supported version, Initial type), placed before DTLS so that no
other validator runs on a QUIC datagram; the IKE fixed-position probe can still
add a competing candidate and the usual ambiguity rules apply. `quic()` parses
the long header with bounds on every length, then removes protection with keys
derived from public values. `aes.py` is a table-driven AES-128 encryption core
(T-tables), a GCM with byte-windowed GHASH tables built per key in about 0.5 ms,
and HKDF-SHA256; none of it handles secret material or needs constant time,
because every input is attacker-visible and the output is data the client sent
in the clear by design. GCM tag failure or a frame outside the Initial set
never produces an error status: the structural identification stands and the
evidence says `initial_protection=unverified`, so a damaged datagram cannot be
turned into a false negative or a different protocol.

`QuicAssembler` is host-owned, bounded (LRU over Destination Connection IDs,
8 fragments and 16 KiB per entry) and cleared on capture gaps; DatagramInspector
itself still retains no input. Analyzer sizes it from the UDP flow limit.
`DatagramMatch` carries optional signature contexts with a family so that the
tls-family `ssl-req-*` signatures apply to QUIC ClientHellos; contexts remain
internal. Per-Initial cost is about 2 ms (AES-CTR of 75 blocks dominates);
`Config.quic_decrypt=False` keeps structural recognition only. Rate limiting
of Initial floods remains the host's responsibility (THREAT-MODEL T14).

## Decoder expansion and text ambiguity (v0.27)

New parsers live in six modules by domain (`session_text.py`, `windows.py`,
`vpn.py`, `telemetry.py`, `ics.py`, `datainfra.py`) and register through the
same three tables as before: `dispatch.FIRST_BYTE`/`select` for TCP prefix
routing, `registry.PARSERS`/`FACTORIES` for parser construction, and
`datagram.VALIDATORS` plus the candidate-selection block for UDP. `select`
still returns exactly one family (or `None` to wait); ambiguous first bytes
(0x00/0x01 length-prefixed frames, 0x03 TPKT, 0x04/0x63.. EtherNet-IP versus
CQL/text, 0x68, 0xff) are resolved by fixed-position tests inside the prefix,
never by scanning. The Kafka probe decides at 8 bytes so that whole feeds and
3-byte fragments select identically (fragmentation-equivalence test).

`AmbiguousPrefix` (a subclass of `UnsupportedPrefix`) carries a candidate
tuple. `Inspector._finish` turns it into a terminal `unknown` observation whose
only evidence is `ambiguous_candidates` with strength `context`; the direction
inspected no more bytes. `appid.session_verdict` reads that evidence from both
directions, and when the intersection has exactly one family builds a verdict
with status `correlated` from the catalog entry. Correlation needs two
observations from the same session; a hint, a port or a single direction never
produces it (SR-2, SR-25).

`TPKTParser` is a two-stage parser: TPKT framing, then a byte test on the X.224
body chooses `RDPParser` or `COTPParser` and adopts the child's protocol name,
reason and evidence. `TelnetParser` is a byte-at-a-time state machine with a
64-byte command bound. UDP validators follow the `DatagramMatch` contract for
encryption-only results (WireGuard, OpenVPN) and the `(protocol, reason)`
contract otherwise. Every new validator bounds counts by `min(config.max_headers,
N)` and refuses lengths that disagree with the datagram before touching bodies.

## Application shift (v0.28)

A parser announces a boundary by setting `shift = (boundary, expected_family)`
when it completes; its `feed` must return the consumed count exactly at the
boundary. `Inspector` then publishes the identification, drops the parser and
creates an inner `Inspector` (`_next`) with the remaining byte budget
(`replace(config, max_bytes=remaining)`; fewer than 64 bytes left ends the
shift as `shifted_payload=budget_exhausted`), the same rules and signatures,
and `protocol_hint=expected_family` whose evidence provenance is
`shift:<boundary>` rather than `caller`. Later `feed` calls are forwarded; the
inner metrics are added to the outer ones so `bytes_inspected` never exceeds
the input. Every inner event is merged by `_shift_result`: an identified inner
observation becomes the outer observation with `shift`/`shift_from` evidence
and the carrier's hostname/application kept only when the inner offers none; a
terminal non-identified inner observation re-publishes the carrier with
`shifted_payload` context. Events carry kind `shifted`. `end()` on a pending
shift ends the inner phase (`shifted_payload=incomplete`); `invalidate()`
discards it. One shift per direction: the inner Inspector may itself continue
(fingerprints) but a second boundary is not followed.

The SMTP STARTTLS watch reuses the post-identification continuation: the
EHLO line completes the identification and `LineParser.feed` returns at that
line even when more bytes are present, so the Inspector publishes first and
routes the following lines through `_continue`, where a parse error ends the
watch quietly instead of turning an identified EHLO into `malformed`. A shift
discovered during a continuation (STARTTLS) starts the inner phase from the
bytes after that line.

`RDPParser` now also validates the server Connection Confirm; `TPKTParser`
routes 0xd0 to it and copies the child's scope and shift. `WebSocketParser`
lives in `upgrade.py` and is registered as a hint-only family. `appid._build`
accepts the carrier application (`shifted_from`), appends it to
`implicitly_uses` and accepts the carrier's standard ports.

## Heuristics and flow risks (v0.29)

`heuristics.py` computes a `PayloadProfile` in one pass with a 256-entry
histogram and classifies it; `heuristic_evidence` turns it into four
`heuristic`-strength Evidence rows. `Inspector` reuses the bounded
unknown-payload buffer that custom signatures introduced: `_unknown_limit` is
the larger of `signature_bytes` (when a signature set wants `unknown-tcp`) and
`heuristic_bytes` (when heuristics are on); zero means the old immediate
`unknown`. `DatagramInspector._unknown` profiles the datagram directly.
`dns_with_contexts` returns a `DatagramMatch` with shape evidence when
heuristics are on (the plain tuple otherwise), so the default UDP path is
unchanged.

`risks.py` holds the documented `RISKS` table and `flow_risks(verdict, client,
server)`: one pass over each direction's evidence collecting only the eight
fields it reads, early return of the shared empty tuple, about 1-2 µs.
`appid.session_verdict` wraps the former merge (`_session_verdict`) and attaches
the risks with `Verdict._replace`, so every verdict path (classify, session
records, live events) carries them without touching the merge rules. TLS
ClientHello parsing gained an optional `offered` out-parameter so the version
evidence costs a small list rather than a full `ClientHelloInfo`.

## Policy evaluation and the unified entry point (v0.30)

`policy.py` turns a validated JSON document into `Rule` objects whose
conditions are frozensets (names resolved through the catalog aliases, ports
parsed into exact/range/dynamic tables) and evaluates them in order against a
`Verdict` plus the session transport and server port. The engine itself is
untouched: `Analyzer._record` and the live classification emitter call
`Policy.evaluate` after the verdict exists and attach `Decision.fields()`
(action, rule, reasons) to the record or event. Policies are operator input:
loading is strict (unknown keys and names are errors, 1024 rules, 4 MiB) and
nothing in a policy is executed or interpolated. `Policy.lint` reports
dependency conflicts by evaluating synthetic verdicts for the catalog's
`implicitly_uses`/`depends_on` entries, and rules that cannot match.

`protodetect.py` is a thin argparse front end: `analyze` and `live` forward
their remaining arguments to the existing scripts' `main()` (so their option
documentation stays authoritative), `protocols`/`apps`/`demo` call the demo
scripts, `risks` prints the RISKS table, `policy lint|test` and `signatures
lint` validate operator files, and `version` reads pyproject. Broken pipes
from paging tools end the delegated command quietly.

## pcapng framing (v0.31)

`capture_stream.PcapStreamDecoder` recognizes the format from the first four
bytes (pcapng Section Header Block magic, else one of the four classic
magics) and keeps two incremental parsers behind one `feed`/`end` contract.
The pcapng parser reads a block only once its whole `total_length` is
buffered, after checking the length (>= 12, multiple of 4, <= 1 MiB + 64
KiB) and its trailer copy; Section Header Blocks set the byte order and reset
the interface table (<= 256 interfaces per section), Interface Description
Blocks supply link type, snapshot length and `if_tsresol`, Enhanced and
Simple Packet Blocks become `CaptureRecord`s with their interface's link type,
and every other block type is counted and skipped. Options are walked with
bounds before any value is read. A failure clears the buffer and closes the
decoder exactly as for classic input. `packets.read_pcap_records` is now a
64 KiB chunked loop over the same decoder, so offline and live paths cannot
diverge, and `analyze_pcap` decodes frames with `link_packets.decode_frame`
by link type.

## S7comm through the cotp-connect shift (v0.32)

`COTPParser` validates both X.224 connection TPDUs and sets
`shift = ("cotp-connect", "s7comm")`; `TPKTParser` copies the shift from its
child and now routes a confirm to `RDPParser` only when the body is an RDP
negotiation response. `s7.S7Parser` is a `FrameParser` on the TPKT length with
the COTP data header checked in `frame_size` and the S7 header/parameter rules
in `validate`; it is registered hint-only (`s7comm`), so a bare S7 PDU without
the connection is never selected from the TPKT prefix. No dispatch table
changed: the shift mechanism of v0.28 carries the new family.

## Host-driven shift (v0.33)

`Inspector.open_shift(boundary, expected=None)` reopens a terminal identified
Inspector as the carrier of a shift whose boundary another direction
established. It refuses when the observation is not identified, already
shifted or pending, or when fewer than 64 budget bytes remain; it never
emits an event by itself (the shifted phase publishes when its bytes arrive)
and marks the `shift` evidence with source `wire:peer` so consumers can tell a
peer-derived boundary from one the direction announced. `Analyzer._correlate_connect`
runs after every identification event on a TCP connection and reads only
evidence (`http_method`, `shift`, `http_status`); `SessionManager` already
feeds every contiguous byte to the Inspector, so the server's tunnel bytes
reach the reopened phase without any change to reassembly. Live capture uses
the same Analyzer and gains the behaviour unchanged.

## Output schemas (v0.34)

`schemas/*.schema.json` describe the three JSON Lines surfaces (session
records, live events, offline rows) with closed objects and listed
enumerations; `tools/schema_check.py` implements the draft-07 subset they
use (types, enum/const, properties/required/additionalProperties, items,
bounds, oneOf/anyOf, local $ref) so validation needs no dependency.
test_schema.py runs both tools over the synthetic captures under every
shape-changing option and validates every line, which turns an accidental
field addition into a test failure and documents the contract in OUTPUT.md.

## ClientHello hot path (v0.35)

`parse_hello` reads the fixed fields and walks the extension list with
explicit offsets and bound checks instead of the `Reader` helper (which stays
for the rare SNI/ALPN/list sub-structures and for the server hello). The
rewrite is behaviour-preserving by construction: each slice is preceded by
the same comparison the helper performed and raises the same `ParseError`
message, and `tools/compare_client_hello.py` compares results and exceptions
with a baseline tree over every truncation and seeded mutations. The engine
contract that a hot-path change must keep its error semantics (AGENTS.md) is
checked this way rather than asserted.

## Shift-only parsers (v0.36)

`HTTP2ServerParser` shows the pattern for a parser that exists only behind a
shift or an explicit candidate: it is registered in `PARSERS` (so the shift's
expected family resolves and `--tcp-hint` can name it) but has no catalog
family of its own because it reports the existing `http/2` protocol name. The
dispatch tables never route to it, so a bare server SETTINGS frame stays
unknown without the 101 that explains it.
