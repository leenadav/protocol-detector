# Protocol detector v0.11

A standalone Python 3.9+ protocol classification engine and passive observation
tool. **35 protocol families**, with explicit profiles rather than claims of full
protocol/session validation. No Python runtime dependencies. Live capture uses
an installed `tcpdump`; ordinary demos and tests require no capture privileges.
We are staying in Python. This release does not integrate with or modify an SWG.

Start with [START-HERE.md](START-HERE.md) for Hebrew instructions.

## Run

```bash
cd ~/protocol-detector
make test
make demo
make protocols
make interfaces
make live INTERFACE=en0 DURATION=60
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
TLS ClientHello, BGP, SMB2/3, DNS, SNMP, TFTP, STOMP, NATS, IMAP, RDP, FastCGI and rsync detections,
including server-direction handshakes. Separate modes also check MySQL, MongoDB
and RADIUS with explicit candidates. It is opt-in, outside
`make test`. `sample-expanded.pcap` is generated synthetic data with reordered
TCP segments and UDP messages on arbitrary ports.

If capture permission is denied, grant permission to the capture helper according
to your OS setup. The `--stdin` mode accepts a classic PCAP pipe from a separately
privileged tcpdump; keep Python unprivileged. See START-HERE for a Mac command.

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
| live_capture.py | Bounded live loop, readable/JSON events and capture diagnostics |
| capture_stream.py | Incremental PCAP framing |
| link_packets.py | Link/IPv4 decoding |
| sessions.py, analyze_pcap.py | Bounded prefix reassembly and observer lifecycle |
| live_smoke.py | Opt-in real loopback verification |
| protocol_fixtures.py, protocol_demo.py | Synthetic protocol examples |
| benchmark_v08.py | Current comparison and adapter measurements |

## Current limits

Live TCP needs SYN and SYN-ACK. No attaching midway through a connection, complete
TCP endpoint validation, IP fragment reassembly, TLS decryption, QUIC/HTTP3, PCAPNG
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
