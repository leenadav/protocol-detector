# Go engine architecture

This is a map of the Go engine under [`go/`](../go/) as it stands on
`claude/go-migration`. It describes what the code does, read from the package
sources and their doc comments. It is not a readiness statement: the port is
experimental, the Python 3.9 engine remains the behavioural reference, and the
decisions and evidence behind the design live in the documents linked in
[Boundaries](#boundaries), not here.

Module: `github.com/leenadav/protocol-detector/go` (see
[`go/go.mod`](../go/go.mod)). The single external dependency,
`golang.org/x/crypto` (with `golang.org/x/sys`), is vendored under
[`go/vendor/`](../go/vendor/).

Entry point: [`go/cmd/protodetect`](../go/cmd/protodetect/main.go), a CLI with the
subcommands `version`, `cases`, `replay`, `analyze`, `present`,
`decrypt-capture`, `live`, `live-decrypt`, `control-replay`, `serve`,
`serve-worker` and `bench`.

## 1. Package map

`go/internal` holds 35 top-level entries (34 packages and the `protocols/`
directory, which groups nine protocol packages). Each is listed once below, in
groups.

### Input decoding

| Package | What it does |
|---|---|
| [`capture`](../go/internal/capture/) | Incremental classic PCAP (all four magics) and pcapng framing: section header, interface description, enhanced and simple packet blocks; other blocks are skipped. Every length is checked before a slice is taken; a failure closes the decoder. |
| [`transport`](../go/internal/transport/) | Decodes one captured frame into an IPv4 TCP segment or UDP datagram: Ethernet (up to two VLAN tags), BSD/OpenBSD loopback, Linux cooked v1/v2 and raw IPv4. IPv6, IPv4 fragments and other transports are rejected with a typed reason, plus the flow endpoints when readable. |
| [`ascii`](../go/internal/ascii/) | ASCII-only case mapping, matching Python's `bytes.lower()`/`upper()`. Go's Unicode-aware mappings would accept some non-ASCII tokens as keywords. |
| [`names`](../go/internal/names/) | DNS hostname normalization shared by HTTP `Host` and TLS SNI: lowercase ASCII labels, no IP literals. |
| [`buffer`](../go/internal/buffer/) | Bounded byte primitives. Ownership rule ([ADR 0001](../migration/adr/0001-ownership-and-resources.md)): a caller's slice may be reused once a call returns; anything kept is copied. |

### Transport and reassembly

| Package | What it does |
|---|---|
| [`session`](../go/internal/session/) | `Manager` and `Tracker`: TCP connection lifecycle (handshake, half-close, FIN/RST, idle timeout, eviction) and UDP flows. Feeds ordered, de-duplicated deltas to a per-direction `Sink`. |
| [`reassembly`](../go/internal/reassembly/) | One direction's bounded initial window (`Stream`): sequence numbers, retained window, and each contiguous byte handed out exactly once. Transport only; it knows nothing about protocols. |
| [`sessionid`](../go/internal/sessionid/) | Deterministic session id from transport and both endpoints, independent of direction. BLAKE2s with an 8-byte digest, so no address or port is exposed in it. |

### Protocol parsers and heuristics

| Package | What it does |
|---|---|
| [`parsing`](../go/internal/parsing/) | Vocabulary shared by the engine and every family parser: failure classes and reason sentences (compared verbatim with Python), the `NotPorted` marker for paths the Go backend lacks, and the `Parser`/`Result` interface the inspector drives. |
| [`protocols/textroute`](../go/internal/protocols/textroute/) | Text route: the HTTP/1 start-line and header profile and the HTTP/2 path (`http2.go`). Other text families end in `NotPorted`. The package doc comment still says `httpx`; the package clause is `textroute`. |
| [`protocols/tlsx`](../go/internal/protocols/tlsx/) | TLS and DTLS hello profiles: ClientHello structure with SNI/ALPN as assertions, bounded TLS 1.2/1.3 ServerHello and HelloRetryRequest. Nothing is decrypted or authenticated; fingerprints and certificate watch are `NotPorted`. |
| [`protocols/quicx`](../go/internal/protocols/quicx/) | QUIC v1/v2 Initial and Version Negotiation recognition. With `quic_decrypt`, client Initial protection is removed using keys derived from public values; only the allowed frames are accepted and the CRYPTO stream is assembled for SNI/ALPN. |
| [`protocols/dnsx`](../go/internal/protocols/dnsx/) | DNS layout validator and DNS-over-TCP framing. Names are validated and never emitted. |
| [`protocols/framed`](../go/internal/protocols/framed/) | Initial binary-message families on a shared frame parser (PostgreSQL, RFB, BitTorrent, memcached, FINS, AFP, ZMTP, Bolt) and two line protocols (rsync, STOMP). Every advertised size is bounded before the buffer grows. |
| [`protocols/hpack`](../go/internal/protocols/hpack/) | RFC 7541 header-block decoding, bounded for passive inspection (field count, string length, header list and dynamic table). `tables.go` is generated from the RFC appendices and marked DO NOT EDIT. |
| [`protocols/fingerprint`](../go/internal/protocols/fingerprint/) | Derived handshake fingerprints: JA3/JA4, JA3S/JA4S, HASSH and the HTTP/2 SETTINGS string. A digest of structural fields only, at best an implementation family. |
| [`protocols/x509x`](../go/internal/protocols/x509x/) | Bounded structural walk of a leaf X.509 certificate from a TLS 1.2 Certificate message: what the structure says about itself, not who it names. |
| [`protocols/heuristics`](../go/internal/protocols/heuristics/) | Payload shape for traffic no profile matched (entropy, printable and zero ratios over a bounded prefix). Never identifies an application; evidence strength is `heuristic`. |

### Session analyzer and engine

| Package | What it does |
|---|---|
| [`engine`](../go/internal/engine/) | The inspector: `New` and `Feed` take bytes of one connection direction and `Select` (in `dispatch.go`) picks candidate parsers from the first bytes, mirroring Python's decision table. Owns the family factory, the HTTP/2 and continuation handling, and the UDP `Datagram` inspector. It has no package doc comment. |
| [`analyzer`](../go/internal/analyzer/) | Drives `session` with the engine attached as each direction's sink. Per UDP payload it classifies; when a connection or flow ends it produces one session record: verdict, risks, layered view and structured unknown. Holds the `policy` and `signatures` attachments. |
| [`events`](../go/internal/events/) | Live event envelopes, a bounded sequenced log read by cursor, and a deterministic reducer into the session view. |
| [`errs`](../go/internal/errs/) | Structured, payload-free errors: a closed code, the scope (direction, flow, capture, worker, process), and the limit involved. |
| [`telemetry`](../go/internal/telemetry/) | Integer counters and fixed-bucket histograms at component boundaries. Counts and durations only; no payload, names or keys. |
| [`clock`](../go/internal/clock/) | Separates wall-clock reads from components that need time, so tests run deterministically. Capture timestamps are inputs, not host reads. |
| [`contracts`](../go/internal/contracts/) | Typed observations, events, metrics and configuration shared by all components, serialized in the Python reference's shape so the harness compares field by field. |

### App-ID and content

| Package | What it does |
|---|---|
| [`content`](../go/internal/content/) | Loads and validates the versioned detection content pack (`pack.json`, with `history.json` and an embedded copy), applying the same checks as the Python loader: duplicates, unknown categories, unresolved references. Also version comparison and digest support (`digest.go`). |
| [`appid`](../go/internal/appid/) | One or two directional observations become a session verdict (catalog application or session outcome) with category, risk and port-usage metadata. Adds no parsing. |
| [`policy`](../go/internal/policy/) | Ordered rules over session verdicts (allow, deny, alert), first match wins, otherwise the default. Never inspects payload or changes a verdict; the decision is a label the host acts on. |
| [`signatures`](../go/internal/signatures/) | Custom application signatures from JSON, compiled once and evaluated over bounded parser contexts. A match contributes only the signature's name. |

### Offline analysis, decryption and live capture

| Package | What it does |
|---|---|
| [`analyze`](../go/internal/analyze/) | The offline `analyze` command over a PCAP or pcapng file: runs `capture`, `transport` and `analyzer`, and writes rows with the reference's key order via `pyjson`. `present.go` renders the readable view. |
| [`decrypt`](../go/internal/decrypt/) | Offline, bounded TLS key-log decryption with supplied secrets. Records are authenticated with the logged secrets; Finished transcripts and certificate trust are not verified. No clock, file or socket; the key provider is injected. |
| [`keylogcap`](../go/internal/keylogcap/) | Offline key-log decryption adapter: reassembles each TCP direction once under a retention budget, feeds one TLS decoder per connection and reports one row per connection. |
| [`live`](../go/internal/live/) | Host capture adapter: `tcpdump` owns capture; this process stays unprivileged, inspects the initial message of each stream and emits metadata events only (no payload, credentials or names). |
| [`livedecrypt`](../go/internal/livedecrypt/) | Bounded live decryption worker: packets from `tcpdump`, reassembly, record authentication in bounded slices, append-only key-log reads. Failures are reported as fixed codes. Platform-specific files for Unix and non-Unix. |

### CLI, dashboard service and jobs

| Package | What it does |
|---|---|
| [`serve`](../go/internal/serve/) | Loopback-only dashboard service: bounded handler pool, live control endpoints (`/api/live/*`), admission-controlled analysis and decryption jobs, and the static page. Answers match the Python server's status, body and headers. `worker.go` is the serve-worker process. |
| [`livectl`](../go/internal/livectl/) | Bounded live metadata bridge behind the dashboard endpoints: the retained run state (`state.go`) and process control (`process.go`). Unix and non-Unix variants. |
| [`jobs`](../go/internal/jobs/) | Bounded asynchronous worker jobs with admission control: at most `MaxRunning` run and `MaxQueued` wait; the rest are refused. Lifetimes, bounded retention of finished outcomes, idempotent cancel and shutdown. |
| [`ojson`](../go/internal/ojson/) | JSON values with Python `json` semantics: ordered objects, exact integer digits, `json.loads`-style decode and `json.dumps(allow_nan=False)`-style encode. |
| [`pyjson`](../go/internal/pyjson/) | Writes rows exactly as Python's `json.dumps` does with defaults, with the key order stated by the caller, so text consumers keep working. |

### Test support and differential harness

| Package | What it does |
|---|---|
| [`testframes`](../go/internal/testframes/) | Builds synthetic Ethernet/IPv4 TCP and UDP frames for tests, byte-compatible with the Python sample generator. Never transmitted. |
| [`parity`](../go/internal/parity/) | Reads the shared differential cases (`migration/fixtures/cases.json`) and writes a backend's results in the shape `migration/parity/compare.py` reads. |
| [`replay`](../go/internal/replay/) | Runs the shared cases through the Go backend. A case it cannot answer yields `{"unsupported": reason}`, never a detection. Used by `protodetect replay`. |
| [`bench`](../go/internal/bench/) | Times the feed loop on the shared benchmark workloads (latency distributions and allocations). Reported, not a correctness check; gated builds use the `benchgate` and `loadbench` tags. |

## 2. Data flow: one flow from bytes to JSON

Offline `analyze` path, for one TCP connection. Packages in the order the data
passes through them:

1. **`capture`**: `Decoder.Feed` frames the file bytes into records (timestamp,
   link type, frame bytes). Bounded; a framing error closes the decoder.
2. **`transport`**: `Decode` turns each frame into a `TCP` segment or a `UDP`
   datagram, or a typed `Reject` carrying the endpoints when readable.
3. **`analyzer`**: `Analyzer.Process` dispatches by packet type and hands TCP
   segments to `session`.
4. **`session`**: tracks the connection and its per-direction windows. Each
   payload goes through **`reassembly`**, and only ordered, de-duplicated
   bytes reach the direction's sink.
5. **`engine`**: the sink is an `engine.Inspector`. `Feed` uses `Select` to
   choose candidate parsers from the first bytes, runs the matching
   **`protocols/*`** parser (with **`parsing`** results and **`heuristics`**
   when nothing matched), and applies any **`signatures`**. The output is
   `contracts` events and an `Observation` per direction.
6. **`analyzer`** (on connection end): the two observations go to
   **`appid`**.`SessionVerdictWith`, which uses the **`content`** pack, then
   **`policy`**`.Evaluate` attaches a decision label. The session record is
   built with the layered view, risks and unknown structure.
7. **`analyze`**: rows are rendered with **`pyjson`** in the reference's key
   order and written to stdout as JSON lines. **`telemetry`** counters are
   recorded at each boundary.

UDP follows the same shape: `analyzer` calls `engine.Datagram.InspectFlow`
(QUIC via **`protocols/quicx`** where enabled) and then `session.Tracker.ProcessUDP`.

Live and decryption paths reuse the same parts: `live` and `livedecrypt` take
packets from `tcpdump` (`live` through `session`/`analyzer`; `livedecrypt`
through `keylogcap`/`decrypt`), and `serve` exposes them through the
`/api/live/*` endpoints with state in `livectl`, events in `events`, and jobs in
`jobs`.

The differential path is separate: `replay` runs the cases in
`migration/fixtures/cases.json`. Stream cases go to `engine` directly; session
cases go through `analyzer` and `session` without a capture file. `parity`
writes the results in the shape the comparator reads.

## 3. Boundaries

- **No socket, TLS or policy I/O in the detector.** The host owns sockets,
  TLS termination, policy enforcement, timeouts and forwarding. The engine
  analyzes bytes already read; `policy` returns a label and never acts. The
  `live` and `serve` packages run `tcpdump` and a loopback HTTP service, but
  they are host-side adapters, not part of the detection path.
- **Evidence, not identity.** SNI, ALPN, ports and fingerprints (JA3/JA4,
  HASSH) are evidence about traffic. They are not authenticated identity:
  `decrypt` authenticates records with supplied secrets only and does not verify
  Finished transcripts or certificate trust.
- **Scope of input.** The transport layer rejects IPv6 and IPv4 fragments
  (`transport`). Tests use synthetic frames (`testframes`). Results on
  external traffic are not established by the committed fixtures.
- **Python is the reference.** The Python 3.9+ engine stays the behavioural
  reference; the Go port is compared against it by the shared cases and
  harness in `migration/`. Fixture agreement does not establish full feature
  parity or production readiness.
- Design decisions and state are recorded in:
  - [ADR 0001: ownership and resources](../migration/adr/0001-ownership-and-resources.md)
  - [ADR 0002: toolchain, layout and dependencies](../migration/adr/0002-toolchain-layout-dependencies.md)
  - [`migration/CONTRACTS.md`](../migration/CONTRACTS.md): the contracts the Go and Python sides share
  - [`migration/STATUS.md`](../migration/STATUS.md): milestone and batch status

## 4. Build and test

Toolchain: `go/go.mod` declares `go 1.27.4` and has no separate `toolchain`
line, so the compiler is `go1.27.4`. The Makefile derives `GO_TOOLCHAIN` and
`GO_MINIMUM` from that line. Each target below is defined in the
[`Makefile`](../Makefile):

| Command | What it runs |
|---|---|
| `make go-check` | gofmt check, `go vet`, `go test -race ./...`, and a 5–20 s fuzz run for each listed fuzz target, all with `-mod=vendor`. |
| `make go-check-minimum` | `go vet` and `go test -race` on the minimum Go version from `go.mod`. |
| `make go-build` | `CGO_ENABLED=0 go build -trimpath -o go/bin/protodetect ./cmd/protodetect`. |
| `make go-vendor-check` | Re-vendors into a git-ignored directory and fails if `go/vendor`, `go.mod` or `go.sum` differ or are uncommitted. |
| `make go-drift` | Runs `tools/check_go_drift.py`. |
| `make parity-go` | `protodetect replay` over the shared cases, then `compare.py` and `verify_families.py`. Needs Python 3. |
| `make parity-control`, `parity-server`, `schema-go`, `adversarial` | Compare the built binary against the Python reference (control replay, server, JSON schemas, adversarial inputs). Each depends on `go-build`. |
| `make bench-gate` | Allocation and retention gates under the `benchgate` tag. |
| `make bench-load` | Synthetic load test (10,000 and 100,000 flows) under the `loadbench` tag. Reported only, not a gate. |

Verification status for this document: **unverified by build.** Go and `make`
are not installed on the machine where this file was written, so no command
above was run. The package list was checked against `ls go/internal` (35
entries) and the target names were checked against the Makefile by reading.
The statements about package behaviour come from the package doc comments and
the code paths named above.

## 5. Known gaps in the documentation

- `go/internal/engine` has no package doc comment; its role is described here
  from the code.
- `go/internal/protocols/textroute` has a doc comment that names `httpx`; the
  package clause is `textroute`.

Both are code-side items for the Engine lane; this file does not change code.
