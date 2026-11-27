# Security review A14: the 26/11 merge train on main (PRO-497)

Security Reviewer (AppSec), 2026-11-27. Base: `main` at `5cb35d29e6392b1d96d75c3f569baa378a0efe68` (tag
`python-final`). Method: read the merged diffs of each fix, try to defeat each one, and run the packages they
touch (`session`, `decrypt`, `keylogcap`, `quicx`, `analyze`, `analyzer`, `live`, `livectl`, `engine`,
`detector`: all `ok` on go1.27.4). Synthetic frames only; no traffic was captured.

## Verdicts

| # | Fix | Merged as | Verdict |
|---|---|---|---|
| 1 | SEC-SESS-1 half-open budget and eviction, TCP and UDP (`go/internal/session/tracker.go`) | #124 (`3647d2f`) | VERIFIED for what it claims; two residual gaps, SEC-SESS-2 (P2) and SEC-SESS-3 (P3) |
| 2 | SEC-KEY-1 residual: closed key-log connections release and zero their secrets | #144 (`ee45823`) | VERIFIED; one P3 residual in the key provider (SEC-KEY-2) |
| 3 | SEC-QUIC-1: an exhausted QUIC connection stays a sticky marker | #145 (`359b444`) | VERIFIED |
| 4 | PRO-119 decrypt memory bound and key zeroing | #150 (`6c6d4dd`) | VERIFIED (SEC-KEY-2 applies here too) |
| 5 | `udp_flow_limit` / `tcp_connection_limit` reported; main's Go test build fixed | #148 (`6a27cb0`), #156 (`5cb35d2`) | VERIFIED for those two counters; the other tracker counters are still dropped (SEC-LIM-11, P3) |
| 6 | Skip-marked reproducers of PRO-477 | #153 (`765feee`) | 7 of 10 still skip; no fix task visible in the repository or on GitHub (below) |

## Findings

| ID | Sev | Where | Attacker input | Impact |
|---|---|---|---|---|
| SEC-SESS-2 | P2 | `session/tracker.go:518-520`, `:572` | One valid DNS query per spoofed source port: 32 datagrams (analyze), 128 (`protodetect live`) per idle timeout (60 s) | Each flood flow is decided by its first datagram, so it leaves the half-open queue at once (`settle`, `:572`) and is never evicted. A table of decided flows refuses every new flow (`udp_flow_limit`) for the full idle timeout. The budget only stops floods of undecided datagrams. Silent in live (SEC-LIM-7). |
| SEC-SESS-3 | P3 | `session/tracker.go:631-634`, `:686` | A SYN plus a forged SYN-ACK per tuple: 64 packets fill a 32-connection table. In asymmetric mode the SYN plus one client data segment is enough; in midstream mode, one data segment (`:647-660`) | Established connections are never evicted for a new SYN, so new connections read `LIMIT` until the idle timeout. A passive sensor cannot authenticate the server side, so this is the limit of the fix, not a defect in it. It does not apply to `go/detector`, where the host admits each flow (`MaxFlows`, `RefusedFlowLimit`). |
| SEC-KEY-2 | P3 | `decrypt/keys.go:236-262` | A key-log fragment that fails validation after earlier valid lines, or that repeats a known line | Secrets decoded into `fresh`/`pending` before a rejecting line (`:238-258`), and the duplicate copy that passes `hmac.Equal` (`:255`), are dropped without being zeroed. #144 and #150 zero every other copy. The exposure is bounded (256 KiB of key log per provider), and the caller's key-log string cannot be zeroed in Go anyway. |
| SEC-LIM-11 | P3 | `analyze/analyze.go` (summary), `session/tracker.go:331,334,463-476` | A flood that hits the half-open budget | #148 copies only `udp_flow_limit` and `tcp_connection_limit`. `half_open_evicted`, `udp_half_open_evicted`, `half_open_timeout`, `udp_half_open_timeout`, `midstream_connections` and `asymmetric_connections` are still dropped from the analyze summary and live counts. Evictions show as per-session `end_reason`. A half-open timeout keeps the reference's idle reason, so it can't be told from a normal idle end. This is the rest of the scope the PRO-477 audit assigned to the SEC-LIM-1 fix. |

### Evidence

- **SEC-SESS-2:** `analyzer.TestSecGapUDPDecidedFloodLocksOutNewFlows` (`go/internal/analyzer/a14_gap_test.go`).
  32 identified DNS flows leave 0 half-open entries. The victim's DNS flow is refused at t = 1 s and t = 59 s,
  and `udp_flow_limit` reads 2. `session.TestUDPFloodEvictsOnlyUndecidedFlows` pins the same refusal as intended
  behaviour ("A table full of decided flows still refuses a new flow, as before"), so this finding is about the
  contract, not a regression.
- **SEC-SESS-3:** `analyzer.TestSecGapTCPForgedHandshakeFloodLocksOutNewConnections`. All 32 forged handshakes
  read "Tracking both directions", and the victim's SYN reads "LIMIT: too many tracked connections".
- **SEC-KEY-2:** code reading (`return 0, fail(...)` at `keys.go:238-258` returns with `fresh` and `pending` still
  holding decoded secrets; the `continue` at `:255` drops `secret` unzeroed). There is no reproducer, because Go
  cannot observe freed memory in a test.
- **SEC-LIM-11:** code reading (`analyze.go` sets only the two counters, from `an.Tracker.Counts`).

Both reproducers skip with their ID (`secGap`, the `limitGap` convention of PRO-477). They fail, asking for the
marker to be removed, once a fix admits the victim. Run them with
`cd go && go test ./internal/analyzer -run SecGap -v`.

### Recommended fixes

- **SEC-SESS-2:** when the UDP table is full, evict the least recently active decided flow (it is already
  identified, so its record loses nothing it would report), or bound the flows per source address. Either way,
  count the eviction.
- **SEC-SESS-3:** optional. Evict the oldest idle established connection that has carried no payload since its
  handshake, with a counter. Otherwise document the limit in the SEC-SESS-1 contract. Not needed for `go/detector`.
- **SEC-KEY-2:** `clear` every staged secret on each early return and the duplicate copy before `continue`.
- **SEC-LIM-11:** copy the remaining `Tracker.Counts` entries into the summary and live counts. The half-open
  timeout deserves its own end reason (a parity delta, the engine lane's call).

## What was tried and held

- **SEC-SESS-1, SYN flood:** only half-open states are evicted, oldest first, and before allocation
  (`tracker.go:320-335`). A real handshake completes during the flood in all three observation modes
  (`TestRealConnectionPassesASYNFloodInEveryObservationMode`).
- **SEC-SESS-1, retransmission:** a retransmitted SYN returns before any state change (`:624-628`). A half-open
  TCP state expires from `Start`, never from `Time` (`:292-294`), so neither a repeated SYN nor a bare ACK extends
  it. A new ISN on the same tuple re-queues the tuple at the back but cannot grow the table.
- **SEC-SESS-1, UDP:** undecided flows are capped at 3/4 of the table and expire after 5 s of silence. A
  keep-alive flood is still evicted oldest first, because the queue order is creation order.
- **SEC-SESS-1, mixed with completed connections:** decided flows and established connections are never evicted
  for a new state. For a full table of them, see SEC-SESS-2 and SEC-SESS-3.
- **SEC-KEY-1 (#144):** `release` wipes both directions and zeroes the client random. The TLS 1.3 traffic
  secrets and IVs are copies (`append([]byte{}, secret...)`), and KeyUpdate clears the old secret. The TLS 1.2
  key block is zeroed once (shared by both directions). The KeyProvider's own bytes are left to `Release`, which
  zeroes them. On the key-log path, a closed connection calls `Discard` before its row is kept
  (`keylogcap/decryptor.go:323`). An `open` event never replaces a live decoder, because the coordinator emits
  `open` only for a tuple with no retained state and `close` removes that state first. The finished window is
  bounded at 4096, and the oldest slot is set to nil before the window moves.
- **SEC-QUIC-1 (#145):** an over-budget merge sets `exhausted`, keeps the pre-overflow bytes, and answers
  `Exhausted` without merging or assembling (`assembler.go:302`). The contradiction check runs first, so a
  conflicting ClientHello still becomes the conflict marker. The marker ends, like every entry, by Reset, idle
  expiry or LRU eviction. A flood of other DCIDs can evict it, but a new DCID would reach a fresh entry anyway, and
  that eviction counter is already SEC-LIM-8.
- **PRO-119 (#150):** the record framer moves its tail into a fresh buffer of under 16645 bytes after each framed
  record. Queued record slots are cleared before the queue advances. The hello buffers are dropped once
  negotiated (34 bytes kept for TLS 1.2). The handshake epoch's secret and IV are zeroed when the handshake
  ends. `KeyProvider.Expire` zeroes before it deletes, and `keylogcap.Analyze` defers `Release` on every return.
  A non-typed validator error becomes a fixed `malformed` failure, never a panic or a positive result
  (`engine/datagram.go`).
- **#148 / #156:** the analyze JSON summary always carries `udp_flow_limit` and `tcp_connection_limit`; the text
  summary shows them when they are non-zero. `detector.Stats.RefusedFlowLimit` counts admission refusals.
  SEC-LIM-1, -2 and -6 are now plain assertions, and the analyze package builds and passes.

## Item 6: PRO-477 reproducers still skipped (on `5cb35d2`)

| ID | Test | Fix task |
|---|---|---|
| SEC-LIM-3 | `analyze.TestLimitGapAnalyzeTCPWithoutStartInSummary` | none visible |
| SEC-LIM-4 | `analyze.TestLimitGapPresentFlowLimitInMeta` | none visible |
| SEC-LIM-5 | `analyze.TestLimitGapPresentSessionEventCap` | none visible |
| SEC-LIM-7 | `live.TestLimitGapLiveUDPFlowLimitInSummary` | none visible |
| SEC-LIM-8 | `analyzer.TestLimitGapQUICAssemblerEvictionIsReported` | none visible |
| SEC-LIM-9 | `analyzer.TestLimitGapUDPRecordHidesLaterCompleteObservation` | none visible |
| SEC-LIM-10 | `livectl.TestLimitGapEventViewQualityOutlivesRetention` | none visible |

SEC-LIM-1, -2 and -6 were fixed by PRO-448 / PRO-481 and are now plain assertions.

"None visible" means no open GitHub issue or pull request names the ID (searched `SEC-LIM` in issues and PRs: only
the closed #153 and #156), and no engine document (`migration/STATUS.md`, `migration/LANE-BRIEF.md`) records a
task for it. Paperclip tasks cannot be seen from this lane. The fix requests are therefore restated below, so that
each has a task.

Other skips seen in the same run are post-merge backlog items, not this audit's: `PM1`, `PM2` and `PM3` in
`analyzer`, and `PM2`, `PM6` and `PM8` in `engine`.

## Routing

- FIX SEC-SESS-2: P2 a table of attacker-decided UDP flows (one valid DNS query each) refuses every new flow for the idle timeout; the half-open budget never sees them (go/internal/session/tracker.go:518)
- FIX SEC-SESS-3: P3 forged SYN/SYN-ACK pairs fill the TCP table with established connections that are never evicted for a new SYN (go/internal/session/tracker.go:631)
- FIX SEC-KEY-2: P3 secrets staged by a rejected or duplicate key-log line are dropped without zeroing (go/internal/decrypt/keys.go:236)
- FIX SEC-LIM-11: P3 half-open eviction and timeout counters and the other Tracker.Counts are still missing from the analyze summary and live counts (go/internal/analyze/analyze.go)
- FIX SEC-LIM-3, -4, -5, -7, -8, -9, -10: still open from PRO-477 with no visible fix task (docs/security/LIMITS-AUDIT-PRO-477.md)
