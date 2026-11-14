# Culvert lab kit: detector, log, UI and policy integration (2026-11-14)

This directory is the backup of a local lab that runs the protocol detector inside a local copy of Culvert. It follows `docs/integration/PROTODETECT-CULVERT-WORKING-PLAN.md`. Nothing here was pushed to, or proposed for, KidCarmi/Culvert.

**One deviation from the plan, at Lee's request (2026-11-14):** the plan gates any enforcement behind a separate phase (L7) with a threat model and adversarial qualification. This lab already contains a per-rule protocol restriction with an enforce mode. It is a lab demonstration with the limits listed below, not a qualified control.

## What was built on the Culvert lab branch

Base: Culvert `52eb9d1e4482adc9773afc4db77109acad617625`, local branch `lab/protocol-detector` (4 commits, push disabled). The patch is `culvert-lab-52eb9d1.patch`; it leaves out `frontend/dist`, which `npm run build` regenerates.

| Area | Change |
|---|---|
| Detector | A Culvert-owned interface (`internal/protodetect`) with three engines: off, a scripted fake, and a thin wrapper over this repository's `go/detector`. Built through `go.work`; Culvert's `go.mod` and `go.sum` are untouched. |
| Relay | CONNECT bypass tunnels only. Each direction is observed for a bounded prefix (write first, then feed the detector), then the relay returns to Culvert's normal copy path. |
| Log | The result rides Culvert's own `TUNNEL_CLOSED` entry as a nested `pd` block: its own schema version, closed vocabularies, absent when nothing was observed. Host names go through Culvert's keyed destination pseudonymizer. |
| Signals | Three advisory flags in the `pd` block: `nonstandard_port` (for example HTTP on 9000), `host_mismatch` (client-asserted host differs from the CONNECT destination), `server_unresolved` (server reply not recognised). They are not verdicts. |
| Policy | `PolicyRule.AppRestriction`: an Allow rule may name the protocol families allowed on its tunnels, in `monitor` or `enforce` mode, with an explicit action for "could not be identified". |
| New frontend (`frontend/`) | Traffic: an Application / Protocol column, a protocol-mix bar and an evidence panel in the row detail. Access Rules: the restriction in the rule editor and in the rules list. Rebuilt with the pinned Node 24.19.0. |
| Legacy UI | The same Application / Protocol column with expandable evidence (done before the request to use the new frontend). |

## How the restriction behaves

| Situation | Monitor | Enforce |
|---|---|---|
| Client protocol identified and in the allowed list | Passes; verdict `allowed` | Held bytes are forwarded; verdict `allowed` |
| Client protocol identified (or named by its prefix as outside the profile) and not in the list | Passes; verdict `would_block` | Tunnel closed; verdict `blocked`; no client byte forwarded |
| Could not be identified (unknown, incomplete, budget exhausted, unsupported, engine failure) | The rule's unknown action, recorded as `allowed` or `would_block` | The rule's unknown action: forwarded, or closed with nothing forwarded |
| Detector unavailable (off, refused, breaker open) | Same, with reason `detector_unavailable` | Same: an enforce rule never silently allows |

Details that matter:
- **A restriction can only narrow an Allow.** It is rejected on other rule types and can't turn a block into an allow.
- **What is held.** In enforce mode the client's first bytes are held, up to 16 KiB and the observation window, including bytes sent in the same write as the CONNECT header. The server's bytes are not held, so a server-first banner still reaches the client.
- **Only an identification can allow.** A result of "outside profile" names a family from the prefix alone, before its structure is validated. It can refuse a tunnel; it can never match the allowed list.
- **Decided once.** The verdict is taken when the client direction leaves "detecting"; it never changes afterwards.
- **Logged even on quiet rules.** A block is written as `APP_BLOCKED` even when the rule doesn't log traffic.

## Codex's advisory read (2026-11-14) and what changed

Codex read the patch as advice, not as a review round ([issue #2 comment 6880722498](https://github.com/leenadav/protocol-detector/issues/2#issuecomment-6880722498)). It could not run anything, so its points are source traces.

| Point | Outcome |
|---|---|
| 1. The hold could reach 20479 bytes, past its 16 KiB budget | Fixed: reads are sized to what is left of the budget. Regression test `TestLabHoldNeverExceedsItsBudget`. |
| 2. The window was read before it was initialised | Fixed: initialisation runs before the expiry is computed. No dedicated test. |
| 3. A short write without an error could drop bytes | Fixed: treated as `io.ErrShortWrite` at both write sites. No scripted-Conn test yet. |
| 4. Idle timing differs from the unmodified relay | Not fixed. The tap stamps activity per read; the unmodified loop stamps when its copy returns. Byte-hash tests don't cover this. |
| 5. Expiry releases the parser state, not everything | Not fixed, documented: the 4 KiB tap buffer and, in enforce mode, the held bytes live until a blocked write returns. |
| 6. `outside_profile` counted as a named protocol on the allow side | Fixed: only an identification can match the allowed list. Decision-table tests. |

Still to test, from the same read: a valid allowed opening followed by another protocol in the same read and in the next one; CONNECT, Upgrade and STARTTLS transitions; unknown=allow at byte, feed and time exhaustion.

## Results of the run in `results/`

`results/index.html` is the check matrix, `results/observatory.html` the same run in the Protocol Observatory's design, and `shots/` holds photos of Culvert's own UI.

84 checks: 83 passed, 0 failed, 1 known gap.

- **Traffic unchanged (builds A–E):** every scenario passed, and the delivered bytes have the same hash on all five builds.
- **Detector off (A, B):** no detector records.
- **Real detector (D):** TLS (with SNI), SSH in both directions, SMTP and HTTP identified; PostgreSQL reported outside the profile; unrecognised bytes unknown; 1-byte writes an explicit `budget_exhausted`; a silent tunnel `incomplete`/`expired` after the 3-second window.
- **Policy, real detector (D):**
  - TLS to the TLS-only host passed.
  - An SSH client, unrecognised bytes and an HTTP request pipelined with the CONNECT header were each blocked, and the recording origin received **0 client bytes** in each case.
  - The same SSH client to the monitor-mode host passed and was recorded as `would_block`.
- **Policy, detector off (F):** the enforce rule blocked everything with reason `detector_unavailable`; the monitor rule passed traffic and recorded `would_block`.
- **Panics (E):** every tunnel still delivered every byte.
- **After 300 short tunnels:** the engine held 0 flows on C, D and E. This is measured with one quiet probe tunnel afterwards, because a record's counters are read while other tunnels may still be open.
- **SSRF guard:** 403 on every build for `127.0.0.1`, `10.0.0.1`, `198.18.0.1` and `169.254.169.254`.
- **Known gap, reproduced live:** the server side of a TLS handshake that uses X25519MLKEM768 is `unknown` (work item #4). It also raises the `server_unresolved` signal.
- **Splice (earlier run of this lab):** during a 32 MiB echo, `strace -f -c -e trace=splice` counted 256 splice calls on A and 217 on D, with the same delivered hash.

Tests on the lab branch:
- Go: `go test -run 'TestLab|Policy|ProxyE2E|RelayBuf|TunnelIdle|TunnelBypass|TunnelDrain|FrontendV2|ConfigSurface|LogEntry|Reqlog|APIContract|OpenAPI|UIContract' .` passed (378 tests) before the advisory fixes, plus `./internal/logstore` and `./internal/reqlog`. After the fixes, `TestLab` passed under the race detector and the subset without the last five patterns passed again. Culvert's full test suite was not run.
- Frontend: `npm run typecheck`, `npm run lint`, `npm run format:check` and `npm test` (791 tests) passed.

## What this does not show

- **Not a qualified security control.** No threat model, red-team pass or false-positive measurement stands behind the enforce mode.
- **Only the first message is checked.** After an allowed first message, the rest of the tunnel is not inspected. A client can send a valid TLS ClientHello and then anything, and two cooperating endpoints can imitate a protocol's opening.
- **Encrypted content is opaque.** "TLS allowed" says nothing about what is inside the TLS session. SNI and ALPN are client assertions.
- **Only CONNECT bypass tunnels.** Inspected tunnels, non-TLS fallbacks, SOCKS5, WebSocket and plain HTTP are untouched. A restriction on a rule whose tunnels are inspected has no effect.
- **Rule storage only.** The new rule field is not registered in Culvert's config surfaces, snapshot, OpenAPI contract, policy tester, commit-review diff or learning mode. Detector settings are environment variables.
- **One container, not two VMs. No performance or memory measurement.**
- **Untested paths:** expiry while a direction is blocked in `Write`, idle-timeout parity with the unmodified relay (known to differ, see Codex's point 4), short writes, and holding under a slow client beyond the window.
- **Not reviewed.** The Culvert lab change has had no Codex round, by decision.

## Reproduce

1. Clone Culvert at `52eb9d1`, create `lab/protocol-detector`, apply `culvert-lab-52eb9d1.patch`, and disable push on that clone.
2. Copy `go.work.example` to a `go.work` naming your Culvert checkout and this repository's `go/`.
3. Frontend: Node 24.19.0 and npm 11.17.0 (the versions `frontend/package.json` pins), then `npm ci` and `npm run build` in `frontend/`.
4. Build A with `GOWORK=off go build -o culvert-A .` on the unpatched commit, and the lab binary with `GOWORK=<your go.work> go build -o culvert-lab .` on the lab branch.
5. `tools/start-lab.sh` starts the origins and the six proxies. `tools/lab_admin.py 19093 D` and `tools/lab_admin.py 19095 F` create the lab admin and the three rules. `tools/run-live.sh` runs the scenarios; `tools/observatory.py` renders the Observatory-style page. The scripts assume `/home/user/culvert-lab`.

| Build | What it is | Proxy port |
|---|---|---|
| A | Unmodified Culvert | 18080 |
| B | Lab build, detector off | 18081 |
| C | Lab build, fake engine | 18082 |
| D | Lab build, real detector, restriction rules, new UI at `/app` | 18083 |
| E | Lab build, fake engine that panics on every call | 18084 |
| F | Lab build, detector off, same restriction rules | 18085 |

The lab admin password is generated per run and kept in a mode-0600 file under the lab's `run/` directory; it is not in this repository.
