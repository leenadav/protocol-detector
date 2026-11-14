# Culvert lab kit: first live run (2026-11-14)

This directory is the backup of a local lab that runs the protocol detector inside a local copy of Culvert, in observe mode. It follows `docs/integration/PROTODETECT-CULVERT-WORKING-PLAN.md` (phases L0, L1, L3 and L4, first pass). Nothing here was pushed to, or proposed for, KidCarmi/Culvert.

## What ran

Five proxies side by side, each with its own data directory, all on loopback:

| Build | What it is | Port |
|---|---|---|
| A | Unmodified Culvert `52eb9d1e4482adc9773afc4db77109acad617625` | 18080 |
| B | Lab build, detector off | 18081 |
| C | Lab build, scripted fake engine | 18082 |
| D | Lab build, real detector (`go/detector` at `0eb7ee7`), profile http, tls, ssh, smtp | 18083 |
| E | Lab build, fake engine that panics on every call | 18084 |

Fifteen synthetic scenarios run against every build (`tools/runner.py`). Each one first checks the traffic itself, then checks the detector's record against an expectation written from what the scenario sends.

## Results of this run

Open `results/index.html`. In summary:

- **Traffic:** every scenario passed on every build. Where bytes are echoed, the hash of what was delivered is identical on all five builds: 1 MiB, 32 MiB, bytes pipelined with the CONNECT header, half-close, 1-byte writes.
- **Detector off (A, B):** no detector records at all.
- **Real detector (D):**
  - TLS ClientHello identified with its SNI.
  - SSH identified in both directions, including the server-first banner.
  - SMTP client identified.
  - HTTP inside a tunnel identified in both directions.
  - PostgreSQL reported as outside the profile.
  - Unrecognised bytes reported as unknown.
  - 1-byte writes ended as an explicit `budget_exhausted`, never left at `detecting`.
  - A silent tunnel ended as `incomplete`/`expired` after the 3-second window, and a byte sent afterwards still passed.
  - After 300 short tunnels the engine held 0 flows.
- **Injected panics (E):** every tunnel still delivered every byte; the flows were quarantined.
- **SSRF guard:** CONNECT to `127.0.0.1`, `10.0.0.1`, `198.18.0.1` and `169.254.169.254` returned 403 on every build.
- **One known gap, reproduced live:** on D, the server side of the TLS scenario is `unknown` ("Server key share group outside supported profile"). The scenario's client and origin both use OpenSSL 3.5.9, which negotiates the X25519MLKEM768 hybrid group by default. The same origin through curl with OpenSSL 3.0.13 (X25519) was identified. This is work item #4.
- **Splice:** during a 32 MiB echo, `strace -f -c -e trace=splice` counted 256 splice calls on A and 217 on D, with the same delivered hash. `results/splice-trace-*.txt` hold the raw counts. This shows the kernel splice path is used after the observation hands back; it was a tracing run, not a performance run.
- **Culvert's own tests on the lab branch:** `go test -run 'TestProxyE2E|RelayBuf|TunnelIdle|TunnelBypass' .` passed with the detector off.

## What this run does not show

- **One container, not two VMs.** Client, proxies and origins share one host and one loopback interface.
- **No performance or capacity result.** Timings on the page are context only. No memory measurement was taken.
- **Lab addresses.** The origins are on `203.0.113.10` (RFC 5737), added to `lo`. Unmodified Culvert reached them through its real resolver and dial with every protection on, so no SSRF exception was needed. That is proven for this container only.
- **Only the CONNECT bypass path is tapped.** Inspect paths, non-TLS fallbacks, SOCKS5, WebSocket and the facts-only phase (L2) are untouched.
- **Blocked-write expiry was not exercised.** The timer-based expiry is implemented; the "one or both directions blocked in Write" cases are not tested yet.
- **Idle-clock parity is not tested.** The tap stamps activity per chunk while observing; `idleCopyCounted` stamps when `io.Copy` returns.
- **Logging is a lab log line** (`PROTODETECT {json}`), not the ADR-0011-style block on the log entry. Hostnames pass through Culvert's `redactHost` switch.
- **Wiring is by environment variable**, not a config surface.
- **Not reviewed.** The Culvert lab change has had no Codex round, by decision.

## Reproduce

1. Clone Culvert at `52eb9d1` and apply `culvert-lab-52eb9d1.patch` on a local branch `lab/protocol-detector`. Disable push on that clone.
2. Copy `go.work.example` to a `go.work` that names your two checkouts (Culvert, and this repository's `go/`).
3. Build A with `GOWORK=off go build -o culvert-A .` on the unpatched commit, and the lab binary with `GOWORK=<your go.work> go build -o culvert-lab .` on the lab branch.
4. `tools/start-lab.sh` starts the origins and the five proxies; `tools/run-live.sh` runs the scenarios and keeps `results/index.html` current. The scripts assume `/home/user/culvert-lab`; adjust the paths.

Binaries of this run (sha256): `culvert-A` `df4bf3c64959ede9…a487ff`, `culvert-lab` `54f2b63a15903193…2df311`. Compiler go1.27.4, Linux 6.18.44.

Lab environment variables (lab build only):

| Variable | Meaning |
|---|---|
| `CULVERT_LAB_PROTODETECT` | `off` (default), `fake` or `real` |
| `CULVERT_LAB_PD_FAMILIES` | Profile for the real engine |
| `CULVERT_LAB_PD_WINDOW_MS` | Observation window; the run used 3000 |
| `CULVERT_LAB_PD_FAKE_PANIC` | `observe`, `end`, `expire` or `finish` |
