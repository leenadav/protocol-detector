# Drift check: lab patches on Culvert `a0aecf8` (PRO-578, 2026-11-27)

**Verdict: the patches apply cleanly.** Every hunk of `culvert-lab-ef94311.patch` (4 commits) and
`culvert-lab-ef94311-childapp.patch` (1 commit) applies to Culvert `main`
`a0aecf8e1dbe6fbc2b385896c045759a6f4ce30b` exactly: no 3-way merge, no offset, no conflict. None of the 397
upstream commits since `ef94311` touches a file the patches change. The lab tests and the 74 smoke checks
give the same results as on `ef94311`. None of the integration facts in plan section 3 changed. Some line
numbers in section 3 are stale, and they were already stale on `ef94311`.

Local only. The clone is a fresh read-only clone of `https://github.com/KidCarmi/Culvert.git`, with push
disabled (`git remote set-url --push origin DISABLED`). Nothing was pushed or proposed upstream.

## 1. Base

| | Commit |
|---|---|
| Old lab base | `ef9431189490f7f85bb32d6fe7e7b6b8be5b0844` |
| Culvert `main` when this check started (2026-11-27) | `a0aecf8e1dbe6fbc2b385896c045759a6f4ce30b` (2026-11-26 22:15 +0200, "Merge pull request #2121: AGT-900 …") |
| Commits `ef94311..a0aecf8` | 397 (380 files, +72,322 / −2,786; the largest areas are `cmd/culvert-maint/`, `internal/`, `test/` and `docs/`) |
| Local lab branch | `lab/protocol-detector-a0aecf8`, head `3d3769b442c6448582b6837a7411a83f45ab071f` (5 lab commits on `a0aecf8`) |
| Detector | `go/` of this repository at `main` `cc1566d8500af7b5fba877bccaa9db120666b7f3`, through `go.work` |
| Toolchain | go1.27.4 linux/amd64. Culvert `go.mod` is unchanged: `go 1.27.0`, `toolchain go1.27.4` |

## 2. Per-hunk result

Method: `git am -3` of both patches in order on `a0aecf8`, then, in a separate worktree, `git apply -v` of
each commit in turn. That reports any hunk that needed an offset or did not apply. No hunk did either. The
last column counts `git log ef94311..a0aecf8 -- <file>`.

| Commit | File | Hunks | Result | Upstream commits on the file |
|---|---|---|---|---|
| 1/4 observe CONNECT-bypass tunnels | `internal/protodetect/protodetect.go` | 1 (new file) | clean | — (path absent upstream) |
| | `internal/protodetect/real.go` | 1 (new file) | clean | — |
| | `protodetect_lab.go` | 1 (new file) | clean | — |
| | `proxy_tunnel.go` | 2 | clean | 0 |
| 2/4 evidence and offered ALPN | `internal/protodetect/protodetect.go` | 1 | clean | — |
| | `internal/protodetect/real.go` | 1 | clean | — |
| | `protodetect_lab.go` | 1 | clean | — |
| 3/4 short write as `io.ErrShortWrite` | `protodetect_lab.go` | 2 | clean | — |
| 4/4 SEC-CULV-1/2 | `internal/protodetect/protodetect.go` | 2 | clean | — |
| | `protodetect_lab.go` | 6 | clean | — |
| | `protodetect_lab_test.go` | 1 (new file) | clean | — |
| childapp (PRO-504) | `childapp_lab.go`, `childapp_lab_test.go` | 1 + 1 (new files) | clean | — |
| | `internal/pdobs/pdobs.go`, `pdobs_test.go` | 1 + 1 (new files) | clean | — |
| | `internal/protodetect/apps.go`, `real_apps.go`, `real_apps_test.go` | 1 + 1 + 1 (new files) | clean | — |
| | `internal/logstore/logstore.go` | 1 | clean | 0 |
| | `logstore.go` | 1 | clean | 0 |
| | `proxy_tunnel.go` | 2 | clean | 0 |
| | `proxy_tunnel_h2.go` | 1 | clean | 0 |
| | `store.go` | 2 | clean | 0 |

Totals: 33 hunks; 33 clean, 0 resolved by 3-way merge, 0 conflicts. No new upstream file collides with a path
the patches create (`internal/protodetect/`, `internal/pdobs/`, `protodetect_lab*.go`, `childapp_lab*.go`).

**Refreshed patch.** `culvert-lab-a0aecf8.patch` is `git format-patch a0aecf8..lab/protocol-detector-a0aecf8`,
with the 5 commits of the two old patches in their order. Its added and removed lines are byte-identical to
the two old patches together (`cmp` of the `+`/`-` lines). Only the `index` lines and commit headers differ.
The old patches are unchanged. To apply it:

```sh
git -C culvert checkout -b lab/protocol-detector-a0aecf8 a0aecf8e1dbe6fbc2b385896c045759a6f4ce30b
git -C culvert am lab/culvert/culvert-lab-a0aecf8.patch
```

## 3. Tests on the lab branch

The raw summary is in `results-a0aecf8/tests.txt`. All tests ran with `-race` and `-count=1`, except the
repeat run.

| Run | Result |
|---|---|
| `go build .` (lab binary) and `go vet . ./internal/protodetect ./internal/pdobs ./internal/logstore`; `gofmt -l` on the lab files | builds; vet exit 0; gofmt lists no file |
| `./internal/protodetect ./internal/pdobs ./internal/logstore` | 3 × `ok`; 47 top-level tests passed, 1 skipped (`TestChaos62_UnreadableStoreDirectoryRefusesRatherThanMinting`: running as root) |
| Root package, the `ef94311` filter `Tunnel\|Idle\|Relay\|Bypass\|CONNECT\|Connect\|Drain\|TestLab` | **209 passed**, 0 failed, 1 skipped. Unmodified `a0aecf8`, same filter: 198 passed, 0 failed, 1 skipped. The difference is exactly the 11 `TestLab*` tests. On `ef94311` the lab branch had 198 with the 5 SEC-CULV tests, before the 6 childapp tests existed |
| Root package, a wider filter (adds `ChildApp\|H2\|LogEntry\|Store`) | 407 passed, 0 failed, 2 skipped |
| `-count=10 -run TestLab` | `ok`: 110 runs (11 tests × 10), no failure, no race report |

The skips come from the environment, not from the patch: `TestUNAUTH_CONNECT_EstablishesTunnel` needs
external DNS (`example.com`), and `TestCandidateQualification_RealDockerImageStore` needs a Docker daemon. The
first one skips on unmodified `a0aecf8` too.

**Smoke.** `tools/start-lab-visibility.sh` was run once with `LAB_CULVERT_BASE=a0aecf8`, on fresh data
directories, 2026-11-27 11:46:20 to 11:46:51 UTC. Build A is unmodified `a0aecf8`. Builds B to E are the lab
binary (B off, C fake engine, D real detector, E fake engine with an injected panic). Results are in
`results-a0aecf8/`.
- **74 checks, 74 passed** (15 scenarios on builds A to E; the 32 MiB echo runs on 4 builds).
- **0 cells differ from `results-ef94311/`** in traffic verdict, detector verdict or detector text.
- **Byte identity:** the 7 hashed scenarios delivered the same bytes on every build, as on `ef94311`.
- Not run: the 30-minute endurance, the load tests and the restriction cells. The restriction cells are not on
  the visibility branch.

## 4. Upstream changes against plan section 3

The plan's section 3 (constraints and facts) was checked on `52eb9d1`. The table compares `ef94311` with
`a0aecf8`.

| Assumption (plan section 3) | Upstream change `ef94311..a0aecf8` | Plan line now stale? |
|---|---|---|
| `idleCopyCounted` with splice through `io.Copy`, read deadlines only, every `armInterval` | `proxy_tunnel.go`: 0 commits. `idleCopyCounted` is at `:407`, its `SetReadDeadline` at `:422`. There is still no `SetWriteDeadline` in `proxy_tunnel.go` | Facts hold. **Line numbers stale** (`:267`, `:283` are `52eb9d1` positions; already `:407`, `:422` on `ef94311`) |
| Idle clock: the activity stamp updates when `io.Copy` returns | 0 commits on `proxy_tunnel.go` | Holds |
| `relayCounted` recovers and closes both connections | 0 commits. The recover is at `:462` (`relayCounted` `:460`) | Fact holds. **Line numbers stale**: `:322` is now `:462`. `:927`, `:1163` and `proxy_tunnel_h2.go:265` no longer hold a `recover()`: they were removed between `52eb9d1` and `ef94311` (`8b7a3fde8`, `af222144b`), not in this range. The remaining relay recover in `proxy_tunnel.go` is at `:1291` |
| `socks5.go` recovers (`:210`, `:628`); SOCKS5 runs no policy evaluation | **1 commit:** `5bdbaea7a` (2026-11-23) "refuse zoned IPv6 destinations before any matcher or dial". `socks5DestHostValidity` replaces `normalizeHostStrict` at the canonicalization gate, and a zoned IPv6 literal in the DOMAIN form is refused as `INVALID_HOST` with a reason. Still no `evalAccessRules` in `socks5.go` | "No policy evaluation" holds. The protection list could add "zoned-IPv6 refusal" (IPv6 is out of the lab's scope). **Line numbers stale**: `:628` is `:680` (`:675` on `ef94311`) |
| `crashguard.go` | 0 commits | Holds |
| ADR-0042, `internal/alpnpeek` (main owns the peek, the package owns the parse) | 0 commits on both | Holds |
| ADR-0011, `internal/decryptobs` (the log-block rules) | 0 commits on both | Holds |
| ADR-0002/0003, ADR-0025, ADR-0026, ADR-0037 with `proxy_tunnel_drain.go`, `config_surfaces.go` | 0 commits on each | Holds |
| Dependency gates (`pr-deep-gate.yml`) and toolchain (`go.mod`, `go.sum`) | 0 commits | Holds |
| Prebuffer bugs (`docs/ci/proxy-quality-architecture.md`) | 0 commits | Holds |

Other upstream changes near the integration, which no plan line covers:
- `internal/ssrf` (`68620f3da`, `02eb12511`, 2026-11-24): a zoned IPv6 address is never public.
- `proxy.go` (`5bdbaea7a`, `911080026`): the CONNECT and HTTP paths refuse zoned destinations after the source
  gates.
- `proxy.go` (`dc4e01dad`): POL-004 keeps unknown actions for fail-closed enforcement.

All of them run before the tunnel is relayed, so the observed copy is unchanged. They are IPv6 or policy
changes, outside a visibility-only, IPv4 lab. The smoke run's SSRF scenario gives the same result as on
`ef94311`. The new ADRs 0056 to 0062 cover MCP telemetry, the MCP live tier, listener faults, the SaaS-feed
decoder, the data-dir writer lock and the maintenance agent. None of them touches the relay, the tunnel log or
decryption observability.

## 5. Proposed plan edits (not applied)

The plan itself is unchanged in this task. Proposed edits to
`docs/integration/PROTODETECT-CULVERT-WORKING-PLAN.md` section 3:

1. Intro line "Each was checked in the Culvert source at `52eb9d1`": add "re-checked on `a0aecf8`
   (2026-11-27, `lab/culvert/DRIFT-a0aecf8.md`)".
2. Splice fast path: `proxy_tunnel.go:267` → `:407`, `:283` → `:422`.
3. Panics: replace "`proxy_tunnel.go:322`, `:927`, `:1163`; `proxy_tunnel_h2.go:265`; `socks5.go:210`, `:628`"
   with "`proxy_tunnel.go:462` (`relayCounted`), `:1291`; `socks5.go:210`, `:680`". Note that the H2 relay no
   longer has its own `recover()` (since `ef94311`).
4. SOCKS5: append "and refuses zoned IPv6 destinations at the canonicalization gate (`5bdbaea`)".
5. Section 2 or 6.3 (base): record that the lab base can move to `a0aecf8`, using `culvert-lab-a0aecf8.patch`,
   with no code change.
