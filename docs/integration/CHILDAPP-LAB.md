# Child applications in the Culvert lab (PRO-504, 2026-11-27)

The detector's application classifier (`go/detector` `AppClassifier.Classify`, engine PR #163, PRO-492) runs
on Culvert's decrypted-request path in the local lab. Each inner HTTP request of an inspected tunnel gets a
verdict. At tunnel end, the distinct verdicts go into a `pd` block on a log-only `TUNNEL_CLOSED` entry. This is
visibility only: no policy, block decision, header, body or deadline changes. Nothing was pushed or proposed to
KidCarmi/Culvert. The clone's push URL is disabled.

- **Base:** Culvert `main` `ef9431189490f7f85bb32d6fe7e7b6b8be5b0844`, plus the 4 commits of
  `lab/culvert/culvert-lab-ef94311.patch`, plus the 1 commit of `lab/culvert/culvert-lab-ef94311-childapp.patch`.
  The lab commit is `88d2c0a4` on the local branch `lab/childapp-ef94311`. The SHA depends on the committer
  date; the tree does not. A fresh `git am` of both patches gives an identical tree (checked: 0 diff lines).
- **Detector:** this branch's `go/` (based on `claude/engine-PRO-492-child-apps` `dadc6bd`), used through
  `go.work`.

## What the lab patch adds

| File (Culvert) | What |
|---|---|
| `internal/pdobs/pdobs.go` | The closed vocabularies of the `pd` block: basis (`none`, `server_name`, `request_rule`), limit (`child_rule_evaluations`, `child_path_bytes`, `child_field_bytes`) and the 11 reasons. Any other value becomes `unknown`. `AppName` accepts only a content-data name shape (`[a-z0-9][a-z0-9._-]{0,63}`), so a host, path or free text cannot enter the block. Modelled on `internal/decryptobs`; the ADR draft (PRO-496) proposes it. |
| `internal/protodetect/apps.go`, `real_apps.go` | A Culvert-owned `AppClassifier` interface. `real_apps.go` is the only file that names the library, and it adds a second `recover` layer. `TestPdobsCoversTheLibraryAppVocabulary` fails if the library gains a value that `pdobs` does not list. |
| `childapp_lab.go` | `CULVERT_LAB_CHILDAPP=real` turns it on (default off). Optional limits: `CULVERT_LAB_CHILDAPP_MAX_RULES` and `_MAX_PATH`. The per-tunnel tally has a per-tunnel mutex (no global lock). It keeps at most 8 distinct verdicts and counts the rest in `apps_dropped`. |
| `proxy_tunnel.go` (`runH1InspectLoop`), `proxy_tunnel_h2.go` (`handleInspectH2`) | Two hook lines each. One notes the request right after it is read; in H2 that is before the reshape clears `RequestURI`. The other is a deferred close log. `note` never touches the request. |
| `internal/logstore/logstore.go`, `store.go`, `logstore.go` | `Entry.PD *ProtoDetectBlock` with `json:"pd,omitempty"` (absent when off), carried by `AuthLogFields.PD`. |

The classifier input comes from the request as the client sent it:
- the SNI of the client's TLS leg;
- the inner `Host`;
- the method;
- the raw origin-form `RequestURI` with its query;
- `Content-Type`;
- `Content-Length`, or -1 when unknown;
- the WebSocket upgrade flag;
- at most 32 header names.

The response size is always -1. The proxy classifies before the round trip, and the library records `direction`
without enforcing it.

### The `pd` block

```json
"pd": {"schema_version": 1, "requests": 3,
       "apps": [{"app": "gmail-uploading", "container": "gmail", "basis": "request_rule", "limit": "",
                 "reasons": ["child_rule_matched"], "count": 2},
                {"app": "google-base", "container": "", "basis": "server_name", "limit": "",
                 "reasons": ["no_child_rule_matched"], "count": 1}],
       "apps_dropped": 0, "child_release": "2026.11.1", "content_release": "2026.11.9"}
```

- **Explicit serialization.** Every field is written explicitly (ADR-0011 serialization rule), so "no
  application" can be queried.
- **Redaction.** The block carries no host, path, query or header value. The entry's own `host` is pseudonymized
  at `persistLogEntry`, the keyed-HMAC chokepoint, when `decryption_redact_hosts` is on, the same as every other
  entry.
- **New entry.** At `ef94311`, inspected tunnels write no `TUNNEL_CLOSED` entry, because the inspect-success
  terminal logs per inner request. The lab adds one only when the classifier is on.
  - It is gated by the rule's log-traffic flag.
  - `action_taken` is `lab_childapp_summary`.
  - Its byte counts are 0, because the inspected path counts bytes per request and the lab adds no per-tunnel
    counter.

## Tests (Culvert lab, `childapp_lab_test.go`, real library)

| Test | Shows |
|---|---|
| `TestLabChildAppVerdicts/gmail_upload_is_the_child` | `POST /upload/gmail/v1/users/me/messages?uploadType=media`, `message/rfc822` on `gmail.googleapis.com` gives `app=gmail-uploading container=gmail basis=request_rule`. |
| `TestLabChildAppVerdicts/unowned_host_has_no_app` | `unowned.example` gives `app="" container=""`, basis `none`, reason `host_unowned`. |
| `TestLabChildAppVerdicts/non-canonical_path_has_no_child` | A `..` segment gives the catalog parent only: `app=google-base container=""`, basis `server_name`, reason `path_not_canonical`. |
| `TestLabChildAppVerdicts/limit_hit_names_the_parent_only` | With `MaxPathBytes` 16: `app=google-base container=""`, `limit=child_path_bytes`, reason `work_limit`. |
| `TestLabChildAppInspectedH1TunnelLogsAppsOnTunnelClosed` | End to end through `runH1InspectLoop` over in-memory TLS, 3 keep-alive requests. Every request still gets 200. One `TUNNEL_CLOSED` entry has `requests=3`, `gmail-uploading`×2 and `google-base`×1. With redaction on, `host` is `h_…` and the JSON contains neither `googleapis`, `/upload` nor `uploadType`. |
| `TestLabChildAppInspectedH2TunnelLogsAppsOnTunnelClosed` | End to end through `handleInspectH2` with 4 concurrent streams. One entry, `gmail-uploading`×4. |
| `TestLabChildAppTunnelClosedHonoursLogTraffic` | A rule with `logTraffic:false` writes no entry; with no rule, the entry is written. |
| `TestLabChildAppTallyIsBounded` | 8 distinct verdicts are kept and the rest go to `apps_dropped`. Open values (a host-shaped app name, an unknown basis, reason or limit, a bad release) are logged as `unknown` or "". |
| `TestLabChildAppOffIsByteIdenticalAndAllocationFree` | Off: 0 allocations per tunnel for the three hooks (`testing.AllocsPerRun`, 200 runs), no entry written, and no `pd` key in the JSON. |
| `TestPdobsCoversTheLibraryAppVocabulary`, `TestClosedSetsPassAndEverythingElseIsUnknown` | `pdobs` equals the library's vocabularies; the name shape check holds. |

Runs, all with Go 1.27.4 and `GOWORK` set to the lab `go.work`:
- `go test -race -count=20 -run TestLab .` passed. It covers these tests and the 5 existing SEC-CULV tests.
- The race run of `internal/pdobs`, `internal/protodetect`, `internal/logstore`, `internal/reqlog`,
  `internal/apicontract` and `internal/contracts` passed.
- `go test -race -run 'Tunnel|Idle|Relay|Bypass|CONNECT|Connect|Drain|Inspect|LogEntry|Redact|LogURI|Lab' .`:
  355 top-level tests passed, 0 failed.
- `go test ./...` in workspace mode: 130 packages passed. 4 tests in 2 packages failed:
  - `TestAdmissionMigration_CoverageRejectsOmittedEngine` builds a temporary module outside `go.work`;
  - `TestGODEBUG_ReviewedPinsAreCompiledIn` and `TestGODEBUG_CompiledDefaultsMatchReviewedBaseline`, because
    `go.work` does not carry `go.mod`'s `godebug` pins;
  - `cmd/rootshard` `TestPilot_EndToEnd`, which refuses a directory outside the workspace.

  The same 4 fail on the lab branch without this commit under the same kind of `go.work`. `cmd/rootshard`
  passes with `GOWORK=off`. The root package cannot be tested with `GOWORK=off`, because the lab imports the
  detector through `go.work`. These failures come from the workspace setup, not from this change.

## Cost per decrypted request against the ADR-0011 budget

Local CPU work on a shared 4-vCPU container (Intel Xeon 2.10 GHz). These are not production latency figures. Raw
`go test -bench` output is in `lab/culvert/results-childapp/bench.txt`: 6 runs each, 8 for the end-to-end arms.
The figures below are medians.

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| `BenchmarkRealAppsClassify/child` (library only: gmail upload, child matched) | 2,718 | 1,328 | 20 |
| `BenchmarkRealAppsClassify/parent` (owned host, no child) | 1,654 | 728 | 13 |
| `BenchmarkRealAppsClassify/unowned` | 357 | 96 | 4 |
| `BenchmarkLabChildAppNote/child` (lab hook: request view, Classify, tally) | 2,671 | 1,392 | 23 |
| `BenchmarkLabChildAppNote/parent` | 1,648 | 760 | 15 |
| `BenchmarkLabChildAppNote/unowned` | 556 | 128 | 6 |
| `BenchmarkLabChildAppTunnel` (tally, one request, close snapshot; `persistLogEntry` excluded) | 3,486 | 1,844 | 27 |
| `BenchmarkLabChildAppInspectedH1/off` (whole inspected request: client, `runH1InspectLoop`, origin) | 41,183 | 8,866 | 67 |
| `BenchmarkLabChildAppInspectedH1/on` | 48,441 | 10,252 | 90 |

- **Per decrypted request, on:**
  - 23 allocations (child), 15 (parent) or 6 (unowned).
  - Of these, the library accounts for 20, 13 and 4. The lab hook adds 2 to 3 (the header-name slice and the
    reasons copy).
  - About 1.4 KB and 2.7 µs for a child match.
- **End to end:** +23 allocations (67 to 90) and +1.4 KB, the same as the hook alone. Latency was +7 µs at the
  median (41.2 to 48.4 µs), with the run ranges overlapping (off 39.7 to 44.8, on 43.0 to 52.1), so the added
  latency is between the isolated 2.7 µs and about 7 µs.
- **Per tunnel:** 4 more allocations (27 vs 23) for the tally and the snapshot, plus Culvert's own cost for the
  new log entry.
- **Off:** 0 added allocations (tested), no lock and no entry, so ADR-0011's off rule holds.

**Against the budget.**
- **ADR-0011 §4** allows at most 1 allocation per session for the `dec` block. The `pd` app path takes 6 to 23
  allocations **per request**, so it is outside that budget, like the protocol observation that the ADR draft
  (PRO-496, section 6) already amends.
- **The ADR draft** sets ceilings per observed flow, not per decrypted request. Its section 6 needs a new row,
  proposed here as "application verdict per decrypted request: ≤ 24 allocations, ≤ 1.5 KB; per tunnel ≤ 4 more".
  The gate would be the library's own allocation test plus a Culvert benchgate on `BenchmarkLabChildAppNote`.
- **For scale:** Culvert's whole proxied HTTP request is 82 allocations (gate 85) at `ef94311`, and one
  inspected request in this harness is 67. A child match adds about a third.
- **Biggest lever:** the library's 20 allocations dominate. Engine could return reasons without a copy and build
  the verdict without per-call slices. That is an engine-lane change and is not made here.

## Limits of this lab

- The verdict is computed before the round trip, so it never sees a response size. `direction` rules are
  recorded by the library and not enforced, so nothing is lost today.
- The H2 path reads `:path` from `RequestURI` before the reshape. If Culvert ever sets `RequestURI` empty earlier,
  the fallback is `URL.RequestURI()`, which re-escapes the path.
- Rules from wave 0 mostly describe vendor APIs (`client_scope: api`). A browser session of Gmail is `gmail` or
  `google-base`, not a child (`docs/CHILD-APPS.md`).
