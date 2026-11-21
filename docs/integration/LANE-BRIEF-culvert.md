# Culvert integration lane brief: read this first

The onboarding note for a fresh chat taking any task in the Culvert integration-preparation lane. **Update this
brief at the end of every task**, in the same push as the task: §2 (state), §5 (open items), §6 (frozen and
queued SHAs), and a §7 line for every new pitfall.

## 1. Purpose and scope

The lane prepares the Go detector for in-process use by the Culvert proxy (KidCarmi/Culvert), following
`docs/integration/PROTODETECT-CULVERT-WORKING-PLAN.md`.

- **Branch:** `claude/culvert-integration-prep`, fast-forward pushes only. Commits are authored as Lee, with the
  session trailers.
- **Scope, decided:**
  - visibility only (decision 3, 2026-11-17);
  - first profile TLS, HTTP/1, SSH and SMTP with evidence, every other family named only (decision 4,
    2026-11-18);
  - enforcement and restriction (L7) out of scope.
- **Owns:** the public package `go/detector` and the Go code it needs, `go/consumertest`, `lab/culvert/`,
  `docs/integration/` and `docs/governance/`.
- **Read-only here:**
  - Python reference, `.py` tests, generators and shared fixtures, unless Lee approves a case;
  - `.github/` and the CI tools: copies only, with Lee's word, of what the Platform & CI lane already landed.
- **Never:**
  - merge, rebase, force-push, tag, release or change settings;
  - post GitHub comments, which includes no review requests until Lee lifts that;
  - push anything to KidCarmi/Culvert, open PRs there or contact upstream.

  The Culvert clone's push URL is disabled.
- **Data:** synthetic and loopback only. The lab's origins are on RFC 5737 addresses.

## 2. Current state (2026-11-21, after PRO-81)

- **Plan:** every approved detector-side item is done (4.1 to 4.3, and #10 completed). The governance policies
  are in force; no tag and no setting exists.
- **Lab:**
  - **Current:** visibility only, on Culvert `main` `ef94311`. Local branch `lab/protocol-detector-ef94311`, head
    `8a50573c`, against detector `0aa53ac`. 74 of 74 observation checks pass; Culvert's tunnel, relay and drain
    tests pass, 193 under `-race`.
  - **First lab:** on `52eb9d1`, branch `lab/protocol-detector`, with the restriction demonstration. Kept
    unchanged: 84 of 84 checks on 2026-11-17.
- **Culvert team request** (`docs/integration/CULVERT-TEAM-REQUEST.md`): anchors refreshed at `ef94311`. It
  covers the SNI finding, UDP/HTTP3 and the allocation gap. It is not sent; Lee decides.
- **Allocation gap:** detector TLS 191 allocations per flow, against Culvert's whole HTTP forward at 82 and the
  plan's hypothesis of 64. Waiting on Culvert's budget; no tuning toward a number nobody set.

## 3. Where things live

1. `AGENTS.md`, then the working plan (sections 4.3a, 13 and the review queue under 4.3a).
2. `migration/STATUS.md`, section "Culvert integration preparation": every item with SHAs and evidence.
3. `go/detector/doc.go`: the package contract (containment, memory, results). `go/CHANGES.md`: unreleased changes.
4. `docs/governance/`: versioning, signed tags, the settings note (single-owner trap).
5. `lab/culvert/README.md`, plus the patches `culvert-lab-52eb9d1.patch` and `culvert-lab-ef94311.patch`.
6. `lab/culvert/tools/`: `start-lab-visibility.sh` and `runner.py`. Results are in `results/` (52eb9d1) and
   `results-ef94311/`.

## 4. How to verify

From the repository root, before every push: `make check`, then `make go-check`, then `make go-check-minimum`.
At `0aa53ac` they gave 833 tests OK, parity 6725 of 6725 and Go parity 6651 of 6651 with 74 listed gaps.

The lab, on this container:
1. In `/home/user/kidcarmi/culvert` on branch `lab/protocol-detector-ef94311`, build
   `GOWORK=/home/user/culvert-lab/go.work go build -o /home/user/culvert-lab/bin/culvert-lab .`.
2. Build A from an unmodified worktree at the base: `GOWORK=off go build -o .../bin/culvert-A .`.
3. Run `LAB_CULVERT_BASE=ef94311 sh tools/start-lab-visibility.sh` from `/home/user/culvert-lab`.

Culvert's allocation gates need `-tags benchgate`.

## 5. Open items (all waiting on someone else)

- Codex's review of the frozen milestone and the queued commits (Sunday).
- The Culvert team's answers (request items 1 to 6), and Lee's decision to send the request.
- Repository settings and the first `go/v0.x.y` tag (Lee).

## 6. Frozen and queued SHAs

- **Frozen milestone:** `8d28748..725cd95` (base `d725890`): #15, #14, #16. Never change it.
- **Queued for a later round:** listed in the working plan, under 4.3a "Review queue". The PRO-81 commit is added
  there in the same push.

## 7. Pitfalls

- **`pkill -f` matches its own invoker.** The lab scripts' `pkill -f "bin/culvert-"` also kills a wrapper shell
  whose command line contains that text, and an orphaned script's final cleanup then stops the next run's
  servers. Invoke the scripts with nothing matchable in the command, and check `ps` for leftovers before a rerun.
- **The Culvert clone is shallow.** Commit counts over its history are unreliable; quote first-parent counts, or
  none.
- **A `.github/CODEOWNERS` already existed.** Look for an existing file before drafting a replacement.
- **The permission system refuses some combined commands,** for example a CI-file copy or a push chained with a
  build. Run the safe parts on their own, and stop and report if a write is refused.
- **Pronouns:** Lee's are not stated. Use neutral wording.
