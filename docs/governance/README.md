# Governance (working plan section 12)

Adopted by Lee on 2026-11-18. No tag exists, and no repository setting was changed by this adoption.

| File | What it governs | State |
|---|---|---|
| `.github/CODEOWNERS` | who owns each area | in force on branches that carry it; it replaced the earlier file, keeping all its lines |
| `VERSIONING.md` | version and deprecation rules for the Go module's public package `go/detector` | in force |
| `RELEASE-TAGS.md` | the signed `go/vX.Y.Z` tag procedure | in force; Lee is the release owner until another is named |
| `allowed_signers` | the keys that may sign release tags | empty until a release owner's key is added |

## Repository settings: what to turn on, and the single-owner trap

These are settings only the repository owner can change. Nothing here has been changed. `SSDLC.md` ("would
complete the gate") notes that branch protection was not available on the repository's plan when it was
written, so check availability first. Rulesets and branch protection offer the same rules; the names below are
GitHub's ruleset names (https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets).

**The trap.** GitHub states that "pull request authors cannot approve their own pull requests"
(https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/reviewing-changes-in-pull-requests/approving-a-pull-request-with-required-reviews).
With `@leenadav` as the only code owner, a rule requiring code-owner review, or any approval, blocks every pull
request Lee opens, and every pull request a session opens under Lee's account. Nobody else can satisfy
the rule. The only ways through are a bypass, which defeats the rule, or a second owner with write access.

| Setting (ruleset on `main`) | Safe with one owner? | Why |
|---|---|---|
| Restrict deletions | yes | Nobody needs to delete `main` |
| Block force pushes | yes | History on `main` is never rewritten (also a standing rule of the review loop) |
| Require status checks to pass: `ci gate (all jobs)` and the CodeQL analysis | yes | Machines approve, not people; the release controller already demands both |
| Require a pull request before merging, required approvals **0** | yes | Every change goes through a pull request, which runs the checks and the behaviour diff, but no human approval is required |
| Require conversation resolution | yes | The author can resolve their own threads |
| Require review from Code Owners | **no** | Blocks Lee's own pull requests (the trap above) |
| Required approvals 1 or more | **no** | Same trap |
| Require approval of the most recent reviewable push | **no** | Needs someone other than the last pusher |
| Dismiss stale pull request approvals when new commits are pushed | harmless, no effect | There are no approvals to dismiss while approvals are 0 |
| Require signed commits | **not yet** | The sessions' commits are not signed; turning it on would refuse their pushes |
| Require linear history | **no** | The branches carry merge commits (for example `cce9d33`) |

| Setting (tag ruleset on `go/v*`) | Safe with one owner? | Why |
|---|---|---|
| Restrict updates | yes | A pushed version must never move (`RELEASE-TAGS.md`) |
| Restrict deletions | yes | Same |
| Restrict creations, with Lee on the bypass list | yes | Only the release owner creates version tags |

Once a second owner with write access is named and added to `.github/CODEOWNERS`, the three "no" rows for
reviews become safe: require review from Code Owners, with required approvals at 1.
