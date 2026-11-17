# Versioning and deprecation policy for the Go module (draft)

Status: **draft for Lee** (working plan section 12, 2026-11-17). Nothing here is in force until Lee adopts it.
No tag has been created.

Sources: the Go modules reference (https://go.dev/ref/mod: "Versions", "Module paths", "Major version
suffixes", "`retract` directive", "Deprecation"), "Publishing a module" (https://go.dev/doc/modules/publishing)
and "Module version numbering" (https://go.dev/doc/modules/version-numbers).

## What is versioned

- **The module** `github.com/leenadav/protocol-detector/go`, in the `go/` directory of this repository.
- **Its API is one package: `go/detector`.** Everything under `go/internal/` cannot be imported from outside the
  module, a rule the Go toolchain enforces, so it carries no compatibility promise. `go/cmd/protodetect` is a
  program, not an API.
- **Detection content** (the content pack, `release.version` and its pack digest, `migration/CONTENT-DIGEST.md`)
  is versioned on its own and pinned by the module; see "Behaviour and content" below.
- **The Python package** (`protocol-stream-engine`, tags `v*`, `publish-release.yml`) has its own versions. The
  two version lines are independent.

## Tags

A module that is not at the repository root takes its directory as a tag prefix ("Module paths"). Versions of
this module are therefore tags named **`go/vMAJOR.MINOR.PATCH`**, for example `go/v0.1.0`. The release
workflow's `v*` trigger does not match them, so a Go tag never starts a Python release. Tags are created only by
the procedure in `RELEASE-TAGS.md`, signed, and never moved or deleted once pushed: Go tools check every download
against the first copy they saw, so changing a published version breaks its users ("Publishing a module").

## Phase v0: what may change, and how

Go treats every v0 version as unstable, with no compatibility requirement ("Versions"). This policy is stricter,
because Culvert compiles against the package:

| Change | Allowed in | Recorded |
|---|---|---|
| Bug fix, no API change | patch | release notes |
| New exported identifier, new `Config` field whose zero value keeps the old behaviour | minor | release notes |
| New value in a closed vocabulary (`Outcome`, `Reason`, `Direction`, `EndCause`, evidence class) | minor | release notes, "New values" |
| Removed or renamed identifier, changed signature, changed meaning of an existing value, changed default | minor, never patch | release notes, "Breaking", with the migration |
| Raising the `go` line in `go/go.mod` (the consumer minimum, ADR 0002) | minor | release notes, "Breaking" |

- **Closed vocabularies may grow.** A consumer handles a value it does not know through the type's `Valid` and a
  default branch, never by assuming the current list is complete. This is the one compatibility rule this
  policy asks of consumers.
- **Deprecate before removing,** where it can be done: the identifier gets a `Deprecated:` paragraph in its doc
  comment, naming the replacement, and stays for at least one minor release before it is removed.
- **A bad published version is retracted,** never re-tagged: a `retract` directive with a reason goes into
  `go/go.mod` and ships in the next version ("`retract` directive"). Users then no longer upgrade to it
  automatically; existing builds keep working.

## v1 and later

- **v1.0.0** promises compatibility for the whole v1 line. Proposed criteria: the Culvert lab has run phase L4 on
  the real detector, the facade has had a review with no actionable findings, and Lee decides.
- **From v1:** removal or incompatible change only in a new major version. Deprecated identifiers stay until
  then.
- **v2 and later** change the module path to `github.com/leenadav/protocol-detector/go/v2` ("Major version
  suffixes"); tags become `go/v2.x.y`.

## Behaviour and content

A detection change can change what a flow reports without changing the API. It is not a breaking API change,
but it is not invisible either:

- a parser fix that changes outcomes: patch or minor, with the behaviour diff (`tools/compare_engine.py`, the CI job "behaviour diff against the previous commit") in the
  release notes;
- a new content pack: at least a minor version, with the new `release.version`, release digest and pack digest
  (`content.EmbeddedPackDigest`) in the release notes;
- a change of the profile families or of what evidence a family emits: minor, under "Breaking" when evidence is
  removed or reclassified, because consumers may log or pseudonymize it.

## Compatibility matrix

Each release adds one row (template):

| Detector module | Content release | Pack digest | Minimum Go (`go` line) | Build Go (`toolchain`) | Culvert commits tested | Lab run |
|---|---|---|---|---|---|---|
| `go/v0.x.y` | `2026.11.x` | `…` | `1.27.0` | `1.27.4` | `…` | `lab/culvert/results/…` |

## Open points for Lee

1. Adopt this policy, or change it.
2. The v1 criteria above.
3. Whether a new content pack needs a minor version (proposed) or may ship in a patch.
