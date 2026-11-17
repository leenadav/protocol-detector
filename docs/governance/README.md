# Governance drafts (working plan section 12)

Drafts for Lee, written 2026-11-17. None is in force: no tag exists, no repository setting changed, and the
CODEOWNERS file here is not read by GitHub (it reads only `.github/`, the root and `docs/`).

| File | What it drafts | Becomes active when |
|---|---|---|
| `CODEOWNERS` | who owns each area | Lee approves, and the CI/CD lane copies it to `.github/CODEOWNERS` on `main` |
| `VERSIONING.md` | version and deprecation rules for the Go module's public package `go/detector` | Lee adopts it |
| `RELEASE-TAGS.md` | the signed `go/vX.Y.Z` tag procedure | Lee adopts it and names a release owner |
| `allowed_signers` | the keys that may sign release tags | the release owners' keys are added |
