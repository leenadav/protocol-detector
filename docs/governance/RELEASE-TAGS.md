# Signed release tags for the Go module

Status: **in force** (adopted by Lee, 2026-11-18; working plan section 12). No tag has been created, and no
repository setting has been changed. Tag names and version rules are in `VERSIONING.md`.

Sources: GitHub, "Signing tags" and "Telling Git about your signing key"
(https://docs.github.com/en/authentication/managing-commit-signature-verification); Go, "Publishing a module"
(https://go.dev/doc/modules/publishing).

## Who and when

- **Who:** Lee, or a release owner Lee names (section 12, "Governance: a release owner"); until one is named,
  Lee. The tagger's signing key
  is registered on their GitHub account as a *signing* key, so GitHub shows the tag as verified.
- **When**, all of these:
  1. the commit is on `main` (the repository's release rule for `v*` tags, kept for `go/v*` by this procedure);
  2. CI passed on that exact commit: the `ci` gate, including `go-engine` and `go-minimum`, and `codeql`;
  3. a review result names that exact commit with no actionable findings;
  4. Lee has decided to release.

## One-time setup (SSH signing, Git 2.34 or later)

```bash
git config --global gpg.format ssh
```

```bash
git config --global user.signingkey ~/.ssh/id_ed25519.pub
```

GPG works the same way with `git config --global user.signingkey <key id>` and no `gpg.format` line. To check SSH
signatures locally, Git needs an allowed-signers file; the `allowed_signers` file in this directory holds the
release owners' public keys, and is empty until one is added.

## Creating a release (example: go/v0.1.0)

1. In a clean checkout of the exact commit, run the gates:

   ```bash
   make check
   ```

   ```bash
   make go-check
   ```

   ```bash
   make go-check-minimum
   ```

   `go mod tidy` must leave `go/go.mod` unchanged (the module has no `require` or `replace` lines,
   `TestModuleIsStandardLibraryOnly` in `go/detector`).
2. Create the annotated, signed tag on that commit:

   ```bash
   git tag -s go/v0.1.0 -m "go/v0.1.0" <commit>
   ```

3. Verify it before anything leaves the machine:

   ```bash
   git -c gpg.ssh.allowedSignersFile=docs/governance/allowed_signers tag -v go/v0.1.0
   ```

4. Push that one tag only, never `--tags`:

   ```bash
   git push origin go/v0.1.0
   ```

5. Make the version known to the module proxy, then fetch it from an empty module as a consumer would:

   ```bash
   GOPROXY=proxy.golang.org go list -m github.com/leenadav/protocol-detector/go@v0.1.0
   ```

6. Record the release: the compatibility-matrix row (`VERSIONING.md`), the content release and pack digest, the CI
   run and the review result.

## Never

- Move, re-create or delete a pushed tag. The module proxy and checksum database keep the first copy, and a
  changed tag fails every later download with a security error. Fix forward with a new patch version and, if
  needed, a `retract` directive.
- Push a tag from an automated session. A tag is a release decision.

## Not covered by a tag signature

A signature says who tagged which commit. The module's content is authenticated separately, by the Go checksum
database, and the content pack by its pinned digest. Provenance for built artifacts (SLSA-style attestations)
exists for the Python release (`publish-release.yml`) and is a separate item for the Go module.

## Settings this procedure assumes but does not make

- Protecting `go/v*` tags from deletion and update (a tag ruleset): a repository setting, Lee's.
- Verifying tag signatures in CI before a release is recorded: a workflow change, the CI/CD lane's.
