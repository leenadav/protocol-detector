# Releasing

Status: **draft**. The pipeline below is built and dry-run tested. No tag or release has been created. Cutting a
release is Lee's decision.

There is one release controller, `.github/workflows/publish-release.yml`. Policy rule 5 in
`tools/check_workflow_policy.py` keeps it the only workflow a tag can run, and the only one that can write.

## What a release contains

The read-only `build` job produces every file below in `dist/`:

| File | What it is |
|---|---|
| `protocol_stream_engine-<version>.tar.gz` and `...-py3-none-any.whl` | The Python sdist and wheel, after the full gate and a wheel smoke test |
| `protodetect-<version>-<os>-<arch>[.exe]` | The Go binary for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64 and windows/amd64 |
| `protodetect-<version>-go.cdx.json` | CycloneDX 1.5 SBOM of the Go binaries: every linked module with its go.sum hash, and the Go toolchain |
| `sbom.cdx.json`, `product-sbom.cdx.json` | CycloneDX SBOMs of the Python build toolchain and of the complete Python product (the wheel and the decryption extra) |
| `requirements-decryption.lock.txt` | The hash-pinned lock of the decryption extra |
| `SHA256SUMS` | SHA-256 of every file above |

The Go binaries are reproducible. `tools/build_go_release.py` builds each target twice and fails if the two builds
differ. Each build uses its own empty `GOCACHE`. The build environment is:

- the pinned Go (1.27.4, `GOTOOLCHAIN=local`);
- `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`, `-ldflags "-s -w -buildid= -X main.version=<version>"`;
- `GOPROXY=off`, with the committed vendor tree (`GOFLAGS=-mod=vendor`).

`-X main.version=<version>` stamps the release version (already checked against `VERSION`) into
`go/cmd/protodetect`'s `var version`. It changes the bytes, but both builds get the same flag, so the
double-build comparison still holds. After building, the tool runs the linux/amd64 binary as
`protodetect version`. The release fails unless the second word of the output is exactly the release version. So
a binary named `protodetect-<version>-*` that reports some other version cannot be published. That covers a
`const version`, which `-X` silently ignores, and a renamed variable.

A commit without `go/go.mod` builds no Go binary and says so. If `go/go.mod` is present and `go/cmd/protodetect`
is missing (a renamed or deleted main package), the release fails instead of publishing a tag with no Go binaries.

The SBOM is built from the binaries' own embedded build information. Every module they link must be listed in
`go/vendor/modules.txt`. The SBOM has no timestamp and a serial number derived from its content, so it is
reproducible too.

## Signing and provenance

On a `v*` tag, the `publish` job is the only job with `contents`, `id-token` and `attestations` write. It works in
this order:

1. Downloads the build job's files and re-checks them against `SHA256SUMS`.
2. Runs `actions/attest-build-provenance` over every file. This issues a Sigstore-signed SLSA provenance
   attestation: keyless, bound by OIDC to this workflow, the tag and the commit, and logged publicly in Rekor.
3. Runs `gh attestation verify` on every file, against this workflow, the tag ref, the commit and a
   GitHub-hosted runner, before anything is published.
4. Runs `gh release create`.

Policy rules 4 and 8 pin the gate and publish jobs step for step.

## Dry runs (publish nothing)

These events run the release gate and the build job only. The publish job requires a pushed tag.

- `workflow_dispatch`, on any branch.
- A push or pull request that changes the controller, its tools or `go/go.mod`.

A dry run produces the same `dist/` files, uploaded as the `release-dist-<sha>` artifact (7 days). It also
exercises signing without creating any public record:

1. `tools/release_provenance.py` writes an in-toto Statement v1 with an SLSA provenance v1 predicate over every
   file in `dist/`. This is the same shape the real attestation carries, marked `dryRun: true`.
2. It signs the statement with an Ed25519 key generated for that run only. The private key never leaves a
   temporary directory.
3. It verifies the digests and the signature.

The statement, signature and public key are uploaded as `release-dry-run-<sha>`, never as release assets, together
with `DRY-RUN.txt`, which says the key proves the mechanics, not identity. The real signature cannot be dry-run:
issuing it writes to the public transparency log and the repository's attestation store.

To dry-run by hand:

```
gh workflow run publish-release.yml --ref <branch>
```

## Cutting a release (Lee's decision only)

1. Make `pyproject.toml`'s version, `protodetect.py version` and the changelog agree. The build job fails when the
   tag is not `v` plus that version.
2. Merge to `main` and wait for the push runs of `ci` and `codeql` on that commit to pass. The release gate
   requires both, and requires the tagged commit to be on `main`.
3. Push the tag: `git tag -a v<version> <commit> -m "v<version>" && git push origin v<version>`.
4. Check the run. Every file must show "Attestation verified", and the release must list every file in the
   table above.

## Verifying a release as a user

```
sha256sum -c SHA256SUMS
gh attestation verify protodetect-<version>-linux-amd64 --repo leenadav/protocol-detector \
  --signer-workflow leenadav/protocol-detector/.github/workflows/publish-release.yml
```

To check reproducibility, build the binary yourself and compare it with the release file:

```
cd go && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOFLAGS=-mod=vendor \
  go build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X main.version=<version>" -o protodetect ./cmd/protodetect
```

Use Go 1.27.4 at the tagged commit. The result must match the published file byte for byte.

## Not covered yet

- **No real tag has been run.** The tag-only steps (attest, verify, publish) are pinned by policy and were last
  exercised in review, not in a real release.
- **No separate detached signature:** there are no cosign or GPG signatures beyond the Sigstore attestations.
  A long-lived signing key would be a new secret, which is Lee's decision.
