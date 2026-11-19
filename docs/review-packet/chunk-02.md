# Chunk 02 (Tier 1): release supply chain (387 lines)

**Diff:** `git diff e927d44 ddc557d -- tools/build_go_release.py tools/release_provenance.py tools/check_workflow_policy.py`
**Commits:** b57b819, 8a129c7 (the two release tools); 5442d05 (the policy self-test).

**What changed, and why**
- **`build_go_release.py` (new, 187 lines), run in publish-release's read-only build job.**
  - It builds `go/cmd/protodetect` for 5 targets, each twice with its own empty GOCACHE and GOTMPDIR (L51–55), and fails if the two outputs differ.
  - Build flags (L38): `CGO_ENABLED=0 -trimpath -buildvcs=false -ldflags "-s -w -buildid="`.
  - It writes a CycloneDX 1.5 SBOM from `go version -m -json` (L62–83) and requires every linked module to appear in `go/vendor/modules.txt` (L85–96).
  - Output goes into `dist/`, which the existing controller checksums, attests (Sigstore) and verifies before publishing.
- **`release_provenance.py` (new, 185 lines), dry runs only.**
  - It writes an in-toto Statement v1 / SLSA v1 statement over `dist/` (L54–75).
  - It signs it with an Ed25519 key generated per run through openssl (L81–96): the private key stays in a temp dir that is deleted.
  - It verifies the digests and the signature (L98–118).
  - The output is a separate artifact, never published. The real signing is the unchanged publish job's `attest-build-provenance`.
- **`check_workflow_policy.py`:** only the self-test changes. `in_job()` (L1178) anchors three scanner-job mutations (L2400–2402) that broke when the tests job gained setup-go. No rule logic changed.

**Risks to check**
1. **Reproducibility:** can a non-reproducible input slip past the two-build comparison (L112–118)? Both builds share the checkout and toolchain. Is that the right claim, and is it stated correctly in `docs/RELEASING.md`?
2. **SBOM completeness:** is the SBOM complete and honest? Deps come only from the binary's build info. Could a linked module be missing from `Deps`? Does `module_problems` refuse modules not in `vendor/modules.txt`?
3. **Path handling:** the output directory is resolved to absolute (L108). Can any artifact path escape `dist/`? File names use `--version`, validated by the `VERSION` regex (L39).
4. **Dry-run key:** can the private key reach the artifact (L86–92, self-test L135)? Is it acceptable that `DRY-RUN.txt` is the only marker distinguishing it from a release signature?
5. **Statement format:** does the statement claim anything the dry run doesn't do? `dryRun: true`; builder id `github-hosted`.
6. **Policy self-test:** does `in_job` still mutate the intended scanner job, so the self-test keeps proving rule 15?

**Already run (no need to redo)**
- **Self-tests** pass on CPython 3.13 and 3.9 for both tools: tampered file, added file, tampered statement, SBOM determinism, vendor cross-check.
- **Local reproducible build:** 5 targets, each built twice and identical.
- **Hosted dry runs:** publish-release 44559157154 (dispatch) and 44559135301 (push) on `8a129c7`, plus 44561555092 on main. The build job succeeded and publish was skipped.
- **CodeQL:** `py/side-effect-in-assert` was fixed in b57b819. CodeQL is green on `ddc557d`.

**Out of scope:** the `publish` job's attest, verify and release steps (unchanged and pinned); cosign or GPG detached signatures (not added; a long-lived key would be a new secret, Lee's decision).
