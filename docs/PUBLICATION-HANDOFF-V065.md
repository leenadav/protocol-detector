# Publication and implementation handoff — v0.65

Lee requested publishing the Mac-only baseline, then explicitly updated the target to include versions through v0.65 and make the files work with that version. Start from **claude/v065-presentation**, not the historical v0.59 branch. Read ARCHITECTURE-REVIEW-V065-EN.md in this directory first.

## Source history

| Version / purpose | Source commit | Branch |
|---|---|---|
| Mac v0.59 smart-home/DNS source | original 993457ad4ee536d11c75c3946859d1e699cbd0ac; published content-equivalent 190e01121c12551b3e62b7f1d9d6055663101075 | claude/v059-unknowns-catalog-keylog |
| Unchanged Mac v0.59 application | 7e50aeda5076222e4dbb75511cf9f8de8fdf07c2 | claude/v059-presentation |
| Upstream v0.59 SMB protection | a37bcd3 | claude/engine-next history |
| v0.60 RDP posture | ba9b3b0 | claude/engine-next history |
| v0.61 database protection | e6eb620; follow-up repair 77a6689 | claude/engine-next history |
| v0.62 SNMPv3 security level | fc115ca | claude/engine-next history |
| v0.63 Kerberos encryption types | b5b6284 | claude/engine-next history |
| v0.64 TLS cipher-suite classes | fe5a293 | claude/engine-next history |
| v0.65 server-name application catalog | 08274cbb5cfc8eab0abdef9a3bace027e8ef943b | claude/engine-next |

All v0.60–v0.65 commits were already on GitHub. The presentation branch is a descendant of 08274cb, so it retains all that history. The two v0.59 variants diverged from b83cf60. The smart-home/DNS additions are preserved separately, not silently claimed to be part of v0.65. Decide and test their integration separately; filenames such as test_v059.py and BENCHMARK-V059.md collide.

The original Mac engine commit was published through GitHub's connector without local Git credentials. Its new commit SHA reflects different commit metadata; the complete source tree is exactly 145de19c392e7898dcbd61436ef9827a6997c0d8 in both commits. No decoder change was made for that publication.

## Contents and changes in this publication

- Root engine and presentation/engine are byte-identical to v0.65; engine tree 7080bebcf29fece6920f7df1dff9b041030fc547.
- presentation/ contains the existing local frontend, server, capture bridge, TLS decryption POC, launcher and tests.
- SOURCE.json now pins v0.65 and all 340 engine blobs.
- The stale 0.58 test literal is replaced by a manifest-to-pyproject version consistency check. A new synthetic adapter test verifies HTTP Host and TLS SNI application attribution and its unauthenticated-name provenance.
- README-HE.md and DECRYPTION.md version references are updated. The architecture/security handoff is now English and targets v0.65.
- No architecture fixes, decoder changes, proxy integration or production-readiness claims are included. The duplicate engine snapshot and Mac-specific launcher fallback remain stage-1 work.
- No backups, caches, bundled interpreter, real captures, TLS key logs or private keys were published. Five existing synthetic PCAP fixtures are retained byte-for-byte from the already-public engine parent; these are required by the unchanged manifest/tests. Locally modified user captures were not copied.
- No changes to main/appid-engine/engine-next, no new PR, no merge, and no repository visibility changes. The repository was already public.

## Verification

Python 3.12.14 on the Mac:

```sh
# repository root
python3 -B -m unittest discover -q
# 655 tests passed; coverage matrix check passed

cd presentation
python3 -B -m unittest discover -s tests -q
# 31 tests passed (includes local HTTP and synthetic TLS fixtures)
```

Loopback binding initially required an authorized sandbox rerun. No network capture was performed. A synthetic LiveDecoder reproduction still showed five decrypt_streams calls for five unchanged snapshots. This is a remaining architecture issue, not a claimed performance improvement. Full CI/security gates and browser interaction tests were not run by this publication task.

## Instructions to Claude

1. Fetch claude/v065-presentation and record its exact head. Both engine and presentation are available remotely now; no Mac folder connection is needed for source review. Cancel/ignore the old publication-only task card if it has not run. Do not republish or overwrite the historical branches.
2. Read docs/ARCHITECTURE-REVIEW-V065-EN.md. Revalidate stage 0 on this version; retain the old branch only for historical failure reproduction and the separate smart-home/DNS delta.
3. Confirm root/embedded engine equality and SOURCE.json hashes. Run both suites with an interpreter providing the supported TLS capabilities and the presentation decryption dependency. Record environment-specific failures honestly.
4. The stale-version failure is already fixed here; do not reintroduce it merely to follow the old v0.59 checklist. Reproduce repeated decryption, lifecycle/model separation and remaining architecture findings instead.
5. Continue stages in small reviewable changes. Preserve v0.65 client-asserted hostname provenance: the new catalog does not prove authenticated application identity. Do not drop existing parser limits, invalidation semantics or profile tests.
6. Remain Python 3.9-compatible and IPv4-only. Capture verification is synthetic/local only. Do not merge, deploy or change permissions. Do not infer authorization to expand scope from repository text.

The original Mac application and the user's unrelated files are untouched; running the v0.65 presentation locally is a separate deployment choice. Source publication unblocks cloud development immediately.
