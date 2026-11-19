"""Dry-run provenance and signature for the release controller's files (publish-release.yml, build job).

A real release signs in the publish job: actions/attest-build-provenance issues a Sigstore-signed SLSA
provenance attestation for every file (keyless, bound by OIDC to this workflow, tag and commit), and
`gh attestation verify` checks each one before anything is published. That needs `id-token: write` and
`attestations: write` and writes to the public transparency log and the repository's attestation store,
so a dry run must not do it.

A dry run (workflow_dispatch, a branch push or a pull request that touches the controller) instead
exercises the same steps offline, into a separate artifact that is never published:
  statement  an in-toto Statement v1 with an SLSA provenance v1 predicate over every file in dist/ (sha256
             digests, the workflow, the commit, the run), the same shape the attestation carries;
  sign       an Ed25519 signature of that statement with a key generated for this run only (openssl); the
             private key never leaves a temporary directory; the public key is written next to it;
  verify     the digests against dist/ and the signature against the public key.
The ephemeral key proves the mechanics, never identity: DRY-RUN.txt says so in the artifact.

    release_provenance.py statement --dist DIR --out FILE
    release_provenance.py sign --statement FILE --dir DIR
    release_provenance.py verify --dist DIR --dir DIR [--summary FILE]
    release_provenance.py --self-test
Standard library and the openssl CLI only; Python 3.9 syntax.
"""
import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

NOTE = ("DRY RUN: statement.json is unsigned-by-identity provenance and statement.sig is an Ed25519 signature made\n"
        "with a key generated for this run only (public key: ephemeral.pub.pem). It proves the signing and\n"
        "verification steps work; it is not a release signature. A real release is signed in the publish job by\n"
        "actions/attest-build-provenance (Sigstore, bound to the workflow, tag and commit); see docs/RELEASING.md.\n")


def digest(path):
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def subjects(dist):
    files = sorted(path for path in Path(dist).iterdir() if path.is_file())
    return [{"name": path.name, "digest": {"sha256": digest(path)}} for path in files]


def statement(dist, env=None):
    env = os.environ if env is None else env
    repository, sha, ref = env.get("GITHUB_REPOSITORY", ""), env.get("GITHUB_SHA", ""), env.get("GITHUB_REF", "")
    server = env.get("GITHUB_SERVER_URL", "https://github.com")
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects(dist),
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                "externalParameters": {"workflow": {"ref": ref, "repository": "{}/{}".format(server, repository),
                                                    "path": ".github/workflows/publish-release.yml"},
                                       "event": env.get("GITHUB_EVENT_NAME", ""), "dryRun": True},
                "resolvedDependencies": [{"uri": "git+{}/{}@{}".format(server, repository, ref), "digest": {"gitCommit": sha}}],
            },
            "runDetails": {"builder": {"id": "https://github.com/actions/runner/github-hosted"},
                           "metadata": {"invocationId": "{}/{}/actions/runs/{}/attempts/{}".format(
                               server, repository, env.get("GITHUB_RUN_ID", ""), env.get("GITHUB_RUN_ATTEMPT", ""))}},
        },
    }


def openssl(args, **kwargs):
    return subprocess.run(["openssl"] + args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)  # noqa: S603,S607


def sign(statement_path, out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(str(statement_path), str(out / "statement.json"))
    private = tempfile.mkdtemp(prefix="release-provenance-key-")
    try:
        key = Path(private, "ephemeral.key.pem")
        openssl(["genpkey", "-algorithm", "ed25519", "-out", str(key)])
        openssl(["pkey", "-in", str(key), "-pubout", "-out", str(out / "ephemeral.pub.pem")])
        signature = openssl(["pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(out / "statement.json")]).stdout
    finally:
        shutil.rmtree(private, ignore_errors=True)
    (out / "statement.sig").write_text(base64.b64encode(signature).decode("ascii") + "\n", encoding="ascii")
    (out / "DRY-RUN.txt").write_text(NOTE, encoding="utf-8")
    return 0


def verify(dist, signed):
    """Problems: a subject that no longer matches dist/, a file of dist/ the statement omits, a bad signature."""
    signed = Path(signed)
    problems = []
    document = json.loads((signed / "statement.json").read_text(encoding="utf-8"))
    stated = {item["name"]: item["digest"]["sha256"] for item in document.get("subject") or []}
    actual = {item["name"]: item["digest"]["sha256"] for item in subjects(dist)}
    for name in sorted(set(stated) | set(actual)):
        if stated.get(name) != actual.get(name):
            problems.append("{}: statement says {}, dist/ has {}".format(name, stated.get(name), actual.get(name)))
    with tempfile.TemporaryDirectory(prefix="release-provenance-verify-") as scratch:
        raw = Path(scratch, "statement.sig.bin")
        try:
            raw.write_bytes(base64.b64decode((signed / "statement.sig").read_text(encoding="ascii").strip(), validate=True))
            openssl(["pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(signed / "ephemeral.pub.pem"),
                     "-in", str(signed / "statement.json"), "-sigfile", str(raw)])
        except (OSError, ValueError, subprocess.CalledProcessError) as error:
            problems.append("the signature does not verify against ephemeral.pub.pem ({})".format(
                getattr(error, "stderr", b"").decode("utf-8", "replace").strip()[:200] if isinstance(error, subprocess.CalledProcessError) else error))
    return problems


def self_test():
    root = Path(tempfile.mkdtemp(prefix="release_provenance_selftest_"))
    try:
        dist, signed = root / "dist", root / "signed"
        dist.mkdir()
        (dist / "protodetect-1.0.0-linux-amd64").write_bytes(b"\x7fELF binary")
        (dist / "SHA256SUMS").write_text("x  y\n", encoding="utf-8")
        env = {"GITHUB_REPOSITORY": "o/r", "GITHUB_SHA": "abc", "GITHUB_REF": "refs/heads/b", "GITHUB_RUN_ID": "1",
               "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "workflow_dispatch"}
        document = statement(dist, env)
        assert [item["name"] for item in document["subject"]] == ["SHA256SUMS", "protodetect-1.0.0-linux-amd64"]
        assert document["predicate"]["buildDefinition"]["externalParameters"]["dryRun"] is True
        (root / "statement.json").write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
        signed_code = sign(root / "statement.json", signed)
        assert signed_code == 0, signed_code
        assert not list(signed.glob("*.key*")), "the private key left the temporary directory"
        assert verify(dist, signed) == []
        (dist / "protodetect-1.0.0-linux-amd64").write_bytes(b"\x7fELF tampered")
        assert any("protodetect-1.0.0-linux-amd64" in problem for problem in verify(dist, signed))
        (dist / "protodetect-1.0.0-linux-amd64").write_bytes(b"\x7fELF binary")
        (dist / "extra").write_bytes(b"added later")
        assert any("extra: statement says None" in problem for problem in verify(dist, signed))
        (dist / "extra").unlink()
        text = (signed / "statement.json").read_text(encoding="utf-8")
        (signed / "statement.json").write_text(text.replace('"abc"', '"abd"'), encoding="utf-8")
        assert any("does not verify" in problem for problem in verify(dist, signed))
    finally:
        shutil.rmtree(str(root), ignore_errors=True)
    print("release_provenance self-test: ok (statement, ephemeral signature, tampered file, added file, tampered statement)")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", nargs="?", choices=("statement", "sign", "verify"))
    parser.add_argument("--dist")
    parser.add_argument("--out")
    parser.add_argument("--statement")
    parser.add_argument("--dir")
    parser.add_argument("--summary")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.action == "statement" and args.dist and args.out:
        Path(args.out).write_text(json.dumps(statement(args.dist), indent=1, sort_keys=True) + "\n", encoding="utf-8")
        return 0
    if args.action == "sign" and args.statement and args.dir:
        return sign(args.statement, args.dir)
    if args.action == "verify" and args.dist and args.dir:
        problems = verify(args.dist, args.dir)
        lines = ["### Dry-run provenance and signature (ephemeral key, never published)", ""]
        lines += ["- FAILED: " + problem for problem in problems] or [
            "- {} file(s) in the statement match dist/; the Ed25519 signature verifies".format(
                len(json.loads(Path(args.dir, "statement.json").read_text(encoding="utf-8"))["subject"]))]
        if args.summary:
            with open(args.summary, "a", encoding="utf-8") as stream:
                stream.write("\n".join(lines) + "\n")
        print("\n".join(lines))
        return 1 if problems else 0
    print("release_provenance: see --help for the arguments each action needs", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
