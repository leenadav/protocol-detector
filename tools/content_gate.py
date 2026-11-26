"""Content-pack gate (the `content-pack` ci job): a research batch's content release must hold together.

The content pack is the detection content both runtimes load: the Python tables (protocol_engine/content.py,
locked in protocol_engine/content_lock.json), exported as migration/fixtures/content.json, embedded by the Go
backend as go/internal/content/pack.json, and the earlier releases it can roll back to
(go/internal/content/history.json, written by migration/content_history.py). The gate checks, in order:

1. `make content`: the schema, the content lock and the release history (protocol_engine.content.check:
   every earlier release reproduces exactly the digest it was published with, the engine's C11 fix);
2. `make content-pack`: the exported pack and the release history equal what the Python content states;
3. go/internal/content/pack.json is byte for byte migration/fixtures/content.json;
4. no duplicate or conflicting identifier, in the current pack and in every earlier release's host catalog
   (`scan_pack` below): no JSON object repeats a key; application names and aliases are unique and an
   alias names no application; host entries are unique, name catalog applications, claim each domain once,
   and the lookup tables (app_domains, suffixes, web_fronts) are exactly the ones the entries state; a web
   front belongs to one application; protocol names map to catalog applications; the history's releases
   are keyed by their own versions and its current release is the pack's and the lock's;
5. Python/Go parity on content: `go test ./internal/content/...`, in which the Go backend loads the same
   pack and history, recomputes every component digest and release digest and refuses any it does not
   reproduce (on the pinned compiler, vendored, with no download: tools/go_ci.py).

On a commit without the Go content pack (main before the migration lands: none of PACK_FILES exists) the
job passes and says so; `make content`, the Python content gate, still runs there inside `make check`. A
commit with only part of the pack fails. Nothing here is detection logic; the checks read data only.

Without the Python reference (PRO-401, Lee 2026-11-25: neither protocol_engine/content.py nor its lock exists)
checks 1 and 2, which compare the Python content with the pack, have nothing to compare and are reported as not
run; checks 3 to 5 still run, and check 5 (the Go side recomputing every component and release digest of the pack
and of each earlier release) is then the digest gate. Only part of the reference (the content tables without
their lock, or the lock alone) fails.

    content_gate.py [--summary FILE]
    content_gate.py --self-test
Standard library only; Python 3.9 syntax.
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import go_ci  # noqa: E402

PACK_FILES = (Path("migration/content_history.py"), Path("go/internal/content/history.json"),
              Path("go/internal/content/pack.json"))
EXPORT = Path("migration/fixtures/content.json")
LOCK = Path("protocol_engine/content_lock.json")
REFERENCE = Path("protocol_engine/content.py")
TARGETS = ("content", "content-pack")
DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


class DuplicateKey(ValueError):
    pass


def strict_load(text, label):
    """json.loads that refuses an object repeating a key (json keeps the last one silently)."""
    def pairs(items):
        seen = {}
        for key, value in items:
            if key in seen:
                raise DuplicateKey("{}: key {!r} appears twice in one object".format(label, key))
            seen[key] = value
        return seen
    return json.loads(text, object_pairs_hook=pairs)


def host_catalog_problems(catalog, applications, label):
    problems = []
    entries = catalog.get("entries") or []
    names = [entry.get("name") for entry in entries]
    for name in sorted({name for name in names if names.count(name) > 1}):
        problems.append("{}: host entry {} appears more than once".format(label, name))
    for name in sorted(set(names) - applications):
        problems.append("{}: host entry {} names no catalog application".format(label, name))
    owner = {}
    for entry in entries:
        for domain in entry.get("domains") or []:
            if not isinstance(domain, str) or not DOMAIN.match(domain):
                problems.append("{}: {} lists {!r}, not a lower-case host name".format(label, entry.get("name"), domain))
            elif domain in owner and owner[domain] != entry.get("name"):
                problems.append("{}: domain {} is claimed by both {} and {}".format(label, domain, owner[domain], entry.get("name")))
            elif domain in owner:
                problems.append("{}: {} lists domain {} twice".format(label, entry.get("name"), domain))
            owner.setdefault(domain, entry.get("name"))
    fronts = {}
    for entry in entries:
        for front in entry.get("web_fronts") or []:
            if front in fronts and fronts[front] != entry.get("name"):
                problems.append("{}: web front {} is claimed by both {} and {}".format(label, front, fronts[front], entry.get("name")))
            fronts.setdefault(front, entry.get("name"))
            if front in owner and owner[front] != entry.get("name"):
                problems.append("{}: {} is a domain of {} and a web front of {}".format(label, front, owner[front], entry.get("name")))
    expected = {
        "app_domains": {entry.get("name"): sorted(entry.get("domains") or []) for entry in entries},
        "suffixes": owner,
        "web_fronts": fronts,
    }
    stated = {key: catalog.get(key) for key in expected}
    stated["app_domains"] = {key: sorted(value) for key, value in (catalog.get("app_domains") or {}).items()}
    for key, wanted in expected.items():
        if stated[key] != wanted:
            differing = sorted(set(wanted) ^ set(stated[key] or {}) | {k for k in set(wanted) & set(stated[key] or {})
                                                                        if wanted[k] != stated[key][k]})
            problems.append("{}: {} does not match the entries (first difference: {})".format(label, key, differing[:3]))
    return problems


def scan_pack(pack, history, lock):
    """Every duplicate or conflicting identifier in the pack, its release history and the lock (check 4)."""
    problems = []
    applications = pack.get("applications") or []
    names = [app.get("name") for app in applications]
    for name in sorted({name for name in names if names.count(name) > 1}):
        problems.append("pack: application {} appears more than once".format(name))
    catalog = set(names)
    aliases = [alias for app in applications for alias in app.get("aliases") or []]
    for alias in sorted({alias for alias in aliases if aliases.count(alias) > 1}):
        problems.append("pack: alias {} belongs to more than one application".format(alias))
    for alias in sorted(set(aliases) & catalog):
        problems.append("pack: alias {} is also an application name".format(alias))
    for protocol, app in sorted((pack.get("protocol_names") or {}).items()):
        if app not in catalog:
            problems.append("pack: protocol {} maps to {}, which is no catalog application".format(protocol, app))
    problems += host_catalog_problems(pack.get("host_catalog") or {}, catalog, "pack")
    current = (pack.get("release") or {}).get("version")
    if history.get("current") != current:
        problems.append("history: current release {} is not the pack's {}".format(history.get("current"), current))
    if lock is not None and (lock.get("version") != current or lock.get("digest") != (pack.get("release") or {}).get("digest")):
        problems.append("lock: release {} digest {} is not the pack's {} {}".format(
            lock.get("version"), lock.get("digest"), current, (pack.get("release") or {}).get("digest")))
    for version, release in sorted((history.get("releases") or {}).items()):
        stated = (release.get("release") or {}).get("version")
        if stated != version:
            problems.append("history: release keyed {} states version {}".format(version, stated))
        if version == current:
            problems.append("history: the current release {} is also listed as an earlier one".format(version))
        problems += host_catalog_problems(release.get("host_catalog") or {}, catalog, "history {}".format(version))
    return problems


def survey():
    present = [path for path in PACK_FILES if path.is_file()]
    makefile = go_ci.read("Makefile") or ""
    return {"present": present, "missing": [path for path in PACK_FILES if path not in present],
            "targets": [target for target in TARGETS if re.search(r"^{}\s*:".format(re.escape(target)), makefile, re.M)],
            "reference": [path for path in (REFERENCE, LOCK) if path.is_file()]}


def decide(tree):
    """("skip" | "run" | "fail", problems) from which content files exist."""
    if not tree["present"]:
        return "skip", []
    problems = []
    if tree["missing"]:
        problems.append("the content pack is partial: {} present but {} missing".format(
            ", ".join(map(str, tree["present"])), ", ".join(map(str, tree["missing"]))))
    reference = tree.get("reference", [REFERENCE, LOCK])
    if len(reference) == 1:
        problems.append("the Python content reference is partial: {} present but {} missing".format(
            reference[0], ({REFERENCE, LOCK} - set(reference)).pop()))
    for target in TARGETS if reference else ():
        if target not in tree["targets"]:
            problems.append("Makefile has no `{}` target".format(target))
    return ("fail", problems) if problems else ("run", [])


def run(summary):
    title = "### Content-pack gate"
    action, problems = decide(survey())
    if action == "skip":
        go_ci.summarise(summary, [title, "", "No Go content pack on this commit ({} absent): nothing to check here; the "
                                             "Python content gate (`make content`) runs in `make check`.".format(
                                                 ", ".join(map(str, PACK_FILES)))])
        return 0
    if action == "fail":
        go_ci.summarise(summary, [title, ""] + ["- FAILED: " + problem for problem in problems])
        return 1
    lines, failed = [title, ""], 0
    reference = LOCK.is_file()
    for target in TARGETS if reference else ():
        code = subprocess.run(["make", target], check=False).returncode  # noqa: S603,S607
        lines.append("- `make {}`: exit {}".format(target, code))
        failed += code != 0
    if not reference:
        lines.append("- `make content`, `make content-pack`: not run, the Python content reference is removed (PRO-401); "
                     "the Go content parity below recomputes every digest")
    pack_text = PACK_FILES[2].read_bytes()
    if pack_text != EXPORT.read_bytes():
        lines.append("- FAILED: {} differs from {}".format(PACK_FILES[2], EXPORT))
        failed += 1
    try:
        found = scan_pack(strict_load(pack_text.decode("utf-8"), str(PACK_FILES[2])),
                          strict_load(PACK_FILES[1].read_text(encoding="utf-8"), str(PACK_FILES[1])),
                          strict_load(LOCK.read_text(encoding="utf-8"), str(LOCK)) if reference else None)
    except (OSError, ValueError) as error:
        found = [str(error)]
    lines += ["- FAILED: " + problem for problem in found] or ["- identifiers: no duplicate or conflicting id"]
    failed += bool(found)
    tree, go_problems = go_ci.toolchain_problems()
    if tree is None:
        go_problems = ["{} is missing: the Go side of the content parity cannot run".format(go_ci.GO_MOD)]
    if go_problems:
        lines += ["- FAILED: " + problem for problem in go_problems]
        failed += 1
    else:
        command = ["go", "test", "-count=1", "./internal/content/..."]
        code = subprocess.run(command, cwd="go", env=go_ci.go_env(tree.get("vendored")), check=False).returncode  # noqa: S603,S607
        lines.append("- Go content parity `{}`: exit {}".format(" ".join(command), code))
        failed += code != 0
    go_ci.summarise(summary, lines)
    return 1 if failed else 0


def self_test():
    app = {"name": "a", "aliases": ["alpha"]}
    pack = {"applications": [app, {"name": "b", "aliases": []}], "protocol_names": {"http": "a"},
            "release": {"version": "2", "digest": "d2"},
            "host_catalog": {"entries": [{"name": "a", "domains": ["a.com", "x.a.com"], "web_fronts": ["af.com"]},
                                         {"name": "b", "domains": ["b.com"], "web_fronts": []}],
                             "app_domains": {"a": ["x.a.com", "a.com"], "b": ["b.com"]},
                             "suffixes": {"a.com": "a", "x.a.com": "a", "b.com": "b"}, "web_fronts": {"af.com": "a"}}}
    history = {"current": "2", "releases": {"1": {"release": {"version": "1"}, "host_catalog": {
        "entries": [{"name": "a", "domains": ["a.com"]}], "app_domains": {"a": ["a.com"]}, "suffixes": {"a.com": "a"},
        "web_fronts": {}}}}}
    lock = {"version": "2", "digest": "d2"}
    assert scan_pack(pack, history, lock) == [], scan_pack(pack, history, lock)

    def changed(path, value, base=pack):
        copy = json.loads(json.dumps(base))
        target = copy
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        return copy
    host = ["host_catalog"]
    cases = {
        "duplicate application": (changed(["applications"], [app, app]), history, lock, "application a appears more than once"),
        "alias twice": (changed(["applications"], [app, {"name": "b", "aliases": ["alpha"]}]), history, lock, "alias alpha belongs"),
        "alias is a name": (changed(["applications"], [{"name": "a", "aliases": ["b"]}, {"name": "b", "aliases": []}]),
                            history, lock, "alias b is also an application name"),
        "protocol to unknown app": (changed(["protocol_names"], {"http": "z"}), history, lock, "maps to z"),
        "domain claimed twice": (changed(host + ["entries"], [{"name": "a", "domains": ["a.com"]}, {"name": "b", "domains": ["a.com"]}]),
                                 history, lock, "domain a.com is claimed by both a and b"),
        "duplicate host entry": (changed(host + ["entries"], [{"name": "a", "domains": ["a.com"]}, {"name": "a", "domains": ["c.com"]}]),
                                 history, lock, "host entry a appears more than once"),
        "host entry not an app": (changed(host + ["entries"], [{"name": "z", "domains": ["z.com"]}]), history, lock, "names no catalog"),
        "suffix table stale": (changed(host + ["suffixes"], {"a.com": "b", "x.a.com": "a", "b.com": "b"}), history, lock,
                               "suffixes does not match"),
        "web front of two apps": (changed(host + ["entries"], [{"name": "a", "domains": ["a.com"], "web_fronts": ["f.com"]},
                                                               {"name": "b", "domains": ["b.com"], "web_fronts": ["f.com"]}]),
                                  history, lock, "web front f.com is claimed by both"),
        "front is another app's domain": (changed(host + ["entries"], [{"name": "a", "domains": ["a.com"]},
                                                                       {"name": "b", "domains": ["b.com"], "web_fronts": ["a.com"]}]),
                                          history, lock, "a.com is a domain of a and a web front of b"),
        "not a host name": (changed(host + ["entries"], [{"name": "a", "domains": ["A.com/x"]}]), history, lock, "not a lower-case host"),
        "history current differs": (pack, dict(history, current="3"), lock, "is not the pack's 2"),
        "history key mismatch": (pack, {"current": "2", "releases": {"9": history["releases"]["1"]}}, lock, "keyed 9 states version 1"),
        "history lists current": (pack, {"current": "2", "releases": {"2": changed(["release"], {"version": "2"},
                                                                                     history["releases"]["1"])}},
                                  lock, "also listed as an earlier one"),
        "history domain conflict": (pack, {"current": "2", "releases": {"1": changed(["host_catalog", "entries"],
                                                                                       [{"name": "a", "domains": ["a.com"]},
                                                                                        {"name": "b", "domains": ["a.com"]}],
                                                                                       history["releases"]["1"])}},
                                    lock, "history 1: domain a.com is claimed by both"),
        "lock differs": (pack, history, {"version": "2", "digest": "other"}, "lock: release 2 digest other"),
    }
    for label, (case_pack, case_history, case_lock, expected) in cases.items():
        found = scan_pack(case_pack, case_history, case_lock)
        assert any(expected in problem for problem in found), (label, found)
    try:
        strict_load('{"a": 1, "b": {"c": 1, "c": 2}}', "x")
        raise AssertionError("a repeated key was accepted")
    except DuplicateKey as error:
        assert "'c' appears twice" in str(error), error
    assert decide({"present": [], "missing": list(PACK_FILES), "targets": []}) == ("skip", [])
    assert decide({"present": list(PACK_FILES), "missing": [], "targets": list(TARGETS)}) == ("run", [])
    action, problems = decide({"present": PACK_FILES[:1], "missing": list(PACK_FILES[1:]), "targets": list(TARGETS)})
    assert action == "fail" and "partial" in problems[0], problems
    action, problems = decide({"present": list(PACK_FILES), "missing": [], "targets": ["content"]})
    assert action == "fail" and "`content-pack`" in problems[0], problems
    # PRO-401: without the reference the Python targets are not required; half a reference fails.
    assert decide({"present": list(PACK_FILES), "missing": [], "targets": [], "reference": []}) == ("run", [])
    action, problems = decide({"present": list(PACK_FILES), "missing": [], "targets": list(TARGETS), "reference": [REFERENCE]})
    assert action == "fail" and "reference is partial" in problems[0], problems
    action, problems = decide({"present": list(PACK_FILES), "missing": [], "targets": [], "reference": [REFERENCE, LOCK]})
    assert action == "fail" and "`content`" in problems[0], problems
    assert scan_pack(pack, history, None) == [], "no lock to compare without the reference"
    print("content_gate self-test: ok ({} identifier refusals, duplicate keys, 7 tree decisions)".format(len(cases)))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--summary", help="append a markdown summary here (GITHUB_STEP_SUMMARY)")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    return self_test() if args.self_test else run(args.summary)


if __name__ == "__main__":
    sys.exit(main())
