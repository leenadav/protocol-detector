"""The detection content pack, edited directly: check it, or add a batch of applications as a new release (PRO-411).

Since PRO-411 the Go side's content files are the source of truth, edited only through this tool:

- go/internal/content/pack.json: the current release (application catalog, server-name catalog, vocabularies,
  protocol names, risks, and the release block with its component and release digests); migration/fixtures/
  content.json is a byte-for-byte copy that the Go tests load;
- go/internal/content/history.json: every earlier release the binary can roll back to (its release block and
  server-name catalog, C11);
- go/internal/content/lock.json: the append-only ledger of every published release (version, dates, digest,
  components, host-entry count, note and review). The pack's release block is the current entry; nothing in
  the lock is ever rewritten, so a published digest cannot change without a reviewable diff of a ledger line.

Nothing here imports the Python engine (protocol_engine/), and nothing is detection logic: the checks read data.

    content_pack.py check
        The pack, the history and the lock agree, and every file is in its canonical layout (below). Mirrors the
        Go loader's validation (go/internal/content: content.go parse, digest.go computeDigests) and the CI gate's
        identifier scan: unique names and aliases, known categories, technologies, characteristics and outcomes,
        valid ports, resolved references, lower-case host names claimed once, lookup tables equal to the entries,
        every component and release digest recomputed (CJ1, migration/CONTENT-DIGEST.md), numeric version order.

    content_pack.py add BATCH.json [--version V] [--released YYYY-MM-DD] [--reviewed YYYY-MM-DD]
                                   [--note TEXT] [--review TEXT] [--dry-run]
        Adds the batch's applications and server-name entries as a new content release: the current release moves
        to history.json unchanged (its published digest is kept, C11), the version goes up (default: the next under
        the numbering rule, 2026.11.8 -> 2026.11.9 -> 2026.12.0), the digests are recomputed, the lock gains one
        entry, and the whole new tree must pass `check` before any file is written. A batch only adds: a name, alias or domain
        already in the pack is refused. docs/CONTENT-BATCHES.md describes the batch format and the procedure.

    content_pack.py --self-test [--e2e]
        Unit checks on in-memory packs. --e2e also copies the content files, migration/ and the Go module to a
        temporary tree WITHOUT protocol_engine/ and protocol_adapters/, adds docs/examples/content-batch-example.json
        there, and runs `check`, tools/check_content.py and every Go test (`go test ./...`) in it (needs the pinned Go).

Standard library only; Python 3.9 syntax.
"""
import argparse
import copy
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACK = Path("go/internal/content/pack.json")
FIXTURE = Path("migration/fixtures/content.json")
HISTORY = Path("go/internal/content/history.json")
LOCK = Path("go/internal/content/lock.json")
EXAMPLE = Path("docs/examples/content-batch-example.json")

MAX_PACK_BYTES = 16 << 20       # go/internal/content.MaxPackBytes
MAX_BATCH_BYTES = 4 << 20       # a batch file larger than this is refused before it is parsed
MAX_BATCH_ENTRIES = 2000        # applications plus server-name entries in one batch
MAX_DOMAINS_PER_ENTRY = 256
MAX_DEPTH = 16                  # go/internal/content.maxDigestDepth

APPLICATION_FIELDS = ("name", "category", "subcategory", "technology", "risk", "description", "characteristics",
                      "standard_ports", "secure_ports", "implicitly_uses", "depends_on", "container", "aliases")
HOST_FIELDS = ("name", "category", "subcategory", "technology", "risk", "description", "characteristics",
               "domains", "web_fronts")
SHARED_FIELDS = HOST_FIELDS[:7]   # a server-name entry states these fields of its catalog application
HOST_APP_USES = ["ssl", "web-browsing"]  # what a server-name application implicitly uses (host_apps.catalog_entries)
COMPONENTS = ("application_catalog", "families", "host_catalog", "risks")
RELEASE_FIELDS = ("version", "digest", "released", "reviewed", "components")
LOCK_FIELDS = ("version", "digest", "released", "reviewed", "components", "host_entries", "pack_digest", "note", "review")
PACK_DIGEST_PREFIX = "protodetect-content-pack-v1\n"  # go/internal/content.PackDigestPrefix
SEVERITIES = ("low", "medium", "high")
# PRO-31/PRO-34 numbering rule (Hermes): YYYY.MM.N, month 01..12, one-digit N; after N=9 the next month segment
# starts at 0. String and numeric order then agree (go/internal/content/version_test.go enforces it too).
VERSION = re.compile(r"^[0-9]{4}\.(0[1-9]|1[0-2])\.[0-9]$")
DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX16 = re.compile(r"^[0-9a-f]{16}$")
# A lower-case host name of at least two labels, as the engine normalizes server names (no trailing dot).
DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
PORT = re.compile(r"^(tcp|udp)/(dynamic|[0-9]{1,5}(-[0-9]{1,5})?)$")


class ContentError(ValueError):
    pass


# -- reading and writing ----------------------------------------------------------------------------------------

def strict_load(text, label):
    """json.loads that refuses a repeated key, a non-integer number and nesting beyond the Go bound."""
    def pairs(items):
        seen = {}
        for key, value in items:
            if key in seen:
                raise ContentError("{}: key {!r} appears twice in one object".format(label, key))
            seen[key] = value
        return seen

    def no_float(text):
        raise ContentError("{}: number {} is not a plain integer".format(label, text))
    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_float=no_float,
                           parse_constant=no_float)
    except ContentError:
        raise
    except ValueError as error:
        raise ContentError("{}: not JSON ({})".format(label, error))
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if depth > MAX_DEPTH:
            raise ContentError("{}: nested too deeply".format(label))
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, int) and not isinstance(item, bool) and abs(item) >= 10 ** 16:
            raise ContentError("{}: integer {} is outside the digest contract".format(label, item))
        elif isinstance(item, str) and "\ufffd" in item:
            raise ContentError("{}: string is not valid Unicode".format(label))
    return value


def dumps(document):
    """The canonical file layout of pack.json, history.json and lock.json (tools/export_content.py's, unchanged)."""
    return json.dumps(document, indent=1, sort_keys=True) + "\n"


def read_tree(root):
    root = Path(root)
    texts = {}
    for path in (PACK, FIXTURE, HISTORY, LOCK):
        try:
            texts[path] = (root / path).read_bytes()
        except OSError as error:
            raise ContentError("{} cannot be read: {}".format(path, error.strerror or error))
    if len(texts[PACK]) > MAX_PACK_BYTES:
        raise ContentError("{} is larger than the Go loader's {} bytes".format(PACK, MAX_PACK_BYTES))
    tree = {}
    for key, path in (("pack", PACK), ("history", HISTORY), ("lock", LOCK)):
        try:
            text = texts[path].decode("utf-8")
        except UnicodeDecodeError:
            raise ContentError("{} is not UTF-8".format(path))
        tree[key] = strict_load(text, str(path))
        tree[key + "_text"] = text
    tree["fixture_bytes"] = texts[FIXTURE]
    return tree


def write_tree(root, pack, history, lock):
    root = Path(root)
    text = dumps(pack).encode("utf-8")
    for path, data in ((PACK, text), (FIXTURE, text), (HISTORY, dumps(history).encode("utf-8")),
                       (LOCK, dumps(lock).encode("utf-8"))):
        target = root / path
        temporary = target.with_name(target.name + ".tmp")
        temporary.write_bytes(data)
        os.replace(str(temporary), str(target))


# -- digests (CJ1, migration/CONTENT-DIGEST.md; go/internal/content/digest.go) ---------------------------------

def cj1(value):
    """Keys sorted, ", " and ": " separators, ASCII with \\u escapes: json.dumps's defaults, which CJ1 states."""
    return json.dumps(value, sort_keys=True, ensure_ascii=True)


def chain(parts):
    hasher = hashlib.sha256()
    for part in parts:
        hasher.update(cj1(part).encode("ascii"))
        hasher.update(b"\0")
    return hasher.hexdigest()


def host_component(entries):
    return chain(entries)


def application_component(applications):
    ordered = sorted(applications, key=lambda app: app["name"])
    return chain([[app["name"], [app[field] for field in APPLICATION_FIELDS]] for app in ordered])


def risk_component(risks):
    return chain([[name, [risks[name]["severity"], risks[name]["description"]]] for name in sorted(risks)])


def release_digest(components):
    return chain([components[name] for name in sorted(components)])[:16]


def pack_digest(pack):
    """The pack digest: SHA-256 over the prefix and the CJ1 encoding of the whole document (Digests.Pack in Go)."""
    return hashlib.sha256((PACK_DIGEST_PREFIX + cj1(pack)).encode("ascii")).hexdigest()


# -- versions ---------------------------------------------------------------------------------------------------

def version_key(version):
    """YYYY.MM.N compared per component as integers (2026.11.9 < 2026.11.10; go content.CompareVersions)."""
    return tuple(int(part) for part in version.split("."))


def next_version(version):
    """The next version under the numbering rule: 2026.11.8 -> 2026.11.9 -> 2026.12.0 -> ... 2026.12.9 -> 2027.01.0."""
    year, month, number = (int(part) for part in version.split("."))
    if number < 9:
        number += 1
    else:
        year, month, number = (year + 1, 1, 0) if month == 12 else (year, month + 1, 0)
    return "{:04d}.{:02d}.{}".format(year, month, number)


def valid_date(text):
    if not isinstance(text, str) or not DATE.match(text):
        return False
    try:
        datetime.date.fromisoformat(text)
    except ValueError:
        return False
    return True


# -- validation ---------------------------------------------------------------------------------------------------

def _strings(value):
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _port_ok(spec):
    match = PORT.match(spec) if isinstance(spec, str) else None
    if not match:
        return False
    if match.group(2) == "dynamic":
        return True
    return all(1 <= int(part) <= 65535 for part in match.group(2).split("-"))


def application_problems(app, vocabulary, label):
    if not isinstance(app, dict):
        return ["{}: an application is not an object".format(label)]
    if set(app) != set(APPLICATION_FIELDS):
        return ["{}: application {!r} has fields {} (want exactly {})".format(
            label, app.get("name"), sorted(app), ", ".join(APPLICATION_FIELDS))]
    name, problems = app["name"], []
    if not isinstance(name, str) or not name or name != name.strip():
        return ["{}: application without a usable name: {!r}".format(label, name)]
    categories = vocabulary.get("categories") or {}
    if app["category"] not in categories or app["subcategory"] not in categories.get(app["category"], ()):
        problems.append("{}: {}: unknown category {!r}/{!r}".format(label, name, app["category"], app["subcategory"]))
    if app["technology"] not in (vocabulary.get("technologies") or ()):
        problems.append("{}: {}: unknown technology {!r}".format(label, name, app["technology"]))
    if not isinstance(app["risk"], int) or isinstance(app["risk"], bool) or not 1 <= app["risk"] <= 5:
        problems.append("{}: {}: risk {!r} is not 1 to 5".format(label, name, app["risk"]))
    if not isinstance(app["description"], str) or not app["description"].strip():
        problems.append("{}: {}: empty description".format(label, name))
    for field in ("characteristics", "standard_ports", "secure_ports", "implicitly_uses", "depends_on", "aliases"):
        if not _strings(app[field]):
            problems.append("{}: {}: {} is not a list of strings".format(label, name, field))
        elif len(set(app[field])) != len(app[field]):
            problems.append("{}: {}: {} repeats an item".format(label, name, field))
    if _strings(app["characteristics"]):
        for item in app["characteristics"]:
            if item not in (vocabulary.get("characteristics") or ()):
                problems.append("{}: {}: unknown characteristic {!r}".format(label, name, item))
    for field in ("standard_ports", "secure_ports"):
        for spec in app[field] if _strings(app[field]) else ():
            if not _port_ok(spec):
                problems.append("{}: {}: invalid port specification {!r}".format(label, name, spec))
    if app["container"] is not None and not isinstance(app["container"], str):
        problems.append("{}: {}: container is neither null nor a name".format(label, name))
    return problems


def catalog_problems(catalog, applications, label):
    """A server-name catalog: entries, and the lookup tables the Go loader and the engine derive from them."""
    if not isinstance(catalog, dict) or set(catalog) != {"entries", "app_domains", "web_fronts", "suffixes"}:
        return ["{}: host_catalog must have exactly entries, app_domains, web_fronts and suffixes".format(label)]
    entries, problems = catalog["entries"], []
    if not isinstance(entries, list):
        return ["{}: host_catalog entries is not a list".format(label)]
    domains, fronts, suffixes = {}, {}, {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != set(HOST_FIELDS):
            problems.append("{}: host entry {!r} must have exactly {}".format(
                label, entry.get("name") if isinstance(entry, dict) else entry, ", ".join(HOST_FIELDS)))
            continue
        name = entry["name"]
        if name in domains:
            problems.append("{}: host entry {} appears more than once".format(label, name))
            continue
        app = applications.get(name)
        if app is None:
            problems.append("{}: host entry {} names no catalog application".format(label, name))
        elif label == "pack":
            # Earlier releases keep the entries they were published with (C11); only the current one must agree
            # with the application catalog the release ships.
            for field in SHARED_FIELDS:
                if entry[field] != app[field]:
                    problems.append("{}: host entry {} states {} {!r}, its application {!r}".format(
                        label, name, field, entry[field], app[field]))
        if not _strings(entry["domains"]) or not _strings(entry["web_fronts"]):
            problems.append("{}: {}: domains and web_fronts must be lists of strings".format(label, name))
            continue
        if not entry["domains"] and not entry["web_fronts"]:
            problems.append("{}: host entry {} lists no domain".format(label, name))
        domains[name] = list(entry["domains"])
        for domain in entry["domains"]:
            if not DOMAIN.match(domain):
                problems.append("{}: {} lists {!r}, not a lower-case host name".format(label, name, domain))
            elif domain in suffixes:
                problems.append("{}: domain {} is claimed by both {} and {}".format(label, domain, suffixes[domain], name)
                                if suffixes[domain] != name else "{}: {} lists domain {} twice".format(label, name, domain))
                continue
            suffixes.setdefault(domain, name)
        for front in entry["web_fronts"]:
            if not DOMAIN.match(front):
                problems.append("{}: {} lists web front {!r}, not a lower-case host name".format(label, name, front))
            elif front in fronts:
                problems.append("{}: web front {} is claimed by both {} and {}".format(label, front, fronts[front], name))
                continue
            fronts.setdefault(front, name)
    for front, name in fronts.items():
        if front in suffixes and suffixes[front] != name:
            problems.append("{}: {} is a domain of {} and a web front of {}".format(label, front, suffixes[front], name))
    stated = {"app_domains": catalog["app_domains"], "web_fronts": catalog["web_fronts"], "suffixes": catalog["suffixes"]}
    for key, wanted in (("app_domains", domains), ("web_fronts", fronts), ("suffixes", suffixes)):
        if stated[key] != wanted:
            have = stated[key] if isinstance(stated[key], dict) else {}
            differing = sorted(set(wanted) ^ set(have) | {k for k in set(wanted) & set(have) if wanted[k] != have[k]})
            problems.append("{}: {} does not match the entries (first difference: {})".format(label, key, differing[:3]))
    return problems


def release_block_problems(release, label):
    if not isinstance(release, dict) or set(release) != set(RELEASE_FIELDS):
        return ["{}: the release block must have exactly {}".format(label, ", ".join(RELEASE_FIELDS))]
    problems = []
    if not isinstance(release["version"], str) or not VERSION.match(release["version"]):
        problems.append("{}: version {!r} breaks the numbering rule YYYY.MM.N (month 01..12, N 0..9)".format(
            label, release["version"]))
    for field in ("released", "reviewed"):
        if not valid_date(release[field]):
            problems.append("{}: {} {!r} is not a YYYY-MM-DD date".format(label, field, release[field]))
    components = release["components"]
    if not isinstance(components, dict) or set(components) != set(COMPONENTS) or \
            not all(isinstance(v, str) and HEX64.match(v) for v in components.values()):
        problems.append("{}: components must be exactly {} as SHA-256 values".format(label, ", ".join(COMPONENTS)))
    elif release["digest"] != release_digest(components):
        problems.append("{}: release digest {!r} is not the digest of its components ({})".format(
            label, release["digest"], release_digest(components)))
    return problems


def pack_problems(pack):
    """The Go loader's validation of the current pack, and its digests recomputed."""
    if not isinstance(pack, dict) or set(pack) != {"schema", "release", "vocabulary", "protocol_names", "applications",
                                                   "host_catalog", "risks"}:
        return ["pack: the top level must be exactly schema, release, vocabulary, protocol_names, applications, "
                "host_catalog and risks"]
    if pack["schema"] != 1:
        return ["pack: schema {!r} is not 1".format(pack["schema"])]
    problems = release_block_problems(pack["release"], "pack")
    vocabulary = pack["vocabulary"]
    if not isinstance(vocabulary, dict) or set(vocabulary) != {"categories", "technologies", "characteristics", "outcomes"} \
            or not vocabulary["categories"] or not vocabulary["technologies"] or not vocabulary["characteristics"]:
        return problems + ["pack: the vocabulary must state categories, technologies, characteristics and outcomes"]
    applications = pack["applications"]
    if not isinstance(applications, list):
        return problems + ["pack: applications is not a list"]
    by_name = {}
    for app in applications:
        found = application_problems(app, vocabulary, "pack")
        problems += found
        if isinstance(app, dict) and isinstance(app.get("name"), str):
            if app["name"] in by_name:
                problems.append("pack: application {} appears more than once".format(app["name"]))
            by_name.setdefault(app["name"], app)
    if problems:
        return problems
    names = [app["name"] for app in applications]
    if names != sorted(names):
        problems.append("pack: applications are not in name order")
    aliases = {}
    for app in applications:
        for reference in app["implicitly_uses"] + app["depends_on"] + ([app["container"]] if app["container"] else []):
            if reference not in by_name:
                problems.append("pack: {} refers to {}, which is no catalog application".format(app["name"], reference))
        for alias in app["aliases"]:
            if alias in by_name:
                problems.append("pack: alias {} is also an application name".format(alias))
            elif alias in aliases:
                problems.append("pack: alias {} belongs to {} and {}".format(alias, aliases[alias], app["name"]))
            aliases.setdefault(alias, app["name"])
    for outcome in vocabulary["outcomes"]:
        if outcome not in by_name:
            problems.append("pack: session outcome {} has no catalog entry".format(outcome))
    protocol_names = pack["protocol_names"]
    if not isinstance(protocol_names, dict):
        problems.append("pack: protocol_names is not an object")
    else:
        for protocol, app in sorted(protocol_names.items()):
            if app not in by_name:
                problems.append("pack: protocol {} maps to {}, which is no catalog application".format(protocol, app))
    risks = pack["risks"]
    if not isinstance(risks, dict) or not all(isinstance(v, dict) and set(v) == {"severity", "description"}
                                              and v["severity"] in SEVERITIES for v in risks.values()):
        problems.append("pack: every risk needs exactly a low, medium or high severity and a description")
        risks = None
    problems += catalog_problems(pack["host_catalog"], by_name, "pack")
    if problems:
        return problems
    stated = pack["release"]["components"]
    recomputed = {"application_catalog": application_component(applications),
                  "host_catalog": host_component(pack["host_catalog"]["entries"]), "risks": risk_component(risks)}
    for name, value in sorted(recomputed.items()):
        if stated[name] != value:
            problems.append("pack: component {} is {}, the content's is {}".format(name, stated[name], value))
    return problems


def history_problems(history, pack):
    if not isinstance(history, dict) or set(history) != {"schema", "current", "releases"} or history["schema"] != 1 \
            or not isinstance(history["releases"], dict):
        return ["history: must be exactly schema 1, current and a releases object"]
    current = pack["release"]["version"]
    problems = []
    if history["current"] != current:
        problems.append("history: current release {} is not the pack's {}".format(history["current"], current))
    applications = {app["name"]: app for app in pack["applications"]}
    for version, earlier in sorted(history["releases"].items()):
        label = "history {}".format(version)
        if not isinstance(earlier, dict) or set(earlier) != {"release", "host_catalog"}:
            problems.append("{}: must be exactly a release block and a host_catalog".format(label))
            continue
        found = release_block_problems(earlier["release"], label)
        problems += found
        if found:
            continue
        if earlier["release"]["version"] != version:
            problems.append("history: release keyed {} states version {}".format(version, earlier["release"]["version"]))
        elif version_key(version) >= version_key(current):
            problems.append("history: release {} is not earlier than the current {}".format(version, current))
        found = catalog_problems(earlier["host_catalog"], applications, label)
        problems += found
        if not found and host_component(earlier["host_catalog"]["entries"]) != earlier["release"]["components"]["host_catalog"]:
            problems.append("{}: its server-name catalog no longer reproduces its published host component (C11)".format(label))
    return problems


def lock_problems(lock, pack, history):
    if not isinstance(lock, dict) or set(lock) != {"schema", "releases"} or lock["schema"] != 1 \
            or not isinstance(lock["releases"], list) or not lock["releases"]:
        return ["lock: must be exactly schema 1 and a non-empty releases list"]
    problems, versions = [], []
    for entry in lock["releases"]:
        if not isinstance(entry, dict) or set(entry) != set(LOCK_FIELDS):
            problems.append("lock: an entry must have exactly {}".format(", ".join(LOCK_FIELDS)))
            continue
        problems += release_block_problems({k: entry[k] for k in RELEASE_FIELDS}, "lock {}".format(entry["version"]))
        for field in ("note", "review"):
            if not isinstance(entry[field], str) or not entry[field].strip():
                problems.append("lock {}: {} is empty".format(entry["version"], field))
        if entry["pack_digest"] is not None and not (isinstance(entry["pack_digest"], str) and HEX64.match(entry["pack_digest"])):
            problems.append("lock {}: pack_digest is neither null nor a SHA-256 value".format(entry["version"]))
        versions.append(entry["version"])
    if problems:
        return problems
    if [version_key(v) for v in versions] != sorted({version_key(v) for v in versions}):
        problems.append("lock: releases are not in strictly increasing numeric version order")
    published = {version: {"release": earlier["release"], "hosts": len(earlier["host_catalog"]["entries"])}
                 for version, earlier in history["releases"].items()}
    published[pack["release"]["version"]] = {"release": pack["release"], "hosts": len(pack["host_catalog"]["entries"])}
    if set(versions) != set(published):
        problems.append("lock: lists releases {} but the pack and history carry {}".format(
            sorted(set(versions) ^ set(published)), "these differently"))
    if versions and versions[-1] != pack["release"]["version"]:
        problems.append("lock: the last release {} is not the pack's {}".format(versions[-1], pack["release"]["version"]))
    elif lock["releases"][-1]["pack_digest"] != pack_digest(pack):
        problems.append("lock {}: pack_digest {} is not the pack's {} (the current release changed without a new "
                        "version?)".format(versions[-1], lock["releases"][-1]["pack_digest"], pack_digest(pack)))
    for entry in lock["releases"]:
        state = published.get(entry["version"])
        if state is None:
            continue
        for field in RELEASE_FIELDS:
            if entry[field] != state["release"][field]:
                problems.append("lock {}: {} differs from the published release".format(entry["version"], field))
        if entry["host_entries"] != state["hosts"]:
            problems.append("lock {}: host_entries {} but the release has {}".format(entry["version"], entry["host_entries"],
                                                                                     state["hosts"]))
    dates = [entry["released"] for entry in lock["releases"]]
    if dates != sorted(dates):
        problems.append("lock: release dates go backwards")
    return problems


def tree_problems(tree):
    problems = pack_problems(tree["pack"])
    if problems:
        return problems
    problems += history_problems(tree["history"], tree["pack"])
    if not problems:
        problems += lock_problems(tree["lock"], tree["pack"], tree["history"])
    for key, path in (("pack", PACK), ("history", HISTORY), ("lock", LOCK)):
        if tree[key + "_text"] != dumps(tree[key]):
            problems.append("{} is not in the canonical layout (indent 1, sorted keys, ASCII): edit it with "
                            "tools/content_pack.py".format(path))
    if tree["fixture_bytes"] != tree["pack_text"].encode("utf-8"):
        problems.append("{} is not a byte-for-byte copy of {}".format(FIXTURE, PACK))
    return problems


def check(root=ROOT):
    try:
        tree = read_tree(root)
    except ContentError as error:
        return [str(error)], None
    return tree_problems(tree), tree


# -- adding a batch -----------------------------------------------------------------------------------------------

def host_application(entry):
    """The catalog application of a server-name entry, as the reference built it (host_apps.catalog_entries)."""
    app = {field: copy.deepcopy(entry[field]) for field in SHARED_FIELDS}
    app.update({"standard_ports": [], "secure_ports": [], "implicitly_uses": list(HOST_APP_USES), "depends_on": [],
                "container": None, "aliases": []})
    return app


def read_batch(path):
    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError as error:
        raise ContentError("batch {} cannot be read: {}".format(path, error.strerror or error))
    if size > MAX_BATCH_BYTES:
        raise ContentError("batch {} is {} bytes; the limit is {}".format(path, size, MAX_BATCH_BYTES))
    try:
        text = path.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        raise ContentError("batch {} is not UTF-8".format(path))
    return strict_load(text, "batch {}".format(path))


def batch_problems(batch):
    if not isinstance(batch, dict) or not set(batch) <= {"schema", "release", "applications", "host_catalog"} \
            or batch.get("schema") != 1:
        return ["batch: the top level must be schema 1 with release, and applications and/or host_catalog"]
    release = batch.get("release", {})
    if not isinstance(release, dict) or not set(release) <= {"version", "released", "reviewed", "note", "review"}:
        return ["batch: release may state only version, released, reviewed, note and review"]
    applications = batch.get("applications", [])
    catalog = batch.get("host_catalog", {"entries": []})
    if not isinstance(applications, list) or not isinstance(catalog, dict) or set(catalog) != {"entries"} \
            or not isinstance(catalog["entries"], list):
        return ["batch: applications must be a list and host_catalog exactly {\"entries\": [...]}"]
    count = len(applications) + len(catalog["entries"])
    if count == 0:
        return ["batch: adds nothing"]
    if count > MAX_BATCH_ENTRIES:
        return ["batch: {} records; the limit is {} per batch".format(count, MAX_BATCH_ENTRIES)]
    problems = []
    for entry in catalog["entries"]:
        if not isinstance(entry, dict) or not set(HOST_FIELDS) - {"web_fronts"} <= set(entry) <= set(HOST_FIELDS):
            problems.append("batch: host entry {!r} must have {} (web_fronts optional)".format(
                entry.get("name") if isinstance(entry, dict) else entry, ", ".join(HOST_FIELDS)))
        elif len(entry["domains"] if isinstance(entry["domains"], list) else ()) + \
                len(entry.get("web_fronts") or ()) > MAX_DOMAINS_PER_ENTRY:
            problems.append("batch: host entry {} lists more than {} names".format(entry["name"], MAX_DOMAINS_PER_ENTRY))
    return problems


def apply_batch(pack, history, lock, batch, version=None, released=None, reviewed=None, note=None, review=None):
    """(new pack, new history, new lock) with the batch added as a new release, or ContentError."""
    problems = batch_problems(batch)
    if problems:
        raise ContentError("\n".join(problems))
    stated = batch.get("release", {})
    current = pack["release"]
    version = version or stated.get("version") or next_version(current["version"])
    released = released or stated.get("released") or datetime.date.today().isoformat()
    reviewed = reviewed or stated.get("reviewed") or released
    note = note or stated.get("note")
    review = review or stated.get("review")
    if not isinstance(version, str) or not VERSION.match(version):
        raise ContentError("version {!r} breaks the numbering rule YYYY.MM.N (month 01..12, N 0..9)".format(version))
    if version_key(version) <= version_key(current["version"]):
        raise ContentError("version {} is not after the current {} (versions only go up; numeric per component)".format(
            version, current["version"]))
    for label, date in (("released", released), ("reviewed", reviewed)):
        if not valid_date(date):
            raise ContentError("{} {!r} is not a YYYY-MM-DD date".format(label, date))
    if released < current["released"] or reviewed < released:
        raise ContentError("dates: released {} must not precede the current release's {}, and reviewed {} must not "
                           "precede released".format(released, current["released"], reviewed))
    for label, text in (("note", note), ("review", review)):
        if not isinstance(text, str) or not text.strip():
            raise ContentError("the release needs a {} (--{} or the batch's release.{})".format(label, label, label))

    existing = {app["name"] for app in pack["applications"]}
    existing_aliases = {alias for app in pack["applications"] for alias in app["aliases"]}
    added = {}
    for app in batch.get("applications", []):
        name = app.get("name") if isinstance(app, dict) else None
        if name in existing or name in existing_aliases:
            raise ContentError("batch: application {} is already in the catalog (a batch only adds)".format(name))
        if name in added:
            raise ContentError("batch: application {} appears more than once".format(name))
        added[name] = copy.deepcopy(app)
    entries = []
    for raw in batch.get("host_catalog", {}).get("entries", []):
        entry = copy.deepcopy(raw)
        entry.setdefault("web_fronts", [])
        name = entry["name"]
        if name in existing or name in existing_aliases:
            raise ContentError("batch: host entry {} is already in the catalog (a batch only adds)".format(name))
        if name in added:
            for field in SHARED_FIELDS:
                if added[name].get(field) != entry.get(field):
                    raise ContentError("batch: host entry {} states {} {!r}, its batch application {!r}".format(
                        name, field, entry.get(field), added[name].get(field)))
        else:
            added[name] = host_application(entry)
        entries.append(entry)

    new_pack = copy.deepcopy(pack)
    new_pack["applications"] = sorted(new_pack["applications"] + list(added.values()), key=lambda app: str(app["name"]))
    catalog = new_pack["host_catalog"]
    catalog["entries"] = catalog["entries"] + entries
    for entry in entries:
        if isinstance(entry.get("domains"), list) and isinstance(entry.get("web_fronts"), list):
            catalog["app_domains"][entry["name"]] = list(entry["domains"])
            for domain in entry["domains"]:
                catalog["suffixes"].setdefault(domain, entry["name"])
            for front in entry["web_fronts"]:
                catalog["web_fronts"].setdefault(front, entry["name"])
    # Application fields first: a malformed record must be reported as such, not as a digest error.
    problems = [problem for app in added.values() for problem in application_problems(app, pack["vocabulary"], "batch")]
    if problems:
        raise ContentError("\n".join(problems))
    components = dict(current["components"])  # families carries over: a batch adds no protocol family
    components.update(application_catalog=application_component(new_pack["applications"]),
                      host_catalog=host_component(catalog["entries"]), risks=risk_component(new_pack["risks"]))
    new_pack["release"] = {"version": version, "digest": release_digest(components), "released": released,
                           "reviewed": reviewed, "components": components}

    new_history = copy.deepcopy(history)
    new_history["current"] = version
    new_history["releases"][current["version"]] = {"release": copy.deepcopy(current),
                                                   "host_catalog": copy.deepcopy(pack["host_catalog"])}
    new_lock = copy.deepcopy(lock)
    new_lock["releases"].append({"version": version, "digest": new_pack["release"]["digest"], "released": released,
                                 "reviewed": reviewed, "components": components, "host_entries": len(catalog["entries"]),
                                 "pack_digest": pack_digest(new_pack), "note": note.strip(), "review": review.strip()})
    text = dumps(new_pack)
    tree = {"pack": new_pack, "history": new_history, "lock": new_lock, "pack_text": text,
            "history_text": dumps(new_history), "lock_text": dumps(new_lock), "fixture_bytes": text.encode("utf-8")}
    problems = tree_problems(tree)
    if not problems and len(text.encode("utf-8")) > MAX_PACK_BYTES:
        problems.append("the new pack would exceed the Go loader's {} bytes".format(MAX_PACK_BYTES))
    if problems:
        raise ContentError("\n".join(problems))
    return new_pack, new_history, new_lock


def add(root, batch_path, dry_run=False, **release):
    problems, tree = check(root)
    if problems:
        raise ContentError("the content tree does not pass `check` before the batch:\n" + "\n".join(problems))
    batch = read_batch(batch_path)
    pack, history, lock = apply_batch(tree["pack"], tree["history"], tree["lock"], batch, **release)
    if not dry_run:
        write_tree(root, pack, history, lock)
    return pack, tree["pack"]


def summary(pack):
    release = pack["release"]
    return "release {} digest {} ({} applications, {} host entries, {} risks)".format(
        release["version"], release["digest"], len(pack["applications"]), len(pack["host_catalog"]["entries"]),
        len(pack["risks"]))


# -- self-test ----------------------------------------------------------------------------------------------------

def _fixture():
    vocabulary = {"categories": {"media": ["photo-video"], "unknown": ["session-outcome"]},
                  "technologies": ["browser-based", "network-protocol"], "characteristics": ["widely-used"],
                  "outcomes": ["unknown-tcp"]}
    apps = [{"name": "ssl", "category": "media", "subcategory": "photo-video", "technology": "network-protocol", "risk": 2,
             "description": "TLS", "characteristics": [], "standard_ports": ["tcp/443"], "secure_ports": [],
             "implicitly_uses": [], "depends_on": [], "container": None, "aliases": ["tls"]},
            {"name": "unknown-tcp", "category": "unknown", "subcategory": "session-outcome", "technology": "network-protocol",
             "risk": 1, "description": "unknown", "characteristics": [], "standard_ports": [], "secure_ports": [],
             "implicitly_uses": [], "depends_on": [], "container": None, "aliases": []},
            {"name": "web-browsing", "category": "media", "subcategory": "photo-video", "technology": "browser-based",
             "risk": 1, "description": "web", "characteristics": [], "standard_ports": ["tcp/80"], "secure_ports": [],
             "implicitly_uses": [], "depends_on": [], "container": None, "aliases": []}]
    entry = {"name": "vid", "category": "media", "subcategory": "photo-video", "technology": "browser-based", "risk": 2,
             "description": "Vid", "characteristics": ["widely-used"], "domains": ["vid.example"], "web_fronts": []}
    apps.append(host_application(entry))
    apps.sort(key=lambda app: app["name"])
    catalog = {"entries": [entry], "app_domains": {"vid": ["vid.example"]}, "web_fronts": {},
               "suffixes": {"vid.example": "vid"}}
    risks = {"r": {"severity": "low", "description": "a risk"}}
    components = {"application_catalog": application_component(apps), "families": "0" * 64,
                  "host_catalog": host_component(catalog["entries"]), "risks": risk_component(risks)}
    release = {"version": "2026.11.9", "digest": release_digest(components), "released": "2026-11-19",
               "reviewed": "2026-11-19", "components": components}
    pack = {"schema": 1, "release": release, "vocabulary": vocabulary, "protocol_names": {"tls": "ssl"},
            "applications": apps, "host_catalog": catalog, "risks": risks}
    history = {"schema": 1, "current": "2026.11.9", "releases": {}}
    lock = {"schema": 1, "releases": [dict(release, host_entries=1, pack_digest=pack_digest(pack), note="first", review="test")]}
    return pack, history, lock


def _tree(pack, history, lock):
    text = dumps(pack)
    return {"pack": pack, "history": history, "lock": lock, "pack_text": text, "history_text": dumps(history),
            "lock_text": dumps(lock), "fixture_bytes": text.encode("utf-8")}


def _batch(*entries, applications=()):
    return {"schema": 1, "release": {"note": "batch", "review": "self-test", "released": "2026-11-25"},
            "applications": list(applications), "host_catalog": {"entries": list(entries)}}


def _entry(name, *domains, **fields):
    entry = {"name": name, "category": "media", "subcategory": "photo-video", "technology": "browser-based", "risk": 2,
             "description": name.title(), "characteristics": [], "domains": list(domains)}
    entry.update(fields)
    return entry


def self_test():
    pack, history, lock = _fixture()
    assert tree_problems(_tree(pack, history, lock)) == [], tree_problems(_tree(pack, history, lock))

    # After 2026.11.9 the numbering rule moves on to 2026.12.0; the old release moves to history unchanged.
    new_pack, new_history, new_lock = apply_batch(pack, history, lock, _batch(_entry("music", "music.example")))
    assert new_pack["release"]["version"] == "2026.12.0", new_pack["release"]
    assert new_history["releases"]["2026.11.9"]["release"] == pack["release"]
    assert [e["version"] for e in new_lock["releases"]] == ["2026.11.9", "2026.12.0"]
    assert new_pack["release"]["digest"] != pack["release"]["digest"]
    assert tree_problems(_tree(new_pack, new_history, new_lock)) == []
    assert next(a for a in new_pack["applications"] if a["name"] == "music")["implicitly_uses"] == HOST_APP_USES
    # A second batch keeps both earlier releases' digests (C11).
    third, third_history, third_lock = apply_batch(new_pack, new_history, new_lock,
                                                   _batch(_entry("pics", "pics.example", web_fronts=["www.pics.org"])))
    assert third["release"]["version"] == "2026.12.1"
    assert {v: r["release"]["digest"] for v, r in third_history["releases"].items()} == {
        "2026.11.9": pack["release"]["digest"], "2026.12.0": new_pack["release"]["digest"]}
    assert third_lock["releases"][1]["pack_digest"] == pack_digest(new_pack)
    # An application batch record with ports, aliases and a reference.
    service = {"name": "svc", "category": "media", "subcategory": "photo-video", "technology": "network-protocol",
               "risk": 3, "description": "Service", "characteristics": [], "standard_ports": ["tcp/9000-9010"],
               "secure_ports": ["udp/dynamic"], "implicitly_uses": ["ssl"], "depends_on": [], "container": None,
               "aliases": ["service"]}
    out = apply_batch(pack, history, lock, _batch(applications=[service]))
    assert any(app["name"] == "svc" for app in out[0]["applications"])

    refusals = {
        "existing name": (_batch(_entry("vid", "other.example")), "already in the catalog"),
        "existing alias": (_batch(_entry("tls", "other.example")), "already in the catalog"),
        "claimed domain": (_batch(_entry("music", "vid.example")), "domain vid.example is claimed by both vid and music"),
        "domain twice in batch": (_batch(_entry("a1", "x.example"), _entry("a2", "x.example")), "claimed by both a1 and a2"),
        "bad domain": (_batch(_entry("music", "Music.Example")), "not a lower-case host name"),
        "single label": (_batch(_entry("music", "localhost")), "not a lower-case host name"),
        "trailing dot": (_batch(_entry("music", "music.example.")), "not a lower-case host name"),
        "no domain": (_batch(_entry("music")), "lists no domain"),
        "unknown category": (_batch(_entry("music", "m.example", category="nope")), "unknown category"),
        "unknown subcategory": (_batch(_entry("music", "m.example", subcategory="email")), "unknown category"),
        "unknown characteristic": (_batch(_entry("music", "m.example", characteristics=["fast"])), "unknown characteristic"),
        "risk out of range": (_batch(_entry("music", "m.example", risk=6)), "risk 6 is not 1 to 5"),
        "risk bool": (_batch(_entry("music", "m.example", risk=True)), "is not 1 to 5"),
        "unknown technology": (_batch(_entry("music", "m.example", technology="magic")), "unknown technology"),
        "web front is a domain": (_batch(_entry("music", "m.example", web_fronts=["vid.example"])),
                                  "vid.example is a domain of vid and a web front of music"),
        "extra field": (_batch(_entry("music", "m.example", ports=["tcp/1"])), "must have"),
        "missing field": (_batch({"name": "music", "domains": ["m.example"]}), "must have"),
        "empty batch": (_batch(), "adds nothing"),
        "bad port": (_batch(applications=[dict(service, standard_ports=["tcp/70000"])]), "invalid port"),
        "unresolved reference": (_batch(applications=[dict(service, depends_on=["ghost"])]), "refers to ghost"),
        "alias collides": (_batch(applications=[dict(service, aliases=["ssl"])]), "alias ssl is also an application"),
        "alias reused": (_batch(applications=[dict(service, aliases=["tls"])]), "alias tls belongs to ssl and svc"),
        "duplicate in batch": (_batch(applications=[service, service]), "appears more than once"),
        "entry disagrees with its application": (
            _batch(_entry("svc", "svc.example", technology="browser-based"), applications=[service]), "states technology"),
    }
    for label, (batch, expected) in refusals.items():
        try:
            apply_batch(pack, history, lock, batch)
        except ContentError as error:
            assert expected in str(error), (label, str(error))
        else:
            raise AssertionError("{}: the batch was accepted".format(label))
    versions = (("same version", {"version": "2026.11.9"}, "is not after"),
                                    ("older version", {"version": "2026.11.8"}, "is not after"),
                                    ("earlier month", {"version": "2026.10.9"}, "is not after"),
                                    ("two-digit N", {"version": "2026.11.10"}, "numbering rule"),
                                    ("unpadded month", {"version": "2026.12.0".replace(".12.", ".9.")}, "numbering rule"),
                                    ("bad version", {"version": "v2"}, "numbering rule"),
                                    ("bad date", {"released": "2026-13-01"}, "is not a YYYY-MM-DD"),
                                    ("date backwards", {"released": "2026-11-01"}, "must not precede"),
                                    ("no review", {"review": " "}, "needs a review"))
    for label, kwargs, expected in versions:
        batch = _batch(_entry("music", "m.example"))
        if label == "no review":
            batch["release"].pop("review")
        try:
            apply_batch(pack, history, lock, batch, **{k: v for k, v in kwargs.items() if k != "review"})
        except ContentError as error:
            assert expected in str(error), (label, str(error))
        else:
            raise AssertionError("{}: accepted".format(label))

    # Tampering the check finds.
    def tampered(edit):
        p, h, l = copy.deepcopy(new_pack), copy.deepcopy(new_history), copy.deepcopy(new_lock)
        edit(p, h, l)
        return " | ".join(tree_problems(_tree(p, h, l)))
    cases = {
        "silent re-edit of the current release": (lambda p, h, l: next(a for a in p["applications"] if a["name"] == "ssl").update(risk=5),
                                                   "component application_catalog"),
        "digest edited": (lambda p, h, l: p["release"].update(digest="0" * 16), "is not the digest of its components"),
        "earlier host catalog edited": (lambda p, h, l: h["releases"]["2026.11.9"]["host_catalog"]["entries"][0].update(
            description="x"), "no longer reproduces its published host component"),
        "earlier digest edited": (lambda p, h, l: h["releases"]["2026.11.9"]["release"].update(digest="1" * 16),
                                  "is not the digest of its components"),
        "lock rewritten": (lambda p, h, l: l["releases"][0].update(digest=l["releases"][1]["digest"]), "lock 2026.11.9"),
        "pack edited outside the digests": (lambda p, h, l: p["protocol_names"].update(tls2="ssl"), "pack_digest"),
        "lock entry dropped": (lambda p, h, l: l["releases"].pop(0), "lock: lists releases"),
        "lock out of order": (lambda p, h, l: l["releases"].reverse(), "numeric version order"),
        "history current": (lambda p, h, l: h.update(current="2026.11.9"), "is not the pack's"),
        "history newer than current": (lambda p, h, l: h["releases"].update({"2026.12.5": h["releases"].pop("2026.11.9")}),
                                       "keyed 2026.12.5"),
        "suffix table stale": (lambda p, h, l: p["host_catalog"]["suffixes"].update({"vid.example": "music"}),
                               "suffixes does not match"),
        "applications out of order": (lambda p, h, l: p["applications"].reverse(), "not in name order"),
        "outcome without entry": (lambda p, h, l: p["vocabulary"]["outcomes"].append("incomplete"), "session outcome"),
        "protocol to unknown app": (lambda p, h, l: p["protocol_names"].update(x="ghost"), "maps to ghost"),
        "risk severity": (lambda p, h, l: p["risks"]["r"].update(severity="dire"), "severity"),
        "entry and app disagree": (lambda p, h, l: p["host_catalog"]["entries"][0].update(risk=4), "states risk"),
    }
    for label, (edit, expected) in cases.items():
        found = tampered(edit)
        assert expected in found, (label, found)
    layout = _tree(new_pack, new_history, new_lock)
    layout["pack_text"] = json.dumps(new_pack)
    layout["fixture_bytes"] = layout["pack_text"].encode("utf-8")
    assert any("canonical layout" in p for p in tree_problems(layout))
    copy_differs = _tree(new_pack, new_history, new_lock)
    copy_differs["fixture_bytes"] = b"{}"
    assert any("byte-for-byte copy" in p for p in tree_problems(copy_differs))
    for text, expected in (('{"a": 1, "a": 2}', "appears twice"), ('{"a": 1.5}', "not a plain integer"),
                           ('{"a": NaN}', "not a plain integer"), ("[" * 20 + "]" * 20, "nested too deeply"),
                           ('{"a": 10000000000000000}', "outside the digest contract")):
        try:
            strict_load(text, "x")
        except ContentError as error:
            assert expected in str(error), (text, error)
        else:
            raise AssertionError(text)
    assert version_key("2026.11.9") < version_key("2026.11.10")
    assert [next_version(v) for v in ("2026.11.8", "2026.11.9", "2026.12.9", "2025.09.9")] == [
        "2026.11.9", "2026.12.0", "2027.01.0", "2025.10.0"]
    # CJ1 equals the Go encoder on non-ASCII text (pyjson.String: \u escapes, lower-case hex).
    assert cj1({"b": "\u00e9", "a": [1, None, True]}) == '{"a": [1, null, true], "b": "\\u00e9"}'

    # The committed tree passes.
    problems, tree = check(ROOT)
    assert problems == [], problems
    print("content_pack self-test: ok ({} batch refusals, {} tamper cases; committed tree {})".format(
        len(refusals) + len(versions), len(cases) + 2, summary(tree["pack"])))
    return 0


def e2e(go_required=True):
    """The example batch added in a copy of the tree without the Python engine; every content check run there."""
    with tempfile.TemporaryDirectory(prefix="content-batch-e2e-") as folder:
        work = Path(folder)
        # migration/ (cases.json, the golden files, the parity lists), the signature example and the licence files are
        # what the Go tests read outside go/, so `go test ./...` runs here as in the repository (PRO-428).
        shutil.copytree(str(ROOT / "migration"), str(work / "migration"), ignore=shutil.ignore_patterns("__pycache__"))
        for name in ("signatures-example.json", "LICENSE", "NOTICE"):
            shutil.copyfile(str(ROOT / name), str(work / name))
        for path in (PACK, FIXTURE, HISTORY, LOCK, EXAMPLE):
            (work / path).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(str(ROOT / path), str(work / path))
        shutil.copytree(str(ROOT / "tools"), str(work / "tools"), ignore=shutil.ignore_patterns("__pycache__"))
        for folder_name in ("protocol_engine", "protocol_adapters"):
            assert not (work / folder_name).exists()
        before = strict_load((work / PACK).read_text(encoding="utf-8"), str(PACK))
        new_pack, _ = add(work, work / EXAMPLE)
        batch = read_batch(work / EXAMPLE)
        added = len(batch.get("host_catalog", {}).get("entries", [])) + len(
            [a for a in batch.get("applications", []) if a["name"] not in
             {e["name"] for e in batch.get("host_catalog", {}).get("entries", [])}])
        assert len(new_pack["applications"]) == len(before["applications"]) + added, "applications not added"
        assert version_key(new_pack["release"]["version"]) > version_key(before["release"]["version"])
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        scan = ("import sys; sys.path.insert(0, 'tools'); import content_gate as g; "
                "f = lambda p: g.strict_load(open(p, encoding='utf-8').read(), p); "
                "found = g.scan_pack(f('{}'), f('{}'), f('{}')); "
                "same = open('{}', 'rb').read() == open('{}', 'rb').read(); "
                "print('identifiers: ' + ('; '.join(found) or 'no duplicate or conflicting id') + ', copy identical: ' + str(same)); "
                "sys.exit(1 if found or not same else 0)").format(PACK, HISTORY, LOCK, PACK, FIXTURE)
        steps = [[sys.executable, "-B", "tools/content_pack.py", "check"], [sys.executable, "-B", "tools/check_content.py"],
                 [sys.executable, "-B", "-c", scan]]
        lines = []
        for command in steps:
            result = subprocess.run(command, cwd=str(work), env=env, check=False, capture_output=True, text=True)  # noqa: S603
            label = "content_gate.scan_pack" if command[2] == "-c" else " ".join(command[2:])
            lines.append("{}: exit {}: {}".format(label, result.returncode, " / ".join(result.stdout.strip().splitlines())))
            if result.returncode != 0:
                raise ContentError("e2e step failed: " + lines[-1] + result.stderr)
        go = shutil.which("go")
        if go is None:
            if go_required:
                raise ContentError("e2e: no `go` on PATH; the Go content tests are part of this check")
            lines.append("go test: not run (no go on PATH)")
        else:
            shutil.copytree(str(ROOT / "go"), str(work / "go_full"), symlinks=True,
                            ignore=shutil.ignore_patterns("pack.json", "history.json", "lock.json"))
            for path in (PACK, HISTORY, LOCK):
                shutil.copyfile(str(work / path), str(work / "go_full" / path.relative_to("go")))
            shutil.rmtree(str(work / "go"))
            os.rename(str(work / "go_full"), str(work / "go"))
            go_env = dict(env, GOFLAGS="-mod=vendor", GOPROXY="off", GOWORK="off")
            go_env.setdefault("GOTOOLCHAIN", "local")
            # Every Go test, not only the content package's: the frozen-answer replays run the frozen release
            # (go/internal/content/frozen/), the current-content tests and the serve catalog run the batch (PRO-428).
            command = [go, "test", "-count=1", "./..."]
            result = subprocess.run(command, cwd=str(work / "go"), env=go_env, check=False, capture_output=True, text=True)  # noqa: S603
            packages = [line for line in result.stdout.splitlines() if line.startswith(("ok ", "ok\t"))]
            lines.append("go test ./...: exit {}, {} packages ok".format(result.returncode, len(packages)))
            if result.returncode != 0:
                failed = [line for line in (result.stdout + result.stderr).splitlines() if line.startswith(("FAIL", "---", "    "))]
                raise ContentError("e2e Go tests failed on the batch:\n" + "\n".join(failed[:80]))
        print("content batch e2e: ok, {} -> {} (+{} applications) without protocol_engine/ or protocol_adapters/".format(
            before["release"]["version"], new_pack["release"]["version"], added))
        for line in lines:
            print("  " + line)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--e2e", action="store_true", help="with --self-test: the example batch in a Python-free copy")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("check", help="the pack, history and lock agree")
    adding = sub.add_parser("add", help="add a batch as a new content release")
    adding.add_argument("batch")
    adding.add_argument("--version")
    adding.add_argument("--released")
    adding.add_argument("--reviewed")
    adding.add_argument("--note")
    adding.add_argument("--review")
    adding.add_argument("--dry-run", action="store_true", help="validate and report; write nothing")
    args = parser.parse_args(argv)
    if args.self_test:
        code = self_test()
        return code or (e2e() if args.e2e else 0)
    if args.command == "add":
        try:
            pack, before = add(ROOT, args.batch, dry_run=args.dry_run, version=args.version, released=args.released,
                               reviewed=args.reviewed, note=args.note, review=args.review)
        except ContentError as error:
            print("content batch refused:\n" + str(error))
            return 1
        print("content batch {}: {} -> {}".format("checked (dry run, nothing written)" if args.dry_run else "added",
                                                  before["release"]["version"], summary(pack)))
        return 0
    if args.command == "check":
        problems, tree = check(ROOT)
        for problem in problems:
            print("content: " + problem)
        if problems:
            return 1
        print("content pack ok: {}; {} releases in the lock, earlier: {}".format(
            summary(tree["pack"]), len(tree["lock"]["releases"]),
            ", ".join(sorted(tree["history"]["releases"], key=version_key))))
        return 0
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
