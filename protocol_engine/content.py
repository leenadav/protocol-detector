"""D08: detection content versioning, provenance, review dates and rollback.

"Content" is the administrative data a verdict is looked up in once a structural
identification exists: the built-in server-name catalog (host_apps.py), the
application catalog (applications.py), the family inventory (catalog.py) and the
flow-risk table (risks.py). Parsers are engine code and follow the package
version; content has its own release history so that a session record can say
which catalog classified it, a reviewer can see when each entry was last looked
at, and an operator can run an earlier catalog (`select(version)`) without
changing the engine.

Releases are `YYYY.MM.N`. `content_lock.json` next to this module records the
digest of the current content; `tools/check_content.py` fails when the content
changed without a new release entry, so every catalog edit is dated and named.
Rollback covers the server-name catalog, whose earlier states are kept here as
the differences from the current entries; the application catalog and the family
inventory change only with engine releases and roll back with the package.
"""
import hashlib
import json
from collections import namedtuple
from pathlib import Path
from types import MappingProxyType

Release = namedtuple("Release", "version released reviewed review note")

HISTORY = (
    Release("2025.10.0", "2025-10-24", "2025-10-24",
            "engine-lane self-review; independent Codex rounds on v0.65 (issue #2)",
            "v0.65 built-in server-name catalog: 51 services on operator-owned domains"),
    Release("2026.11.0", "2026-11-07", "2026-11-07",
            "engine-lane self-review (D03); independent review pending on PR #18",
            "provider web fronts separated from service domains; OpenAI split into ChatGPT, platform and web front; "
            "github.io (tenant hosting) removed; TeamViewer/AnyDesk apex and www names are web fronts"),
)
CURRENT = HISTORY[-1].version
LOCK_PATH = Path(__file__).with_name("content_lock.json")

# Server-name catalog entries as they were at an earlier release, where they differ from the current
# tables: None means the entry did not exist yet; a dict names the fields that were different.
# Entry layout (host_apps._HOST_APPS): name, category, subcategory, technology, risk, description,
# characteristics, domains, web_fronts (optional).
_PRIOR_HOST_STATE = MappingProxyType({
    "2025.10.0": MappingProxyType({
        "github": {"domains": ("github.com", "githubusercontent.com", "githubassets.com", "github.io"), "web_fronts": ()},
        "openai-chatgpt": {"description": "OpenAI ChatGPT and API",
                           "domains": ("openai.com", "chatgpt.com", "oaiusercontent.com", "oaistatic.com"), "web_fronts": ()},
        "openai-platform": None,
        "teamviewer": {"web_fronts": ()},
        "anydesk": {"web_fronts": ()},
    }),
})
_FIELDS = ("name", "category", "subcategory", "technology", "risk", "description", "characteristics", "domains", "web_fronts")
# Provenance of server-name entries: how a domain earns its place and how it is checked.
HOST_BASIS = "operator-owned-domain"
HOST_SOURCE = "public domain ownership and the service's own documentation; shared CDNs, cloud hosting and tenant domains excluded"


class ContentError(ValueError):
    pass


def releases():
    return HISTORY


def release(version):
    for item in HISTORY:
        if item.version == version:
            return item
    raise ContentError("Unknown content version " + repr(version))


def _entry_dict(entry):
    values = dict(zip(_FIELDS, entry))
    values.setdefault("web_fronts", ())
    return values


def host_entries(version=None):
    """Server-name catalog entries (dicts) as of `version` (default: current)."""
    from .host_apps import _HOST_APPS
    version = CURRENT if version is None else version
    release(version)
    entries = [_entry_dict(entry) for entry in _HOST_APPS]
    for item in reversed(HISTORY):
        if item.version < version:
            break
        prior = _PRIOR_HOST_STATE.get(item.version)
        if not prior:
            continue
        rebuilt = []
        for entry in entries:
            change = prior.get(entry["name"], {})
            if change is None:
                continue
            rebuilt.append(dict(entry, **change))
        entries = rebuilt
    return tuple(entries)


def host_provenance(version=None):
    """Per-entry provenance: first release carrying the entry, last review date, basis and source."""
    version = CURRENT if version is None else version
    current = {entry["name"] for entry in host_entries(version)}
    first = {}
    for item in HISTORY:
        if item.version > version:
            break
        for entry in host_entries(item.version):
            first.setdefault(entry["name"], item.version)
    reviewed = release(version).reviewed
    return MappingProxyType({name: MappingProxyType({"since": first[name], "reviewed": reviewed, "basis": HOST_BASIS, "source": HOST_SOURCE})
                             for name in sorted(current)})


def _hash(parts):
    hasher = hashlib.sha256()
    for part in parts:
        hasher.update(json.dumps(part, sort_keys=True, default=str).encode("utf-8"))
        hasher.update(b"\0")
    return hasher.hexdigest()


def component_digests(version=None):
    """Digest per content component; the host component follows the selected version."""
    from .applications import APPLICATIONS
    from .catalog import supported_protocols
    from .risks import RISKS
    return MappingProxyType({
        "host_catalog": _hash([entry for entry in host_entries(version)]),
        "application_catalog": _hash([(name, list(app.__dict__.values())) for name, app in sorted(APPLICATIONS.items())]),
        "families": _hash([(item.family, list(item.transports), item.scope, item.profile, item.requires_hint) for item in supported_protocols()]),
        "risks": _hash([(name, list(RISKS[name])) for name in sorted(RISKS)]),
    })


_DIGESTS = {}


def digest(version=None):
    """Content digest for a release; cached per process (the tables of a release never change at run time)."""
    version = CURRENT if version is None else version
    cached = _DIGESTS.get(version)
    if cached is None:
        components = component_digests(version)
        cached = _DIGESTS[version] = _hash([components[name] for name in sorted(components)])[:16]
    return cached


def description(version=None):
    """The content release with its digests, for `protodetect content` and the lock file."""
    version = CURRENT if version is None else version
    item = release(version)
    return {"version": item.version, "released": item.released, "reviewed": item.reviewed, "review": item.review,
            "note": item.note, "digest": digest(version), "components": dict(component_digests(version)),
            "host_entries": len(host_entries(version))}


# -- process-wide selection (rollback) --

_SELECTED = [CURRENT]


def select(version):
    """Run the server-name catalog as of `version` in this process; returns the pin for records."""
    from . import host_apps
    release(version)
    host_apps.rebuild(host_entries(version))
    _SELECTED[0] = version
    return pinned()


def selected():
    return _SELECTED[0]


def pinned():
    """What a session record pins: the content version in force and its digest."""
    return {"version": _SELECTED[0], "digest": digest(_SELECTED[0])}


# -- lock file --

def read_lock(path=LOCK_PATH):
    with open(path, "rb") as handle:
        return json.loads(handle.read().decode("utf-8"))


def write_lock(path=LOCK_PATH):
    data = description()
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(data, indent=2, sort_keys=True) + "\n")
    return data


def check(path=LOCK_PATH):
    """Problems between the content tables, the release history and the lock file (empty when consistent)."""
    problems = []
    versions = [item.version for item in HISTORY]
    if versions != sorted(versions) or len(set(versions)) != len(versions):
        problems.append("content releases are not strictly increasing")
    for item in HISTORY:
        for field in ("released", "reviewed"):
            value = getattr(item, field)
            if len(value) != 10 or value[4] != "-" or value[7] != "-" or not (value[:4] + value[5:7] + value[8:]).isdigit():
                problems.append("release {} has a malformed {} date".format(item.version, field))
    for version in _PRIOR_HOST_STATE:
        if version not in versions:
            problems.append("prior host state for unknown release " + version)
    names = {entry["name"] for entry in host_entries()}
    for version, prior in _PRIOR_HOST_STATE.items():
        for name, change in prior.items():
            if name not in names:
                problems.append("prior state of {} names an unknown entry {}".format(version, name))
            elif change is not None and not set(change) <= set(_FIELDS):
                problems.append("prior state of {} changes unknown fields of {}".format(version, name))
    for item in HISTORY:
        try:
            from .host_apps import build_tables
            build_tables(host_entries(item.version))
        except (ValueError, ContentError) as error:
            problems.append("catalog at {} does not build: {}".format(item.version, error))
    try:
        lock = read_lock(path)
    except (OSError, ValueError):
        problems.append("content lock missing or unreadable: run tools/check_content.py --update after adding a release")
        return problems
    current = description()
    if lock.get("version") != current["version"]:
        problems.append("content lock names {} but the current release is {}".format(lock.get("version"), current["version"]))
    if lock.get("digest") != current["digest"]:
        changed = sorted(name for name, value in current["components"].items() if lock.get("components", {}).get(name) != value)
        problems.append("content changed ({}) without a new release entry: add a Release to protocol_engine/content.py HISTORY, "
                        "then run tools/check_content.py --update".format(", ".join(changed) or "digest"))
    elif lock.get("components") != current["components"] or lock.get("host_entries") != current["host_entries"]:
        # The aggregate agrees but the lock's own metadata does not: a hand-edited or stale lock file.
        problems.append("content lock metadata is inconsistent with the tables (per-component digests or host_entries differ while "
                        "the aggregate digest matches): regenerate it with tools/check_content.py --update")
    return problems
