"""Convert an App Research child-app wave (research/child-apps/wave-N.json) into engine rules (PRO-492).

Usage:
    python3 -B tools/child_apps_wave.py WAVE.json --version 2026.11.1 --write
        writes go/internal/childapp/childapps.json and docs/child-apps/<wave>-rules.md
    python3 -B tools/child_apps_wave.py WAVE.json --check
        exits 1 when the committed files differ from a fresh conversion (at the committed release version);
        `make check` runs it on migration/fixtures/child-apps/wave-0.json, a byte copy of App Research's file
    python3 -B tools/child_apps_wave.py --self-test

Only cited function children become rules. The conversion is literal and conservative; whatever it cannot carry
over exactly is either dropped as a broader condition (recorded in the report) or skipped (recorded with the reason):

- `<parent>-base` children are the parent itself in the engine (app=<parent>, container empty): no rule.
- A host must be a DNS name claimed in the pack's server-name catalog; its owner, when not the parent, goes into
  depends_on. A host template such as {box-upload-server} skips the signal.
- path_exact becomes a literal path pattern, path_prefix a prefix, path_pattern a pattern ({name} is one
  non-empty run inside a segment). A placeholder whose name says it is a path ({file_path}, {item-path}) may span
  several segments, so that pattern is skipped.
- A content type with a scope note in parentheses, or */*, drops the content-type condition (broader).
- direction is not carried over as a condition: the engine reads it from body sizes, which a proxy often knows only
  after the response, while method and path already name the function. The report lists it per child.
- query and header_present are carried over as written; anything else in them skips the signal.
Python 3.9, standard library only.
"""
import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACK = ROOT / "go" / "internal" / "content" / "pack.json"
OUT = ROOT / "go" / "internal" / "childapp" / "childapps.json"
DOCS = ROOT / "docs" / "child-apps"
HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
MEDIA = re.compile(r"^[a-z0-9][a-z0-9.+-]*/([a-z0-9][a-z0-9.+-]*|\*)$")
METHOD = re.compile(r"^[A-Z][A-Z_-]{0,31}$")
PLACEHOLDER = re.compile(r"\{([^{}/]+)\}")


def catalog(pack):
    """(domain -> owner, web fronts) of the pack's server-name catalog."""
    domains, fronts = {}, set()
    for entry in pack["host_catalog"]["entries"]:
        for domain in entry["domains"]:
            domains[domain] = entry["name"]
        fronts.update(entry.get("web_fronts", []))
    return domains, fronts


def owner(host, domains, fronts):
    if host in fronts:
        return None
    labels = host.split(".")
    for i in range(len(labels)):
        name = domains.get(".".join(labels[i:]))
        if name:
            return name
    return None


def convert_paths(signal, notes):
    """(prefixes, patterns) from a research signal; None when a path condition was present but none survived."""
    prefixes = list(signal.get("path_prefix") or [])
    patterns = []
    for path in signal.get("path_exact") or []:
        if "{" in path or "}" in path:
            notes.append("path_exact {} has a template: skipped".format(path))
            continue
        patterns.append(path)
    for path in signal.get("path_pattern") or []:
        names = PLACEHOLDER.findall(path)
        if any("path" in name.lower() for name in names):
            notes.append("pattern {} has a path variable that may span segments: skipped".format(path))
            continue
        patterns.append(path)
    had = any(signal.get(k) for k in ("path_prefix", "path_exact", "path_pattern"))
    if had and not prefixes and not patterns:
        return None
    return prefixes, patterns


def convert_signal(child, signal, domains, fronts, owners, notes):
    hosts = signal.get("host")
    if not isinstance(hosts, list) or not hosts:
        notes.append("host is not a list of names ({!r}): signal skipped".format(hosts))
        return None
    for host in hosts:
        if not HOST.match(host):
            notes.append("host {} is not a DNS name: signal skipped".format(host))
            return None
        who = owner(host, domains, fronts)
        if who is None:
            notes.append("host {} is not claimed in the server-name catalog: signal skipped".format(host))
            return None
        owners.add(who)
    rule = {"hosts": sorted(set(hosts))}
    methods = signal.get("method")
    methods = [methods] if isinstance(methods, str) else list(methods or [])
    if methods:
        if not all(METHOD.match(m) for m in methods):
            notes.append("method {!r} is not a token: signal skipped".format(methods))
            return None
        rule["methods"] = sorted(set(methods))
    paths = convert_paths(signal, notes)
    if paths is None:
        notes.append("no path condition survived: signal skipped")
        return None
    prefixes, patterns = paths
    if prefixes:
        rule["path_prefixes"] = prefixes
    if patterns:
        rule["path_patterns"] = patterns
    types = signal.get("content_type") or []
    if types:
        if all(MEDIA.match(t) for t in types) and "*/*" not in types:
            rule["content_types"] = sorted(set(types))
        else:
            notes.append("content type {} has notes or */*: condition dropped (broader)".format(types))
    query = signal.get("query")
    if query:
        rule["query"] = [query] if isinstance(query, str) else list(query)
    headers = signal.get("header_present")
    if headers:
        rule["header_present"] = list(headers)
    if signal.get("websocket") is True:
        rule["websocket"] = True
    if signal.get("direction") not in (None, "none"):
        notes.append("direction {} not a condition (method and path name the function)".format(signal["direction"]))
    if set(rule) == {"hosts"}:
        notes.append("no function condition: signal skipped")
        return None
    return rule


def convert(wave, pack, version):
    """(component, report rows). Report rows are (child, outcome, notes)."""
    domains, fronts = catalog(pack)
    apps = {a["name"]: a for a in pack["applications"]}
    children, report = [], []
    for service in wave["services"]:
        for child in service["children"]:
            notes = []
            name, parent = child["id"], child["parent"]
            if child.get("function") == "base":
                report.append((name, "parent", ["the parent {} itself (app={}, container empty)".format(parent, parent)]))
                continue
            if child.get("status") != "cited":
                report.append((name, "skipped", ["status {}".format(child.get("status"))]))
                continue
            if parent not in apps:
                report.append((name, "skipped", ["parent {} is not a catalog application".format(parent)]))
                continue
            evidence = [c["url"] for c in child.get("citations", []) if str(c.get("url", "")).startswith("https://")]
            if not evidence:
                report.append((name, "skipped", ["no https citation"]))
                continue
            owners, rules = set(), []
            for signal in child.get("signals", []):
                rule = convert_signal(child, signal, domains, fronts, owners, notes)
                if rule is not None and len(rules) < 32:
                    rules.append(rule)
            if not rules:
                report.append((name, "skipped", notes or ["no signal"]))
                continue
            scope = child.get("client_scope", "all")
            description = "{} {} ({} scope; App Research {} {})".format(service["service"], child["function"], scope,
                                                                      wave.get("task", ""), wave.get("wave", ""))
            entry = {"name": name, "container": parent, "description": description[:512]}
            depends = sorted(o for o in owners if o != parent)
            if depends:
                entry["depends_on"] = depends
            entry["evidence"] = list(dict.fromkeys(evidence))[:8]
            entry["rules"] = rules
            children.append(entry)
            report.append((name, "rule", notes))
    component = {"schema": 1, "release": {
        "version": version,
        "note": "child applications from App Research {} wave {} ({}); converted by tools/child_apps_wave.py".format(
            wave.get("task", ""), wave.get("wave", ""), wave.get("date", "")),
        "review": "engine-lane conversion review (PRO-492); citations by App Research ({})".format(wave.get("task", ""))},
        "children": children}
    return component, report


def render_component(component):
    lines = ['{', ' "schema": 1,', ' "release": ' + json.dumps(component["release"], sort_keys=True) + ',', ' "children": [']
    for i, child in enumerate(component["children"]):
        lines.append("  " + json.dumps(child) + ("," if i + 1 < len(component["children"]) else ""))
    lines += [" ]", "}"]
    return "\n".join(lines) + "\n"


def render_report(wave, report):
    counts = {}
    for _, outcome, _ in report:
        counts[outcome] = counts.get(outcome, 0) + 1
    out = ["# Child-app rules from {} wave {} (generated)".format(wave.get("task", ""), wave.get("wave", "")), "",
           "Generated by `tools/child_apps_wave.py` from App Research's `research/child-apps/wave-{}.json`; do not edit."
           .format(wave.get("wave", "")), "",
           "Outcomes: {}.".format(", ".join("{} {}".format(v, k) for k, v in sorted(counts.items()))), "",
           "| Child | Outcome | Notes |", "|---|---|---|"]
    for name, outcome, notes in report:
        out.append("| `{}` | {} | {} |".format(name, outcome, "<br>".join(n.replace("|", "\\|") for n in notes) or "-"))
    return "\n".join(out) + "\n"


def self_test():
    pack = {"applications": [{"name": "dropbox"}, {"name": "google-base"}, {"name": "gmail"}],
            "host_catalog": {"entries": [{"name": "dropbox", "domains": ["dropboxapi.com"], "web_fronts": ["www.db.example"]},
                                         {"name": "google-base", "domains": ["googleapis.com"]},
                                         {"name": "gmail", "domains": ["mail.google.com"]}]}}
    wave = {"task": "T", "wave": 0, "date": "d", "services": [{"service": "S", "children": [
        {"id": "gmail-base", "function": "base", "parent": "gmail", "status": "cited"},
        {"id": "gmail-x", "function": "uploading", "parent": "gmail", "status": "cited", "client_scope": "api",
         "citations": [{"url": "https://doc.example/a"}, {"url": "research/x.md"}],
         "signals": [{"host": ["gmail.googleapis.com"], "method": "POST", "path_pattern": ["/u/{id}/send", "/f/{file_path}"],
                      "content_type": ["message/* (on some paths)"], "query": "uploadType=media|resumable",
                      "direction": "upload", "websocket": False},
                     {"host": "pack app_domains[gmail]", "method": "GET"}]},
        {"id": "dropbox-y", "function": "downloading", "parent": "dropbox", "status": "cited",
         "citations": [{"url": "https://doc.example/b"}],
         "signals": [{"host": ["{server}"], "method": "GET", "path_exact": ["/2/x"]}]},
        {"id": "dropbox-z", "function": "x", "parent": "dropbox", "status": "unverified", "signals": []}]}]}
    component, report = convert(wave, pack, "2026.11.1")
    assert [c["name"] for c in component["children"]] == ["gmail-x"], component
    child = component["children"][0]
    assert child["depends_on"] == ["google-base"] and child["evidence"] == ["https://doc.example/a"], child
    assert child["rules"] == [{"hosts": ["gmail.googleapis.com"], "methods": ["POST"], "path_patterns": ["/u/{id}/send"],
                               "query": ["uploadType=media|resumable"]}], child["rules"]
    outcomes = {name: outcome for name, outcome, _ in report}
    assert outcomes == {"gmail-base": "parent", "gmail-x": "rule", "dropbox-y": "skipped", "dropbox-z": "skipped"}, outcomes
    text = render_component(component)
    assert json.loads(text) == component and text.endswith("}\n")
    assert "| `dropbox-y` | skipped |" in render_report(wave, report)
    print("child_apps_wave self-test: ok")
    return 0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("wave", nargs="?")
    parser.add_argument("--version")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.wave or args.write == args.check or (args.write and not args.version):
        parser.error("give WAVE.json and exactly one of --write (with --version) or --check")
    if args.check and not args.version:
        args.version = json.loads(OUT.read_text(encoding="utf-8"))["release"]["version"]
    wave = json.loads(Path(args.wave).read_text(encoding="utf-8"))
    pack = json.loads(PACK.read_text(encoding="utf-8"))
    component, report = convert(wave, pack, args.version)
    outputs = {OUT: render_component(component), DOCS / "wave-{}-rules.md".format(wave.get("wave", "")): render_report(wave, report)}
    if args.write:
        DOCS.mkdir(parents=True, exist_ok=True)
        for path, text in outputs.items():
            path.write_text(text, encoding="utf-8")
        print("child apps: {} children written to {}".format(len(component["children"]), OUT.relative_to(ROOT)))
        return 0
    stale = [str(p.relative_to(ROOT)) for p, text in outputs.items() if not p.exists() or p.read_text(encoding="utf-8") != text]
    print("child apps: " + ("stale: " + ", ".join(stale) if stale else "ok ({} children)".format(len(component["children"]))))
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
