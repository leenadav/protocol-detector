#!/usr/bin/env python3
"""Check a child-apps research file (research/child-apps/wave-*.json) and render its Markdown table.

Usage:
  python3 -B research/tools/check_child_apps.py research/child-apps/wave-0.json           # check only
  python3 -B research/tools/check_child_apps.py research/child-apps/wave-0.json --write-md
  python3 -B research/tools/check_child_apps.py --self-test

The check enforces the rule-field policy of PRO-495: a child with rule signals has at least one citation
with a URL and an access date; parents exist in the content pack (or are listed as proposed); ids are
unique; directions are from a fixed set; and the rendered Markdown matches the JSON.
Python 3.9, standard library only.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACK = ROOT / "go" / "internal" / "content" / "pack.json"
DIRECTIONS = {"upload", "download", "bidirectional", "none"}
STATUSES = {"cited", "pack-only"}
FUNCTIONS = {"base", "uploading", "downloading", "posting", "sharing", "voice-video", "file-transfer",
             "remote-control"}
# Ids proposed by earlier research batches and not yet in the pack.
PROPOSED_PARENTS = {"google-gemini-api": "batch G, research/apps/google-gemini-api.md"}
SIGNAL_KEYS = {"host", "method", "path_exact", "path_prefix", "path_pattern", "query", "content_type",
               "header_present", "direction", "websocket"}
FORBIDDEN_TEXT = ("TODO", "TBD", "FIXME", "XXX")


def pack_ids(pack_path=PACK):
    with open(pack_path, encoding="utf-8") as f:
        return {a["name"] for a in json.load(f)["applications"]}


def check(doc, known_ids):
    """Return a list of error strings (empty when the document is valid)."""
    errors = []
    seen = set()
    text = json.dumps(doc)
    for word in FORBIDDEN_TEXT:
        if word in text:
            errors.append("placeholder text %r present" % word)
    services = doc.get("services")
    if not isinstance(services, list) or not services:
        return errors + ["no services"]
    for svc in services:
        name = svc.get("service", "?")
        parent = svc.get("parent")
        if parent not in known_ids:
            errors.append("%s: parent %r not in the pack" % (name, parent))
        if not svc.get("children"):
            errors.append("%s: no children" % name)
        for ch in svc.get("children", []):
            cid = ch.get("id")
            where = "%s/%s" % (name, cid)
            if not cid or cid in seen:
                errors.append("%s: missing or duplicate id" % where)
            seen.add(cid)
            if ch.get("parent") not in known_ids and ch.get("parent") not in PROPOSED_PARENTS:
                errors.append("%s: parent %r neither in the pack nor proposed" % (where, ch.get("parent")))
            if ch.get("function") not in FUNCTIONS:
                errors.append("%s: unknown function %r" % (where, ch.get("function")))
            if ch.get("status") not in STATUSES:
                errors.append("%s: unknown status %r" % (where, ch.get("status")))
            cites = ch.get("citations", [])
            if ch.get("status") == "cited":
                if not cites:
                    errors.append("%s: cited child without a citation" % where)
                for c in cites:
                    if not c.get("url") or not c.get("accessed") or not c.get("locator"):
                        errors.append("%s: citation lacks url, accessed or locator" % where)
            sigs = ch.get("signals", [])
            if not sigs:
                errors.append("%s: no signals" % where)
            for s in sigs:
                extra = set(s) - SIGNAL_KEYS
                if extra:
                    errors.append("%s: unknown signal keys %s" % (where, sorted(extra)))
                if not s.get("host"):
                    errors.append("%s: signal without host" % where)
                if s.get("direction") not in DIRECTIONS:
                    errors.append("%s: bad direction %r" % (where, s.get("direction")))
                if not isinstance(s.get("websocket"), bool):
                    errors.append("%s: websocket must be true or false" % where)
        for ns in svc.get("not_separable", []):
            if not ns.get("function") or not ns.get("reason"):
                errors.append("%s: not_separable row lacks function or reason" % name)
            pid = ns.get("proposed_id")
            if pid and pid in seen:
                errors.append("%s: proposed id %r is also a rule child" % (name, pid))
        for b in svc.get("source_blocked", []):
            if not b.get("url") or not b.get("needed"):
                errors.append("%s: source_blocked row lacks url or needed" % name)
    return errors


def counts(doc):
    children = [c for s in doc["services"] for c in s["children"]]
    with_rules = [c for c in children if c["status"] == "cited" and c["function"] != "base"]
    cited = [c for c in children if c["status"] == "cited"]
    return {
        "services": len(doc["services"]),
        "children": len(children),
        "children_cited": len(cited),
        "function_children_with_rules": len(with_rules),
        "citations": sum(len(c.get("citations", [])) for c in children),
        "not_separable": sum(len(s.get("not_separable", [])) for s in doc["services"]),
        "source_blocked": sum(len(s.get("source_blocked", [])) for s in doc["services"]),
    }


def _cell(v):
    return str(v).replace("|", "\\|").replace("\n", " ")


def _sig_text(s):
    parts = []
    if s.get("method"):
        parts.append(s["method"])
    host = ", ".join(s["host"]) if isinstance(s["host"], list) else s["host"]
    paths = s.get("path_exact") or s.get("path_prefix") or s.get("path_pattern")
    if paths:
        kind = "=" if "path_exact" in s else ("^" if "path_prefix" in s else "~")
        parts.append("`%s` %s`%s`" % (host, kind, "`, `".join(paths)))
    else:
        parts.append(host)
    if s.get("query"):
        parts.append("?" + s["query"])
    if s.get("content_type"):
        parts.append("CT " + "; ".join(s["content_type"]))
    if s.get("header_present"):
        parts.append("hdr " + ", ".join(s["header_present"]))
    parts.append(s["direction"])
    if s.get("websocket"):
        parts.append("WebSocket")
    return " ".join(parts)


def render_md(doc):
    c = counts(doc)
    out = [
        "# Child apps, wave 0 (PRO-495, feeds PRO-492)",
        "",
        "Generated from `wave-0.json` by `research/tools/check_child_apps.py --write-md`; edit the JSON, not this "
        "file. Pack base: %s. Accessed %s." % (doc["pack_base"], doc["date"]),
        "",
        "**Counts:** %(services)d services, %(children)d children (%(children_cited)d with citations, "
        "%(function_children_with_rules)d function children with rule fields), %(citations)d citations, "
        "%(not_separable)d functions recorded as not separable, %(source_blocked)d blocked sources." % c,
        "",
        "**Read first:** " + doc["visibility"],
        "",
        "Rule-field policy:",
        "",
    ]
    out += ["- " + p for p in doc["rule_field_policy"]]
    out += ["", "Signal notation: `=` exact path, `^` path prefix, `~` path pattern (`{name}` is one variable "
            "segment); CT = request content type; hdr = request header that must be present.", "",
            "PRO-491 overlap: " + doc["pro491_overlap"], "",
            "## Children with citations", "",
            "| Service | Child id | Function | Parent | Scope | Signals | Sources |",
            "|---|---|---|---|---|---|---|"]
    for s in doc["services"]:
        for ch in s["children"]:
            sig = "<br>".join(_cell(_sig_text(x)) for x in ch["signals"])
            src = "<br>".join("[%d](%s)" % (i + 1, x["url"]) if x["url"].startswith("http") else _cell(x["url"])
                              for i, x in enumerate(ch.get("citations", []))) or "none (pack only)"
            out.append("| %s | `%s` | %s | `%s` | %s | %s | %s |" % (
                _cell(s["service"]), ch["id"], ch["function"], ch["parent"], ch["client_scope"], sig, src))
    out += ["", "## Functions that cannot be separated by these signals", "",
            "| Service | Function | Proposed id | Why |", "|---|---|---|---|"]
    for s in doc["services"]:
        for ns in s.get("not_separable", []):
            out.append("| %s | %s | %s | %s |" % (_cell(s["service"]), _cell(ns["function"]),
                                                  "`%s`" % ns["proposed_id"] if ns.get("proposed_id") else "",
                                                  _cell(ns["reason"])))
    out += ["", "## Sources not readable from this environment (for Research Lab)", "",
            "| Service | URL | Why | Needed |", "|---|---|---|---|"]
    for s in doc["services"]:
        for b in s.get("source_blocked", []):
            out.append("| %s | %s | %s | %s |" % (_cell(s["service"]), b["url"], _cell(b["why"]), _cell(b["needed"])))
    out += ["", "## Host notes for Engine", ""]
    for s in doc["services"]:
        if s.get("host_note"):
            out.append("- **%s**: %s" % (s["service"], s["host_note"]))
    out.append("")
    return "\n".join(out)


def _self_test():
    ids = {"p"}
    good = {"services": [{"service": "S", "parent": "p", "children": [
        {"id": "p-up", "function": "uploading", "parent": "p", "status": "cited", "client_scope": "api",
         "signals": [{"host": ["h"], "method": "POST", "path_exact": ["/u"], "direction": "upload",
                      "websocket": False}],
         "citations": [{"url": "https://x", "accessed": "2026-11-27", "locator": "l"}]}]}],
        "pack_base": "b", "date": "d", "visibility": "v", "rule_field_policy": ["r"], "pro491_overlap": "o"}
    assert check(good, ids) == [], check(good, ids)
    bad = json.loads(json.dumps(good))
    bad["services"][0]["children"][0]["citations"] = []
    assert any("without a citation" in e for e in check(bad, ids))
    bad = json.loads(json.dumps(good))
    bad["services"][0]["parent"] = "nope"
    assert any("not in the pack" in e for e in check(bad, ids))
    bad = json.loads(json.dumps(good))
    bad["services"][0]["children"][0]["signals"][0]["direction"] = "sideways"
    assert any("bad direction" in e for e in check(bad, ids))
    bad = json.loads(json.dumps(good))
    bad["services"][0]["children"].append(dict(bad["services"][0]["children"][0]))
    assert any("duplicate id" in e for e in check(bad, ids))
    bad = json.loads(json.dumps(good))
    bad["services"][0]["children"][0]["notes"] = "TODO later"
    assert any("placeholder" in e for e in check(bad, ids))
    md = render_md(good)
    assert "`p-up`" in md and "`h` =`/u`" in md, md
    print("check_child_apps self-test: ok")
    return 0


def main(argv):
    if argv[1:] == ["--self-test"]:
        return _self_test()
    if len(argv) < 2:
        print(__doc__)
        return 2
    path = Path(argv[1])
    doc = json.loads(path.read_text(encoding="utf-8"))
    errors = check(doc, pack_ids())
    md_path = path.with_suffix(".md")
    md = render_md(doc)
    if "--write-md" in argv[2:]:
        md_path.write_text(md, encoding="utf-8")
    elif not md_path.exists() or md_path.read_text(encoding="utf-8") != md:
        errors.append("%s is out of date: run with --write-md" % md_path.name)
    for e in errors:
        print("FAILED:", e)
    print(json.dumps(counts(doc), sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
