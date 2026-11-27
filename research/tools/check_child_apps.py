#!/usr/bin/env python3
"""Check a child-apps research file (research/child-apps/wave-*.json, schema child-apps/v1).

Usage:
  python3 -B research/tools/check_child_apps.py research/child-apps/wave-0.json
  python3 -B research/tools/check_child_apps.py --self-test

Rules checked (PRO-495):
- every parent_app_id exists in the content pack (go/internal/content/pack.json);
- child ids are unique across the file;
- verified=false: every signals field and citation_url is null (a proposal, never a rule);
- verified=true: an http(s) citation_url and at least one non-null signal;
- direction and separability take known values; signals carry exactly the schema's fields;
- the "Result" line of the sibling .md states the same counts as the JSON.
Python 3.9, standard library only.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACK = ROOT / "go" / "internal" / "content" / "pack.json"
SIGNAL_FIELDS = {"host_sni", "http_method", "path_pattern", "content_type", "direction", "websocket", "transport"}
DIRECTIONS = {None, "upload", "download", "both"}
SEPARABILITY = {"partial", "host-only", "not-separable", "blocked"}
PLACEHOLDERS = ("TODO", "TBD", "FIXME")


def pack_ids(pack_path=PACK):
    with open(pack_path, encoding="utf-8") as f:
        return {a["name"] for a in json.load(f)["applications"]}


def counts(doc):
    kids = [c for s in doc["services"] for c in s["children"]]
    verified = [c for c in kids if c["verified"]]
    pages = {u for c in verified for u in [c["citation_url"]] + c.get("citation_also", [])}
    return {"services": len(doc["services"]), "children": len(kids), "verified": len(verified),
            "pages": len(pages), "unverified": len(kids) - len(verified)}


def check(doc, known_ids, md_text=None):
    errors = []
    if doc.get("schema") != "child-apps/v1":
        errors.append("schema is not child-apps/v1")
    text = json.dumps(doc)
    for word in PLACEHOLDERS:
        if word in text:
            errors.append("placeholder text %r present" % word)
    seen = set()
    for svc in doc.get("services", []):
        name = svc.get("service", "?")
        if svc.get("parent_app_id") not in known_ids:
            errors.append("%s: parent_app_id %r not in the pack" % (name, svc.get("parent_app_id")))
        if svc.get("separability") not in SEPARABILITY:
            errors.append("%s: unknown separability %r" % (name, svc.get("separability")))
        if not svc.get("children"):
            errors.append("%s: no children" % name)
        for c in svc.get("children", []):
            cid = c.get("child_id")
            where = "%s/%s" % (name, cid)
            if not cid or cid in seen:
                errors.append("%s: missing or duplicate child_id" % where)
            seen.add(cid)
            sig = c.get("signals") or {}
            if set(sig) != SIGNAL_FIELDS:
                errors.append("%s: signals fields differ from the schema" % where)
            if sig.get("direction") not in DIRECTIONS:
                errors.append("%s: bad direction %r" % (where, sig.get("direction")))
            if c.get("verified") is True:
                urls = [c.get("citation_url")] + list(c.get("citation_also", []))
                if not all(isinstance(u, str) and u.startswith(("https://", "http://")) for u in urls):
                    errors.append("%s: verified child without an http(s) citation" % where)
                if all(v is None for v in sig.values()):
                    errors.append("%s: verified child without any signal" % where)
            elif c.get("verified") is False:
                if any(v is not None for v in sig.values()) or c.get("citation_url") is not None:
                    errors.append("%s: unverified child carries signals or a citation" % where)
            else:
                errors.append("%s: verified must be true or false" % where)
    if md_text is not None and doc.get("services"):
        n = counts(doc)
        want = ("%(services)d services, %(children)d proposed children, **%(verified)d verified with an official "
                "citation** (%(pages)d distinct pages); %(unverified)d unverified" % n)
        if want not in md_text:
            found = re.search(r"\d+ services, \d+ proposed children[^\n]*", md_text)
            errors.append("md Result line out of date: want %r, found %r" % (want, found.group(0) if found else None))
    return errors


def _self_test():
    ids = {"p"}
    nul = {k: None for k in SIGNAL_FIELDS}
    good = {"schema": "child-apps/v1", "services": [{"service": "S", "parent_app_id": "p", "separability": "partial",
            "children": [
                {"child_id": "p-up", "verified": True, "citation_url": "https://x",
                 "signals": dict(nul, host_sni=["h"], http_method="POST", direction="upload")},
                {"child_id": "p-dl", "verified": False, "citation_url": None, "signals": dict(nul)}]}]}
    md = "1 services, 2 proposed children, **1 verified with an official citation** (1 distinct pages); 1 unverified"
    assert check(good, ids, md) == [], check(good, ids, md)
    cases = [
        (lambda d: d["services"][0].update(parent_app_id="nope"), "not in the pack"),
        (lambda d: d["services"][0]["children"][0].update(citation_url=None), "without an http(s) citation"),
        (lambda d: d["services"][0]["children"][1]["signals"].update(host_sni=["h"]), "carries signals"),
        (lambda d: d["services"][0]["children"][0]["signals"].update(direction="sideways"), "bad direction"),
        (lambda d: d["services"][0]["children"][1].update(child_id="p-up"), "duplicate"),
        (lambda d: d["services"][0]["children"][0]["signals"].update(host_sni=None, http_method=None,
                                                                      direction=None), "without any signal"),
        (lambda d: d["services"][0]["children"][0]["signals"].pop("websocket"), "signals fields"),
        (lambda d: d["services"][0].update(separability="maybe"), "separability"),
        (lambda d: d["services"][0].update(note="TODO"), "placeholder"),
    ]
    for mutate, expect in cases:
        bad = json.loads(json.dumps(good))
        mutate(bad)
        errs = check(bad, ids, md)
        assert any(expect in e for e in errs), (expect, errs)
    assert any("Result line" in e for e in check(good, ids, "0 services"))
    print("check_child_apps self-test: ok (%d tamper cases)" % (len(cases) + 1))
    return 0


def main(argv):
    if argv[1:] == ["--self-test"]:
        return _self_test()
    if len(argv) != 2:
        print(__doc__)
        return 2
    path = Path(argv[1])
    doc = json.loads(path.read_text(encoding="utf-8"))
    md_path = path.with_suffix(".md")
    errors = check(doc, pack_ids(), md_path.read_text(encoding="utf-8") if md_path.exists() else "")
    for e in errors:
        print("FAILED:", e)
    print(json.dumps(counts(doc), sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
