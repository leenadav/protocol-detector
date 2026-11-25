"""Build one catalog batch in the pack.json record format from the PRO-259 proposals (PRO-406).

    python3 tools/make_pack_batch.py KIND START COUNT OUT [--checks FILE]

KIND is service or gaming_publisher_domain. Rows come from catalog-proposals (main list and gaming hold;
the name-mismatch hold is never read), sorted by candidate_rank. Rows whose domain does not resolve
(checks file, `unresolved` list of app_ids) are dropped with that reason. Output carries `applications`
and `host_entries` in the shape of go/internal/content/pack.json plus an `evidence` list and `dropped`.
Standard library only; reads data, no network.
"""
import argparse
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent / "catalog-proposals"
NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")
CATEGORY_FIX = {("business-systems", "internet-utility"): ("general-internet", "internet-utility"),
                ("media", "internet-utility"): ("general-internet", "internet-utility"),
                ("media", "general-business"): ("business-systems", "general-business")}


def load(name):
    return json.loads((HERE / name).read_text(encoding="utf-8"))["entries"]


def build(rows):
    apps, hosts, evidence = [], [], []
    for r in rows:
        cat, sub = CATEGORY_FIX.get((r["category"], r["subcategory"]), (r["category"], r["subcategory"]))
        desc = r["name"] if r["entry_kind"] == "service" else r["name"] + " (game publisher site)"
        common = {"category": cat, "characteristics": [], "description": desc, "name": r["app_id"], "risk": 2,
                  "subcategory": sub, "technology": "browser-based"}
        apps.append(dict(common, aliases=[], container=None, depends_on=[], implicitly_uses=["ssl", "web-browsing"],
                         secure_ports=[], standard_ports=[]))
        hosts.append(dict(common, domains=list(r["domains"]), web_fronts=[]))
        evidence.append({"name": r["app_id"], "domains": r["domains"], "source_url": r["source_url"],
                         "source_note": r["source_note"], "wikidata": r["wikidata"],
                         "category_normalized": (r["category"], r["subcategory"]) != (cat, sub)})
    return apps, hosts, evidence


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kind")
    ap.add_argument("start", type=int)
    ap.add_argument("count", type=int)
    ap.add_argument("out")
    ap.add_argument("--checks")
    a = ap.parse_args()
    unresolved = set(json.loads(Path(a.checks).read_text())["unresolved"]) if a.checks else set()
    rows = [r for r in load("wikidata-1-3000.json") + load("wikidata-1-3000-gaming-publishers-hold.json")
            if r["entry_kind"] == a.kind]
    rows.sort(key=lambda r: r["candidate_rank"])
    dropped = {"domain_does_not_resolve": [r["app_id"] for r in rows if r["app_id"] in unresolved],
               "invalid_name": [r["app_id"] for r in rows if not NAME.match(r["app_id"])]}
    skip = {x for v in dropped.values() for x in v}
    keep = [r for r in rows if r["app_id"] not in skip][a.start:a.start + a.count]
    apps, hosts, evidence = build(keep)
    doc = {"kind": a.kind, "start": a.start, "count": len(keep), "dropped": dropped,
           "applications": apps, "host_entries": hosts, "evidence": evidence}
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(doc, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    print(a.out, len(keep), {k: len(v) for k, v in dropped.items()})


if __name__ == "__main__":
    main()
