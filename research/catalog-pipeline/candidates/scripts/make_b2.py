#!/usr/bin/env python3
"""Slice ranks 1001-3000 of the PRO-197 pipeline output (same ordering as top1000) into *-b2.jsonl.
Usage: python3 tools/make_b2.py --date 2026-11-22 [--lo 1001 --hi 3000]"""
import argparse, json, os
R = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), "research", "candidates")
ap = argparse.ArgumentParser(); ap.add_argument("--date", required=True)
ap.add_argument("--lo", type=int, default=1001); ap.add_argument("--hi", type=int, default=3000)
a = ap.parse_args()
rows = [json.loads(l) for l in open(f"{R}/wikidata-{a.date}.jsonl")]
hi = [r for r in rows if r["high_confidence"]]
hi.sort(key=lambda r: (-r["sitelinks"], -r["confidence"]))
top = [json.loads(l) for l in open(f"{R}/top1000-{a.date}.jsonl")]
seen = {d for r in top for d in r["domains"]}
topq = {r["wikidata"] for r in top}
EXTRA_SHARED = {"free.fr","neocities.org","000webhostapp.com","weebly.com","wix.com","webs.com","tripod.com","angelfire.com","geocities.com","orange.fr","wanadoo.fr","sfr.fr","laposte.net","bluehost.com","godaddy.com","hostinger.com","one.com","ovh.com","ovh.net","infomaniak.com","netlify.app","vercel.app","herokuapp.com","pages.dev","web.app","firebaseapp.com","azurewebsites.net","fly.dev","glitch.me","repl.co","itch.io","tumblr.com","substack.com","medium.com","livejournal.com","fc2.com","hatenablog.com","jimdofree.com","jimdo.com","strikingly.com","carrd.co","notion.site","webflow.io","square.site","myshopify.com"}
BAD_CLASSES = {"web hosting service","internet service provider","free web hosting service","web hosting","blog hosting service","website builder","telecommunications company"}
def shared2(r):
    return any(d in EXTRA_SHARED or d.endswith(tuple("." + e for e in EXTRA_SHARED)) for d in r["domains"]) or bool(BAD_CLASSES & set(r.get("wd_classes", [])))
shared_removed = [r for r in hi if r["wikidata"] not in topq and shared2(r)]
rest = [r for r in hi if r["wikidata"] not in topq and not shared2(r)]
dd, removed_top, removed_dup = [], 0, 0
for r in rest:
    if any(d in seen for d in r["domains"]):
        removed_top += any(d in {x for t in top for x in t["domains"]} for d in r["domains"]); removed_dup += 1; continue
    seen.update(r["domains"]); dd.append(r)
n_slice = a.hi - a.lo + 1
sl = dd[:n_slice]
with open(f"{R}/wikidata-{a.date}-b2.jsonl", "w") as f:
    for n, r in enumerate(sl, a.lo): f.write(json.dumps(dict(r, rank=n), ensure_ascii=False, sort_keys=True) + "\n")
st = json.load(open(f"{R}/stats-{a.date}.json"))
st["b2"] = {"range": [a.lo, a.hi], "written": len(sl), "high_confidence_total": len(hi), "deduped_pool": len(dd), "removed_extra_shared_hosting_isp": len(shared_removed), "removed_overlap_or_duplicate_domain": removed_dup,
            "min_sitelinks_in_b2": min((r["sitelinks"] for r in sl), default=None)}
json.dump(st, open(f"{R}/stats-{a.date}-b2.json", "w"), indent=1)
print(json.dumps(st, indent=1))
