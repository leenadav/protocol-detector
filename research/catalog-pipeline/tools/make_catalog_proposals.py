#!/usr/bin/env python3
"""PRO-259: Wikidata candidates 1-3000 (top1000 + b2) -> name-based catalog proposals.
Uses the stored passive checks (no new network). Writes research/catalog-proposals/wikidata-1-3000.json + skipped file + stats."""
from collections import Counter
import json, os, re, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wikidata_candidates as W
R = W.OUT; DATE = "2026-11-22"
src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "make_b2.py")).read()
EXTRA = set(re.findall(r'"([^"]+)"', re.search(r"EXTRA_SHARED = \{(.*?)\}", src, re.S).group(1)))
BAD = set(re.findall(r'"([^"]+)"', re.search(r"BAD_CLASSES = \{(.*?)\}", src, re.S).group(1)))
SHARED = W.SHARED_HOSTING | EXTRA
NOT_TRAFFIC = {"file format", "authority file", "brand", "project", "metaverse", "taxonomic database", "medical database"}
INSTIT = re.compile(r"\.(edu|gov|int|mil)$|\.(ac|gov|gc)\.[a-z]{2}$|^canada\.ca$")
def existing():
    repo = "/home/hermes/projects/protocol-detector"
    doms, names = set(open(W.CATALOG).read().split()), set()
    for f in ("protocol_engine/host_apps.py", "protocol_engine/applications.py"):
        try: s = subprocess.check_output(["git", "-C", repo, "show", "origin/claude/app-research:" + f], text=True, stderr=subprocess.DEVNULL)
        except Exception: continue
        doms |= set(re.findall(r'"([a-z0-9-]+(?:\.[a-z0-9-]+)+)"', s)); names |= set(re.findall(r'^\s*\("([a-z0-9-]+)",\s*"', s, re.M))
    try:
        pk = json.loads(subprocess.check_output(["git", "-C", repo, "show", "origin/main:go/internal/content/pack.json"], text=True, stderr=subprocess.DEVNULL))
        names |= {a["name"] for a in pk["applications"]}
        doms |= set(re.findall(r'"([a-z0-9-]+(?:\.[a-z0-9-]+)+)"', json.dumps(pk["host_catalog"])))
    except Exception as e: print("pack.json not read:", e, file=sys.stderr)
    return doms, names
ORG = {"organization", "nonprofit organization", "fact-checking organisation", "public company", "enterprise", "business", "project", "software project", "research project", "brand", "company", "news agency", "pornographic film studio"}
SERVICE = {"website", "online service", "online database", "search engine", "social networking service", "web browser", "mobile app", "video streaming service", "online community", "instant messaging client", "web application", "online newspaper", "news website", "daily newspaper", "newspaper", "magazine", "web series", "webcomic"}
SOFT = {"free software", "software", "open-source software", "free and open-source software", "application software", "Linux distribution", "operating system", "software library", "programming language", "web framework", "software framework", "JavaScript library", "integrated development environment", "compiler", "text editor", "GNU package", "Python package", "computer program", "proprietary software", "free operating system", "lightweight Linux distribution", "media player software", "BitTorrent client", "mobile operating system", "video editing software", "database management system", "application programming interface", "content management system"}
MANUAL_SKIP = {"sr.ht": "shared_hosting_forge_tenant_domain", "kadokawa.co.jp": "publisher_site_linked_item_is_a_work_title", "tolweb.org": "information_project_not_a_service"}  # from the PRO-259 review sample
OVERRIDES = {  # PRO-259 review fixes: domain -> field changes
    "renoise.com": {"subcategory": "general-business"}, "musepack.net": {"subcategory": "general-business"},
    "zonealarm.com": {"subcategory": "general-business"}, "labcenter.com": {"name": "Labcenter Electronics"}}
def is_shared(d): return d in SHARED or d.endswith(tuple("." + s for s in SHARED))
cand = []
for fn in ("top1000-%s.jsonl" % DATE, "wikidata-%s-b2.jsonl" % DATE):
    cand += [json.loads(l) for l in open(os.path.join(R, fn))]
cdoms, cnames = existing()
out, skip, ids, usedd = [], [], set(), set()
def sk(c, why): skip.append({"wikidata": c["wikidata"], "name": c["name"], "domain": (c["domains"] or [None])[0], "reason": why})
for i, c in enumerate(cand, 1):
    ds = c.get("domains") or []; ck = c.get("checks", {}); wc = set(c.get("wd_classes", []))
    if not ds: sk(c, "no_domain"); continue
    d = ds[0]
    if any(is_shared(x) for x in ds): sk(c, "shared_or_tenant_domain"); continue
    if BAD & wc: sk(c, "hosting_isp_or_site_builder_class"); continue
    if INSTIT.search(d): sk(c, "institutional_domain_not_an_app"); continue
    if wc and wc <= NOT_TRAFFIC: sk(c, "not_a_traffic_bearing_app"); continue
    if not c.get("websites") or d not in c["websites"]: sk(c, "no_source_stating_domain"); continue
    if any(x in cdoms for x in ds): sk(c, "already_in_catalog"); continue
    if not c.get("high_confidence") or ck.get("redirect_offsite") or ck.get("parked") or not ck.get("tls_name_ok"): sk(c, "failed_passive_checks"); continue
    if re.fullmatch(r"Q\d+", c["name"]): sk(c, "label_is_qid"); continue
    if d in usedd: sk(c, "duplicate_domain"); continue
    if wc & ORG and not (wc & (SERVICE | SOFT)): sk(c, "organization_or_project_not_a_service"); continue
    if d in MANUAL_SKIP: sk(c, MANUAL_SKIP[d]); continue
    base = re.sub(r"[^a-z0-9-]", "", d.split(".")[0].lower())
    if not base: sk(c, "empty_id"); continue
    aid = base
    if aid in cnames or aid in ids:
        aid = re.sub(r"[^a-z0-9-]", "", d.lower().replace(".", "-"))
    if aid in cnames or aid in ids: sk(c, "duplicate_app_id"); continue
    ids.add(aid); usedd.add(d)
    gaming = c["subcategory"] == "gaming"
    kind = "gaming_publisher_domain" if gaming else ("software_project" if wc & SOFT else "service")
    sub = c["subcategory"]
    if kind == "software_project" and sub == "general-business": sub = "software-development"
    nm = c["name"]; name_note = None
    if gaming:  # linked Wikidata item is a game title; use the domain label as the publisher-name placeholder
        name_note = "linked_item_name=%r (a game/work title, not the publisher); name is a domain-label placeholder" % c["name"]
        nm = d.split(".")[0].replace("-", " ").title()
    if sub in ("auth-service", "generative-ai", "audio-streaming", "photo-video") and not (wc & {"video streaming service", "online service", "web application", "social networking service"}):
        sub = "software-development" if wc & SOFT else "internet-utility"   # these subcategories were unreliable in the review sample
    ov = OVERRIDES.get(d, {}); nm = ov.get("name", nm); sub = ov.get("subcategory", sub)
    out.append({"app_id": aid, "name": nm, "category": c["category"], "subcategory": sub, "entry_kind": kind, "name_review": name_note,
        "domains": [d], "source_url": "https://www.wikidata.org/wiki/%s" % c["wikidata"],
        "source_note": "Wikidata CC0 P856 official website: %s" % c["websites"][d], "wikidata": c["wikidata"],
        "candidate_rank": i, "sitelinks": c["sitelinks"], "gaming_publisher_domain": gaming})
od = os.path.join(W.ROOT, "research", "catalog-proposals"); os.makedirs(od, exist_ok=True)
def name_ok(e):
    n = re.sub(r"[^a-z0-9]", "", e["name"].lower()); l = re.sub(r"[^a-z0-9]", "", e["domains"][0].split(".")[0].lower())
    toks = [re.sub(r"[^a-z0-9]", "", t.lower()) for t in e["name"].split()]
    return bool(l) and (l in n or n in l or any(len(t) >= 3 and (t in l or l in t) for t in toks))
mism = [e for e in out if not e["gaming_publisher_domain"] and not name_ok(e)]
mid = {id(e) for e in mism}
json.dump({"version": 1, "generated": DATE, "note": "HOLD: name does not match the domain (product/org name on a vendor or parent domain); needs a service/publisher name before use", "entries": mism}, open(os.path.join(od, "wikidata-1-3000-name-mismatch-hold.json"), "w"), ensure_ascii=False, indent=1)
main = [e for e in out if not e["gaming_publisher_domain"] and id(e) not in mid]; gam = [e for e in out if e["gaming_publisher_domain"]]
json.dump({"version": 1, "generated": DATE, "source": "Wikidata CC0 candidates ranks 1-3000", "entries": main}, open(os.path.join(od, "wikidata-1-3000.json"), "w"), ensure_ascii=False, indent=1)
json.dump({"version": 1, "generated": DATE, "note": "HOLD: gaming-publisher domains pending App Research triage; names are placeholders", "entries": gam}, open(os.path.join(od, "wikidata-1-3000-gaming-publishers-hold.json"), "w"), ensure_ascii=False, indent=1)
with open(os.path.join(od, "wikidata-1-3000-skipped.jsonl"), "w") as f:
    for s in skip: f.write(json.dumps(s, ensure_ascii=False) + "\n")
rc = {}
for s in skip: rc[s["reason"]] = rc.get(s["reason"], 0) + 1
st = {"candidates": len(cand), "entries": len(out), "main_entries": len(main), "gaming_hold": len(gam), "name_mismatch_hold": len(mism), "entries_by_kind": dict(Counter(e["entry_kind"] for e in out)), "skipped": len(skip), "skipped_by_reason": rc, "entries_by_category": dict(Counter(e["category"] for e in out)), "gaming_publisher_domain": len(gam)}
json.dump(st, open(os.path.join(od, "wikidata-1-3000-stats.json"), "w"), indent=1)
print(json.dumps(st, indent=1))
