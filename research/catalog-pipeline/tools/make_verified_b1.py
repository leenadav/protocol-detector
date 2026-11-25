#!/usr/bin/env python3
"""PRO-253: top-N Wikidata candidates -> verified catalog entries (batch 1).
Usage: python3 tools/make_verified_b1.py [--n 200] [--date 2026-11-22]
Reads research/candidates/top1000-<date>.jsonl (Wikidata CC0). Re-verifies with cheap passive checks:
DNS, one verified TLS handshake (cert must cover the domain), one HTTPS GET (<=4 redirects, final host).
Writes research/catalog-batches/verified-b1-<date>.jsonl, rejected-b1-<date>.jsonl, stats-b1-<date>.json, sample20-b1-<date>.md"""
import argparse, json, os, re, socket, ssl, subprocess, sys, concurrent.futures as cf
import http.client, urllib.parse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wikidata_candidates as W
ROOT = W.ROOT; UA = W.UA
CTX = ssl.create_default_context()
PSL = W.load_psl()

def existing_catalog():
    """Domains + names of the current content (origin/claude/app-research host_apps.py + applications.py), via git show."""
    repo = "/home/hermes/projects/protocol-detector"
    doms, names = set(open(W.CATALOG).read().split()), set()
    for f in ("protocol_engine/host_apps.py", "protocol_engine/applications.py"):
        try: src = subprocess.check_output(["git", "-C", repo, "show", "origin/claude/app-research:" + f], text=True)
        except Exception: continue
        doms |= set(re.findall(r'"([a-z0-9-]+(?:\.[a-z0-9-]+)+)"', src))
        names |= set(re.findall(r'^\s*\("([a-z0-9-]+)",\s*"', src, re.M))
    return doms, names

def covers(cert, host):
    for t, v in cert.get("subjectAltName", ()):
        if t == "DNS":
            v = v.lower()
            if v == host or (v.startswith("*.") and host.split(".", 1)[-1] == v[2:] and "." in host): return True
    return False

def check(dom):
    r = {"dns": False, "tls_covers": False, "tls_host": None, "http_status": None, "final_host": None, "final_same_org": False, "error": None}
    try: socket.getaddrinfo(dom, 443); r["dns"] = True
    except Exception as e: r["error"] = "dns:" + type(e).__name__; return r
    for h in (dom, "www." + dom):
        try:
            with socket.create_connection((h, 443), timeout=8) as s, CTX.wrap_socket(s, server_hostname=h) as t:
                if covers(t.getpeercert(), h) or covers(t.getpeercert(), dom): r["tls_covers"] = True; r["tls_host"] = h; break
        except Exception as e: r["error"] = "tls:" + type(e).__name__
    if not r["tls_covers"]: return r
    host, path = r["tls_host"], "/"
    try:
        for _ in range(5):
            c = http.client.HTTPSConnection(host, timeout=8, context=CTX)
            c.request("GET", path, headers={"User-Agent": UA, "Range": "bytes=0-2047"}); resp = c.getresponse()
            r["http_status"] = resp.status; r["final_host"] = host
            loc = resp.getheader("Location"); resp.read(2048); c.close()
            if resp.status in (301, 302, 303, 307, 308) and loc:
                u = urllib.parse.urlparse(urllib.parse.urljoin("https://%s%s" % (host, path), loc))
                if u.scheme != "https" or not u.hostname: break
                host, path = u.hostname, (u.path or "/") + ("?" + u.query if u.query else "")
                continue
            break
    except Exception as e: r["error"] = "http:" + type(e).__name__
    if r["final_host"]:
        icann, private = PSL
        r["final_same_org"] = (W.registrable(r["final_host"], icann, private)[0] == dom)
    return r

STRICT_BAD = re.compile(r"institution|university|government|organi[sz]ation|database|authority file|encyclop|dictionary|news|magazine|museum|library|"
    r"foundation|company|publisher|studio|franchise|media franchise|sports|film|television|album|band|musical", re.I)
def norm(t): return re.sub(r"[^a-z0-9]", "", t.lower())
def identity(c, host):
    """strict: the product's own homepage must name it (title / og:site_name contains the label or the domain stem)."""
    try:
        cn = http.client.HTTPSConnection(host, timeout=8, context=CTX)
        cn.request("GET", "/", headers={"User-Agent": UA, "Range": "bytes=0-32767"}); rp = cn.getresponse()
        html = rp.read(32768).decode("utf-8", "ignore"); cn.close()
    except Exception as e: return "identity_probe_failed:" + type(e).__name__
    t = " ".join(re.findall(r"<title[^>]*>(.*?)</title>", html, re.S | re.I) + re.findall(r'og:site_name"[^>]*content="([^"]+)', html, re.I) + re.findall(r'content="([^"]+)"[^>]*og:site_name', html, re.I))
    t = norm(t); stem = norm(c["domains"][0].split(".")[0]); lab = norm(re.split(r"[:(\-]", c["name"])[0])
    if not t: return "no_title_identity_unconfirmed"
    if lab and lab in t: return None
    if stem and stem in t and (stem in norm(c["name"]) or lab in stem or stem in lab): return None
    return "homepage_does_not_name_item"
NOT_TRAFFIC = {"file format", "authority file", "brand", "project", "metaverse", "taxonomic database", "medical database"}
def slug(dom):
    s = dom.split(".")[0]; return re.sub(r"[^a-z0-9-]", "", s.lower())

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--n", type=int, default=200); ap.add_argument("--date", default="2026-11-22"); ap.add_argument("--src", default="top1000-{date}.jsonl"); ap.add_argument("--tag", default="b1"); ap.add_argument("--strict", action="store_true", help="identity + publisher/institution filters (batch 2+)"); ap.add_argument("--exclude", nargs="*", default=[])
    a = ap.parse_args()
    cand = [json.loads(l) for l in open(os.path.join(W.OUT, a.src.format(date=a.date)))]
    cdoms, cnames = existing_catalog()
    for ex in a.exclude:
        for l in open(ex):
            o = json.loads(l); cdoms.update(o.get("domains") or [o.get("domain")]); cnames.add(o.get("name"))
    stage = {"candidates": len(cand)}; rej = []; pool = []
    for c in cand:
        d = c["domains"][0]
        if any(x in cdoms for x in c["domains"]) or slug(d) in cnames: rej.append((c, "already_in_catalog")); continue
        if set(c["wd_classes"]) <= NOT_TRAFFIC: rej.append((c, "not_a_traffic_bearing_app:" + ",".join(c["wd_classes"]))); continue
        if re.search(r"\.(edu|gov|int|mil)$|\.(ac|gov|gc)\.[a-z]{2}$|^canada\.ca$", d): rej.append((c, "institutional_domain_not_an_app")); continue
        if a.strict and (STRICT_BAD.search(" ".join(c["wd_classes"])) and not re.search("software|app|service|browser|platform", " ".join(c["wd_classes"]), re.I)): rej.append((c, "reference_institution_or_content_site")); continue
        if a.strict and c["subcategory"] == "gaming" and norm(d.split(".")[0]) not in norm(c["name"]): rej.append((c, "publisher_domain_multi_title")); continue
        if not c.get("high_confidence"): rej.append((c, "not_high_confidence")); continue
        pool.append(c)
    stage["after_catalog_and_class_filter"] = len(pool)
    pool = pool[: int(a.n * (4 if a.strict else 1.6))]
    with cf.ThreadPoolExecutor(32) as ex: chk = list(ex.map(lambda c: check(c["domains"][0]), pool))
    if a.strict:
        with cf.ThreadPoolExecutor(32) as ex:
            ids = list(ex.map(lambda ck: identity(ck[0], ck[1]["final_host"]) if ck[1]["final_same_org"] and ck[1]["tls_covers"] and (ck[1]["http_status"] or 999) < 400 else None, zip(pool, chk)))
    else: ids = [None] * len(pool)
    ver, seen = [], set(); stage["rechecked"] = len(pool)
    for (c, k), idr in zip(zip(pool, chk), ids):
        d = c["domains"][0]; why = None
        if not k["dns"]: why = "dns_fail"
        elif not k["tls_covers"]: why = "tls_cert_does_not_cover_name:" + str(k["error"])
        elif k["http_status"] is None or k["http_status"] >= 400: why = "http_status:%s" % k["http_status"]
        elif not k["final_same_org"]: why = "final_host_offsite:" + str(k["final_host"])
        elif idr: why = idr
        elif slug(d) in seen: why = "duplicate_slug"
        if why: rej.append((c, why)); continue
        if len(ver) >= a.n: stage["rechecked_not_needed"] = stage.get("rechecked_not_needed", 0) + 1; continue
        seen.add(slug(d)); ver.append((c, k))
    od = os.path.join(ROOT, "research", "catalog-batches"); os.makedirs(od, exist_ok=True)
    with open(os.path.join(od, "verified-%s-%s.jsonl" % (a.tag, a.date)), "w") as f:
        for c, k in ver:
            gaming = c["subcategory"] == "gaming"
            f.write(json.dumps({
                "name": slug(c["domains"][0]), "category": c["category"], "subcategory": c["subcategory"],
                "technology": "browser-based", "risk": 2,
                "description": "%s (%s)" % (c["name"], c["domains"][0]), "characteristics": [],
                "domains": [c["domains"][0]], "web_fronts": [],
                "match": {"type": "tls-sni/http-host", "suffix": c["domains"][0]},
                "source": "Wikidata CC0 %s" % c["wikidata"], "wikidata": c["wikidata"], "wikidata_label": c["name"], "sitelinks": c["sitelinks"],
                "evidence": {"dns": True, "tls_cert_covers": k["tls_host"], "http_status": k["http_status"], "final_host": k["final_host"], "checked": a.date},
                "note": "one entry per registrable domain; label is the most-linked Wikidata item on that domain" + ("; publisher domain may serve several titles" if gaming else "")},
                ensure_ascii=False, sort_keys=True) + "\n")
    with open(os.path.join(od, "rejected-%s-%s.jsonl" % (a.tag, a.date)), "w") as f:
        for c, why in rej: f.write(json.dumps({"name": c["name"], "wikidata": c["wikidata"], "domain": c["domains"][0], "rank": c["rank"], "reason": why}, ensure_ascii=False) + "\n")
    rc = {}
    for c, why in rej: rc[why.split(":")[0]] = rc.get(why.split(":")[0], 0) + 1
    stage.update(verified=len(ver), rejected=len(rej), rejected_by_reason=rc)
    json.dump(stage, open(os.path.join(od, "stats-%s-%s.json" % (a.tag, a.date)), "w"), indent=1)
    with open(os.path.join(od, "sample20-%s-%s.md" % (a.tag, a.date)), "w") as f:
        f.write("| # | entry | wikidata | domain | category | tls cert | final host |\n|---|---|---|---|---|---|---|\n")
        for i, (c, k) in enumerate(ver[:20], 1):
            f.write("| %d | %s | %s | %s | %s/%s | %s | %s |\n" % (i, c["name"], c["wikidata"], c["domains"][0], c["category"], c["subcategory"], k["tls_host"], k["final_host"]))
    print(json.dumps(stage, indent=1))
main()
