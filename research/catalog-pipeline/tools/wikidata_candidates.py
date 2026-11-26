#!/usr/bin/env python3
"""Wikidata (CC0) candidate pipeline for the app catalog.
Stages: fetch -> normalise -> check -> rank.  Usage:
  python3 tools/wikidata_candidates.py all --date 2026-11-22 [--min-sitelinks 3]
Cache dir: .cache/ (SPARQL JSON, PSL).  Output: research/candidates/wikidata-<date>.jsonl,
research/candidates/top1000-<date>.jsonl, research/candidates/stats-<date>.json
"""
import argparse, json, os, re, socket, ssl, sys, time, concurrent.futures as cf
import http.client, urllib.parse, urllib.request


def _rd(path, **kw):
    with open(path, **kw) as fh:
        return fh.read()


def _wj(obj, path, **kw):
    with open(path, "w") as fh:
        json.dump(obj, fh, **kw)


def _wb(path, data):
    with open(path, "wb") as fh:
        fh.write(data)

UA = "ProtocolDetectorResearch/0.1 (research-lab; passive catalog candidate pipeline; CC0 data only)"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(ROOT, ".cache")
OUT = os.path.join(ROOT, "research", "candidates")
CATALOG = os.path.join(OUT, "catalog-domains-2026.11.9.txt")

# root class -> (label, catalog category hint, subcategory hint)
ROOTS = {
    "Q7397": ("software", "business-systems", "general-business"),
    "Q620615": ("mobile app", "business-systems", "general-business"),
    "Q7889": ("video game", "media", "gaming"),
    "Q35127": ("website", "general-internet", "internet-utility"),
    "Q193424": ("web service", "business-systems", "general-business"),
    "Q1668024": ("service on Internet", "general-internet", "internet-utility"),
    "Q202833": ("social media", "collaboration", "social-networking"),
}
# Endpoint: QLever mirror (no throttling, one query per class). Set WIKIDATA_SPARQL to
# https://query.wikidata.org/sparql to use WDQS (then also set WIKIDATA_BANDS=1 and expect 429s).
ENDPOINT = os.environ.get("WIKIDATA_SPARQL", "https://qlever.dev/api/wikidata")
if not ENDPOINT.startswith("https://"):
    raise SystemExit("WIKIDATA_SPARQL must be an https:// URL")
MIN_SL = int(os.environ.get("WIKIDATA_MIN_SITELINKS", "3"))
BANDS = ([(100, None), (50, 100), (30, 50), (20, 30), (12, 20), (8, 12), (5, 8), (3, 5)]
         if os.environ.get("WIKIDATA_BANDS") else [(MIN_SL, None)])
SLEEP = float(os.environ.get("WIKIDATA_SLEEP", "1"))
PREFIXES = """PREFIX wd: <http://www.wikidata.org/entity/>
PREFIX wdt: <http://www.wikidata.org/prop/direct/>
PREFIX wikibase: <http://wikiba.se/ontology#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
"""
KEYWORDS = [  # label keywords in class labels -> (category, subcategory)
    (r"messag|chat|instant", ("collaboration", "instant-messaging")),
    (r"social", ("collaboration", "social-networking")),
    (r"video conf|voip|telephony", ("collaboration", "voip-video")),
    (r"e-?mail", ("collaboration", "email")),
    (r"stream|video sharing|music|podcast|audio", ("media", "audio-streaming")),
    (r"video game|game", ("media", "gaming")),
    (r"photo|image|video", ("media", "photo-video")),
    (r"artificial intelligence|chatbot|language model|generative", ("business-systems", "generative-ai")),
    (r"password|authenticat|identity|security|antivirus|firewall|vpn", ("business-systems", "auth-service")),
    (r"database|dbms", ("business-systems", "database")),
    (r"version control|compiler|ide|integrated development|developer|programming|software develop|framework|library", ("business-systems", "software-development")),
    (r"cloud storage|backup|file hosting|file sharing|storage", ("business-systems", "storage-backup")),
    (r"office|word processor|spreadsheet|presentation|productivity|note", ("business-systems", "office-programs")),
    (r"remote desktop|remote access", ("networking", "remote-access")),
    (r"proxy", ("networking", "proxy")),
    (r"bank|payment|financ|crypto|wallet|exchange", ("business-systems", "general-business")),
    (r"browser|search engine|web service|website", ("general-internet", "internet-utility")),
]
SHARED_HOSTING = set("""github.io githubusercontent.com gitlab.io blogspot.com blogspot.co.uk wordpress.com wixsite.com
weebly.com tumblr.com medium.com substack.com cloudfront.net azurewebsites.net azureedge.net herokuapp.com netlify.app
vercel.app pages.dev workers.dev appspot.com web.app firebaseapp.com s3.amazonaws.com amazonaws.com sourceforge.net
sourceforge.io googlecode.com fandom.com wikia.com itch.io carrd.co notion.site webflow.io myshopify.com
facebook.com twitter.com x.com instagram.com youtube.com linkedin.com play.google.com apps.apple.com wikipedia.org
wikimedia.org archive.org web.archive.org steampowered.com store.steampowered.com t.me reddit.com""".split())
PARKED_HINTS = ("sedoparking", "parkingcrew", "bodis.com", "above.com", "hugedomains", "dan.com", "afternic",
                "godaddy.com/forsale", "domainmarket", "sedo.com", "namecheap.com/domains", "parked")

def log(*a): print(*a, file=sys.stderr, flush=True)

# ---------------- fetch ----------------
def sparql(q, tries=5):
    url = ENDPOINT + "?" + urllib.parse.urlencode({"query": PREFIXES + q, "format": "json"})
    delay = 10
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/sparql-results+json"})  # noqa: S310 -- ENDPOINT checked https:// at import
            with urllib.request.urlopen(req, timeout=600) as r:  # noqa: S310 -- ENDPOINT checked https:// at import
                return json.load(r)
        except urllib.error.HTTPError as e:
            ra = e.headers.get("Retry-After")
            wait = int(ra) if ra and ra.isdigit() else delay
            log(f"  SPARQL HTTP {e.code}; back-off {wait}s"); time.sleep(wait); delay *= 2
        except Exception as e:
            log(f"  SPARQL error {e!r}; back-off {delay}s"); time.sleep(delay); delay *= 2
    raise RuntimeError("SPARQL failed")

def fetch(refresh=False):
    os.makedirs(CACHE, exist_ok=True)
    rows = []
    for root, (rl, _, _) in ROOTS.items():
        for lo, hi in BANDS:
            f = os.path.join(CACHE, f"sparql-{root}-{lo}-{hi}.json")
            if os.path.exists(f) and not refresh:
                data = json.loads(_rd(f))
            else:
                flt = f"?sl>={lo}" + (f" && ?sl<{hi}" if hi else "")
                q = f"""SELECT ?i ?l ?w ?sl ?cl ?dl WHERE {{
  ?i wdt:P31/wdt:P279* wd:{root} ; wdt:P856 ?w ; wikibase:sitelinks ?sl . FILTER({flt})
  ?i rdfs:label ?l FILTER(lang(?l)="en")
  OPTIONAL {{ ?i wdt:P31 ?c . ?c rdfs:label ?cl FILTER(lang(?cl)="en") }}
  OPTIONAL {{ ?i wdt:P178|wdt:P123|wdt:P127 ?d . ?d rdfs:label ?dl FILTER(lang(?dl)="en") }}
}}"""
                log(f"fetch {rl} sitelinks[{lo},{hi})")
                try: data = sparql(q)
                except Exception as e: log("  skipped:", e); continue
                _wj(data, f); time.sleep(SLEEP)
            for b in data["results"]["bindings"]:
                rows.append((root, b))
            log(f"  {rl} [{lo},{hi}) rows so far {len(rows)}")
    return rows

# ---------------- PSL / normalise ----------------
def load_psl():
    f = os.path.join(CACHE, "psl.dat")
    if not os.path.exists(f):
        os.makedirs(CACHE, exist_ok=True)
        req = urllib.request.Request("https://publicsuffix.org/list/public_suffix_list.dat", headers={"User-Agent": UA})
        _wb(f, urllib.request.urlopen(req, timeout=30).read())  # noqa: S310 -- fixed https:// URL
    icann, private, section = set(), set(), None
    for line in _rd(f, encoding="utf-8").splitlines():
        line = line.strip()
        if "BEGIN ICANN" in line: section = icann
        elif "BEGIN PRIVATE" in line: section = private
        if not line or line.startswith("//"): continue
        section.add(line)
    return icann, private

def suffix_of(host, rules):
    labels = host.split(".")
    for i in range(len(labels)):
        cand = ".".join(labels[i:])
        if cand in rules or ("*." + ".".join(labels[i+1:])) in rules:
            return cand
    return None

def registrable(host, icann, private):
    """returns (registrable, status) status: ok | shared (private suffix) | invalid"""
    host = host.lower().strip(".")
    if re.fullmatch(r"[\d.]+", host) or ":" in host or "." not in host: return None, "invalid"
    labels = host.split(".")
    sp = suffix_of(host, private)
    if sp and sp != host:
        return host, "shared"            # tenant under a private suffix (github.io ...)
    se = suffix_of(host, icann) or labels[-1]
    n = len(se.split("."))
    if len(labels) <= n: return None, "invalid"
    return ".".join(labels[-(n+1):]), "ok"

def category_for(rootq, classes):
    text = " ".join(classes).lower()
    for pat, cs in KEYWORDS:
        if re.search(pat, text): return cs
    _, c, s = ROOTS[rootq]; return (c, s)

def normalise(rows):
    icann, private = load_psl()
    catalog = set(_rd(CATALOG).split())
    stats = {"wikidata_rows": len(rows)}
    items = {}
    for root, b in rows:
        qid = b["i"]["value"].rsplit("/", 1)[-1]
        it = items.setdefault(qid, {"qid": qid, "name": b["l"]["value"], "sitelinks": int(b["sl"]["value"]),
                                    "urls": set(), "classes": set(), "developers": set(), "roots": set()})
        it["urls"].add(b["w"]["value"]); it["roots"].add(root)
        if "cl" in b: it["classes"].add(b["cl"]["value"])
        if "dl" in b: it["developers"].add(b["dl"]["value"])
    stats["unique_items"] = len(items)
    out, drop = [], {"no_valid_domain": 0, "shared_hosting": 0, "already_in_catalog": 0, "label_is_qid": 0}
    seen = {}
    for it in items.values():
        if re.fullmatch(r"Q\d+", it["name"]): drop["label_is_qid"] += 1; continue
        doms, shared = {}, False
        for u in it["urls"]:
            try: host = urllib.parse.urlsplit(u if "//" in u else "http://" + u).hostname
            except ValueError: host = None
            if not host: continue
            reg, st = registrable(host, icann, private)
            if st == "invalid": continue
            if st == "shared" or reg in SHARED_HOSTING or host.lower().endswith(tuple("." + s for s in SHARED_HOSTING)):
                shared = True; continue
            doms.setdefault(reg, host.lower())
        if not doms:
            drop["shared_hosting" if shared else "no_valid_domain"] += 1; continue
        if all(d in catalog for d in doms) or any(d in catalog for d in doms):
            drop["already_in_catalog"] += 1; continue
        root = sorted(it["roots"], key=lambda r: list(ROOTS).index(r))[0]
        cat, sub = category_for(root, it["classes"])
        # one candidate per primary domain: keep most popular
        primary = sorted(doms)[0]
        rec = {"name": it["name"], "wikidata": it["qid"], "category": cat, "subcategory": sub,
               "wd_classes": sorted(it["classes"])[:5], "developer": sorted(it["developers"])[:2],
               "domains": sorted(doms), "websites": {d: doms[d] for d in sorted(doms)}, "sitelinks": it["sitelinks"]}
        if primary in seen:
            if seen[primary]["sitelinks"] >= rec["sitelinks"]: drop.setdefault("duplicate_domain", 0); drop["duplicate_domain"] += 1; continue
            drop.setdefault("duplicate_domain", 0); drop["duplicate_domain"] += 1
        seen[primary] = rec
    out = list(seen.values())
    stats["dropped"] = drop; stats["candidates_after_normalise"] = len(out)
    return out, stats

# ---------------- checks ----------------
CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # verifies chain + hostname
CTX.minimum_version = ssl.TLSVersion.TLSv1_2
CTX.load_default_certs()
def check_one(rec):
    res = {"dns": False, "tls": False, "tls_name_ok": False, "http_status": None, "final_host": None,
           "final_registrable": None, "redirect_offsite": False, "parked": False, "error": None}
    host = rec["websites"][rec["domains"][0]]
    reg = rec["domains"][0]
    names = [host] + ([reg] if host != reg else []) + (["www." + reg] if not host.startswith("www.") else [])
    tlshost = None
    for n in names:
        try:
            socket.getaddrinfo(n, 443, proto=socket.IPPROTO_TCP); res["dns"] = True
        except OSError: continue
        try:
            with socket.create_connection((n, 443), timeout=8) as s:
                with CTX.wrap_socket(s, server_hostname=n):   # verifies chain + hostname
                    res["tls"] = True; res["tls_name_ok"] = True; tlshost = n; break
        except ssl.SSLCertVerificationError as e:
            res["tls"] = True; res["error"] = "cert:" + str(e.verify_message)[:60]; tlshost = tlshost or n
        except Exception as e:
            res["error"] = type(e).__name__
    if res["tls_name_ok"]:
        icann, private = _PSL
        cur, hops = tlshost, 0
        try:
            while hops < 4:
                c = http.client.HTTPSConnection(cur, timeout=8, context=CTX)
                c.request("GET", "/", headers={"User-Agent": UA, "Range": "bytes=0-2047"})
                r = c.getresponse(); body = r.read(2048); res["http_status"] = r.status
                loc = r.getheader("Location"); c.close()
                if r.status in (301, 302, 303, 307, 308) and loc:
                    u = urllib.parse.urlsplit(urllib.parse.urljoin(f"https://{cur}/", loc))
                    if u.scheme != "https" or not u.hostname: break
                    cur = u.hostname; hops += 1; continue
                break
            res["final_host"] = cur
            fr, _ = registrable(cur, icann, private)
            res["final_registrable"] = fr
            if fr and fr != reg:
                res["redirect_offsite"] = True
            blob = (cur + " " + body[:2048].decode("latin1").lower())
            if any(h in blob for h in PARKED_HINTS) or "domain is for sale" in blob or "this domain may be for sale" in blob:
                res["parked"] = True
        except Exception as e:
            res["error"] = res["error"] or ("http:" + type(e).__name__)
    return res

def run_checks(cands, workers=64):
    global _PSL
    _PSL = load_psl()
    with cf.ThreadPoolExecutor(workers) as ex:
        for i, (rec, res) in enumerate(zip(cands, ex.map(check_one, cands))):
            rec["checks"] = res
            if i % 500 == 0: log(f"checked {i}/{len(cands)}")

def related(rec):
    """redirect target related to the original (same brand token)?"""
    fr = rec["checks"].get("final_registrable")
    if not fr: return False
    tok = lambda d: re.sub(r"[^a-z0-9]", "", d.split(".")[0])
    a, b = tok(rec["domains"][0]), tok(fr)
    n = re.sub(r"[^a-z0-9]", "", rec["name"].lower())
    return a in b or b in a or b in n or (len(a) > 3 and a[:4] == b[:4])

def score(rec):
    c = rec["checks"]; s = 0.0
    if c["dns"]: s += 0.2
    if c["tls_name_ok"]: s += 0.3
    if c["http_status"] and c["http_status"] < 400: s += 0.2
    if c["redirect_offsite"] and not related(rec): s -= 0.4
    if c["parked"]: s -= 0.6
    import math
    s += min(0.3, math.log10(max(rec["sitelinks"], 1)) / 6)
    rec["confidence"] = round(max(0.0, min(1.0, s)), 3)
    rec["high_confidence"] = bool(c["tls_name_ok"] and c["http_status"] and c["http_status"] < 400
                                  and not c["parked"] and (not c["redirect_offsite"] or related(rec)))

# Wikidata classes that are not applications/services (used only for the top list)
NON_APP = re.compile(r"newspaper|magazine|periodical|broadcast|television|radio|city|town|municipality|village|"
    r"esports|wikimedia|dictionary|encyclopedia|library|university|school|museum|nonprofit|political|"
    r"company$|^business$|publishing|record label|film|album|biological database|character encoding|"
    r"coded character|field of study|community|abandoned project|human settlement|country|organization", re.I)
def appish(rec):
    cl = rec.get("wd_classes", [])
    return not any(NON_APP.search(c) for c in cl)

def write_top(cands, date, stats=None):
    hi = [r for r in cands if r["high_confidence"] and appish(r)]
    hi.sort(key=lambda r: (-r["sitelinks"], -r["confidence"]))
    with open(f"{OUT}/top1000-{date}.jsonl", "w") as f:
        for n, r in enumerate(hi[:1000], 1): r = dict(r, rank=n); f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
    return hi

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("stage", choices=["all", "rerank"]); ap.add_argument("--date", default=time.strftime("%Y-%m-%d"))
    ap.add_argument("--refresh", action="store_true"); ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    if a.stage == "rerank":   # reuse checked output, only rebuild top list + stats
        cands = [json.loads(l) for l in _rd(f"{OUT}/wikidata-{a.date}.jsonl").splitlines()]
        stats = json.loads(_rd(f"{OUT}/stats-{a.date}.json"))
        hi = write_top(cands, a.date)
        stats.update({"high_confidence": sum(1 for r in cands if r["high_confidence"]),
                      "high_confidence_appish": len(hi), "top_written": min(1000, len(hi))})
        _wj(stats, f"{OUT}/stats-{a.date}.json", indent=1); print(json.dumps(stats, indent=1)); return
    rows = fetch(a.refresh)
    cands, stats = normalise(rows)
    cands.sort(key=lambda r: -r["sitelinks"])
    if a.limit: cands = cands[:a.limit]
    run_checks(cands)
    for r in cands: score(r)
    cands.sort(key=lambda r: (-r["confidence"], -r["sitelinks"]))
    with open(f"{OUT}/wikidata-{a.date}.jsonl", "w") as f:
        for r in cands: f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
    hi = write_top(cands, a.date)
    c = lambda k: sum(1 for r in cands if r["checks"][k])
    stats.update({"checked": len(cands), "dns_ok": c("dns"), "tls_name_ok": c("tls_name_ok"),
                  "http_ok": sum(1 for r in cands if r["checks"]["http_status"] and r["checks"]["http_status"] < 400),
                  "redirect_offsite": c("redirect_offsite"), "parked": c("parked"), "high_confidence": len(hi),
                  "top_written": min(1000, len(hi))})
    _wj(stats, f"{OUT}/stats-{a.date}.json", indent=1)
    print(json.dumps(stats, indent=1))
if __name__ == "__main__": main()
