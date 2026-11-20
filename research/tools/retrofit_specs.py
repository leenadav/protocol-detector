"""Method v2 retrofit for research/apps/*.md (items 1, 2, 3 and 5).

Adds, between markers so the script can be re-run:
  - in section 6, "Method v2 vectors": observed app-owned hosts as positives, observed dependency hosts and
    look-alike / label-boundary names as negatives, each checked against attribution_for_host;
  - section 9 (live verification), 10 (observed web-client hosts), 11 (attributes and re-verify date).

usage: retrofit_specs.py CHECKOUT OBSERVATIONS.json [--write]
CHECKOUT is a checkout of the engine with the proposed content applied (the catalog the vectors are checked
against); OBSERVATIONS.json is observe_web.js output. Without --write it prints the summary only.
"""
import datetime
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
checkout, obs_path = Path(sys.argv[1]), Path(sys.argv[2])
WRITE = "--write" in sys.argv
sys.path.insert(0, str(checkout))
from protocol_engine import host_apps  # noqa: E402

attr = host_apps.attribution_for_host
CATALOG = {e[0]: e for e in host_apps._HOST_APPS}
TODAY = datetime.date(2026, 11, 20)
REVERIFY = (TODAY + datetime.timedelta(days=90)).isoformat()
REG = {k: v for k, v in json.loads((ROOT / "apps.json").read_text()).items() if not k.startswith("_")}
def _load_obs(paths):
    """Observation files in order; a later file replaces an earlier one for the same URL. JSON = observe_web.js
    output (pass 1, proxied); TSV = the relayed pass-2 table (direct, Hermes server)."""
    import csv as _c2
    from urllib.parse import urlparse as _up
    reg_urls = {}
    for k, v in json.loads((ROOT / "apps.json").read_text()).items():
        if not k.startswith("_"):
            for u in v["web"]:
                reg_urls[_up(u).hostname] = u
    out = {}
    for path in paths:
        path = Path(path)
        if path.suffix == ".json":
            for r in json.loads(path.read_text()):
                out[r["url"]] = dict(r, source="pass 1 (research cloud, proxied, 2026-11-19)")
            continue
        lines = [l for l in path.read_text().splitlines() if l and not l.startswith("#")]
        for r in _c2.DictReader(lines, delimiter="\t"):
            url = reg_urls.get(r["page_host"])
            if not url:
                continue
            failed = set(filter(None, (r.get("hosts_with_failed_requests") or "").split(",")))
            hosts = {}
            for h in filter(None, ((r.get("first_party_hosts") or "") + "," + (r.get("third_party_hosts") or "")).split(",")):
                hosts[h] = {"requested": None, "failed": 1 if h in failed else 0}
            st = r["status"]
            out[url] = {"url": url, "date": "2026-11-20", "status": st if not st.startswith("ERR") else None,
                        "error": st[4:].strip() if st.startswith("ERR") else None, "final_host": r["final_host"],
                        "hosts": hosts, "source": "pass 2 (Hermes server, direct, 2026-11-20)"}
    return out


OBS = _load_obs(str(obs_path).split(","))

# Shared vendor infrastructure: ids that stand for a vendor's common services, sign-in or CDN.
SHARED_IDS = {"google-base", "google-accounts", "ms-base", "azure-ad", "ms-office365", "google-play", "apple-base", "ms-telemetry",
              "meta-base", "x-base", "linkedin-base", "reddit-base", "quora-base", "tiktok-base", "spotify-base"}
# Unmapped observed hosts, classified by hand (2026-11-19). "owned:<id>" = vendor-owned name of that app's vendor.
UNMAPPED = {
    "dockerstatic.com": ("owned:docker-hub", "Docker static assets (dockerstatic.com); ownership to be shown by certificate in live round 2"),
    "campaign.slackhq.com": ("owned:slack", "Slack marketing (slackhq.com); ownership to be shown by certificate in live round 2"),
    "www.zndsk.com": ("owned:zendesk", "Zendesk short domain (zndsk.com); ownership to be shown by certificate in live round 2"),
    "weblibrary.cdn.getgo.com": ("owned:goto", "GoTo shared web library (getgo.com; for the goto vendor id)"),
    "aadcdn.msauth.net": ("shared", "Microsoft Entra sign-in CDN"),
    "aadcdn.msftauth.net": ("shared", "Microsoft Entra sign-in CDN"),
    "portal.azure.com": ("shared", "Azure portal (Microsoft)"),
    "c.s-microsoft.com": ("shared", "Microsoft shared assets"),
    "bzr.openai.com": ("third", "OpenAI measurement host loaded by unrelated pages (not mapped: openai.com is a web front only)"),
    "bzrcdn.openai.com": ("third", "as above"),
    "static.ads-twitter.com": ("third", "X advertising tag"),
    "pixel.byspotify.com": ("third", "Spotify advertising pixel"),
    "analytics-ipv6.tiktokw.us": ("third", "TikTok pixel"),
    "commonroom.pplxmeasure.com": ("third", "measurement proxy; owner not verified"),
    "google.pplxmeasure.com": ("third", "measurement proxy; owner not verified"),
    "linkedin.pplxmeasure.com": ("third", "measurement proxy; owner not verified"),
    "meta.pplxmeasure.com": ("third", "measurement proxy; owner not verified"),
    "copilot.com": ("owned:ms-copilot", "first-party redirect target of copilot.microsoft.com"),
    "cdn01.boxcdn.net": ("owned:box", "Box static assets loaded by account.box.com (boxcdn.net)"),
    "new-sentry.gitlab.net": ("owned:gitlab", "GitLab-operated error telemetry on gitlab.net"),
    "snowplowprd.trx.gitlab.net": ("owned:gitlab", "GitLab-operated analytics collector on gitlab.net"),
    "logging.getgo.com": ("owned:goto", "GoTo logging (getgo.com; for the Engine lane's goto vendor id)"),
    "api.jive.com": ("owned:goto", "GoTo Connect API (jive.com), a separate GoTo product"),
    "api.workos.com": ("third", "WorkOS, third-party sign-in provider"),
    "browser-intake-us5-datadoghq.com": ("third", "Datadog browser telemetry"),
    "cdn.cookielaw.org": ("third", "OneTrust consent banner"),
    "geolocation.onetrust.com": ("third", "OneTrust consent geolocation"),
    "cdn.userreport.com": ("third", "UserReport survey widget"),
    "challenges.cloudflare.com": ("third", "Cloudflare Turnstile bot check"),
    "images.ctfassets.net": ("third", "Contentful CMS assets"),
    "videos.ctfassets.net": ("third", "Contentful CMS assets"),
    "js.hcaptcha.com": ("third", "hCaptcha"),
    "static.cloudflareinsights.com": ("third", "Cloudflare Web Analytics beacon"),
    "zn39psorncmg7xc7k-logmeinvoc.siteintercept.qualtrics.com": ("third", "Qualtrics survey (customer-named)"),
}
CHAR_REASON = {
    "tunnels-other-applications": "carries other traffic or remote control",
    "prone-to-misuse": "commonly misused (unsanctioned remote access, data exfiltration)",
    "transfers-files": "moves files out of the organisation",
    "evasive": "designed to avoid inspection (relays, proxies or circumvention modes)",
    "used-by-malware": "seen in malware campaigns",
    "excessive-bandwidth": "high bandwidth",
    "widely-used": "widely used by enterprises",
    "pervasive": "present on most managed endpoints",
}
VARIANT = {
    "onedrive-drive-personal-business.md": "consumer and business separated by name (`onedrive.live.com` vs `*.sharepoint.com`)",
    "microsoft-365.md": "business (consumer Outlook.com and Skype are separate ids)",
    "google-workspace.md": "not separated by name: consumer Gmail and Workspace share `mail.google.com`",
    "anthropic-claude.md": "web app and API/console separated by name (`claude.ai` vs `api.anthropic.com`, `platform.claude.com`)",
    "openai-chatgpt.md": "web app and API platform separated by name (`chatgpt.com` vs `api.openai.com`, `platform.openai.com`)",
}
import csv as _csv
LIVE = {r["host"]: r for r in _csv.DictReader(open(ROOT / "live-results-2026-11-20.tsv"), delimiter="\t")}
LIVE_CITE = "live-verified by Hermes from an unproxied vantage, 2026-11-20"
PROBES = {}
for _line in open(ROOT / "live-hosts-r2.txt"):
    _f = _line.split()
    if len(_f) == 2 and not _line.startswith("#"):
        PROBES[_f[0]] = _f[1]


def resolves(r):
    return r is not None and r["rcode"] == "0" and r["a_count"] not in ("0", "")


def live_status(name):
    """(L result text, flags list) for one catalog or observed name."""
    r = LIVE.get(name)
    if r is None:
        return "not in round 1 (added later; in `live-hosts-r2.txt`)", []
    flags = [f for f in r["flags"].split(",") if f not in ("-", "dead")]
    if r["rcode"] == "3":
        return "**NXDOMAIN**: nothing at or below this name exists (RFC 8020); recommend removal after round 2 confirms", ["nxdomain"]
    if not resolves(r):
        probe = PROBES.get(name)
        pr = LIVE.get(probe) if probe else None
        if probe and resolves(pr):
            extra = [f for f in pr["flags"].split(",") if f not in ("-", "dead")]
            return ("apex has no address (normal for a suffix entry); suffix **verified** through documented `%s` "
                    "(TLS %s, cert `%s`%s)" % (probe, pr["tls_ver"], pr["cert_cn"], (", " + ",".join(extra)) if extra else "")), ["no-address"] + extra
        if probe:
            return "apex has no address (normal for a suffix entry); documented probe `%s` queued for round 2" % probe, ["no-address"]
        return "apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source)", ["no-address"]
    parts = []
    if r["tls_error"] not in ("-", ""):
        parts.append("resolves; TLS handshake failed (%s): not a removal reason; round 2 re-checks" % r["tls_error"])
        flags.append("tls-fail")
    else:
        parts.append("**L** resolves; %s, ALPN `%s`, cert `%s` (SAN covers name: %s)" % (r["tls_ver"], r["alpn"], r["cert_cn"], r["san_covers_host"]))
    if "cdn" in flags:
        parts.append("CNAME into shared front end `%s`: name usable, IPs never" % r["cname_last"])
    if "ech" in flags:
        parts.append("HTTPS record carries `ech`: SNI may be an ECH outer name")
    if "h3" in flags:
        parts.append("HTTPS record offers `h3` (QUIC path)")
    return "; ".join(parts), flags


START6, END6 = "<!-- method-v2-vectors:start -->", "<!-- method-v2-vectors:end -->"
START, END = "<!-- method-v2:start -->", "<!-- method-v2:end -->"


def aid(host):
    r = attr(host)
    return r[0] if isinstance(r, tuple) else r


def classify(host, ids):
    a = aid(host)
    if a in ids:
        return "app-owned", a, ""
    if host in UNMAPPED:
        kind, why = UNMAPPED[host]
        if kind == "shared":
            return "shared vendor infra (unmapped)", a, why
        if kind.startswith("owned:"):
            owner = kind.split(":", 1)[1]
            return ("app-owned (unmapped)" if owner in ids else "shared vendor infra (unmapped)"), a, why
        return "third party", a, why
    if a in SHARED_IDS:
        return "shared vendor infra", a, ""
    if a is None:
        return "third party (unclassified)", a, ""
    # another catalog app: same-vendor ids count as shared vendor infra, others as third party
    return ("shared vendor infra" if a.split("-")[0] == next(iter(ids), "").split("-")[0] else "third party"), a, ""


def lookalikes(domains):
    out = []
    seen = set()
    for d in domains[:3]:
        reg = ".".join(d.split(".")[-2:])          # registrable part (approximation; no multi-label public suffixes here)
        for h, why in (("x" + reg, "label boundary"), (d + ".example.invalid", "suffix look-alike")):
            if h not in seen:
                seen.add(h)
                out.append((h, why))
    return out


def fmt(a):
    return "`%s`" % a if a else "no application"


def build(spec, meta):
    ids = meta["ids"]
    entries = [CATALOG[i] for i in ids if i in CATALOG]
    domains = [d for e in entries for d in e[7]]
    observed = {}
    for url in meta["web"]:
        r = OBS.get(url)
        if not r:
            continue
        for h, c in r["hosts"].items():
            o = observed.setdefault(h, {"requested": 0, "failed": 0, "pages": set()})
            o["requested"] = None if c["requested"] is None or o["requested"] is None else o["requested"] + c["requested"]
            o["failed"] += c["failed"]
            o["pages"].add(url)
    rows, pos, neg, fails, gaps = [], [], [], [], []
    for h in sorted(observed):
        cls, a, why = classify(h, ids)
        rows.append((h, observed[h], cls, a, why))
        if cls == "app-owned":
            pos.append((h, a))
        elif cls.startswith("app-owned (unmapped)"):
            pos.append((h, None))
        else:
            neg.append((h, a, cls))
    vec = []
    for h, a in pos:
        ok = a in ids
        vec.append(("O+", h, "one of " + ", ".join("`%s`" % i for i in ids), fmt(aid(h)), "PASS" if ok else "GAP (unmapped)"))
        if not ok:
            gaps.append(h)
    for h, a, cls in neg:
        ok = a not in ids
        vec.append(("D-", h, "not " + "/".join(ids) + " (%s)" % cls, fmt(a), "PASS" if ok else "FAIL"))
        if not ok:
            fails.append(h)
    for h, why in lookalikes(domains):
        a = aid(h)
        ok = a not in ids
        vec.append(("L-", h, "not " + "/".join(ids) + " (%s)" % why, fmt(a), "PASS" if ok else "FAIL"))
        if not ok:
            fails.append(h)
    sec6 = [START6, "", "### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J and K)", ""]
    if vec:
        sec6 += ["O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); "
                 "L- = look-alike or label-boundary name (must not be this app).", "",
                 "| Kind | Input SNI | Expected | Result today | Check |", "|---|---|---|---|---|"]
        sec6 += ["| %s | `%s` | %s | %s | %s |" % v for v in vec]
    else:
        sec6 += ["No catalog id: none."]
    sec6 += ["", END6]
    web = meta["web"]
    live_rows = [(d,) + live_status(d) for d in domains]
    s = [START, "", "## 9. Live verification (L)", "",
         "Source: %s (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). "
         "`L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never "
         "evidence." % LIVE_CITE, ""]
    if live_rows:
        s += ["| Catalog name | Live result (2026-11-20) |", "|---|---|"]
        s += ["| `%s` | %s |" % (d, t) for d, t, f in live_rows]
    else:
        s += ["No catalog names."]
    s += ["",
          "## 10. Observed web-client hosts (dependency mapping)", ""]
    if not web:
        s += ["No public web client or login page for this application (desktop agent, tenant-specific console or API only)."]
    else:
        loaded = [u for u in web if u in OBS]
        missing = [u for u in web if u not in OBS]
        for u in loaded:
            r = OBS[u]
            s.append("- `%s`, %s, loaded without signing in: HTTP %s%s, final host `%s`." % (
                u, r.get("source", "pass 1"), r["status"], (" (" + r["error"] + ")") if r["error"] else "", r["final_host"]))
        for u in missing:
            s.append("- `%s`: **not yet observed** (added after pass 2; listed in `web-urls.txt` for the next server run)." % u)
        if rows:
            s += ["", "Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen "
                  "(\"seen\"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address "
                  "are a lower bound. Pass 1 rows give requests (refused by the research proxy).", "",
                  "| Host | Requests | Class | Attribution today | Live flags | Note |", "|---|---|---|---|---|---|"]
            s += ["| `%s` | %s | %s | %s | %s | %s |" % (h, ("seen" + (" (some failed)" if o["failed"] else "")) if o["requested"] is None
                                                       else "%d (%d refused)" % (o["requested"], o["failed"]), c, fmt(a),
                                                          ",".join(live_status(h)[1]) if h in LIVE else "not checked", w)
                  for h, o, c, a, w in rows]
    deps = sorted({a for _, _, c, a, _ in rows if c.startswith(("shared", "third")) and a} |
                  {h for h, _, c, a, w in rows if c.startswith("third") and not a})
    s += ["", "## 11. Attributes (App-ID model) and re-verify date", ""]
    for e in entries:
        reasons = [CHAR_REASON[c] for c in e[6] if c in CHAR_REASON]
        s.append("- `%s`: %s / %s, %s; characteristics %s; **risk %d**: %s." % (
            e[0], e[1], e[2], e[3], ", ".join("`%s`" % c for c in e[6]) or "none", e[4],
            "; ".join(reasons) if reasons else "no risk-raising characteristic recorded; rating from its category"))
    if not entries:
        s.append("- No catalog entry.")
    s += ["- Functions separated by name: %s." % (", ".join("`%s` (%s)" % (e[0], e[5]) for e in entries) if len(entries) > 1
                                                 else "none beyond the single id"),
          "- Variant: %s." % VARIANT.get(spec, "not separated by name"),
          "- Dependencies (observed, never attributed to this app): %s." % (", ".join("`%s`" % d for d in deps) or "none observed"),
          "- Evasive (ECH, DoH, proxy modes): %s; other modes as stated in sections 2 to 4." % (
              ("**ECH-capable** names (HTTPS record `ech`, 2026-11-20): " + ", ".join("`%s`" % d for d, t, f in live_rows if "ech" in f) +
               ", so `supports-ech` applies and SNI evidence may vanish")
              if any("ech" in f for d, t, f in live_rows) else "no ECH parameter in any verified name's HTTPS record (2026-11-20)"),
          "- QUIC path (`h3` in the HTTPS record): %s." % (", ".join("`%s`" % d for d, t, f in live_rows if "h3" in f) or "none advertised"),
          "- Re-verify by: **%s** (`research/tools/recheck_sources.py` tracks the cited pages)." % REVERIFY, "", END]
    return "\n".join(sec6), "\n".join(s), rows, vec, fails, gaps


def splice(text, block, start, end, anchor_heading=None):
    if start in text:
        a, b = text.index(start), text.index(end) + len(end)
        return text[:a] + block + text[b:]
    if anchor_heading:
        i = text.find(anchor_heading)
        if i >= 0:
            return text[:i] + block + "\n\n" + text[i:]
    return text.rstrip("\n") + "\n\n" + block + "\n"


LIVE_SUMMARY = {}
summary = {"specs": 0, "observed": 0, "owned": 0, "owned_unmapped": [], "deps": 0, "vectors": 0, "fail": []}
for spec, meta in sorted(REG.items()):
    p = ROOT / "apps" / spec
    sec6, tail, rows, vec, fails, gaps = build(spec, meta)
    summary["specs"] += 1
    summary["observed"] += len(rows)
    summary["owned"] += sum(1 for r in rows if r[2] == "app-owned")
    summary["owned_unmapped"] += [r[0] for r in rows if r[2] == "app-owned (unmapped)"]
    summary["deps"] += sum(1 for r in rows if r[2].startswith(("shared", "third")))
    summary["vectors"] += len(vec)
    summary["fail"] += [(spec, h) for h in fails]
    summary.setdefault("gaps", []).extend((spec, h) for h in gaps)
    for e in [CATALOG[i] for i in meta["ids"] if i in CATALOG]:
        for d in e[7]:
            LIVE_SUMMARY[d] = live_status(d)
    if WRITE:
        t = p.read_text()
        t = splice(t, sec6, START6, END6, "## 7. Sources")
        t = splice(t, tail, START, END)
        p.write_text(t)
import collections as _c
cnt = _c.Counter()
for d, (t, f) in LIVE_SUMMARY.items():
    if "nxdomain" in f: cnt["nxdomain"] += 1
    elif "verified" in t and "no-address" in f: cnt["suffix verified via probe"] += 1
    elif "no-address" in f: cnt["apex no address, unprobed"] += 1
    elif "tls-fail" in f: cnt["resolves, TLS failed"] += 1
    elif t.startswith("not in round 1"): cnt["not in round 1"] += 1
    else: cnt["live"] += 1
    for x in ("cdn", "ech", "h3"):
        if x in f: cnt[x] += 1
summary["live"] = dict(cnt)
summary["live_names"] = len(LIVE_SUMMARY)
print(json.dumps(summary, indent=1))
