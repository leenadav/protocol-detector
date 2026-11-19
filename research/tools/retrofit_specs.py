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
TODAY = datetime.date(2026, 11, 19)
REVERIFY = (TODAY + datetime.timedelta(days=90)).isoformat()
REG = {k: v for k, v in json.loads((ROOT / "apps.json").read_text()).items() if not k.startswith("_")}
OBS = {r["url"]: r for r in json.loads(obs_path.read_text())}

# Shared vendor infrastructure: ids that stand for a vendor's common services, sign-in or CDN.
SHARED_IDS = {"google-base", "google-accounts", "ms-base", "azure-ad", "ms-office365", "google-play", "apple-base"}
# Unmapped observed hosts, classified by hand (2026-11-19). "owned:<id>" = vendor-owned name of that app's vendor.
UNMAPPED = {
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
            o["requested"] += c["requested"]
            o["failed"] += c["failed"]
            o["pages"].add(url)
    rows, pos, neg, fails = [], [], [], []
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
            fails.append(h)
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
    sec6 = [START6, "", "### Method v2 vectors (checked 2026-11-19 against `c08773f` plus batches D to I and retrofit R)", ""]
    if vec:
        sec6 += ["O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); "
                 "L- = look-alike or label-boundary name (must not be this app).", "",
                 "| Kind | Input SNI | Expected | Result today | Check |", "|---|---|---|---|---|"]
        sec6 += ["| %s | `%s` | %s | %s | %s |" % v for v in vec]
    else:
        sec6 += ["No catalog id: none."]
    sec6 += ["", END6]
    web = meta["web"]
    s = [START, "", "## 9. Live verification (L)", "",
         "**BLOCKED in the research environment** (2026-11-19): its egress proxy re-terminates TLS, so a handshake would show the "
         "proxy, and direct DNS is not permitted. The tool is `research/tools/live_verify.py`; it runs from an unproxied "
         "vantage point or, DNS only, through an approved DoH resolver. No host below carries an `L` result yet.", "",
         "Names to verify (catalog domains of %s): %s." % (", ".join("`%s`" % i for i in ids) or "none",
                                                        ", ".join("`%s`" % d for d in domains) or "none"), "",
         "## 10. Observed web-client hosts (dependency mapping)", ""]
    if not web:
        s += ["No public web client or login page for this application (desktop agent, tenant-specific console or API only)."]
    else:
        loaded = [u for u in web if u in OBS]
        missing = [u for u in web if u not in OBS]
        for u in loaded:
            r = OBS[u]
            s.append("- `%s`, loaded %s without signing in: HTTP %s%s, final host `%s`." % (
                u, r["date"], r["status"], (" (" + r["error"] + ")") if r["error"] else "", r["final_host"]))
        for u in missing:
            s.append("- `%s`: **not loaded**: its host is not yet on the research allowlist (`allowlist-requests.md`, batch R1)." % u)
        if rows:
            s += ["", "Pass 1 is a lower bound. The proxy refuses hosts not on the allowlist (\"failed\" below), so hosts that "
                  "only scripts from a refused host would contact are missing.", "",
                  "| Host | Requests (refused) | Class | Attribution today | Note |", "|---|---|---|---|---|"]
            s += ["| `%s` | %d (%d) | %s | %s | %s |" % (h, o["requested"], o["failed"], c, fmt(a), w) for h, o, c, a, w in rows]
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
          "- Evasive (ECH, DoH, proxy modes): ECH support unknown until a live HTTPS-record check (section 9); other "
          "modes as stated in sections 2 to 4.",
          "- Re-verify by: **%s** (`research/tools/recheck_sources.py` tracks the cited pages)." % REVERIFY, "", END]
    return "\n".join(sec6), "\n".join(s), rows, vec, fails


def splice(text, block, start, end, anchor_heading=None):
    if start in text:
        a, b = text.index(start), text.index(end) + len(end)
        return text[:a] + block + text[b:]
    if anchor_heading:
        i = text.find(anchor_heading)
        if i >= 0:
            return text[:i] + block + "\n\n" + text[i:]
    return text.rstrip("\n") + "\n\n" + block + "\n"


summary = {"specs": 0, "observed": 0, "owned": 0, "owned_unmapped": [], "deps": 0, "vectors": 0, "fail": []}
for spec, meta in sorted(REG.items()):
    p = ROOT / "apps" / spec
    sec6, tail, rows, vec, fails = build(spec, meta)
    summary["specs"] += 1
    summary["observed"] += len(rows)
    summary["owned"] += sum(1 for r in rows if r[2] == "app-owned")
    summary["owned_unmapped"] += [r[0] for r in rows if r[2] == "app-owned (unmapped)"]
    summary["deps"] += sum(1 for r in rows if r[2].startswith(("shared", "third")))
    summary["vectors"] += len(vec)
    summary["fail"] += [(spec, h) for h in fails]
    if WRITE:
        t = p.read_text()
        t = splice(t, sec6, START6, END6, "## 7. Sources")
        t = splice(t, tail, START, END)
        p.write_text(t)
print(json.dumps(summary, indent=1))
