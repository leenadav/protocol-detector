"""Change tracking for cited sources (research method v2, item 4).

Re-fetches every URL cited in research/apps/*.md section 7 and every machine-readable feed in FEEDS, and
compares with research/source-state.json. Pages are compared by the SHA-256 of their visible text (scripts,
styles and tags removed, whitespace collapsed), feeds by their own version field. Only hashes, versions,
HTTP status and dates are stored; no page content is kept.

usage: recheck_sources.py [--write]      (from the repository root; --write records the new state)
Exit status 0: nothing changed; 1: changes or errors reported.
"""
import datetime
import hashlib
import html
import json
import re
import ssl
import sys
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "source-state.json"
FEEDS = {
    # name: (url, how to read the version)
    "microsoft-365-endpoints": ("https://endpoints.office.com/version/Worldwide?clientrequestid=%s" % uuid.UUID(int=0), "m365"),
    "google-goog-json": ("https://www.gstatic.com/ipranges/goog.json", "google"),
    "google-cloud-json": ("https://www.gstatic.com/ipranges/cloud.json", "google"),
    "salesforce-ip-ranges": ("https://ip-ranges.salesforce.com/ip-ranges.json", "hash"),
}
URL_RE = re.compile(r"`(https://[^`\s]+)`")


def context():
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    bundle = Path("/root/.ccr/ca-bundle.crt")
    if bundle.exists():
        ctx.load_verify_locations(str(bundle))
    return ctx


def fetch(url):
    if not url.startswith("https://"):
        raise ValueError("only https:// sources are fetched")
    req = urllib.request.Request(url, headers={"user-agent": "research-recheck/1"})  # noqa: S310 - https only, checked above
    with urllib.request.urlopen(req, timeout=40, context=context()) as resp:  # noqa: S310 - https only, checked above
        return resp.status, resp.headers.get("etag"), resp.read()


def text_hash(raw):
    x = raw.decode("utf-8", "replace")
    x = re.sub(r"(?is)<(script|style|svg|noscript)[^>]*>.*?</\1>", " ", x)
    x = html.unescape(re.sub(r"<[^>]+>", " ", x))
    return hashlib.sha256(" ".join(x.split()).encode()).hexdigest()


def feed_version(kind, raw):
    if kind == "m365":
        return json.loads(raw).get("latest")
    if kind == "google":
        d = json.loads(raw)
        return "%s %s" % (d.get("syncToken"), d.get("creationTime"))
    return hashlib.sha256(raw).hexdigest()


def cited_urls():
    urls = {}
    for spec in sorted((ROOT / "apps").glob("*.md")):
        text = spec.read_text()
        part = text.split("## 7. Sources", 1)[1].split("\n## ", 1)[0] if "## 7. Sources" in text else ""
        for u in URL_RE.findall(part):
            if "<" in u or "{" in u:
                continue
            urls.setdefault(u, []).append(spec.name)
    return urls


def main(argv):
    old = json.loads(STATE.read_text()) if STATE.exists() else {"pages": {}, "feeds": {}}
    today = datetime.date.today().isoformat()
    noisy = old.get("noisy", [])
    new = {"checked": today, "pages": {}, "feeds": {}, "noisy": noisy}
    changes = []
    for name, (url, kind) in FEEDS.items():
        try:
            status, etag, raw = fetch(url)
            entry = {"url": url, "status": status, "etag": etag, "version": feed_version(kind, raw), "date": today}
        except Exception as exc:  # noqa: BLE001
            entry = {"url": url, "error": type(exc).__name__ + ": " + str(exc)[:80], "date": today}
        new["feeds"][name] = entry
        before = old["feeds"].get(name, {})
        if entry.get("version") != before.get("version") or "error" in entry:
            changes.append("feed %s: %s -> %s" % (name, before.get("version"), entry.get("version") or entry.get("error")))
    for url, specs in cited_urls().items():
        try:
            status, etag, raw = fetch(url)
            entry = {"status": status, "sha256": text_hash(raw), "specs": specs, "date": today}
        except Exception as exc:  # noqa: BLE001
            entry = {"error": type(exc).__name__ + ": " + str(exc)[:80], "specs": specs, "date": today}
        new["pages"][url] = entry
        before = old["pages"].get(url, {})
        if entry.get("sha256") != before.get("sha256") or "error" in entry:
            what = entry.get("error") or ("new" if not before else "text changed")
            if what == "text changed" and url in noisy:
                what += " (noisy page: compare by reading)"
            changes.append("page %s (%s): %s" % (url, ",".join(specs), what))
    for line in changes:
        print(line)
    print("%d feeds, %d pages, %d changes or errors" % (len(new["feeds"]), len(new["pages"]), len(changes)))
    if "--write" in argv:
        STATE.write_text(json.dumps(new, indent=1, sort_keys=True) + "\n")
    return 1 if changes else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
