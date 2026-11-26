# Wikidata candidate pipeline (PRO-197)

Candidate list of applications/services with an official website, for review before they enter the app catalog. Candidates are NOT verified apps.

## Licence
Source data is Wikidata (CC0). No vendor catalog (Palo Alto, Fortinet, Check Point, Zscaler, nDPI) was read or copied.

## Method
1. Fetch (QLever `https://qlever.dev/api/wikidata`, override with `WIKIDATA_SPARQL`; one query per root class, sitelinks >= 3, 1 s between queries, cached in `.cache/`). Root classes: software, mobile app, website, video game, service on the Internet, web service, social media. Fields: label, P856 website, sitelinks, instance-of classes, developer.
2. Normalise to the registrable domain (public suffix list). Drop shared/tenant hosting, domains already in the catalog (`catalog-domains-2026.11.9.txt`), and duplicate domains (keep the most popular item).
3. Cheap checks per candidate: DNS, one verified TLS handshake (chain + hostname), one ranged HTTPS GET following up to 4 redirects (final host recorded), parked-page hints.
4. Confidence score 0..1 (DNS, TLS name ok, HTTP < 400, off-site redirect, parked, log sitelinks). `high_confidence` = TLS name ok, HTTP < 400, not parked, no unrelated off-site redirect.
5. Top list: high confidence, sorted by sitelinks, after dropping Wikidata classes that are not apps (newspapers, cities, Wikimedia projects, esports, organisations; see `NON_APP`).

## Files
- `wikidata-<date>.jsonl`: all checked candidates. `top1000-<date>.jsonl`: ranked top 1,000. `stats-<date>.json`: counts per stage. `sample20-<date>.md`: first 20 rows.

## Regenerate
`python3 tools/wikidata_candidates.py all --date 2026-11-22` (about 25 min, mostly checks). `python3 tools/wikidata_candidates.py rerank --date 2026-11-22` rebuilds only the top list from the checked file.

## Known limits
- Wikidata popularity favours open-source and games over SaaS; the top list needs human/App Research triage. Several items are projects, not traffic-bearing apps.
- A domain can serve a vendor with many apps (e.g. rockstargames.com); one candidate per domain is kept.
- Checks are passive, one request per domain, no sign-in.
