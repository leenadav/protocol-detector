# Wikidata catalog proposals, candidates 1-3000 (PRO-259)

`wikidata-1-3000.json`: 1,579 name-based entries (main list; revision 2 after the Research Lead review) (`app_id`, `name`, `category`, `subcategory`, `domains`, `source_url`, plus `source_note` quoting the Wikidata P856 official website, `wikidata`, `candidate_rank`, `sitelinks`, `gaming_publisher_domain`).
`wikidata-1-3000-skipped.jsonl`: the 158 skipped rows with reasons. `wikidata-1-3000-stats.json`: counts.

Input: `top1000-2026-11-22.jsonl` (ranks 1-1000) + `wikidata-2026-11-22-b2.jsonl` (1001-3000). Source: Wikidata (CC0); no vendor catalog read. No new network traffic: the stored passive checks (DNS, TLS name, HTTP) are reused.

## Counts (revision 3)
| | n |
|---|---|
| candidates | 3000 |
| main entries (`wikidata-1-3000.json`) | 1579 |
| gaming-publisher HOLD (`...-gaming-publishers-hold.json`) | 785 |
| name/domain mismatch HOLD (`...-name-mismatch-hold.json`) | 403 |
| skipped (`...-skipped.jsonl`) | 233 |

Skip reasons: `failed_passive_checks` 106; `institutional_domain_not_an_app` 52; `organization_or_project_not_a_service` 72; manual: `kadokawa.co.jp` (work title), `tolweb.org` (information project), `sr.ht` (shared forge, tenant domain).
The name-mismatch hold holds rows whose `name` shares no token with the domain label (product or org name on a vendor domain, for example Mathematica on wolfram.com, which the 2nd review sample flagged as w3m on sr.ht and OpenSceneGraph on libregamewiki.org). They need a service or publisher name before use.

## Per-row changes
`wikidata-1-3000-rev2-changes.jsonl` lists every row changed against `b788035`: its status (main, a hold, or skipped with reason) and old/new `name` and `subcategory`. Rules behind the changes:
- 4 flagged rows: `renoise`, `musepack`, `zonealarm` subcategory to general-business; `labcenter` name to Labcenter Electronics.
- Subcategories `auth-service`, `generative-ai`, `audio-streaming`, `photo-video` were unreliable and are demoted to `software-development` (software class) or `internet-utility` unless a service class is present.
- Software projects use `entry_kind: software_project` and subcategory `software-development`.
- Gaming rows: `name` is a domain-label placeholder; the linked title is in `name_review`.

## Sample-check results (random.seed(N); random.sample(main, 20))
- Revision 2 list, seed 1: 4/20 wrong (renoise, musepack, zonealarm, labcenter). Fixed above.
- Revision 2 list, seed 2: 4/20 wrong (inference/Dasher, sr/w3m, shueisha/Manga Plus, libregamewiki/OpenSceneGraph). Cause: name/domain mismatch, now held; sr.ht skipped.
- Revision 3 list, seeds 3 and 4 (before the subcategory demotion): names and domains all matched; subcategory doubts in 4 of 40 rows (m0n0wall, wikisciencecompetition, exaile, deviantart), which the demotion rule addresses.
- Revision 3 list, seed 5 (final): names and domains match in 20/20. Doubtful: `abbavoyage` (a concert, not a service), `comodo` and `camfrog` (subcategory software-development is coarse). About 3/20 doubtful, so subcategory is coarse and unverified; name and domain are the checked fields.
A 20-row sample is not a statistical error estimate. The 5 samples overlap, so they are not independent.

## Caveats
- `app_id` = first label of the domain; one entry per registrable domain. Proposals only, no content-pack change.
- Content QA (capture-backed true and false positives) has NOT been run.

Regenerate: `python3 tools/make_catalog_proposals.py` (the changes file was derived once against `b788035`).
