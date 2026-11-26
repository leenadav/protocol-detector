# Batch 1 (services), PRO-406

`batch-1-services.json`: 300 service entries in the `pack.json` record format (`applications` and `host_entries`), plus per-entry `evidence`. Not yet in the shipped pack: the PRO-411 tool adds a batch to `go/internal/content/pack.json`, `history.json` and the lock, and this file is its input. Built by `tools/make_pack_batch.py service 0 300 batches/batch-1-services.json`.

## Counts (services = 774 main rows of `wikidata-1-3000.json`)
| | n |
|---|---|
| service rows | 774 |
| dropped: domain does not resolve (DNS, 2026-11-25) | 3 (`mutopiaproject`, `aozora`, `hanyudacidian`) |
| kept in this batch (candidate_rank order) | 300 |
| left for batch 2 | 471 |

Checks run on all 300: every domain appears in its `source_note` (the Wikidata P856 official website), every domain resolves, no application name, domain, suffix or web front clashes with the shipped 544 applications and 442 host entries, names and domains are unique inside the batch. The 403 name-mismatch rows were not read.

Defaults, since the proposals carry no detection data: `risk` 2, `technology` browser-based, no characteristics, no ports, `implicitly_uses` ssl and web-browsing (the same as every shipped host-named service). `description` is the Wikidata name. 24 rows had a category/subcategory pair outside the pack vocabulary (`business-systems/internet-utility`, `media/internet-utility`, `media/general-business`); they are normalized to `general-internet/internet-utility` or `business-systems/general-business` and flagged `category_normalized`.

Not done: content QA (capture-backed true and false positives), which is a separate gate before release.

## 20 sample rows (random.seed(406))
| # | name | domain | category/subcategory | wikidata |
|---|---|---|---|---|
| 1 | Vevo (`vevo`) | vevo.com | general-internet/internet-utility | Q473873 |
| 2 | VirtualBox (`virtualbox`) | virtualbox.org | business-systems/general-business | Q11393 |
| 3 | Shazam (`shazam`) | shazam.com | general-internet/internet-utility | Q1195495 |
| 4 | eMule (`emule-project`) | emule-project.com | business-systems/general-business | Q217195 |
| 5 | Digg (`digg`) | digg.com | collaboration/social-networking | Q270478 |
| 6 | OpenStack (`openstack`) | openstack.org | business-systems/general-business | Q1470293 |
| 7 | AVG AntiVirus (`avg`) | avg.com | general-internet/internet-utility | Q209691 |
| 8 | Parler (`parler`) | parler.com | collaboration/social-networking | Q64852796 |
| 9 | systemd (`systemd`) | systemd.io | business-systems/general-business | Q286124 |
| 10 | Ask.com (`ask`) | ask.com | general-internet/internet-utility | Q847564 |
| 11 | Bebo (`bebo`) | bebo.com | collaboration/social-networking | Q813559 |
| 12 | Shodan (`shodan`) | shodan.io | general-internet/internet-utility | Q10788800 |
| 13 | XDA Developers (`xda-developers`) | xda-developers.com | general-internet/internet-utility | Q262900 |
| 14 | Picnik (`picnik`) | picnik.com | general-internet/internet-utility | Q1114200 |
| 15 | Devilman Crybaby (`devilman-crybaby`) | devilman-crybaby.com | general-internet/internet-utility | Q47087518 |
| 16 | Corel Painter (`painterartist`) | painterartist.com | business-systems/general-business | Q1070296 |
| 17 | Wiktionary (`wiktionary`) | wiktionary.org | business-systems/general-business | Q151 |
| 18 | Wikisource (`wikisource`) | wikisource.org | business-systems/software-development | Q263 |
| 19 | Wikinews (`wikinews`) | wikinews.org | general-internet/internet-utility | Q964 |
| 20 | CNET (`cnet`) | cnet.com | general-internet/internet-utility | Q1544247 |
