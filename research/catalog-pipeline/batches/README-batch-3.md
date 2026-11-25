# Batch 3 (services), PRO-406

`batch-3-services.json`: 171 entries (service) in the `pack.json` record format, with per-entry `evidence`. Input for the PRO-411 tool; the shipped pack is untouched. Built by `tools/make_pack_batch.py service 600 300 batches/batch-3-services.json --checks <dns-checks>` (rows sorted by candidate_rank, rows that do not resolve removed first; the name-mismatch hold is never read).

- kept: 171; dropped, domain does not resolve (DNS, 2026-11-25): 3 in the whole service set; invalid name: 0
- category pairs normalized to the pack vocabulary in this batch: 10
- checks on every entry: domain in its `source_note`, resolves, no name/domain clash with the shipped 544 applications / 442 host entries, unique inside the batch
- defaults: risk 2, browser-based, no characteristics or ports, implicitly uses ssl and web-browsing. Content QA not run.

## 20 sample rows (random.seed(409))
| # | name | domain | category/subcategory | wikidata |
|---|---|---|---|---|
| 1 | Altium Designer (`altium`) | altium.com | business-systems/general-business | Q441778 |
| 2 | Dribbble (`dribbble`) | dribbble.com | collaboration/social-networking | Q7605173 |
| 3 | Gpg4win (`gpg4win`) | gpg4win.org | business-systems/general-business | Q1502224 |
| 4 | Mailfence (`mailfence`) | mailfence.com | collaboration/email | Q28127375 |
| 5 | Rodovid (`rodovid`) | rodovid.org | business-systems/database | Q649227 |
| 6 | space.com (`space`) | space.com | general-internet/internet-utility | Q3112835 |
| 7 | San Diego Union-Tribune (`sandiegouniontribune`) | sandiegouniontribune.com | general-internet/internet-utility | Q3547109 |
| 8 | canoe.ca (`canoe`) | canoe.com | general-internet/internet-utility | Q902502 |
| 9 | Der Spiegel (`spiegel`) | spiegel.de | general-internet/internet-utility | Q278151 |
| 10 | Joox (`joox`) | joox.com | general-internet/internet-utility | Q28187024 |
| 11 | CozyCot (`cozycot`) | cozycot.com | general-internet/internet-utility | Q1138322 |
| 12 | Publons (`publons`) | publons.com | general-internet/internet-utility | Q18389628 |
| 13 | Autores.uy (`autores`) | autores.uy | business-systems/database | Q22975461 |
| 14 | Taiwan News (`taiwannews`) | taiwannews.com.tw | general-internet/internet-utility | Q697286 |
| 15 | PostSecret (`postsecret`) | postsecret.com | general-internet/internet-utility | Q926804 |
| 16 | Xara Photo & Graphic Designer (`xara`) | xara.com | business-systems/general-business | Q1752634 |
| 17 | Akismet (`akismet`) | akismet.com | business-systems/general-business | Q419217 |
| 18 | Vtiger CRM (`vtiger`) | vtiger.com | business-systems/general-business | Q310477 |
| 19 | SlimBrowser (`slimbrowser`) | slimbrowser.net | general-internet/internet-utility | Q1156978 |
| 20 | Chamilo (`chamilo`) | chamilo.org | business-systems/general-business | Q423221 |
