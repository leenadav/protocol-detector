# Batch 4 (gaming), PRO-406

`batch-4-gaming.json`: 300 entries (gaming_publisher_domain) in the `pack.json` record format, with per-entry `evidence`. Input for the PRO-411 tool; the shipped pack is untouched. Built by `tools/make_pack_batch.py gaming_publisher_domain 0 300 batches/batch-4-gaming.json --checks <dns-checks>` (rows sorted by candidate_rank, rows that do not resolve removed first; the name-mismatch hold is never read).

- kept: 300; dropped, domain does not resolve (DNS, 2026-11-25): 16 in the whole gaming_publisher_domain set; invalid name: 0
- category pairs normalized to the pack vocabulary in this batch: 0
- checks on every entry: domain in its `source_note`, resolves, no name/domain clash with the shipped 544 applications / 442 host entries, unique inside the batch
- defaults: risk 2, browser-based, no characteristics or ports, implicitly uses ssl and web-browsing. Content QA not run.

## 20 sample rows (random.seed(410))
| # | name | domain | category/subcategory | wikidata |
|---|---|---|---|---|
| 1 | Travian (game publisher site) (`travian`) | travian.com | media/gaming | Q170331 |
| 2 | Valvesoftware (game publisher site) (`valvesoftware`) | valvesoftware.com | media/gaming | Q643572 |
| 3 | Warnerbrosgames (game publisher site) (`warnerbrosgames`) | warnerbrosgames.com | media/gaming | Q288811 |
| 4 | Play0Ad (game publisher site) (`play0ad`) | play0ad.com | media/gaming | Q161234 |
| 5 | Fruitninja (game publisher site) (`fruitninja`) | fruitninja.com | media/gaming | Q1987120 |
| 6 | Microids (game publisher site) (`microids`) | microids.com | media/gaming | Q580202 |
| 7 | Core Design (game publisher site) (`core-design`) | core-design.com | media/gaming | Q1123794 |
| 8 | Kotaku (game publisher site) (`kotaku`) | kotaku.com | media/gaming | Q1083295 |
| 9 | Thatgamecompany (game publisher site) (`thatgamecompany`) | thatgamecompany.com | media/gaming | Q677274 |
| 10 | Dmm (game publisher site) (`dmm`) | dmm.com | media/gaming | Q14785138 |
| 11 | Playbalatro (game publisher site) (`playbalatro`) | playbalatro.com | media/gaming | Q124357469 |
| 12 | Rimworldgame (game publisher site) (`rimworldgame`) | rimworldgame.com | media/gaming | Q19581568 |
| 13 | Ghoststorygames (game publisher site) (`ghoststorygames`) | ghoststorygames.com | media/gaming | Q1371495 |
| 14 | Wz2100 (game publisher site) (`wz2100`) | wz2100.net | media/gaming | Q386632 |
| 15 | Grannyhorror (game publisher site) (`grannyhorror`) | grannyhorror.com | media/gaming | Q65051470 |
| 16 | Obradinn (game publisher site) (`obradinn`) | obradinn.com | media/gaming | Q48987695 |
| 17 | Katamaridamacy (game publisher site) (`katamaridamacy`) | katamaridamacy.jp | media/gaming | Q1206519 |
| 18 | Back4Blood (game publisher site) (`back4blood`) | back4blood.com | media/gaming | Q104223925 |
| 19 | Pcsx2 (game publisher site) (`pcsx2`) | pcsx2.net | media/gaming | Q1140432 |
| 20 | Superhotgame (game publisher site) (`superhotgame`) | superhotgame.com | media/gaming | Q16267745 |
