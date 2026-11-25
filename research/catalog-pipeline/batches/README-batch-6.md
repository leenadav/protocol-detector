# Batch 6 (gaming), PRO-406

`batch-6-gaming.json`: 169 entries (gaming_publisher_domain) in the `pack.json` record format, with per-entry `evidence`. Input for the PRO-411 tool; the shipped pack is untouched. Built by `tools/make_pack_batch.py gaming_publisher_domain 600 300 batches/batch-6-gaming.json --checks <dns-checks>` (rows sorted by candidate_rank, rows that do not resolve removed first; the name-mismatch hold is never read).

- kept: 169; dropped, domain does not resolve (DNS, 2026-11-25): 16 in the whole gaming_publisher_domain set; invalid name: 0
- category pairs normalized to the pack vocabulary in this batch: 0
- checks on every entry: domain in its `source_note`, resolves, no name/domain clash with the shipped 544 applications / 442 host entries, unique inside the batch
- defaults: risk 2, browser-based, no characteristics or ports, implicitly uses ssl and web-browsing. Content QA not run.

## 20 sample rows (random.seed(412))
| # | name | domain | category/subcategory | wikidata |
|---|---|---|---|---|
| 1 | Road96 (game publisher site) (`road96`) | road96.com | media/gaming | Q106513305 |
| 2 | Btd6 (game publisher site) (`btd6`) | btd6.com | media/gaming | Q65555252 |
| 3 | Monogame (game publisher site) (`monogame`) | monogame.net | media/gaming | Q13218967 |
| 4 | Otherocean (game publisher site) (`otherocean`) | otherocean.com | media/gaming | Q4044539 |
| 5 | Callofcthulhu Game (game publisher site) (`callofcthulhu-game`) | callofcthulhu-game.com | media/gaming | Q28753372 |
| 6 | Carddass (game publisher site) (`carddass`) | carddass.com | media/gaming | Q3038704 |
| 7 | Conflictdeniedops (game publisher site) (`conflictdeniedops`) | conflictdeniedops.com | media/gaming | Q1408367 |
| 8 | Tonyhawkgame (game publisher site) (`tonyhawkgame`) | tonyhawkgame.com | media/gaming | Q19861425 |
| 9 | Endless Space (game publisher site) (`endless-space`) | endless-space.com | media/gaming | Q30095053 |
| 10 | Picroma (game publisher site) (`picroma`) | picroma.com | media/gaming | Q7486177 |
| 11 | Rose Engine (game publisher site) (`rose-engine`) | rose-engine.org | media/gaming | Q109828410 |
| 12 | Ponos (game publisher site) (`ponos`) | ponos.co.jp | media/gaming | Q20055396 |
| 13 | Zettai Zetsumei (game publisher site) (`zettai-zetsumei`) | zettai-zetsumei.jp | media/gaming | Q840733 |
| 14 | Animalwell (game publisher site) (`animalwell`) | animalwell.net | media/gaming | Q116149653 |
| 15 | Wargame Ee (game publisher site) (`wargame-ee`) | wargame-ee.com | media/gaming | Q2085997 |
| 16 | Demigodthegame (game publisher site) (`demigodthegame`) | demigodthegame.com | media/gaming | Q1185620 |
| 17 | Doodlegod (game publisher site) (`doodlegod`) | doodlegod.com | media/gaming | Q5296988 |
| 18 | Polybridge2 (game publisher site) (`polybridge2`) | polybridge2.com | media/gaming | Q96742827 |
| 19 | Megacatstudios (game publisher site) (`megacatstudios`) | megacatstudios.com | media/gaming | Q124357509 |
| 20 | Develz (game publisher site) (`develz`) | develz.org | media/gaming | Q5315124 |
