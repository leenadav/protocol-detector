# Batch 5 (gaming), PRO-406

`batch-5-gaming.json`: 300 entries (gaming_publisher_domain) in the `pack.json` record format, with per-entry `evidence`. Input for the PRO-411 tool; the shipped pack is untouched. Built by `tools/make_pack_batch.py gaming_publisher_domain 300 300 batches/batch-5-gaming.json --checks <dns-checks>` (rows sorted by candidate_rank, rows that do not resolve removed first; the name-mismatch hold is never read).

- kept: 300; dropped, domain does not resolve (DNS, 2026-11-25): 16 in the whole gaming_publisher_domain set; invalid name: 0
- category pairs normalized to the pack vocabulary in this batch: 0
- checks on every entry: domain in its `source_note`, resolves, no name/domain clash with the shipped 544 applications / 442 host entries, unique inside the batch
- defaults: risk 2, browser-based, no characteristics or ports, implicitly uses ssl and web-browsing. Content QA not run.

## 20 sample rows (random.seed(411))
| # | name | domain | category/subcategory | wikidata |
|---|---|---|---|---|
| 1 | Tekken (game publisher site) (`tekken`) | tekken.com | media/gaming | Q672049 |
| 2 | Fifa2003 (game publisher site) (`fifa2003`) | fifa2003.com | media/gaming | Q2080005 |
| 3 | Fifa2001 (game publisher site) (`fifa2001`) | fifa2001.com | media/gaming | Q2420170 |
| 4 | Killingfloor2 (game publisher site) (`killingfloor2`) | killingfloor2.com | media/gaming | Q16989070 |
| 5 | Relic (game publisher site) (`relic`) | relic.com | media/gaming | Q1116724 |
| 6 | Kongregate (game publisher site) (`kongregate`) | kongregate.com | media/gaming | Q3110042 |
| 7 | Wehappyfewgame (game publisher site) (`wehappyfewgame`) | wehappyfewgame.com | media/gaming | Q20712663 |
| 8 | 1979Revolutiongame (game publisher site) (`1979revolutiongame`) | 1979revolutiongame.com | media/gaming | Q23976492 |
| 9 | Redthreadgames (game publisher site) (`redthreadgames`) | redthreadgames.com | media/gaming | Q844183 |
| 10 | Americanconquest (game publisher site) (`americanconquest`) | americanconquest.ru | media/gaming | Q428715 |
| 11 | Haemimontgames (game publisher site) (`haemimontgames`) | haemimontgames.com | media/gaming | Q2452582 |
| 12 | Hydravision (game publisher site) (`hydravision`) | hydravision.com | media/gaming | Q1563780 |
| 13 | Frogwares (game publisher site) (`frogwares`) | frogwares.com | media/gaming | Q2278376 |
| 14 | Skullgirls (game publisher site) (`skullgirls`) | skullgirls.com | media/gaming | Q766633 |
| 15 | Gabrielknight20Th (game publisher site) (`gabrielknight20th`) | gabrielknight20th.com | media/gaming | Q644433 |
| 16 | Toribash (game publisher site) (`toribash`) | toribash.com | media/gaming | Q2636258 |
| 17 | Springrts (game publisher site) (`springrts`) | springrts.com | media/gaming | Q1754264 |
| 18 | Huniepop (game publisher site) (`huniepop`) | huniepop.com | media/gaming | Q19636551 |
| 19 | F1Manager (game publisher site) (`f1manager`) | f1manager.com | media/gaming | Q111161847 |
| 20 | Blendogames (game publisher site) (`blendogames`) | blendogames.com | media/gaming | Q608746 |
