# Batch 2 (services), PRO-406

`batch-2-services.json`: 300 entries (service) in the `pack.json` record format, with per-entry `evidence`. Input for the PRO-411 tool; the shipped pack is untouched. Built by `tools/make_pack_batch.py service 300 300 batches/batch-2-services.json --checks <dns-checks>` (rows sorted by candidate_rank, rows that do not resolve removed first; the name-mismatch hold is never read).

- kept: 300; dropped, domain does not resolve (DNS, 2026-11-25): 3 in the whole service set; invalid name: 0
- category pairs normalized to the pack vocabulary in this batch: 12
- checks on every entry: domain in its `source_note`, resolves, no name/domain clash with the shipped 544 applications / 442 host entries, unique inside the batch
- defaults: risk 2, browser-based, no characteristics or ports, implicitly uses ssl and web-browsing. Content QA not run.

## 20 sample rows (random.seed(408))
| # | name | domain | category/subcategory | wikidata |
|---|---|---|---|---|
| 1 | Know Your Meme (`knowyourmeme`) | knowyourmeme.com | general-internet/internet-utility | Q2071334 |
| 2 | Change.org (`change`) | change.org | general-internet/internet-utility | Q3090589 |
| 3 | The Daily Wire (`dailywire`) | dailywire.com | general-internet/internet-utility | Q25094513 |
| 4 | Kylie Cosmetics (`kyliecosmetics`) | kyliecosmetics.com | general-internet/internet-utility | Q28859450 |
| 5 | Malayala Manorama (`manoramanews`) | manoramanews.com | general-internet/internet-utility | Q2732186 |
| 6 | SpiderMonkey (`spidermonkey`) | spidermonkey.dev | business-systems/general-business | Q1848400 |
| 7 | Musepack (`musepack`) | musepack.net | business-systems/general-business | Q940967 |
| 8 | Arctic World Archive (`arcticworldarchive`) | arcticworldarchive.org | general-internet/internet-utility | Q55604158 |
| 9 | FamilySearch (`familysearch`) | familysearch.org | business-systems/database | Q3066228 |
| 10 | NAFO (`nafo-ofan`) | nafo-ofan.org | general-internet/internet-utility | Q113640505 |
| 11 | Have I Been Pwned? (`haveibeenpwned`) | haveibeenpwned.com | business-systems/database | Q23214788 |
| 12 | Blic (`blic`) | blic.rs | general-internet/internet-utility | Q883987 |
| 13 | StatCounter (`statcounter`) | statcounter.com | general-internet/internet-utility | Q3497284 |
| 14 | Lifehacker (`lifehacker`) | lifehacker.com | general-internet/internet-utility | Q2407962 |
| 15 | Grubhub (`grubhub`) | grubhub.com | general-internet/internet-utility | Q17019647 |
| 16 | Viaplay (`viaplay`) | viaplay.com | media/audio-streaming | Q18246842 |
| 17 | WebCrawler (`webcrawler`) | webcrawler.com | general-internet/internet-utility | Q2553325 |
| 18 | Shredder (`shredderchess`) | shredderchess.com | business-systems/general-business | Q742279 |
| 19 | FreedomBox (`freedombox`) | freedombox.org | business-systems/general-business | Q51627 |
| 20 | The Star (`thestar`) | thestar.com.my | general-internet/internet-utility | Q3522843 |
