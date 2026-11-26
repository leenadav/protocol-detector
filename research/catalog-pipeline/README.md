# Catalog pipeline (Research Lab)

This directory holds the Research Lab's work from 2026-11-22 and 2026-11-23 (PRO-197, PRO-253, PRO-257 and PRO-259). It was moved here from the lab workspace on the board VM, because that workspace has no push access. Nothing in this directory changes the shipped catalog: these are research inputs. Catalog entries land through separate PRs.

The directory contains:

- `candidates/`: candidates ranked from Wikidata through QLever, from 1 to 6000. The raw 13,340-row pool isn't committed (it is 6.9 MB and can be regenerated). To regenerate it, run `python3 tools/wikidata_candidates.py`, which queries `https://qlever.dev/api/wikidata`.
- `catalog-batches/`: three verified batches (b1, b2 and pro256, 500 rows in total) together with the rows that were rejected, and the reason for each rejection.
- `catalog-proposals/`: proposals built from candidates 1 to 3000 (rev3). In numbers:
  - 2,767 entries, of which 1,579 are main entries.
  - 785 gaming publisher domains, which were on hold. Lee approved including them on 2026-11-25.
  - 403 entries held because of a name mismatch.
  - 233 candidates skipped.
  Statistics are in `wikidata-1-3000-stats.json`.
- `tools/`: the generator scripts, which use only the standard library.

Lee's decisions of 2026-11-25:

- Bring the proposals into the catalog in batches of a few hundred per PR.
- Filter out the `software_project` rows that aren't network services, such as libraries and frameworks.
- Include the gaming publisher domains.
