# Detection content governance (D08)

Detection *content* is the administrative data a verdict is looked up in once a structural
identification exists. It is distinct from the parsers, which are engine code and follow the package
version in `pyproject.toml`.

| component | where | changes how | rolls back how |
|---|---|---|---|
| server-name catalog (`host_apps.py`): 54 services on operator-owned domains, web fronts | content release | new `Release` entry in `protocol_engine/content.py` `HISTORY` | `--content-version X` / `content.select(X)` at run time, per process |
| application catalog (`applications.py`): categories, risk scores, characteristics, ports | content release | same | with the package version (the entries are engine metadata) |
| family inventory (`catalog.py`) and flow-risk table (`risks.py`) | engine release, digested with the content | same | with the package version |

## Releases, review dates, provenance

`protocol_engine/content.py` holds `HISTORY`: one `Release(version, released, reviewed, review, note)` per
content release, versions `YYYY.MM.N`, dates ISO. `review` says who looked at the content and whether an
independent review happened; it is written honestly (the current release records an engine-lane self-review
with the independent review pending on PR #18). `protodetect content` prints the history, the current
digest per component, the lock state and the provenance of every server-name entry: the first release that
carried it (`since`), the review date of the release in force, the basis (`operator-owned-domain`) and the
source rule (public domain ownership and the service's own documentation; shared CDNs, cloud hosting and
tenant domains are excluded by design, see PROTOCOLS.md v0.65 and D03).

## Lock and gate

`protocol_engine/content_lock.json` records the current release, its digest and the digest of each
component. `tools/check_content.py` (`make content`, part of `make check`) fails when:

- the content tables changed and the lock digest no longer matches (the message names the component):
  add a `Release` to `HISTORY` with today's dates and a note, then `tools/check_content.py --update`;
  `--update` refuses to re-lock a changed table under the same version;
- the history is not strictly increasing, a date is malformed, a prior-state entry names an unknown
  release or field, or an earlier release's catalog does not build (duplicate domains or web fronts);
- the lock names another release than `CURRENT`.

A catalog edit therefore always arrives with a dated, described release, and the review that accepted it
is the pull-request review of that commit.

## Pinning

Every session record carries `content: {version, digest}` (the release in force when the Analyzer was
created), the offline summary and the live `started`/`progress`/`summary` events carry the same object,
and custom signature sets keep their own `signature_set` digest (stage 7). Two records with different
`content.digest` values were classified by different catalogs even when the engine version is the same.

## Rollback

`protodetect analyze --content-version 2025.10.0 …` (and `live`) rebuilds the server-name lookup tables
as they were at that release before anything is inspected: entries added later disappear, entries that
changed take their earlier domains and web fronts (the earlier states are kept in `content.py` as the
differences from the current tables, so rolling back needs no earlier package). The selection is
process-wide and taken once at start-up; the records of that run pin the rolled-back version and its
digest. The application catalog, families and risks do not roll back this way: they are engine metadata
and change with the package, whose earlier versions remain installable from the release artifacts.

## Not covered

No remote content feed, signing or distribution exists: content ships with the package. Review dates
record when a human (or, honestly labelled, an engine-lane session) last looked at the release as a whole,
not a per-domain re-verification against live DNS. Custom signatures (SIGNATURES.md) and configured
rules are operator content with their own digest and are not part of the release history.
