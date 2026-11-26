# Adding applications to the catalog (content batches)

Since PRO-411 (2026-11-25) the detection content is edited directly on the Go side. Nothing is exported from the
Python tables any more, and no step below needs or touches `protocol_engine/`.

| File | What it holds |
|---|---|
| `go/internal/content/pack.json` | the current release: applications, server-name catalog, vocabularies, protocol names, risks, digests |
| `migration/fixtures/content.json` | a byte-for-byte copy of `pack.json` (the Go tests load it) |
| `go/internal/content/history.json` | every earlier release, for `--content-version` rollback (C11: its published digest is kept) |
| `go/internal/content/lock.json` | the append-only ledger of every published release: version, dates, digest, components, host-entry count, pack digest, note, review |

Only `tools/content_pack.py` writes these files. Never edit them by hand: `check` refuses a file that is not in the
tool's layout, and a hand edit to the current release without a new version fails its digests.

## The batch file

A batch is JSON in the pack's own record format. Keys outside the ones below are refused, and so is a repeated key.

```json
{
 "schema": 1,
 "release": {"note": "what the batch adds", "review": "who reviewed it, and where"},
 "host_catalog": {"entries": [
  {"name": "example-video", "category": "media", "subcategory": "photo-video", "technology": "browser-based",
   "risk": 2, "description": "Example video streaming service", "characteristics": ["widely-used"],
   "domains": ["video.example", "cdn.video.example"], "web_fronts": ["www.example-video.example"]}
 ]},
 "applications": []
}
```

- **`host_catalog.entries`:** a service identified by server name. Each entry needs every field shown above;
  `web_fronts` may be left out. The tool creates the entry's catalog application the way the reference did:
  `implicitly_uses` is `["ssl", "web-browsing"]`, and there are no ports, aliases or container.
- **`applications`:** full application records, for services that have ports, aliases or references. Each record
  has all 13 fields: name, category, subcategory, technology, risk, description, characteristics,
  standard_ports, secure_ports, implicitly_uses, depends_on, container and aliases. If an application also has a
  server-name entry, the two must agree on the seven fields they share.
- **`release`:** `note` and `review` are required. They can come from the file or from `--note` and `--review`.
  `version`, `released` and `reviewed` are optional.
- **Limits:** at most 2,000 records and 4 MiB per batch, and at most 256 names per entry. The pack must stay
  under the Go loader's 16 MiB.

The checks are the Go loader's, plus the CI gate's identifier scan:

- Categories, subcategories, technologies and characteristics must be in the pack's vocabulary.
- Risk is 1 to 5.
- Ports are `tcp/N`, `udp/N`, `tcp/N-M` or `tcp/dynamic`.
- Every reference must resolve.
- Names and aliases are unique.
- Host names are lower case, have at least two labels and no trailing dot, and each one is claimed by only one
  entry.
- A web front is never another application's domain.

A batch only adds. A name, alias or domain that is already in the pack is refused. Changing or removing an
existing entry is a separate, reviewed release, outside this tool.

## Steps

From the repository root, on a branch cut from current `main`:

```bash
python3 -B tools/content_pack.py add research/catalog-pipeline/batches/batch-1.json --dry-run
```

```bash
python3 -B tools/content_pack.py add research/catalog-pipeline/batches/batch-1.json
```

```bash
make content content-pack
```

The dry run validates the batch and prints the release it would make, without writing anything. The second
command writes all four files. The version goes up under the numbering rule (YYYY.MM.N, month 01 to 12, a single
digit N; after N=9 comes the next month at 0, so 2026.11.9 is followed by 2026.12.0). `--version` sets the
version, and it must be later than the current one. `released` defaults to today, and `reviewed` defaults to
`released`. The previous release moves to `history.json` unchanged, and the lock gains one entry. If anything
fails, nothing is written.

`make content-pack` runs:

- the check;
- the tool's self-test;
- the example batch (`docs/examples/content-batch-example.json`) added in a copy of the tree without
  `protocol_engine/` and `protocol_adapters/`, including the Go content tests. This step needs the pinned Go.

In CI, `tools/content_gate.py` (the `content pack` job) runs the same checks and `go test ./internal/content/...`.

## Before the first real batch merges (open, PRO-411)

The frozen answers of the Go gates were recorded at content release 2026.11.9, and every record carries
`content.version`:

- `migration/fixtures/cases.json`, the `parity-go` replay (1,059 records);
- `migration/fixtures/golden/*.json.gz`, the differentials of `make go-check-parity`. Some of these answers are
  stored only as a SHA-256.

The `protodetect serve` catalog (PR #127) is also a frozen list of the 544 applications.

So a committed batch passes every content check, but it fails `parity-go`, the golden replays and the serve
catalog test until those gates run Go pinned to the release the answers were frozen at (`--content-version
2026.11.9`, which rollback already supports), and until the serve catalog is read from the pack. That follow-up
is separate work in the engine lane. Until it lands, prepare and dry-run batches, but do not merge one.
