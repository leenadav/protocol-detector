# Stage 0 baseline — v0.65 presentation

Stage 0 of docs/ARCHITECTURE-REVIEW-V065-EN.md: confirm the head, inventory it, record a baseline and
reproduce the findings before any change. Run on 2026-11-06 in a Claude cloud container, Linux, synthetic
in-memory traffic only. No capture was taken and no real key log was read. These are Claude-executed local
runs, not GitHub Actions results: Actions jobs do not start on this repository, because of the account's
spending limit.

## Versions and trees

| Item | Value |
|---|---|
| Working baseline | `claude/v065-presentation` at `1d1db29307032532a234d705d7c44b6211f779de`, tree `6a81995d58535e6268892cf9f5f05dfa6773321b` |
| Parent | `claude/engine-next` at `08274cbb5cfc8eab0abdef9a3bace027e8ef943b` (v0.65), tree `7080bebcf29fece6920f7df1dff9b041030fc547` |
| Embedded engine | `presentation/engine` tree is exactly `7080beb...` |
| Root engine | identical to v0.65; the only root-level additions are the two `docs/` handoff files |
| Historical Mac v0.59 | `claude/v059-unknowns-catalog-keylog` at `190e011`, tree `145de19c...` (content of the original local `993457a`) |
| Historical application | `claude/v059-presentation` at `7e50aed`, tree `8a9c73ec...` |
| Dirty changes at start | none |

## Test baseline

| Suite | Interpreter | Result |
|---|---|---|
| Engine, `python3 -B -m unittest discover` | CPython 3.13.16 | 655 tests, OK |
| Engine | CPython 3.11.17 | 655 tests, OK |
| Engine | CPython 3.9.25 | 655 tests, OK |
| Presentation, `python -B -m unittest discover -s tests` | CPython 3.13.16, cryptography 50.0.2 (pinned), OpenSSL 3.0.13 | 31 tests, **1 failure** (below) |
| `make check` | | **fails at lint**: 10 ruff findings in `presentation/` (below) |

The Mac run reported 31/31 presentation tests passing on Python 3.12.14. The difference is environmental and is
explained below; it is not a decryption defect.

### Presentation failure: `test_missing_and_conflicting_tcp_segments`

The synthetic fixture (`poc_decryption/demo.py`) emits SYN, SYN-ACK, the client's bytes in 700-byte pieces in
reverse order, then the client FIN. The test removes `frames[3]`, assuming it is a client data piece. With
OpenSSL 3.0.13 the client flight is 429 bytes, a single piece, so `frames[3]` is the client FIN: dropping it
creates no gap and the record correctly decrypts (`decrypted == 1`). The Mac's newer OpenSSL sends a larger
ClientHello, so its `frames[3]` is data. The test hard-codes a frame index instead of choosing a data segment.
Repair in stage 1: pick a data segment by payload, not by position. Do not relax the assertion.

### `make check` lint failure

`make check` runs `ruff check .` over the whole tree. `presentation/` was added to the tree by the publication
and was never under this gate before. That is review finding A01/A16, now observed:

- 4 × F401, unused imports: `poc_decryption/tls12.py` (`hashlib`), `server.py` (`os`),
  `tests/test_live_decryption.py` (`server`), `tests/test_showcase.py` (`Path`).
- 6 × S603/S310: subprocess calls in `launch.py`, `live_manager.py`, `poc_decryption/live.py`, `server.py`, and
  `urlopen` in `launch.py`. Each needs a justified, narrowly scoped suppression or a fix in stage 1. They are not
  to be blanket-ignored.

## Reproduced findings

`python3 -B tools/stage0_baseline.py` (needs the pinned cryptography). Output on `1d1db29`:

```text
A02 five unchanged snapshots: decrypt_streams calls = 5, bytes re-analyzed = 14375 (capture 2875 bytes)
A02 growth, 10 chunks with a snapshot after each: 2875 bytes fed, 12564 bytes analyzed (4.4x), 3 decrypt calls
A02 key log: 992-byte file, 5 ticks read 4960 bytes (5x)
A04 no-FIN connection, sessions emitted at stop via live_capture (calls analyzer.finish): 1
A04 no-FIN connection, sessions emitted at stop via poc_decryption.live (no finish): 0
A07 Stream at 256 KiB limit: 524288 bytes allocated per direction at creation; 64 bidirectional flows: 65.3 MiB traced
```

- **A02** (confirmed): `LiveDecoder.snapshot` passes the whole accumulated buffer to `analyze_capture` on every
  tick, and unchanged input is decrypted again each time. Re-analysis grows with history: 4.4× the bytes fed for
  10 snapshots, quadratic in the number of snapshots until the 2 MiB cap. `KeyLog.read` seeks to 0 and rereads
  the whole file on every tick.
- **A04** (confirmed by reproduction; the review only inferred it): the decryption live path never calls
  `analyzer.expire` or `analyzer.finish`. A connection without FIN emits no final session when that path
  stops; the plain live path emits one.
- **A07** (confirmed): `Stream` allocates its `buffer` and `present` arrays at full `limit` on creation:
  512 KiB per direction at 256 KiB, 65.3 MiB traced for 64 bidirectional flows before any payload arrives.
- **A01/A16** (confirmed): the lint gate fails on `presentation/`; two engine copies (root and
  `presentation/engine`) are byte-identical today but are not kept identical by any check other than
  `SOURCE.json`.
- A03, A05, A06, A08–A15 are carried forward from the review unchanged. Their code is unchanged between the
  reviewed v0.59 snapshot and v0.65 (`sessions.py`, `engine.py`, `signatures.py`, `live_capture.py`,
  `poc_decryption/`, `server.py`, `live_manager.py`, `web/`). They are reproduced by inspection, not by new
  measurements in this stage.

## Divergent Mac v0.59 work (not in v0.65)

`b83cf60..190e011`: 20 files, +421/−22. It adds `protocol_engine/smarthome.py` (148 lines: LIFX, Tuya, TP-Link)
and the multicast DNS repairs in `datagram.py`, `wire.py`, `catalog.py` and `applications.py`, with fixtures,
`test_v059.py` (104 lines) and `BENCHMARK-V059.md`. Fourteen paths also changed on the v0.59–v0.65 side. The
code collisions are `protocol_engine/applications.py`, `protocol_fixtures.py` and `test_v059.py`; the rest are
documentation. Plan: port it later as its own version (new test and benchmark filenames, for example
`test_v066.py`), with the full behaviour diff, after the stage 1 packaging change. Never mix it into a refactor
PR. Both historical branches stay untouched.

## Exit criteria for stage 0

- [x] Exact head, trees and engine equality recorded.
- [x] Both suites run on the head; differences from the Mac run explained.
- [x] Findings A01, A02, A04 and A07 reproduced with numbers; the rest mapped to unchanged code.
- [x] Divergent v0.59 work inventoried, with a reconciliation plan.
- [x] No product code changed.
