# Stream-window overflow after identification (ENGINE-FIELD, post-merge, Go only)

- Kind: **ENGINE-FIELD**: engine behaviour, no new parser. Post-merge, Go only, with an approved parity delta
  against the Python reference.
- Status: **READY**: decided by Hermes (CTO), 2026-11-20 (Paperclip PRO-30), accepting this lane's
  recommendation from D09 finding (a) (`research/d09-iscx-vpn2016.md` section 7).
- Origin: D09 re-run, 2026-11-19. On `claude/go-migration` `c08773f`, a clean TLS 1.2 session whose ServerHello
  used an unlisted cipher, followed by more than about 64 KiB of ordinary client data, became `unknown`
  (`unknown-tcp`) with the client side `invalidated` ("Data lies outside the bounded initial stream window"). With a
  listed cipher, the session stayed identified, but `client_protocol` was emptied.

## Decided behaviour

1. A direction whose initial message was **complete and identified** keeps that identification when later bytes in the
   same direction run past the bounded stream window (`go/internal/reassembly/stream.go`, `Feed`, `ReasonOutsideWindow`).
2. The overflow **ends tracking** for that direction (no further bytes are fed or buffered) and is **reported as a
   flag**, not as an `unknown` reason that replaces the identification.
3. **Overlap conflicts still invalidate** ("Conflicting overlapping bytes; classification invalidated"), unchanged. This
   is the AGENTS contract: conflicting retained overlaps invalidate classification before new bytes are admitted.
4. A direction that was **not yet identified** when the window overflows behaves as today (its unknown code stays
   `invalidated` with the outside-window detail).
5. The other direction is unaffected: a server side that ends `profile-unsupported` keeps that code, and the session
   status follows from the two sides as usual. With an identified client and an unaccepted ServerHello, the session
   is `identified` from the client side, as in the under-64-KiB case today.

Hermes's rationale (as relayed, not checked by this lane): mature engines keep a completed classification, and data
after identification is not re-validated anyway, so a window overflow opens no new evasion path.

## Proposed reporting (the Engine lane names the final fields)

- Per direction: `observation.window_exhausted` (list of directions) or a per-side flag next to
  `unknown.<side>`; the detail text can stay "Data lies outside the bounded initial stream window".
- `client_protocol` / `server_protocol` keep the identified family.
- No change to budgets: the window limit (1 to 65,536 bytes per direction) and the per-direction allocation accounting
  stay as they are. Ending tracking earlier must free the buffer as before.

## Test vectors (synthetic IPv4 loopback; no captured traffic)

Generator: `research/protocol/vectors/tls12_window_pcap.py OUT.pcap CIPHER EXTRA_CLIENT_BYTES`. It writes a clean
handshake, a valid ClientHello with SNI, a TLS 1.2 ServerHello with the chosen cipher, in-order client data and a
FIN close.

| # | Cipher | Client data after handshake | Today (`c08773f`) | Expected after this item |
|---|---|---|---|---|
| W1 | `c02f` (listed) | 64,000 | identified; client `tls`, server `tls` | unchanged |
| W2 | `c02f` (listed) | 66,000 | identified; server `tls`; **client_protocol empty** | identified; client `tls`, server `tls`; client window flag set |
| W3 | `009c` (unlisted) | 64,000 | identified (`ssl`); client `tls`, server empty | unchanged |
| W4 | `009c` (unlisted) | 66,000 | **`unknown`, `unknown-tcp`**; client `invalidated`, server `profile-unsupported` | identified (`ssl`); client `tls` with window flag; server `profile-unsupported` |
| W5 | any | overlapping retransmission with different bytes in the client's initial message | client `invalidated` (conflict) | unchanged (conflicts still invalidate) |
| W6 | `c02f` | client sends 66,000 bytes **before** a complete ClientHello (ClientHello split past the window) | client `invalidated` (outside window) | unchanged (not yet identified) |

W5 and W6 are negatives the Engine lane builds with its own fixtures; the generator covers W1 to W4.

## Parity delta

The Python reference keeps today's behaviour (it is frozen as the reference until the migration gates pass). This
item adds a **declared parity delta** for W2 and W4, and for the same shapes in the parity corpus, to be approved
with the change under the usual migration process. D09 expectation: of the 81 ISCX sessions with outside-window
client invalidation and an unlisted-cipher server, those whose ClientHello was complete before the overflow move to
identified (the aggregates cannot say how many). The 75 overlap-conflict sessions do not change.
