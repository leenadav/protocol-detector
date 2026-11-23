# Post-merge detection backlog (from the first D09 measurement)

Tracked items, not work in progress. Each is a detection change, so under Lee's policy it is implemented
only **after** `claude/go-migration` is merged and **in Go only** (the Python reference stays frozen until the
migration gates retire it). A Go-only change makes the two engines differ on purpose, so every item must land
with its approved entries in `migration/parity/deltas.json` (case id, both answers, the reason) and, where a
committed case changes, its regenerated expectation. Nothing here is implemented on this branch.

Source: the application-research lane's report `research/d09-iscx-vpn2016.md` (on `claude/app-research`):
ISCX VPN-nonVPN 2016, internal research evaluation only (no redistribution, no data committed, no commercial
right claimed; commercial use stays `UNVERIFIED`). Engine `2fd9452` (Go `protodetect`, which already carries
the RFC 7252 CoAP tightening of `12e1ed0`), content 2026.11.2, default options. Largest session per capture:
63 scorable captures, 41 correct, 1 wrong, 14 unknown, 7 background largest.

Owner of every item: the **engine lane** (Go). The research lane re-runs the D09 measurement on the same five
archives (the report names their SHA-256) to confirm each fix, and adds a finding when the re-run shows one.

## Decisions (Hermes, 2026-11-19)

Research specs in `research/protocol/` on `claude/app-research` (commit `2bbf45c`):

- **UDP flow rule** (folds into PM-1 and PM-2), `research/protocol/udp-flow-decision.md`, options A + C: decide
  a UDP flow on the **first datagram of each direction**; for the weak families (CoAP, OpenVPN) identify only
  when **two consecutive datagrams** of the flow agree. No port gating: detection never uses ports (option D
  rejected). The spec measured 1.35 × 10^-4 (CoAP) and 0.95 × 10^-4 (OpenVPN) per random datagram. When every
  datagram is inspected, that is 20.5% per 1,000-datagram flow for either family. Under A + C it is about p²
  per flow. Trade-off, accepted: a protocol whose first datagram is unrecognisable is no longer found later in
  the flow (spec V4).
- **TLS ServerHello widening** (folds into PM-3), `research/protocol/tls-serverhello-legacy.md`: any
  IANA-registered TLS 1.0 to 1.2 suite keeps the server-side identification. Key exchange and record protection
  are derived from the registered name, and the table is generated from the registry with its date. TLS 1.0/1.1
  (`0x0301`, `0x0302`) are identified with a new risk `tls-deprecated-version-selected` (RFC 8996). Weak selected
  suites (RC4, 3DES, NULL, no forward secrecy) become risk marks. A malformed ServerHello still identifies
  nothing: a selected SCSV (`0x00ff`, `0x5600`), GREASE or unregistered values, SSL 3.0 and a nonzero compression
  method. On the record that means the server side stays unidentified. The session keeps its ClientHello
  identification, today and after, because no ServerHello outcome invalidates a session on a clean flow (see
  PM-3 below).
- **Telegram MTProto** becomes post-merge PROTOCOL item PM-8, `research/protocol/telegram-mtproto.md`. Its CRC
  was confirmed on 2026-11-19, as Hermes asked. Telegram's "MTProto transports" page says only "4 CRC32 bytes
  computed using length, sequence number, and payload together". Current tdlib (`td/mtproto/TcpTransport.cpp`
  and `.h`, master) no longer implements the Full transport: its `OldTransport` wraps the intermediate one. The
  page's other example implementation, MadelineProto
  (`src/Stream/MTProtoTransport/FullStream.php`), hashes with `crc32b_rev`: PHP's `crc32b` (CRC-32/ISO-HDLC, the
  zlib polynomial) with the digest reversed (`HashedBufferedStream::setExtra`/`strrev`), so the field is
  little-endian like the length and seqno. That reproduces the spec's P5 vector (CRC `0x45d4be21`, bytes
  `21bed445`), and the prepared test checks it with Go's `crc32.ChecksumIEEE`.
- **goto.com** (content, done now): vendor-level id `goto` in release 2026.11.9 (`2f6ad4d`).

## Evidence every item needs before it lands

- A **synthetic reproducer** for the false positive or the lost identification, built from the specification
  or the structure the report describes. No captured bytes are committed (AGENTS.md; `tools/check_no_keylogs.py`).
- **Positive cases still identified**: the family's committed parity cases, plus new valid messages where the
  fix narrows the profile.
- The **adversarial suite** (`make adversarial`) and its seeded noise: an item about UDP over-permissiveness
  reports its family's rate on the same random set before and after, as F-ADV-1 did.
- The **D09 re-run** on the same archives with the new engine, compared count for count with the report.
- `make check`, `make go-check`, the behaviour diff (only the intended family moves) and the approved deltas.

## Prepared tests (2026-11-19)

Each item with a reproducible shape has a Go test that asserts the behaviour the item asks for, written before
the merge and without changing detection code. While today's behaviour persists the test **skips** and says what
happens today. Once the fix makes it pass, the helper **fails**, telling whoever made the fix to remove the marker
and assert plainly. So the fix is code plus flipping the test. The reproducers are synthetic, and the Python
reference gives the same answers today.

| Item | Test | Today (skip reason) |
|---|---|---|
| PM-1 | `go/internal/analyzer/postmerge_udp_test.go` `TestPM1_OneOpenVPNLikeDatagramDoesNotDecideTheFlow` | a single datagram that only begins like a V3 client hard reset labels its flow `openvpn`. The control, a client and server hard reset (two agreeing datagrams), is asserted plainly |
| PM-2 | same file, `TestPM2_ALaterCoAPLookingDatagramDoesNotRelabelTheFlow` | one F-ADV-1 survivor at position 250 of a 500-datagram random flow labels the flow `coap`. The control, two consecutive CoAP requests opening a flow, is asserted plainly |
| PM-2(b) | `go/internal/engine/postmerge_test.go` `TestPM2_RefusedWeakProbeIsNoDispatch` | F-ADV-1's reproducer is unknown with code `profile-unsupported` ("Unsupported CoAP code profile") instead of `no-dispatch` |
| PM-3 | `go/internal/analyzer/postmerge_test.go` `TestPM3_ServerHelloWidening` | 0 of the spec's V1 to V5 (`0x009c`, `0xcca8`, `0xc013`, TLS 1.0 with `0x0035`, TLS 1.1 with `0x002f`) identify the server side. The required risks (`tls-no-forward-secrecy` on V1, `tls-deprecated-version-selected` on V4/V5) are absent. The guards (V6 SCSV, V7 GREASE, V8 SSL 3.0, compression 1) stay unidentified and are asserted plainly; so is the `0xc02f` control |
| PM-6 | engine file, `TestPM6_GoogleQUICIsReportedAsQUICOutsideTheProfile` | Q043 public-header and Q046 long-header packets end as `no-dispatch`, naming nothing |
| PM-8 | engine file, `TestPM8_TelegramMTProtoVectors` | 0 of the spec's P1 to P5 are identified (no profile yet). The negatives N1, N3, N4, N5 and N6 are asserted plainly never to be Telegram, and P5's CRC is checked |

The engine-level PM-1 and PM-2(a) tests of `c08773f` moved to the flow level, because the decided rule acts on
the flow, not on one datagram. A single-datagram inspection may still match. The UDP rule's random-flow metric
(spec section 2, seed `20261119`) is rerun with the same seed after the change.

Not testable yet, recorded instead:

- **PM-3, the invalidations.** On a clean flow the unlisted suite does **not** invalidate the session or remove
  its identification: the session stays identified from the ClientHello, and only the server side is lost. A
  session becomes `invalidated` only through reassembly contradictions or capture truncation
  (`Analyzer.reject`, the capture-gap path). So the 211 D09 sessions are most likely an integrity invalidation
  (2016 captures with gaps or conflicting retransmissions), with the server's "cipher outside the profile"
  sentence reported as the server direction's detail. The D09 re-run should report both directions' codes per
  session to confirm it. The prepared test covers the loss of the server-side identification. Today even a plainly malformed
  ServerHello (compression method 1) leaves the session identified and only the server side empty. So "malformed
  still invalidates" in the decision applies to the server side's outcome, not to the session.
- **PM-4, BitTorrent, and PM-5, SIP.** Both profiles are exact. BitTorrent is TCP only and needs the 20-byte
  `\x13BitTorrent protocol` handshake of a 68-byte message. SIP needs a complete request or status line and the
  required headers. Random or proprietary bytes do not produce either, so these 5 sessions are most likely
  genuine stray BitTorrent and SIP flows in those captures, not over-permissive profiles. No structural
  reproducer exists; the D09 re-run's reason sentence and ports decide, and both items may close as "not a
  false positive".

## Items

| ID | Priority | Finding (report section) | Proposed fix direction | Regression evidence specific to the item |
|---|---|---|---|---|
| PM-1 | **P1** (decided: UDP flow rule A + C) | **OpenVPN over UDP**: 13 sessions, all in Skype captures, the largest session in 10 of them (§4.4); no VPN capture contains a tunnel (§4.5), so none of these is a real one. The datagram candidate is selected on the first byte (`0x38`, `0x40`, `0x50`: hard-reset opcodes, key id 0) and length ≥ 14 | Require more of the single datagram: the remaining control-packet layout, consistent with the opcode (session id, the HMAC/packet-id area when tls-auth is present, an empty ACK array and message packet-id 0 in an initial hard reset), and a length within the control profile. Then consider identifying UDP OpenVPN only when the **flow** shows the exchange: a client hard reset answered by a server hard reset that acknowledges the client's session id. A lone datagram would stay `unknown` unless a hint selects OpenVPN, and the hint still never establishes identity | Synthetic Skype-like datagrams starting with each opcode byte; seeded noise rate for `udp/openvpn` before and after; client and server hard-reset pairs (with and without tls-auth) still identified; TCP OpenVPN unchanged |
| PM-2 | **P1** (decided: UDP flow rule A + C; plus reason attribution) | **CoAP over UDP**: 15 sessions in Skype (10) and VoipBuster (5) captures (§4.4), after the RFC 7252 tightening. 1,736 UDP sessions end `profile-unsupported`, often "Unsupported CoAP code profile": CoAP is selected for arbitrary UDP payloads, and its refusal is then reported as the reason the session is unknown | Two parts. (a) **Selection**: unhinted CoAP candidacy needs more than the version bits and token length. For example, a registered code with type/code consistency already at selection, at least one option or a payload, and an option sequence that parses to the end. (b) **Reason attribution**: when a candidate chosen only by a weak first-byte probe refuses, the session's unknown reason should be `no-dispatch`, not `profile-unsupported` naming CoAP. Then the structured unknown reasons (D12) do not blame a protocol that was never there. Optionally, flow-level corroboration (a response echoing the request's message id and token) before identifying unhinted | The F-ADV-1 random set (seed 7, 20,000 datagrams): rate before and after (0.030% at `12e1ed0`); `COAP_VALID` still identified unhinted and hinted; a count of `profile-unsupported` versus `no-dispatch` on the adversarial noise set; D12 reason-code tests |
| PM-3 | **P2** (decided: ServerHello widening) | **TLS 1.2 ServerHello cipher policy**: 211 TCP sessions invalidated after the server's reply; the most frequent reason is "TLS 1.2 cipher outside supported ServerHello profile" (§1, §4.3). A session already identified as TLS from its ClientHello becomes unknown because the server chose a cipher the posture table does not list (`tls_server.py:101`, `tlsx/tls.go:767`) | In a visibility product a correct TLS identification must not be lost to a posture table. An unlisted but well-formed TLS 1.2 cipher in the ServerHello should keep the identification and record the cipher as outside the posture profile (selected cipher unknown or unassessed, no posture verdict). It should not invalidate the session. A malformed ServerHello (bad lengths, a cipher the client never offered, contradictory extensions) still invalidates, as C5 requires. Check PROTOCOLS.md's TLS-posture section and the TLS 1.2 certificate continuation for the same pattern | Synthetic ServerHellos selecting legacy suites seen in 2016 (CBC/SHA-1, RSA key exchange, a suite absent from `_TLS12_CIPHERS`): identification kept, posture "unassessed", no invalidation; a cipher the ClientHello did not offer still invalidates; posture tests for listed ciphers unchanged |
| PM-4 | P3 (likely not a defect, see above) | **BitTorrent**: 3 sessions in VoipBuster captures (§4.4) | The only BitTorrent profile is the exact TCP peer handshake (no UDP DHT or uTP profile exists). Confirm from the D09 re-run (reason sentence, server port) whether these are real BitTorrent flows; tighten nothing unless the re-run shows a non-BitTorrent match | A synthetic reproducer of the matched shape; the BitTorrent positive cases unchanged |
| PM-5 | P3 (likely not a defect, see above) | **SIP**: 2 sessions in an FTPS capture (§4.4, the one `ftp/tls → sip` pair with no plausible source) | Both SIP paths (`_sip_probe` + the text parser over UDP, the text route over TCP) already require a complete request or status line and the required headers. Confirm from the re-run whether these are real SIP flows before changing anything | A synthetic reproducer; the SIP positive cases unchanged |
| PM-6 | P4 (feature) | **UDP/443 before RFC 9000**: an unidentified UDP/443 session is among the three largest unknowns in 32 captures; the six Hangouts/Facebook chat unknowns are all UDP/443 (§4.1, §5). The QUIC profile covers versions 1 and 2 only | Not a bug; a profile gap. Options, to be decided after the merge: a bounded profile for Google QUIC (gQUIC, Q0xx versions) long headers; or an explicit `unknown` reason "QUIC version outside profile" when the long-header form is recognisable but the version is not 1 or 2. Then 2016-era traffic is reported honestly, not as `no-dispatch` | Synthetic gQUIC long headers; the QUIC v1/v2 cases unchanged; a version-negotiation packet stays as today |
| PM-8 | P3 (protocol) | **Telegram MTProto over TCP** (`research/protocol/telegram-mtproto.md`): a new client-direction profile for the abridged, intermediate, padded-intermediate and Full transports. Obfuscated MTProto stays unknown by design | Implement the spec's profile (rules 1 to 4, `mtproto_transport` evidence, no payload or key ids in evidence). Abridged gets the whole-envelope or 64-consistent-bytes rule. The Full transport's CRC is CRC-32/ISO-HDLC little-endian (confirmed above). Go-only, not Python parity (Lee, 2026-11-18) | The spec's P1 to P5 identified; N1 to N6 not; S1 (every split point and single-byte chunking) gives the same final observation (contract C1); a fuzz target over the profile |
| PM-7 | P4 (note) | **XMPP**: 1 session in a Skype chat capture (§4.4), "not verified either way" | Look at it in the re-run only; no change proposed | — |
| PM-9 | P2 (awaiting Lee via Hermes; PRO-201, Codex PRO-13) | **QUIC CRYPTO assembler order**: a merged set over the fragment or byte cap returns Exhausted before the contradiction check, so the entry is dropped without a retraction and the UDP tracker can keep an earlier identity. Python does the same (`quic.py:119-125`, BudgetError at `:331`) | Check contradictions before the cap, so a contradicting set retracts first; Go-only divergence | A contradicting CRYPTO set that also exceeds the cap: retraction, not budget error; non-contradicting oversize set still Exhausted |
| PM-10 | P2 (awaiting Lee via Hermes; PRO-201, Codex PRO-18) | **Session id privacy**: unkeyed, unsalted BLAKE2s over the sorted tuple (`sessionid.go:88`; Python `events.py:46-54`). Guessable offline and linkable across captures | A per-deployment or per-capture salt. Impact: `session_id` changes in decrypt/live rows and the parity differentials, and the dashboard join (`presentation/web/store.js:121`) needs both sides to share the salt. Needs a salt/key policy | Same tuple, two salts: different ids; same salt: stable across directions; parity tooling normalizes the id |
| PM-11 | P2 (awaiting Lee via Hermes; PRO-201, Codex PRO-18) | **Key-log capture state machine** (grouped): (a) every bare SYN closes state before the retransmission check, so a duplicate SYN splits the generation (`coordinator.go:203`, `monitor.go:270`; Python `coordinator.py:140-148`); (b) same-inode truncate-and-regrow of the key log escapes detection (`keylog_unix.go:35-70`; `live.py:66-92`); (c) live mode has no 64-connection refusal, only the `rejected_connections` count (`live.py:113-245`); (d) Advance changes TLS state without dirtying the provisional row (`decryptor.go:353`; `decryptor.py:206`); (e) on TLS failure the inner view (`authenticated=false`) is still emitted (`layers.go:188`; `layers.py:123`) | (a) skip the restart for an identical client/ISN SYN; (b) verify the bytes already read, report `key_log` error; (c) a live refusal row; (d) dirty on any state change; (e) drop the inner view on failure. All Go-only divergences from the live and decrypt differentials | One synthetic script per sub-item in `live_decrypt_diff.py`, with an approved-divergence rule |
| PM-12 | P2 (awaiting Lee via Hermes; PRO-201, Codex PRO-19) | **Signatures** (grouped): (a) `(?!)` is rejected as NotPorted in Go; Python 3.9-3.12 raise SignatureError, 3.13 accepts a never-matching pattern; (b) a signature may reuse a built-in name and its category/risk apply (`appid.py:102`); (c) description key order changes the rendered text but not the digest (`signatures.py:271` vs `:335`); (d) the 4,097th signature is built before the count check (`signatures.py:327`) | (a) Lee picks the reference interpreter; (b) reserve built-in names; (c) render the description from the sorted object, or hash it as given; (d) check the count first. (c) changes signature digests | Per sub-item unit tests, and a parity delta entry for (b) to (d) |
| PM-13 | P2/P3 (awaiting Lee via Hermes; PRO-201, Codex PRO-16, PRO-17) | **Binary profile edges** (grouped): (a) pcapng opt_endofopt with a nonzero length is accepted (`capture_stream.py:177`); (b) SMB2 SESSION_SETUP response with an empty buffer is rejected by `minSize 64+9` (`network.py:113`); (c) NEGOTIATE SecurityMode 2 (signing enabled clear) is accepted (`network.py:281`, PROTOCOLS.md:587); (d) combined SessionFlags (guest and anonymous) are accepted (`network.py:158`); (e) IKEv2 responder proposal number must be 1 (`ikev2.py:64`); (f) GSS NegTokenInit without mechTypes is accepted (`gss.py:219`, RFC 4178 makes it mandatory) | Align each with its RFC and PROTOCOLS.md: (a) refuse; (b) allow an empty buffer; (c) refuse 2; (d) refuse combinations; (e) allow 1..n; (f) require mechTypes. Each needs a PROTOCOLS.md profile update and an approved parity delta | Synthetic positives and negatives per sub-item; parity delta counts |
| PM-14 | Design (Hermes approval before any code; PRO-201, Codex PRO-16) | **Bounded buffer shrink accounting**: growth now charges both arrays (`7aadbef`), but shrinking (Discard or resize to a smaller array) still holds old and new arrays while charging only the difference. Charging both means a buffer that fills its account can never shrink (`TestAggregateAccountBoundsManyBuffers`, `TestAccountFollowsAllocatedCapacity`) | A short design note: current state, options (shrink in place by reslicing; charge both with a reserve headroom; release the old array before allocating the new one), and the effect on Python compatibility (the package has no production importer yet, so none today) | The two existing tests plus a coexistence test for shrinking |

Not items: the VPN captures are inner traffic, so the dataset does not measure OpenVPN detection (§4.5);
"inconsistent" pairs such as ssh → http are other traffic in the same capture, not wrong identifications
(§4.3); the application-level `ssl` results test 2016 names against a 2026 catalog (§4.2, §5).
