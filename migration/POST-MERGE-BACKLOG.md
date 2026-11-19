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
| PM-1 | `go/internal/engine/postmerge_test.go` `TestPM1_UDPOpenVPNNeedsMoreThanTheFirstBytes` | a datagram that only begins like a V3 client hard reset (`0x50`, a session id, a zero at the ACK-array offset, arbitrary bytes) is identified as `openvpn` |
| PM-2(a) | same file, `TestPM2_RandomDatagramsAreNotCoAP` | the 6 seeded random datagrams of F-ADV-1's set are identified as CoAP |
| PM-2(b) | same file, `TestPM2_RefusedWeakProbeIsNoDispatch` | F-ADV-1's reproducer is unknown with code `profile-unsupported` ("Unsupported CoAP code profile") instead of `no-dispatch` |
| PM-3 | `go/internal/analyzer/postmerge_test.go` `TestPM3_UnlistedTLS12SuiteKeepsTheServerSideIdentification` | a ServerHello selecting the offered, unlisted `0x009c` leaves `server_protocol` empty; the control with `0xc02f` (asserted plainly) gives `tls` |
| PM-6 | engine file, `TestPM6_GoogleQUICIsReportedAsQUICOutsideTheProfile` | Q043 public-header and Q046 long-header packets end as `no-dispatch`, naming nothing |

Not testable yet, recorded instead:

- **PM-3, the invalidations.** On a clean flow the unlisted suite does **not** invalidate the session or remove
  its identification: the session stays identified from the ClientHello, and only the server side is lost. A
  session becomes `invalidated` only through reassembly contradictions or capture truncation
  (`Analyzer.reject`, the capture-gap path). So the 211 D09 sessions are most likely an integrity invalidation
  (2016 captures with gaps or conflicting retransmissions), with the server's "cipher outside the profile"
  sentence reported as the server direction's detail. The D09 re-run should report both directions' codes per
  session to confirm it. The prepared test covers the loss of the server-side identification.
- **PM-4, BitTorrent, and PM-5, SIP.** Both profiles are exact. BitTorrent is TCP only and needs the 20-byte
  `\x13BitTorrent protocol` handshake of a 68-byte message. SIP needs a complete request or status line and the
  required headers. Random or proprietary bytes do not produce either, so these 5 sessions are most likely
  genuine stray BitTorrent and SIP flows in those captures, not over-permissive profiles. No structural
  reproducer exists; the D09 re-run's reason sentence and ports decide, and both items may close as "not a
  false positive".

## Items

| ID | Priority | Finding (report section) | Proposed fix direction | Regression evidence specific to the item |
|---|---|---|---|---|
| PM-1 | **P1** | **OpenVPN over UDP**: 13 sessions, all in Skype captures, the largest session in 10 of them (§4.4); no VPN capture contains a tunnel (§4.5), so none of these is a real one. The datagram candidate is selected on the first byte (`0x38`, `0x40`, `0x50`: hard-reset opcodes, key id 0) and length ≥ 14 | Require more of the single datagram: the remaining control-packet layout, consistent with the opcode (session id, the HMAC/packet-id area when tls-auth is present, an empty ACK array and message packet-id 0 in an initial hard reset), and a length within the control profile. Then consider identifying UDP OpenVPN only when the **flow** shows the exchange: a client hard reset answered by a server hard reset that acknowledges the client's session id. A lone datagram would stay `unknown` unless a hint selects OpenVPN, and the hint still never establishes identity | Synthetic Skype-like datagrams starting with each opcode byte; seeded noise rate for `udp/openvpn` before and after; client and server hard-reset pairs (with and without tls-auth) still identified; TCP OpenVPN unchanged |
| PM-2 | **P1** | **CoAP over UDP**: 15 sessions in Skype (10) and VoipBuster (5) captures (§4.4), after the RFC 7252 tightening. 1,736 UDP sessions end `profile-unsupported`, often "Unsupported CoAP code profile": CoAP is selected for arbitrary UDP payloads, and its refusal is then reported as the reason the session is unknown | Two parts. (a) **Selection**: unhinted CoAP candidacy needs more than the version bits and token length. For example, a registered code with type/code consistency already at selection, at least one option or a payload, and an option sequence that parses to the end. (b) **Reason attribution**: when a candidate chosen only by a weak first-byte probe refuses, the session's unknown reason should be `no-dispatch`, not `profile-unsupported` naming CoAP. Then the structured unknown reasons (D12) do not blame a protocol that was never there. Optionally, flow-level corroboration (a response echoing the request's message id and token) before identifying unhinted | The F-ADV-1 random set (seed 7, 20,000 datagrams): rate before and after (0.030% at `12e1ed0`); `COAP_VALID` still identified unhinted and hinted; a count of `profile-unsupported` versus `no-dispatch` on the adversarial noise set; D12 reason-code tests |
| PM-3 | **P2** | **TLS 1.2 ServerHello cipher policy**: 211 TCP sessions invalidated after the server's reply; the most frequent reason is "TLS 1.2 cipher outside supported ServerHello profile" (§1, §4.3). A session already identified as TLS from its ClientHello becomes unknown because the server chose a cipher the posture table does not list (`tls_server.py:101`, `tlsx/tls.go:767`) | In a visibility product a correct TLS identification must not be lost to a posture table. An unlisted but well-formed TLS 1.2 cipher in the ServerHello should keep the identification and record the cipher as outside the posture profile (selected cipher unknown or unassessed, no posture verdict). It should not invalidate the session. A malformed ServerHello (bad lengths, a cipher the client never offered, contradictory extensions) still invalidates, as C5 requires. Check PROTOCOLS.md's TLS-posture section and the TLS 1.2 certificate continuation for the same pattern | Synthetic ServerHellos selecting legacy suites seen in 2016 (CBC/SHA-1, RSA key exchange, a suite absent from `_TLS12_CIPHERS`): identification kept, posture "unassessed", no invalidation; a cipher the ClientHello did not offer still invalidates; posture tests for listed ciphers unchanged |
| PM-4 | P3 (likely not a defect, see above) | **BitTorrent**: 3 sessions in VoipBuster captures (§4.4) | The only BitTorrent profile is the exact TCP peer handshake (no UDP DHT or uTP profile exists). Confirm from the D09 re-run (reason sentence, server port) whether these are real BitTorrent flows; tighten nothing unless the re-run shows a non-BitTorrent match | A synthetic reproducer of the matched shape; the BitTorrent positive cases unchanged |
| PM-5 | P3 (likely not a defect, see above) | **SIP**: 2 sessions in an FTPS capture (§4.4, the one `ftp/tls → sip` pair with no plausible source) | Both SIP paths (`_sip_probe` + the text parser over UDP, the text route over TCP) already require a complete request or status line and the required headers. Confirm from the re-run whether these are real SIP flows before changing anything | A synthetic reproducer; the SIP positive cases unchanged |
| PM-6 | P4 (feature) | **UDP/443 before RFC 9000**: an unidentified UDP/443 session is among the three largest unknowns in 32 captures; the six Hangouts/Facebook chat unknowns are all UDP/443 (§4.1, §5). The QUIC profile covers versions 1 and 2 only | Not a bug; a profile gap. Options, to be decided after the merge: a bounded profile for Google QUIC (gQUIC, Q0xx versions) long headers; or an explicit `unknown` reason "QUIC version outside profile" when the long-header form is recognisable but the version is not 1 or 2. Then 2016-era traffic is reported honestly, not as `no-dispatch` | Synthetic gQUIC long headers; the QUIC v1/v2 cases unchanged; a version-negotiation packet stays as today |
| PM-7 | P4 (note) | **XMPP**: 1 session in a Skype chat capture (§4.4), "not verified either way" | Look at it in the re-run only; no change proposed | — |

Not items: the VPN captures are inner traffic, so the dataset does not measure OpenVPN detection (§4.5);
"inconsistent" pairs such as ssh → http are other traffic in the same capture, not wrong identifications
(§4.3); the application-level `ssl` results test 2016 names against a 2026 catalog (§4.2, §5).
