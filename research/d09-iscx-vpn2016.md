# D09 measurement: ISCX VPN-nonVPN 2016

Application-research lane, 2026-11-18. Internal research evaluation only (Hermes for Lee, 2026-11-18): the
data is used under the dataset pages' research terms with citation, nothing is redistributed, no traffic
or capture-derived data is committed, and no commercial right is claimed. Commercial use stays
`UNVERIFIED` in `datasets.md`; LEE-1 stands.

Dataset citation (required by the dataset page): Gerard Draper-Gil, Arash Habibi Lashkari, Mohammad Mamun,
Ali A. Ghorbani, "Characterization of Encrypted and VPN Traffic Using Time-Related Features", ICISSP 2016,
pages 407-414.

## Headline

- **140 captures** (109 NonVPN, 31 VPN) from all five PCAP archives; **26,611 session records**; every
  run exited 0; analysis is deterministic (37 captures analysed twice gave identical counts).
- **Largest session per capture** (the flow the capture's label most plausibly describes), on the 63
  captures whose protocol the dataset page states: **41 correct, 1 wrong, 14 unknown, 7 where the largest
  session was LAN or host background** (DNS, NetBIOS, SNMP). The other 77 captures are
  **evidence-limited**: the page does not state their protocol (VoIP, Skype, AIM/ICQ, Netflix, Spotify).
- **Likely false positives**, families with no plausible source in this dataset:
  - `openvpn`: 13 sessions, all in Skype captures. It is the largest session in 10 Skype captures.
  - `coap`: 15 sessions in Skype and VoipBuster captures.
  - `bittorrent`: 3 sessions in VoipBuster captures.
  - `sip`: 2 sessions in an FTPS capture.
- **No OpenVPN tunnel was identified in any of the 31 VPN captures**, which carry inner protocols (TLS,
  STUN, DNS) instead. This lane's reading is that the VPN captures were taken inside the tunnel, so they
  measure the inner traffic, not VPN detection.
- **Gaps that matter for 2016 traffic**:
  - 211 TCP sessions were invalidated after the server's reply. The most frequent reason is "TLS 1.2
    cipher outside supported ServerHello profile".
  - An unidentified UDP/443 session is among the three largest unknowns in 32 captures. The QUIC
    profile covers RFC 9000 versions 1 and 2 only, and RFC 9000 was published in May 2021, after this
    traffic was captured.

## 1. Inputs

| Item | Value |
|---|---|
| Engine | Go `protodetect`, built from `claude/go-migration` `2fd94529e29020eba4096e890567655b78185d1e` with go1.27.4 |
| Content | release `2026.11.2`, digest `e0d6e39533a6ae9c` (embedded pack) |
| Archives (SHA-256) | `NonVPN-PCAPs-01.zip` `0ae9c45a0e8d1be6927d6716aa60a26f2f24873e3a86db81e0c54913ad1a102b`; `NonVPN-PCAPs-02.zip` `ac80074ce163e4f3e3eb014048e66c59da0db55bcef93f90504ddefab18d9dc3`; `NonVPN-PCAPs-03.zip` `a2dbb34900765181e4322405d16f75d5249c846a91688289fbedf8e9c9e25fb0`; `VPN-PCAPS-01.zip` `2e96c2115265ad9e26e97e996f189f68832266275121cca42fefa940fa1308ff`; `VPN-PCAPs-02.zip` `07ea3f358a9f06230060deb98cab57c2d33f9e33e7947590f5404ee831a8ba91`. Re-downloads of three archives gave the same hashes |
| Sizes | 0.84 GB, 12.70 GB, 10.34 GB, 0.67 GB, 1.67 GB |
| Source | `https://cicresearch.ca/CICDataset/ISCX-VPN-NonVPN-2016/` (registration with Lee's authorized details, session cookie kept locally and not shared) |

## 2. Labels (independent of the engine)

Labels come only from each capture's file name and the dataset page's category descriptions
(`https://www.unb.ca/cic/datasets/vpn.html`). The engine's output never set a label. Expected families are
assigned **only where the page states the protocol**:

| Label (from name) | Page statement | Expected families |
|---|---|---|
| `email*` | Thunderbird with Gmail "through SMTP/S", "POP3/SSL", "IMAP/SSL" | tls, smtp, imap, pop3 |
| `facebook*chat*`, `hangout*chat*`, `gmailchat*` | Facebook and Hangouts "via web browsers" | tls, http, http2 |
| `youtube*`, `vimeo*` | "Youtube ... and Vimeo services using Chrome and Firefox" | tls, http, http2 |
| `sftp*`, `scp*` | "FTP over SSH (SFTP)"; `scp` taken as SSH from the name | ssh |
| `ftps*` | "FTP over SSL (FTPS)" | ftp, tls |
| `*torrent*` | "uTorrent and Transmission" (BitTorrent) | bittorrent |
| `aim*`, `icq*` | through Pidgin; protocol not stated | none (evidence-limited) |
| `skype*` (chat, files, audio, video) | Skype; protocol not stated | none |
| `*audio*`, `*video*`, `voipbuster*` | voice calls (Facebook, Hangouts, Skype); VoipBuster is named only by the files | none |
| `netflix*`, `spotify*` | not described on the page (named only by the files) | none |
| `vpn_*` | the same application "over VPN" (OpenVPN, UDP mode) | as for the application |

DNS, mDNS, LLMNR, NetBIOS name and session service, SSDP, DHCP, NTP, SNMP and SMB are counted as
**background** in every capture. The page says only the objective application was running, but
operating-system traffic is still present (for example "when we captured voice-calls using hangouts ...
we captured several browsing flows").

Application-level labels (catalog ids) are checked only where the capture name gives a catalog
application: `youtube`, `vimeo`, `facebook`.

## 3. Method and commands

One archive at a time (free disk was 18 to 30 GB): download, hash, then **for each capture** extract it
alone with Info-ZIP `unzip -p` (`NonVPN-PCAPs-02.zip` uses Deflate64, which Python's `zipfile` cannot
read), run the engine, keep aggregates, delete the capture; delete the archive before the next one.

```bash
protodetect analyze CAPTURE --json --sessions
```

Default options were used throughout (`--observation handshake`, no hints, no hostnames, no fingerprints).
That is the product's default, so the results reflect what a deployment would see. Kept per capture:
counts of `(transport, engine_status, family, app, unknown codes)`, the verdict of the largest session by
bytes, and, for the three largest non-identified sessions, transport, server port, byte count, codes and
the engine's reason sentence. No addresses, host names or payload were kept. The runner and scorer are
in the lane's scratch space; this report is the only committed output.

Scoring:

- **Largest session per capture** (primary). Correct: the family is in the expected set. Wrong: an
  identified non-background family outside it. Unknown: not identified (with reason codes). Background
  largest: the largest session was background. Evidence-limited: the page states no protocol.
- **All sessions** (secondary). The same classes per session, with "inconsistent" in place of "wrong",
  because labels are per capture and other traffic shares the capture.

## 4. Results

### 4.1 Largest session per capture

| Category / application | captures | correct | wrong | unknown | background largest | evidence-limited |
|---|---|---|---|---|---|---|
| Email / Thunderbird-Gmail | 4 | 3 | 0 | 0 | 1 | 0 |
| VPN-Email | 2 | 2 | 0 | 0 | 0 | 0 |
| Chat / Facebook web | 5 | 2 | 0 | 1 | 2 | 0 |
| Chat / Hangouts and Gmail web | 5 | 0 | 0 | 5 | 0 | 0 |
| VPN-Chat / Facebook, Hangouts web | 4 | 4 | 0 | 0 | 0 | 0 |
| Streaming / YouTube | 7 | 7 | 0 | 0 | 0 | 0 |
| Streaming / Vimeo | 4 | 4 | 0 | 0 | 0 | 0 |
| VPN-Streaming / YouTube, Vimeo | 3 | 2 | 0 | 1 | 0 | 0 |
| File Transfer / SFTP and SCP | 20 | 16 | 0 | 1 | 3 | 0 |
| VPN-File Transfer / SFTP | 2 | 1 | 0 | 1 | 0 | 0 |
| File Transfer / FTPS | 4 | 0 | 1 (http) | 2 | 1 | 0 |
| VPN-File Transfer / FTPS | 2 | 0 | 0 | 2 | 0 | 0 |
| VPN-P2P / BitTorrent | 1 | 0 | 0 | 1 | 0 | 0 |
| **Scored total** | **63** | **41** | **1** | **14** | **7** | **0** |
| Evidence-limited (AIM/ICQ, Skype, VoIP, VoipBuster, Netflix, Spotify; plain and VPN) | 77 | | | 7 unknown, 1 with no session | | 69 identified |

Unknown reasons on the largest session:

| Reason | captures |
|---|---|
| `no-dispatch` (no supported structure selected) | 14 |
| `invalidated` + `profile-unsupported` | 4 |
| `invalidated` + `malformed` | 2 |
| `invalidated` + `no-dispatch` | 1 |

These are counted across all categories, scored and evidence-limited alike.

The six Chat/Hangouts-Gmail and Chat/Facebook unknowns are `no-dispatch`, and all six largest sessions are
UDP to port 443, which is not standard QUIC (section 5).

### 4.2 Application level (largest session, catalog id)

| Application | expected id | generic carrier (`ssl`) | another id |
|---|---|---|---|
| YouTube (7) | 6 | 1 | 0 |
| Vimeo (4 plain, 2 VPN) | 1 | 4 | 1 |
| Facebook chat (2 plain, 2 VPN) | 0 | 4 | 0 |

`ssl` means the session had no server name, or a 2016 name the current catalog does not hold. Names
were not kept, so this report cannot tell which.

### 4.3 All sessions

| Category | captures | sessions | consistent | inconsistent | unknown | background | evidence-limited |
|---|---|---|---|---|---|---|---|
| Chat | 20 | 2334 | 63 | 0 | 371 | 1772 | 128 |
| Email | 4 | 882 | 193 | 4 | 384 | 301 | 0 |
| File Transfer | 32 | 3111 | 230 | 425 | 1242 | 1039 | 175 |
| Streaming | 19 | 1298 | 314 | 0 | 169 | 722 | 93 |
| VoIP | 34 | 7925 | 0 | 0 | 1570 | 5257 | 1098 |
| VPN-Chat | 10 | 2086 | 112 | 0 | 111 | 1859 | 4 |
| VPN-Email | 2 | 292 | 127 | 6 | 7 | 152 | 0 |
| VPN-File Transfer | 6 | 1076 | 18 | 3 | 888 | 119 | 48 |
| VPN-P2P | 1 | 348 | 0 | 233 | 45 | 70 | 0 |
| VPN-Streaming | 5 | 478 | 110 | 0 | 149 | 146 | 73 |
| VPN-VoIP | 7 | 6781 | 0 | 0 | 839 | 5437 | 505 |

The engine reports DHCP as `dhcp/4`, and it is counted as background (19 sessions).

Inconsistent pairs (expected → found, sessions):

| Pair | sessions |
|---|---|
| ssh → http (SFTP and SCP captures) | 399 |
| ssh → tls | 16 + 3 (VPN) |
| bittorrent → http (VPN P2P) | 225 |
| bittorrent → tls | 8 |
| ftp/tls → http | 8 |
| ftp/tls → sip | 2 |
| mail → http | 4 + 6 (VPN) |

Most of these are other traffic in the same capture. BitTorrent clients reach trackers over HTTP, and
browsers and operating systems fetch certificate checks over HTTP, but neither claim is verified from a
primary source here. So "inconsistent" is **not** counted as a wrong identification. `ftp/tls → sip`
is the one pair with no plausible source (section 4.4).

Unknown reason codes over all sessions:

| Transport | Code | sessions |
|---|---|---|
| UDP | `no-dispatch` | 2292 |
| UDP | `profile-unsupported` | 1736 |
| UDP | `malformed` | 368 |
| UDP | `ambiguous` | 51 |
| UDP | `budget` | 11 |
| TCP | `no-payload` | 545 |
| TCP | `no-handshake` | 288 |
| TCP | `no-dispatch` | 266 |
| TCP | `malformed` | 219 |
| TCP | `invalidated` | 211 |
| TCP | `profile-unsupported` | 190 |
| TCP | `incomplete` | 91 |

Session status overall:

| Status | sessions |
|---|---|
| identified | 20,836 |
| unknown | 4,454 |
| incomplete | 548 |
| malformed | 482 |
| no_handshake | 288 |
| budget_exhausted | 2 |
| invalidated | 1 |

### 4.4 Likely false positives (for the Engine lane)

| Found family | sessions | where | why it is implausible |
|---|---|---|---|
| `openvpn` | 13 | Skype audio, video and file captures (plain 11, VPN 2); the largest session in 10 captures | The page uses OpenVPN only for the VPN sessions; no plain Skype capture should contain it, and no VPN capture shows a tunnel (section 4.5) |
| `coap` | 15 | Skype (10) and VoipBuster (5) captures | The page describes no CoAP application. Separately, 1736 UDP sessions end `profile-unsupported`, and among the three largest unknowns per capture the reason is often "Unsupported CoAP code profile", so the CoAP profile is tried on arbitrary UDP payloads |
| `bittorrent` | 3 | VoipBuster captures | Not a P2P application |
| `sip` | 2 | FTPS capture | Not a VoIP application |
| `xmpp` | 1 | Skype chat capture | Not verified either way; listed for completeness |

These are labelled "likely": the labels are per capture, so a stray real flow cannot be excluded. But the
counts concentrate in two applications with proprietary UDP protocols (Skype, VoipBuster), which points
at permissive UDP profiles (OpenVPN hard-reset, CoAP) rather than stray traffic.

### 4.5 VPN captures

None of the 31 VPN captures contains an identified OpenVPN session. The largest non-identified session
in each VPN capture is spread over ports (UDP 443 in 5, UDP 53 in 4, TCP 443 in 3, others singly), with
none on 1194. The captures instead carry the inner application's protocols, and their consistent counts
resemble the plain captures (for example VPN-Email: 2 of 2 correct). This lane's reading: the VPN captures
were recorded on the tunnel interface after decapsulation. The page does not state the capture point, so
this is an inference. **The dataset therefore does not measure OpenVPN detection**, contrary to the brief's
expectation that VPN flows would be opaque.

## 5. Limitations

- **2016 traffic.** TLS versions and cipher suites, pre-RFC 9000 QUIC, 2016 server names and Flash-era
  streaming. The application-level results test 2016 names against a 2026 catalog.
- **Per-capture labels.** There are no per-flow labels. The largest-session view assumes the largest
  flow is the labelled application. That fails when background is largest (7 captures) and is untested
  for multi-flow applications.
- **Unstated protocols.** 77 of 140 captures are evidence-limited because the page states no protocol.
  Proprietary applications (Skype, AIM/ICQ through Pidgin, VoipBuster, Spotify) cannot be scored.
- **Default options only.** No `--observation midstream`: flows already open at capture start end
  `no-handshake` (288 sessions).
- **Inferences.** The VPN capture point (section 4.5), the UDP/443 interpretation and the explanations of
  inconsistent pairs are this lane's inferences, stated as such.
- **No manifest.** This is not the `tools/evaluate_corpus.py` harness. No manifest was built, because a
  per-flow manifest would need per-flow labels the dataset does not provide. Building one from the
  largest-session rule is possible, but it would be this lane's labelling choice, not the dataset's.

## 6. Recommendations to the Engine lane (via Hermes)

1. Investigate the OpenVPN UDP hard-reset profile and the CoAP UDP profile for false positives on
   proprietary UDP (sections 4.4 and 4.1). These are the only likely wrong identifications found, and in
   10 captures the OpenVPN one is the largest session.
2. The TLS ServerHello profile invalidates sessions with 2016 cipher suites and legacy versions
   (211 sessions). Whether invalidating a valid ClientHello is the intended outcome for an
   older-but-valid ServerHello is a profile decision. In a visibility product it turns a correct TLS
   identification into an unknown.
3. Not a defect: pre-RFC 9000 QUIC on UDP/443 is out of the documented profile (v1/v2).

## 7. Re-run on the engine head (2026-11-19): before and after

Requested by Hermes on 2026-11-19, to test two Engine corrections. Same dataset, same registration details
(the CIC form submitted again from this lane's environment), one archive at a time, each capture deleted after
analysis and each archive before the next download. The session cookie was deleted at the end. No captures,
addresses or host names were kept or committed; only the aggregates below.

### Inputs

| | Before | After |
|---|---|---|
| Engine | Go `protodetect` from `claude/go-migration` `2fd94529e29020eba4096e890567655b78185d1e` | `claude/go-migration` head `c08773fc8da8d210c8e66d67190f883e608d7bb4` |
| Content | release `2026.11.2`, digest `e0d6e39533a6ae9c` | release `2026.11.6`, digest `d425b8adc87db36d` |
| Archives | the five archives of section 1; all five SHA-256 values identical to the first run | same files |

Both builds analysed every capture in the same pass (140 captures, 26,611 session records each, every run
exit 0).

### Result: no change

The two builds' per-capture outputs are **identical** on all 140 captures (every count, reason code,
invalidation detail and watched-family record; only run times differ). The "before" column also reproduces
the first run of this report exactly (largest session: 41 correct, 1 wrong, 14 unknown, 7 background, 77
evidence-limited; 211 sessions with an invalidated side). This is expected: the D09 corrections are
post-merge Go-only items, and `c08773f` only prepares their tests ("no detection change").

| Engine status (both builds) | Sessions |
|---|---|
| identified | 20,836 |
| unknown | 4,454 |
| incomplete | 548 |
| malformed | 482 |
| no_handshake | 288 |
| budget_exhausted | 2 |
| invalidated | 1 |

### Reason codes, both directions, per session (aggregated; identical in both builds)

Sessions not identified, by `(transport, client code, server code)`, all with session code empty unless noted:

| Sessions | Transport | Client | Server |
|---|---|---|---|
| 1,664 | udp | no-dispatch | no-dispatch |
| 935 | udp | profile-unsupported | profile-unsupported |
| 796 | udp | profile-unsupported | (none) |
| 544 | udp | no-dispatch | (none) |
| 535 | tcp | no-payload | no-payload |
| 288 | tcp | (none) | (none), session `no-handshake` |
| 162 | udp | malformed | malformed |
| **157** | tcp | **invalidated** | **profile-unsupported** |
| 136 | udp | malformed | (none) |
| 123 | tcp | no-dispatch | no-dispatch |
| 69 | udp | no-dispatch | malformed |
| 44 | tcp | malformed | no-dispatch |
| 36 | tcp | no-dispatch | malformed |
| 34 | tcp | malformed | malformed |
| 32 | udp | ambiguous | ambiguous |
| 32 | tcp | malformed | invalidated |
| 30 | tcp | malformed | profile-unsupported |
| 26 | tcp | no-dispatch | incomplete |
| 21 | tcp | malformed | incomplete |
| 20 | tcp | incomplete | no-dispatch |
| 19 | udp | ambiguous | (none) |
| 12 | tcp | incomplete | incomplete |
| 9 | udp | no-dispatch | budget |
| 9 | tcp | invalidated | no-dispatch |
| 8 | tcp | incomplete | malformed |

Sessions with an invalidated side: 211 (client side 175, server side 36), by detail (client detail | server detail):

| Sessions | Status | Invalidated side | Details |
|---|---|---|---|
| 81 | unknown | client | "Data lies outside the bounded initial stream window" \| "TLS 1.2 cipher outside supported ServerHello profile" |
| 75 | unknown | client | "Conflicting overlapping bytes; classification invalidated" \| "TLS 1.2 cipher outside supported ServerHello profile" |
| 30 | malformed | server | "Expected plaintext TLS handshake record" \| "Data lies outside the bounded initial stream window" |
| 9 | unknown | client | outside window \| "Prefix outside supported protocol families" |
| 4 | unknown | server | "Prefix outside supported protocol families" \| outside window |
| 12 | various | client or server | outside window or overlap, with SSH, CRLF, SOCKS5, CQL, BitTorrent, TLS-version or tracking-ended details (1 to 4 each) |

Every one ended with "Tracking ended before initial message completed".

### Correction (a): refuted for sessions over 64 KiB of client data; holds below that

Engine's statement: "An unlisted TLS 1.2 suite does not invalidate a clean session; it only loses the
server-side identification. The 211 invalidated sessions were probably reassembly or truncation failures."

- **In the dataset**: every TCP session whose server reply had an unlisted TLS 1.2 cipher (188) also lost the
  client side (157 client `invalidated`, 30 `malformed`, 1 `incomplete`). **None** kept a client-side TLS
  identification. Of the 175 client-side invalidations, 156 have the unlisted-cipher server code.
- **Synthetic reproduction** (IPv4 loopback pcap generated by this lane, no captured traffic: clean TCP
  handshake, valid ClientHello with SNI, in-order data, no loss or overlap, FIN close; both builds give the
  same result):

| ServerHello cipher | Client application data after the handshake | Result |
|---|---|---|
| `0xc02f` (listed) | 0 to 64,000 bytes | identified; client `tls`, server `tls` |
| `0xc02f` (listed) | 66,000 or more bytes | identified, server `tls`, but **`client_protocol` empty** (no reason code) |
| `0x009c` (unlisted) | 0 to 64,000 bytes | identified (`ssl`); client `tls`, server empty: as Engine says |
| `0x009c` (unlisted) | 66,000 or more bytes | **`unknown`, app `unknown-tcp`**; client `invalidated` "Data lies outside the bounded initial stream window", server `profile-unsupported` |

- **Reading**: the window is the 65,536-byte per-direction limit (`go/internal/reassembly/stream.go`, `Feed`).
  When the ServerHello is not accepted, the session keeps tracking, and the client's ordinary application data
  then runs past the window and invalidates the client side, which had already been identified. So the 81
  "outside window" cases are **not** reassembly or truncation failures: the synthetic session has neither. The
  75 "conflicting overlapping bytes" cases do involve real overlapping retransmissions in the captures. They
  are only reached because tracking continued after the unaccepted ServerHello. This lane cannot tell from
  aggregates whether those overlaps are capture artefacts or real conflicts.
- **Consequence**: a clean TLS 1.2 session with an unlisted cipher is reported `unknown` / `unknown-tcp`
  whenever the client sends more than about 64 KiB before the session ends. The adopted TLS widening
  (`protocol/tls-serverhello-legacy.md`) removes the cause for the listed suites only.
- **Recommendations for the Engine lane** (product decisions, not made here):
  1. a regression test with these vectors: generator `research/protocol/vectors/tls12_window_pcap.py`
     (`python3 tls12_window_pcap.py OUT.pcap 009c 66000`; synthetic loopback only), rows as above;
  2. **Decided by Hermes (CTO), 2026-11-20 (PRO-30):** an overflow of the window after a side has been identified
     does **not** revoke that identification. It ends tracking for that side and is reported as a flag, while overlap
     conflicts keep invalidating. Engine item: `research/protocol/window-overflow.md` (post-merge, Go only, approved
     parity delta), with vectors W1 to W6. The row-2 case (`client_protocol` emptied beyond the window) is covered by
     the same item. Today it does for an unlisted cipher, and it clears `client_protocol` even when the session
     is identified (row 2).

### Correction (b): consistent with genuine stray flows (not refuted)

| Family | Capture label | Sessions | Shape (each session) |
|---|---|---|---|
| `bittorrent` | VoIP / other (VoipBuster) | 3 | TCP to port 61009; 7 or 8 packets; **68 client bytes**, 0 server bytes; client direction only; closed with FIN in under 1 s |
| `sip` | File Transfer / FTPS | 2 | UDP to port 5060; 1 datagram of 414 or 416 bytes; client only; idle timeout |

68 bytes is the size of a complete BitTorrent handshake (1 + 19 + 8 + 20 + 20 bytes, BEP 3), sent once and
unanswered. A single SIP-sized request to the SIP port with no reply fits a stray registration or probe from a
VoIP client on the capture host. Neither shape is that of a misread larger flow. Without payloads this lane
cannot prove the source, so (b) is "not refuted", not "confirmed".

### Unchanged findings

The 28 `openvpn` or `coap` sessions of the first run (13 and 15 there; this re-run's tally counts a session that
matched both once) are still identified inside Skype and VoipBuster UDP flows, the largest at 505,042 packets. This matches the adopted UDP flow rule (two consecutive matches; post-merge, Go only),
which these builds do not yet contain.

## 8. Per-application results (method v2, item 5)

From the same aggregates as section 7 (engine head `c08773f`, content 2026.11.6; the old build is identical).
Labels come from capture names (section 2). Only applications that both the label and the catalog name are
scored. Hangouts, AIM, ICQ and VoipBuster have no catalog id. "App-named sessions" counts every identified
session with an application name, including protocol-level names such as `dns` and `ssl`. "Largest session"
is the largest session of the capture.

| Label | Expected app id(s) | Captures | Captures with the app named | Largest session named as the app | Sessions named as the app / all app-named sessions | Top other app names |
|---|---|---|---|---|---|---|
| VPN email | `gmail`, `google-accounts` | 2 | 0 | 0 | 0 / 285 | `dns` 152, `ssl` 111, `mozilla` 16, `ocsp` 6 |
| VPN facebook | `facebook`, `facebook-messenger` | 3 | 2 | 0 | 5 / 1803 | `dns` 1585, `turn` 102, `google-base` 47, `ssl` 26 |
| VPN netflix | `netflix` | 1 | 1 | 0 | 11 / 75 | `dns` 40, `google-base` 9, `web-browsing` 8, `ssl` 6 |
| VPN skype | `ms-teams`, `skype` | 6 | 1 | 0 | 13 / 573 | `dns` 460, `ssl` 36, `google-base` 18, `ssdp` 14 |
| VPN spotify | `spotify` | 1 | 1 | 0 | 4 / 80 | `dns` 42, `google-base` 18, `ssl` 7, `web-browsing` 4 |
| VPN vimeo | `vimeo` | 2 | 2 | 0 | 8 / 49 | `dns` 26, `google-base` 9, `ssl` 5, `google-accounts` 1 |
| VPN youtube | `youtube` | 1 | 1 | 0 | 74 / 125 | `dns` 38, `google-base` 11, `google-ads` 1, `ssl` 1 |
| email | `gmail`, `google-accounts` | 4 | 0 | 0 | 0 / 498 | `dns` 249, `ssl` 192, `netbios-ns` 41, `ssdp` 5 |
| facebook | `facebook`, `facebook-messenger` | 15 | 8 | 0 | 13 / 1748 | `dns` 1255, `turn` 139, `netbios-ns` 107, `stun` 75 |
| gmail | `gmail`, `google-accounts` | 3 | 1 | 0 | 2 / 334 | `dns` 292, `google-base` 21, `netbios-ns` 7, `ssl` 6 |
| netflix | `netflix` | 4 | 4 | 3 | 18 / 106 | `dns` 50, `web-browsing` 24, `netbios-ns` 10, `google-base` 3 |
| skype | `ms-teams`, `skype` | 20 | 11 | 0 | 86 / 2139 | `dns` 1210, `netbios-ns` 180, `ms-update` 130, `xandr` 127 |
| spotify | `spotify` | 4 | 4 | 2 | 12 / 147 | `dns` 69, `netbios-ns` 26, `google-base` 16, `ssl` 11 |
| vimeo | `vimeo` | 4 | 4 | 1 | 123 / 340 | `dns` 139, `ssl` 47, `netbios-ns` 10, `google-ads` 7 |
| youtube | `youtube` | 7 | 7 | 6 | 65 / 536 | `dns` 374, `google-base` 22, `netbios-ns` 18, `ssl` 15 |

Reading:

- **Streaming apps are named reliably by server name**: YouTube in 7 of 7 captures (largest session in 6),
  Netflix 4/4 (3), Vimeo 4/4 (1), Spotify 4/4 (2). The largest session is often the CDN flow that carries
  the media. When the capture-time server name was a shared CDN name, the session gets `google-base` or
  `ssl`. This is correct behaviour (a shared CDN names no application), and it caps per-app recall.
- **Facebook and Skype are named in about half their captures** (8 of 15, 11 of 20). Their calls go over
  STUN/TURN and peer UDP (`turn` 139 and `stun` 75 sessions in the Facebook captures), which carry no name.
- **Gmail is never named in the Thunderbird email captures** (0 of 4): 192 sessions there end as `ssl` (TLS
  without a catalog match). Hypothesis, `UNVERIFIED` (server names were not kept): the 2016 client used
  `googlemail.com` names or sent no SNI. `googlemail.com` is not in the catalog. A re-run that records
  only the server name of `ssl` sessions in the email captures would settle it. That needs Hermes's OK,
  because it keeps host names from the dataset.
- **VPN captures**: the inner traffic is named as well as the non-VPN traffic (VPN YouTube 74 of 125
  app-named sessions), consistent with section 4's reading that the VPN captures were taken inside the tunnel.

## 9. Email captures: server names of the unnamed TLS sessions (2026-11-20)

Hermes's decision 5 (2026-11-20) allowed aggregate server-name counts for the unnamed TLS sessions in the email
captures, with no addresses and no content. Method: the CIC form was submitted again with the same details; only
`NonVPN-PCAPs-01.zip` and `VPN-PCAPS-01.zip` were downloaded (SHA-256 identical to section 1); the six email
captures inside them were extracted one at a time; the engine head build was run with `--hostnames`; the archives
and the cookie were deleted.

| Server name (TLS SNI) | Port | Unnamed sessions (4 non-VPN + 2 VPN captures) |
|---|---|---|
| `smtp.googlemail.com` | 465 | 250 (150 + 100) |
| `imap.googlemail.com` | 993 | 26 (19 + 7) |
| `pop.googlemail.com` | 995 | 18 (14 + 4) |
| no SNI | 13000 | 5 |
| no SNI | 443 | 4 |

**The `googlemail.com` hypothesis of section 8 is confirmed.** All 294 unnamed TLS sessions that carry an SNI
are Gmail under `googlemail.com`. Gmail Help confirms that the domain is Gmail's
(`https://support.google.com/mail/answer/10313`). Patch L adds `googlemail.com` to `gmail` (N2). With L applied, the
email captures' Gmail sessions are named.

