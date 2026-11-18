# Public labelled traffic datasets for corpus D09

Task 2, 2026-11-18. Nothing was downloaded and no traffic data is committed. Every statement comes from
the publisher's own dataset page (read 2026-11-18); anything the page does not state is `UNVERIFIED`.
Licence questions that decide product use are marked **LEE** (a legal or licensing decision, not this
lane's).

## What D09 needs (`docs/CORPUS-EVALUATION.md` on `claude/go-migration`)

1. **Packets with their initial bytes.** The engine inspects initial messages, so a corpus needs pcap or
   pcapng with handshakes and payload. Header-only, truncated or flow-feature datasets cannot be
   scored.
2. **Per-flow labels** (transport, client and server endpoint, family, optionally application) in the
   manifest format, assigned **independently of this engine**: by the generating client, the test-bed
   configuration, or an analyst who did not consult the engine.
3. A **licence that allows local evaluation**. Note that the evaluation is for a commercial product
   (the Culvert gateway).
4. **IPv4** (the engine is IPv4-only). The corpus stays outside the repository; only the manifest digest
   and the report are committed.

## Survey

| Dataset | Packets usable by the engine? | Labels | Licence (as stated) | Fit |
|---|---|---|---|---|
| ISCX VPN-nonVPN 2016 (UNB CIC) | yes: "full packet in pcap format" [D1] | per traffic type and application, by the generating client (one application per capture) [D1] | **conflicting**: dataset page "publicly available for researchers" [D1]; CIC FAQ permits redistribution and answers the commercial-use question the same way [D0]. Commercial use `UNVERIFIED` | **high** technically; licence **pending** |
| ISCX Tor-nonTor 2016 (UNB CIC) | yes: "full packet in pcap format" [D2] | per application, from the workstation capture, transferred to the Tor capture [D2] | conflicting, as for D1 [D2, D0] | medium (Tor traffic is TLS to relays) |
| CIC-IDS2017 (UNB CIC) | yes: "full packet payloads in pcap format" [D3] | per flow (5-tuple, time) as benign or attack, from the test bed; no protocol or application label [D3] | conflicting, as for D1 [D3, D0] | **high** technically; licence **pending** |
| CSE-CIC-IDS2018 (UNB CIC) | not determined from the page | per flow (FlowID, IPs, ports, protocol) from CICFlowMeter, attack scenarios [D4] | not rechecked | not assessed further |
| UNSW-NB15 (UNSW Canberra) | yes: "100 GB of the raw traffic (e.g., Pcap files)" [D5] | attack ground truth (`UNSW-NB15_GT.csv`); records produced with Argus and Bro-IDS [D5] | "Free use ... for academic research purposes ... Use for commercial purposes should be agreed by the authors" [D5] | medium; **LEE** |
| MIRAGE-GenAI-2025, MIRAGE-2019 (Univ. Naples) | `UNVERIFIED`: released "in JSON format, making available the raw traffic data captured" [D6] | per app and activity, from the MIRAGE capture architecture (ChatGPT, Copilot, Gemini mobile apps; 40 apps for 2019) [D6] | CC BY-NC-ND 4.0 [D6] | high relevance; **LEE** (non-commercial, no derivatives) |
| Stratosphere CTU-13 | no: "Pcap files only with the headers information" [D7] | per flow (botnet, normal, background) [D7] | CC BY [D7] | low (no payload) |
| Stratosphere normal captures | partly: some pcaps reduced to DNS only "for privacy reasons" [D8] | per capture ("normal") [D8] | not stated on the page read; `UNVERIFIED` | low |
| CESNET-TLS22 / CESNET-QUIC22 (Zenodo) | no: flows "in compressed CSV files", packet metadata sequences only [D9, D10] | 191 service labels (TLS22) [D9] | CC BY 4.0 [D9, D10] | none for the engine (no bytes) |
| MAWI traffic archive | not determined (IP addresses "scrambled"; payload handling not stated on the page read) [D11] | none (MAWILab anomaly labels, "terminated in December 2024") [D11] | "only research purposes" [D11] | none (unlabelled) |
| CAIDA Anonymized Internet Traces | no: "payload is removed from all packets" [D12] | none [D12] | CAIDA Acceptable Use Agreement [D12] | none |
| Wireshark SampleCaptures | yes (individual files) | per file, by the contributor's description [D13] | not stated on the page read; `UNVERIFIED` | smoke tests only; licence unknown |

### Details of the candidates that can be scored

**D1 · ISCX VPN-nonVPN 2016.** 14 traffic categories (regular and over-VPN): browsing (HTTPS from
Firefox and Chrome), email (Thunderbird with Gmail over "SMTP/S", "POP3/SSL" and "IMAP/SSL"), chat
(Facebook and Hangouts web, Skype, AIM and ICQ through Pidgin), streaming (YouTube, Vimeo), file
transfer (Skype, SFTP, FTPS with FileZilla), VoIP (Facebook, Hangouts, Skype) and P2P (uTorrent,
Transmission). The VPN used OpenVPN in UDP mode. Size: "a total amount of 28GB". Labelling: "all
unnecessary services and applications were closed (The only application executed was the objective of
the capture)", capture filtered to the client's address. The page also admits noise ("when we captured
voice-calls using hangouts ... we captured several browsing flows"). Personal data: test accounts
("Alice and Bob"), traffic to real third-party services; content is mostly TLS-encrypted.

**D3 · CIC-IDS2017.** Five days of capture (3 to 7 July 2017): Monday benign only, then attacks (FTP and
SSH brute force, DoS, Heartbleed, web attacks, infiltration, botnet, DDoS). Benign traffic was generated
by profiles of "25 users based on the HTTP, HTTPS, FTP, SSH, and email protocols". Labelled flows give
"time stamp, source, and destination IPs, source and destination ports, protocols and attack". Victim
and attacker addresses are published (for example web server 192.168.10.50 / 205.174.165.68). Day sizes
are listed (for example "Wednesday, attacks + Normal Activity, 13G"). The page contains no family or
application label. A family label would have to come from the test-bed configuration (which server ran
which service), which D09 accepts as `label_basis: test-bed`.

**D0 · CIC licence: two statements that disagree (rechecked 2026-11-18 at Hermes's request).**

- Dataset pages, "License" section: ISCXVPN2016: "The ISCXVPN2016 dataset is publicly available for
  researchers. If you are using our dataset, you should cite our related research paper ..." [D1].
  CIC-IDS2017: "... are publicly available for researchers. If you are using our dataset, you should cite
  our related paper ..." [D3]. ISCXTor2016: the same wording [D2]. **None of the three grants or mentions
  commercial use.**
- CIC datasets index page `https://www.unb.ca/cic/datasets/index.html`, FAQ [D0]. To "I downloaded the dataset
  ... but I cannot find any license documentation", the answer is: "We try to include a licensing note at the
  bottom of each dataset page, right above the download button. ... With any of our datasets, you may
  redistribute, republish, and mirror our datasets in any form. However, any use or redistribution of the
  data must include a citation to the dataset and the research paper listed." To "What is your policy of
  using your dataset collections by private companies, for commercial use?", the answer is: "You may
  redistribute, republish, and mirror our datasets in any form; however, any use or redistribution of the
  data must include a citation to the dataset and the research paper listed on the webpage."
- Assessment: the FAQ answers a commercial-use question without saying "commercial use is permitted".
  It also defers to the per-page licensing note, and that note says only "available for researchers". Under
  Lee's rule (a licence that **clearly** allows evaluation for a commercial product), **commercial use is
  `UNVERIFIED` for ISCX VPN-nonVPN 2016, ISCX Tor 2016 and CIC-IDS2017.** Batch 2 of this file
  overstated it as permitted; this corrects that.
- Download: each dataset page's "Download this dataset" leads to a registration form
  (`http://cicresearch.ca/CICDataset/ISCX-VPN-NonVPN-2016/`, `http://cicresearch.ca/CICDataset/CIC-IDS-2017/`).
  On 2026-11-18 the form page showed only the form fields (and "Server error. Please try again later."), with
  no file listing before registration.

## Recommendation

**Decided (LEE-1, Hermes for Lee, 2026-11-18):** D09 uses only data whose licence clearly allows
evaluation for a commercial product, unless the authors give written permission. MIRAGE (CC BY-NC-ND)
and UNSW-NB15 (academic) stay excluded.

Under that rule **no surveyed dataset is cleared today**:

- The CIC datasets are the best technical fit, but their licence is conflicting (D0). **Recommended
  action before any download**: obtain CIC's written confirmation that evaluating a commercial product
  with ISCXVPN2016 and CIC-IDS2017 is permitted with citation, through CIC's contact on the dataset pages.
  This is for Hermes or Lee; this lane sends nothing externally.
- The CC BY sets that are cleared for commercial use (CTU-13, CESNET-TLS22, CESNET-QUIC22) cannot be scored
  by this engine: no payload, or flow features only.
- So if CIC does not confirm, the remaining route is the D09 document's own: a test-bed capture labelled
  from the generating clients (for example a Culvert lab run). That is Lee's decision.

If CIC confirms, the order stays as before:

1. **ISCX VPN-nonVPN 2016**: full pcaps, generating-client labels, families the engine claims (TLS,
   including the mail and FTPS sessions, whose implicit-TLS or STARTTLS form the page does not state; SSH
   for SFTP; OpenVPN; BitTorrent; chat clients); 2016-vintage names.
2. **CIC-IDS2017**: full payload, 5-tuple labels, test-bed services; measures wrong identifications.

### First download subset (about 10 GB), for when the licence is cleared

The file listing is visible only after registration, so the files cannot be named or sized here. The
subset is defined by what the pages state, to be matched against the listing Hermes sees:

| Priority | Take | Why | Size known? |
|---|---|---|---|
| 1 | **CIC-IDS2017, Thursday** ("attacks + Normal Activity, 7.8G") [D3] | benign HTTP/HTTPS/FTP/SSH/email from the test bed plus web attacks and infiltration; the smallest day with attacks | yes, 7.8 GB |
| 2 | **ISCX VPN-nonVPN 2016, VPN P2P and P2P** captures | OpenVPN (UDP) [D1] and BitTorrent (uTorrent, Transmission) [D1] | no |
| 3 | **ISCX VPN-nonVPN 2016, Email** captures | Thunderbird over SMTP/S, POP3/SSL, IMAP/SSL [D1] | no |
| 4 | **ISCX VPN-nonVPN 2016, File Transfer** captures (SFTP, FTPS only) | SSH and FTP with TLS [D1] | no |
| 5 | **ISCX VPN-nonVPN 2016, Chat** captures | ICQ and AIM through Pidgin, Skype, web chat [D1] | no |
| skip | ISCX Streaming and VoIP captures; CIC-IDS2017 Monday (11.0G) | large, and they add little family coverage (TLS and UDP media); Monday is benign only | Monday yes |

Rule for priorities 2 to 5: stop when the total reaches about 10 GB, taking one capture per application
before a second capture of any application. Priority 1 alone is 7.8 GB, so for a strict 10 GB cap,
Hermes can take priority 1 plus up to about 2 GB from priorities 2 to 5, or skip priority 1 in a first
round focused on families.

## Decisions

- **LEE-1**: decided (above).
- **LEE-2**: download approved in principle. **Held** by this lane's recommendation until CIC's licence
  is confirmed in writing, because the dataset pages do not clearly allow commercial use.

## Sources (all accessed 2026-11-18)

- [D0] UNB CIC, Datasets index and FAQ, `https://www.unb.ca/cic/datasets/index.html`
- [D1] UNB CIC, "VPN-nonVPN dataset (ISCXVPN2016)", `https://www.unb.ca/cic/datasets/vpn.html`
- [D2] UNB CIC, "Tor-nonTor dataset (ISCXTor2016)", `https://www.unb.ca/cic/datasets/tor.html`
- [D3] UNB CIC, "Intrusion detection evaluation dataset (CIC-IDS2017)", `https://www.unb.ca/cic/datasets/ids-2017.html`
- [D4] UNB CIC, "CSE-CIC-IDS2018", `https://www.unb.ca/cic/datasets/ids-2018.html`
- [D5] UNSW, "The UNSW-NB15 Dataset", `https://research.unsw.edu.au/projects/unsw-nb15-dataset`
- [D6] MIRAGE, `https://traffic.comics.unina.it/mirage/`, `mirage-genai-2025.html`, `mirage-2019.html`
- [D7] Stratosphere Laboratory, "Datasets Overview" (CTU-13), `https://www.stratosphereips.org/datasets-overview`
- [D8] Stratosphere Laboratory, "Normal Captures", `https://www.stratosphereips.org/datasets-normal`
- [D9] Zenodo, "CESNET-TLS22" (v2, published May 24, 2023; newer version exists), `https://zenodo.org/records/7965515`
- [D10] Zenodo, "CESNET-QUIC22" (v1, published December 7, 2022; newer version exists), `https://zenodo.org/records/7409924`
- [D11] MAWI Working Group Traffic Archive, `https://mawi.wide.ad.jp/mawi/`
- [D12] CAIDA, "The CAIDA Anonymized Internet Traces Dataset (April 2008 - January 2019)", `https://www.caida.org/catalog/datasets/passive_dataset/`
- [D13] Wireshark Wiki, "SampleCaptures", `https://wiki.wireshark.org/SampleCaptures`
