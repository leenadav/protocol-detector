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
| ISCX VPN-nonVPN 2016 (UNB CIC) | yes: "full packet in pcap format" [D1] | per traffic type and application, by the generating client (one application per capture) [D1] | redistribution with citation, commercial use included (CIC FAQ) [D0] | **high** (families); medium (applications, 2016 names) |
| ISCX Tor-nonTor 2016 (UNB CIC) | yes: "full packet in pcap format" [D2] | per application, from the workstation capture, transferred to the Tor capture [D2] | as D0 | medium (Tor traffic is TLS to relays) |
| CIC-IDS2017 (UNB CIC) | yes: "full packet payloads in pcap format" [D3] | per flow (5-tuple, time) as benign or attack, from the test bed; no protocol or application label [D3] | as D0 | **high** for false positives and the test-bed families |
| CSE-CIC-IDS2018 (UNB CIC) | not determined from the page | per flow (FlowID, IPs, ports, protocol) from CICFlowMeter, attack scenarios [D4] | as D0 | not assessed further |
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

**D0 · CIC licence (all UNB CIC datasets).** FAQ: "you may redistribute, republish, and mirror our datasets
in any form. However, any use or redistribution of the data must include a citation to the dataset and the
research paper listed." Asked about commercial use by private companies, the FAQ gives the same answer.
Download is through a form at the bottom of each dataset page.

## Recommendation

1. **ISCX VPN-nonVPN 2016: first choice for family-level D09.** Full pcaps; labels from the generating
   client; covers families the engine claims (TLS, including the mail and FTPS sessions, whose
   implicit-TLS or STARTTLS form the page does not state; SSH for SFTP; OpenVPN; BitTorrent); a licence that permits commercial use with citation; small enough (28 GB) to
   evaluate locally. Limits: 2016 vintage, so application-level (server-name) scores would test 2016
   names, not today's catalog, and should be reported separately. The labels are per capture, so a
   per-flow manifest must be built from the capture's stated application without consulting the engine,
   and noisy flows (the browsing in the Hangouts captures) left unlabelled rather than guessed.
2. **CIC-IDS2017: second, for false positives and the test-bed services.** Full payload; per-flow 5-tuple
   labels; same licence. Family labels come from the documented test bed (`label_basis: test-bed`). Its
   main value is the large benign and attack volume, which measures **wrong identifications** (the
   outcome D09 says matters most).
3. **MIRAGE-GenAI-2025: most relevant to the product's generative-AI questions, but held for LEE.** It
   labels ChatGPT, Copilot and Gemini traffic by app and activity, but its CC BY-NC-ND 4.0 licence
   prohibits commercial use and derivatives, and its JSON format is not yet known to contain packet bytes
   the engine can read.

Not recommended: CTU-13, CAIDA (no payload), CESNET (flow features only), MAWI (unlabelled), Wireshark
samples (licence not stated), UNSW-NB15 unless Lee obtains the authors' agreement for commercial use.

A note on scope, not a dataset: none of these public sets reflects 2026 enterprise SaaS and AI host
names. The D09 document itself names "test-bed captures labelled from the generating clients" as an
acceptable corpus. A Culvert lab capture of scripted clients (Microsoft 365, Copilot, Claude, ChatGPT)
would test the current catalog. Whether to produce one is Lee's decision; this lane only notes it.

## Decisions for Lee

- **LEE-1**: may D09 use a dataset whose licence is non-commercial (MIRAGE, CC BY-NC-ND) or
  academic-only (UNSW-NB15), given the evaluation serves a commercial product? Recommended answer from
  this lane: no, unless the authors grant permission in writing.
- **LEE-2**: approve downloading ISCX VPN-nonVPN 2016 (about 28 GB) and CIC-IDS2017 (per-day files) to a
  machine outside the repository, through the CIC download form, for D09.

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
