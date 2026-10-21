# App-ID roadmap (working notes, branch claude/appid-engine)

Goal: evolve the bounded initial-message classifier into a Palo Alto App-ID style
passive application identification product, without abandoning the existing
contracts (structural evidence, explicit budgets, no payload leakage, Python 3.9,
no runtime dependencies, IPv4 only). Each milestone ships with tests, PROTOCOLS/
ARCHITECTURE/README updates, a Hebrew START-HERE note and a paired benchmark.

| Version | Milestone | State |
|---|---|---|
| v0.22 | Verdict layer (web-browsing/ssl/unknown-tcp/incomplete/insufficient-data/not-applicable), application catalog (category, subcategory, technology, risk, characteristics, standard ports, implicitly-uses, depends-on, aliases), application-default port check, bidirectional session verdict, TCP/UDP session ledger records | done |
| v0.23 | Custom App-ID signatures: JSON rule files, string/integer contexts, pattern/equal/less/greater, and/or/negate, ordered conditions, 7-byte literal anchor prefilter, unknown-req-tcp/udp-payload | done |
| v0.24 | Fingerprints: JA3/JA4 (client), JA3S/JA4S (server), HASSH (SSH KEXINIT), HTTP/2 SETTINGS fingerprint | done |
| v0.25 | QUIC v1/v2 Initial: long header, HKDF/AES-128-GCM Initial decryption in pure Python, CRYPTO assembly, SNI/ALPN (h3) | done |
| v0.26 | IP-level protocols and tunnel inner decode | dropped: the engine stays an application-layer classifier over TCP/UDP; non-TCP/UDP IP protocols remain counted as unsupported packets |
| v0.27 | More decoders: FTP, POP3, IMAP client, Telnet, SMB1, NetBIOS, Kerberos, WireGuard, OpenVPN, PPTP, L2TP, TACACS+, SSDP, NetFlow/IPFIX, sFlow, Modbus, DNP3, BACnet, ISO-TSAP, ENIP, IEC104, Kafka, CQL, RTP (hint); greeting/command correlation (220+USER=ftp, +OK=pop3) | done (mDNS/LLMNR and S7comm deferred) |
| v0.28 | Application shift at exact protocol boundaries: CONNECT tunnel, WebSocket/h2c upgrade, SMTP/IMAP/POP3 STARTTLS, FTP AUTH TLS, PostgreSQL/MySQL SSLRequest, RDP negotiation (client request and server confirm) | done |
| v0.29 | Unknown-traffic heuristics (entropy, printable ratio, DNS name shape; opt-in, advisory only) and nDPI-style flow risks on every verdict | done |
| v0.30 | Policy evaluation (allow/deny/alert by app, alias, outcome, category, technology, risk, characteristics, flow risks, ports, encryption, shift carrier; application-default; dependency and never-match warnings), `protodetect` entry point, final docs; the CI matrix shipped with the SSDLC work | done |

Conventions: new parsers get all-split-point, single-byte, mutation and budget
tests; evidence strengths are structural / asserted / offered / derived /
heuristic / configured_mapping / context; no hostname, path, credential or
payload bytes appear in live output unless explicitly enabled.

Status: the roadmap is complete at v0.30; v0.31 added pcapng input, v0.32 S7comm after ISO-TSAP v0.33 server-side CONNECT correlation v0.34 published output schemas and v0.35 the ClientHello hot-path rewrite (post-roadmap work). Later work (mDNS/LLMNR,
SMB1 session setup, HTTP/2 server frames
after h2c, certificate-based risks) is listed in PROTOCOLS.md and RISKS.md
under their exclusions and remains out of scope until requested.
