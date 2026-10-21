# Flow risks and unknown-traffic heuristics (v0.29)

Flow risks are advisory names attached to every session verdict and live
classification event (`risks`). They follow the idea of nDPI flow risks: a
documented condition over evidence the parsers already validated, useful for
policy and triage. A risk never identifies an application, never changes the
engine status, and never reads payload beyond the bounded initial message.
Heuristics (off by default, `Config(heuristics=True)`, CLI `--heuristics`) add
shape evidence for payload no profile matched and for DNS query names; their
evidence strength is `heuristic` and their thresholds are listed here.

## Risk table

| Risk | Severity | Condition (all structural unless marked heuristic) |
|---|---|---|
| `nonstandard-port` | medium | Identified application with `port_usage=nonstandard` (catalog ports, carrier ports after a shift count as standard) |
| `cleartext-credential-protocol` | medium | Identified application whose catalog characteristics include `cleartext-credentials` and no encryption in the session (FTP, POP3, IMAP, SMTP, Telnet, HTTP, ...). A STARTTLS/AUTH TLS shift to `ssl` clears it |
| `obsolete-protocol` | high | SMB1 negotiate; Telnet; SSH banner `1.99`; a ServerHello selecting TLS 1.1 or lower (`selected_tls_version`); RDP request offering only standard RDP security (`rdp_security_flags=0`) or a Connection Confirm selecting it (`rdp_selected_protocol=0`) |
| `tls-legacy-version-offer` | medium | ClientHello whose highest offered version is TLS 1.1 or lower: `supported_versions` when present (GREASE/unknown values skipped, legacy field ignored per RFC 8446 4.2.1), else the legacy field. Evidence `tls_offered_max_version` |
| `tls-missing-sni` | low | ClientHello (evidence `tls_offered_max_version` present) without `server_name` |
| `unknown-high-entropy-payload` | medium | `unknown-tcp`/`unknown-udp` whose profiled prefix has `payload_class=high-entropy` (heuristic, requires heuristics on) |
| `malformed-protocol` | medium | A direction ended `malformed`: a profile was selected and the message violated it |
| `dns-suspicious-query-name` | medium | DNS query with `dns_query_shape=suspicious` (heuristic, requires heuristics on) |
| `http-proxy-tunnel` | low | `http-proxy` verdict (CONNECT) or an application shifted from it |
| `desktop-or-file-sharing-session` | low | Application in rdp, vnc, smb, ftp, bittorrent, rsync, tftp |

Severities are editorial defaults for policy authoring (`protocol_engine.risks.RISKS`).
`protocol_engine.risks.flow_risks(verdict, client, server)` is one pass over
each direction's evidence (about 1-2 µs) and returns a sorted tuple.

## Unknown-payload heuristics

With heuristics on, a stream whose prefix no family selects (dispatch says
unknown) collects up to `heuristic_bytes` (default 512, 16..65536) before the
`unknown` observation is published (or the stream ends); a datagram is profiled
as a whole, bounded by the same limit. The profile is one pass with a 256-entry
histogram:

| Evidence | Meaning |
|---|---|
| `payload_bytes_profiled` | bytes used (<= heuristic_bytes) |
| `payload_entropy` | Shannon entropy, bits per byte, 0.00..8.00 |
| `payload_printable` | fraction of bytes in 0x09, 0x0a, 0x0d, 0x20..0x7e |
| `payload_class` | `insufficient` (< 8 bytes); `text` (printable >= 0.95); `high-entropy` (>= 64 bytes and entropy >= 0.90 x log2(min(size, 256)), the maximum a sample of that size can reach); `sparse-binary` (>= 30% zero bytes); else `binary` |

Encrypted, compressed and random data are indistinguishable at this level:
`high-entropy` means "no plaintext structure", not "a tunnel". With heuristics
on, an unknown stream's observation is published later (after up to
heuristic_bytes instead of at the first undispatchable bytes); custom
unknown-payload signatures use the larger of `signature_bytes` and
`heuristic_bytes`. No payload byte, hash or sample is emitted.

## DNS query-name shape

With heuristics on, every validated DNS message gains `dns_query_labels`,
`dns_query_longest_label`, `dns_label_entropy` (highest byte entropy among
labels of 16+ bytes, lower-cased) and `dns_query_shape`: `suspicious` when a
label is 40+ bytes, the name is 150+ bytes, or a label of 16+ bytes has
entropy >= 4.0 bits per byte; otherwise `ordinary`. The query name itself is
not emitted (it remains available only as a signature context when contexts
are retained). Long encoded labels (tunnelling), algorithmically generated
names and legitimate content-hash labels all trigger it; it is a triage hint.

## Not implemented

Certificate validation, TLS cipher-strength assessment, HTTP header anomaly
scoring, port scan or probing detection, periodicity/beaconing analysis, byte
distribution learning, and any risk that needs more than the initial message.
