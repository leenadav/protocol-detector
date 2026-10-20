# Threat model

Method: STRIDE over the data flow, with each mitigation tied to a test or a
CI gate (SECURITY-REQUIREMENTS.md). Revisit when a trust boundary, asset or
attacker capability changes; the PR template asks for this.

## Assets

- **Correctness of verdicts**: downstream policy may allow or block on them.
- **Confidentiality of inspected traffic**: the tool must not become a
  payload/credential logger.
- **Availability of the inspecting host**: bounded CPU and memory per flow.
- **Integrity of the supply chain**: the published package and CI toolchain.

## Trust boundaries and data flow

```
 untrusted network ──▶ tcpdump (privileged, separate process) ──▶ PCAP pipe
      PCAP file ─────────────────────────────────────────────────▶ PcapStreamDecoder
                                                                      │ records (bounded 64KiB chunks)
                                                                      ▼
                                                     link_packets.decode_frame (IPv4 TCP/UDP only)
                                                                      │
                                     ┌────────────────────────────────┴───────────────────┐
                                     ▼                                                    ▼
                 Analyzer/SessionManager (bounded prefix reassembly)          DatagramInspector (one payload)
                                     │ ordered new bytes                                  │
                                     ▼                                                    ▼
                           Inspector → one parser (prefix dispatch)             ≤3 preselected validators
                                     │ Observation (no payload values)                    │
                                     └──────────────────────┬───────────────────────────┘
                                                            ▼
                                             appid.session_verdict → session record
                                                            ▼
                                        stdout JSON / readable lines (no payload, hostnames opt-in)
```

Everything left of the decoder is attacker-controlled. Configuration (`Config`,
`RuleIndex`, hints, CLI flags) is operator-controlled and trusted. Decrypted
plaintext fed through `feed_decrypted()` is trusted to come from the host TLS
stack. Nothing in the engine performs network I/O.

## Attacker capabilities considered

A1 sends arbitrary bytes on any port. A2 reorders, duplicates, overlaps or
retransmits TCP segments with conflicting content. A3 crafts messages valid in
two protocols at once. A4 inflates advertised lengths/counts (DNS counts, BER
lengths, MQTT varints, FastCGI params, IKE proposals). A5 truncates captures or
induces kernel drops. A6 attempts to make the tool print payload (e.g. hostnames
or SOCKS targets chosen as exfiltration vectors). A7 supplies a malicious PCAP
file (lengths, link types, IPv6). A8 compromises a CI dependency or action.

## Threats and mitigations (STRIDE)

| ID | Threat | Category | Mitigation | Verified by |
|---|---|---|---|---|
| T1 | Port-based or hint-based misidentification (A1) | Spoofing | Structural profiles only; hints restrict candidates; ambiguity → unknown | SR-2, SR-3 |
| T2 | Conflicting overlap keeps a stale label (A2) | Tampering | Conflicts checked before writes; invalidate() retracts; control rejection publishes retraction | SR-4, SR-5 |
| T3 | Dual-valid encodings (DNS/CoAP, DHCP/IKE, DNS/RADIUS) (A3) | Spoofing | Multiple matches → unknown; competing budget failure blocks identification | SR-3 |
| T4 | Work/allocation amplification through advertised sizes (A4) | DoS | Budgets checked before allocation; aggregate work counters; frame size vs max_bytes | SR-1, SR-6 |
| T5 | Capture loss turned into clean EOF (A5) | Repudiation | Truncation/drops emit capture_gap and clear state; exit code 2 | SR-7 |
| T6 | Payload or credential leakage (A6) | Information disclosure | Reasons/evidence contain no values; live output omits hostnames by default; session records opt-in | SR-8, SR-9 |
| T7 | Malicious PCAP structure (A7) | DoS/Tampering | Snaplen/length/timestamp validation; 1MiB snapshot cap; IPv6 and unknown link types rejected | SR-10, SR-11 |
| T8 | Shell injection through interface/BPF (operator input reaching tcpdump) | Elevation | argv only, no shell, strict interface regex | SR-12 |
| T9 | Decrypted-plaintext API misuse (feeding ciphertext) | Spoofing | feed_decrypted requires an identified TLS envelope; source provenance recorded | SR-13 |
| T10 | Reference cycles delaying buffer release under load | DoS | Unbound callbacks, weak owner references; GC-disabled release tests | SR-14 |
| T11 | Compromised CI action or dev dependency (A8) | Tampering | SHA-pinned actions, hash-pinned dev requirements, read-only token, SBOM, provenance attestation | CI gates |
| T12 | Session verdict overstates evidence | Spoofing | Verdict precedence preserves engine status; custom mappings keep base_app; no risk inference from traffic | SR-15 |
| T14 | Flood of 1200-byte QUIC Initials forces about 2 ms of pure-Python AES-GCM each (A1) | DoS | Only Initial-type long headers with supported versions are opened; datagram bounded by max_bytes; `Config.quic_decrypt=False` disables; per-packet cost documented; host owns rate limiting | SR-23, BENCHMARK-V025.md |
| T13 | Operator-authored signature causes regex backtracking blow-up or retains payload (A1 drives input, operator error supplies the pattern) | DoS / Information disclosure | Parse-tree checks, literal anchor, substring prefilter, bounded buffers; contexts internal only | SR-18, SR-19 |

Residual risks: Python regex engines are backtracking; built-in patterns are
anchored and linear, and custom signatures (v0.23) are restricted to a safe
subset with a literal anchor and bounded input, which rules out nested
quantifiers but not every slow pattern (a 4096-wide bounded repeat over a
2000-byte buffer is still linear work per attempt). CPU cost is bounded but not
constant-time; a flood of connections is handled by the connection cap, not by
rate limiting, which belongs to the host.
