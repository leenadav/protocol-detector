# v0.27 decoder expansion: CPU cost

Python 3.13 on Linux-6.18.44-fc-v139-x86_64 (shared cloud container, 4 vCPU).
`benchmark_ab.py --baseline <v0.25 worktree at 57cb64a>` (both trees
byte-compiled, 3 alternations, minimum of 7 x 400 flows, constructor
subtracted), microseconds per flow/datagram. The host was slower than during
the v0.25 run (every absolute number is about 20-25% higher on both trees), so
only the within-run comparison is meaningful.

| Case | v0.25 (same run) | v0.27 | change |
|---|---:|---:|---:|
| http_flow | 132.4 | 127.2 | -3.9% |
| tls_flow | 162.3 | 156.0 | -3.9% |
| tls_server13 | 119.8 | 118.4 | -1.2% |
| ssh_flow | 94.9 | 97.4 | +2.6% |
| dns_datagram | 41.1 | 42.3 | +2.9% |
| dtls_datagram | 45.9 | 47.3 | +3.1% |
| udp_unknown | 21.1 | 22.6 | +7.1% |
| quic_initial | 2598.0 | 2661.5 | +2.4% |

- TCP paths are unchanged within noise: `select` still reads fixed positions
  in the prefix, and the 0x00/0x01 block gained four byte-compares before the
  existing PostgreSQL test (SMB1, PPTP, Kerberos, Modbus) plus the Kafka probe.
- UDP paths pay for the appended candidate probes (NetFlow, sFlow, BACnet,
  Kerberos, OpenVPN, L2TP, EtherNet/IP). On a datagram that matches nothing
  (`udp_unknown`, 32 x 0xff) this is about +1.5 µs; DNS and DTLS run their own
  validator after the same probes (+1.2..1.4 µs). The validators themselves
  never run unless a constant-size probe passes.

## Per-family cost of the new decoders (in-process, minimum of 5 x 2000)

| Stream fixture | bytes | µs |
|---|---:|---:|
| ftp (`FEAT`) | 6 | 17.4 |
| pop3 server (`+OK …`) | 23 | 15.8 |
| imap client (`a001 CAPABILITY`) | 17 | 19.1 |
| telnet (two commands) | 6 | 12.0 |
| smb1 negotiate | 86 | 20.4 |
| netbios-ss | 72 | 26.0 |
| kerberos tcp | 102 | 17.9 |
| tacacs-plus | 24 | 11.6 |
| openvpn tcp | 16 | 18.0 |
| pptp SCCRQ | 156 | 13.9 |
| modbus | 12 | 13.4 |
| dnp3 (two CRC blocks) | 18 | 24.2 |
| iso-tsap | 22 | 15.9 |
| rdp via the TPKT route | 19 | 16.8 |
| ethernet-ip | 28 | 13.8 |
| iec-104 | 6 | 10.0 |
| kafka | 35 | 17.4 |
| cql/4 | 31 | 15.6 |
| ambiguous `220` greeting | 16 | 13.1 |
| ambiguous `USER` command | 12 | 18.6 |

| Datagram fixture | bytes | µs |
|---|---:|---:|
| wireguard | 148 | 7.6 |
| openvpn | 14 | 9.7 |
| l2tp/2 | 38 | 10.8 |
| ssdp (HTTP header block) | 94 | 32.5 |
| netflow/5 (two records) | 120 | 9.3 |
| netflow/9 | 40 | 8.5 |
| ipfix | 32 | 8.3 |
| sflow/5 | 64 | 8.9 |
| bacnet | 12 | 7.9 |
| kerberos udp | 98 | 11.4 |
| ethernet-ip udp | 24 | 11.8 |
| rtp (hint) | 32 | 5.3 |
| dns (existing, reference) | 33 | 12.2 |
| unknown (32 x 0xff, reference) | 32 | 4.7 |

- DNP3 is the most expensive stream decoder per byte because the CRC is a
  bit-serial pure-Python loop (about 0.9 µs per byte); frames are bounded at
  255 user bytes, so the worst case is about 250 µs per frame.
- NetBIOS session requests check 64 encoded letters in a Python generator;
  SSDP reuses the HTTP LineParser and therefore costs the same as a small HTTP
  request.
- Kerberos uses the shared BER helpers with explicit limits; depth is fixed by
  the profile (four nesting levels), so no attacker-chosen recursion exists.

## Verification

381 tests pass (22 new in test_decoders_v027.py, two existing tests adjusted:
`0x05 0x64` now routes to DNP3 instead of SOCKS5, and a tagged IMAP command is
identified rather than rejected). The all-split-point, single-byte, EOF,
fragmentation-equivalence and seeded-mutation suites in test_expansion.py
cover every new stream fixture automatically through `STREAM_CASES`; the
datagram suites cover the new UDP fixtures through `DATAGRAM_CASES` and
`HINTED_DATAGRAM_CASES`. `tools/fuzz_fixtures.py --iterations 300`: 22,200
cases, no crash, no double candidate, no over-inspection.
