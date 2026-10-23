# Benchmark v0.62: SNMPv3 security level

Local CPU work, not production SWG latency. Baseline is v0.61 (19dbe32) in a
worktree. The A/B flows of `benchmark_ab.py` do not include SNMP; the changed
paths are the SNMPv3 datagram and the risk pass, measured directly (fresh
DatagramInspector, then `classify` on the observation; best of five runs of
3000, two runs each):

| Message | v0.61 inspect (us) | v0.62 inspect (us) | v0.61 classify (us) | v0.62 classify (us) |
|---|---|---|---|---|
| SNMPv2c get (`SNMP`) | 25.0, 26.3 | 26.5, 24.8 | 6.1, 6.5 | 7.2, 6.7 |
| SNMPv3 discovery (`SNMPV3_DISCOVERY`) | 32.2, 32.4 | 34.9, 35.7 | 4.4, 4.2 | 6.5, 6.3 |
| SNMPv3 encrypted (`SNMPV3_ENCRYPTED`) | 27.9, 28.4 | 29.0, 28.3 | 4.7, 4.4 | 5.7, 5.6 |

SNMPv3 messages gain one or two evidence rows, and the risk pass keeps the
SNMP level, discovery marker and PDU name of one observation to apply the
exemptions: about 1-2 us more per SNMPv3 classification, bounded by the fixed
number of evidence rows per message. SNMPv1/v2c is within noise.
