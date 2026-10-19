# Review scope: protocol detector v0.12

Review the complete implementation, especially protocol_engine/, sessions.py,
analyze_pcap.py, capture_stream.py and live_capture.py. The implementation
supports 35 families, 31 with automatic profiles; PROTOCOLS.md specifies the
narrow supported profiles and candidate requirements.

v0.12 fixes leading TCP overlaps at the retained origin, preserves offline PCAP
truncation metadata and retracts capture observations after gaps, and rejects
the IPv4 reserved flag consistently in offline and live capture paths.
The compatibility read_pcap API now rejects truncated records; consumers that
need their metadata must use read_pcap_records.

Focus on false positives, malformed/truncated inputs, ambiguous prefixes,
reassembly conflicts and lifecycle, bounded CPU/memory, and missing independent
tests. Provide concrete reproduction inputs where possible.

Verification: 230 unit tests passed on local Python 3.9.6, including twelve new
regression tests with independent overlap-oracle and capture-path checks.
Synthetic IPv4 loopback smoke testing identified 15 sessions across 13 families
with zero reported kernel drops. No customer traffic is included.

BENCHMARK-V012.md documents paired synthetic CPU measurements and limitations.
Ordinary-path changes were approximately 1–2% in this single-host run; the new
conflicting-overlap path intentionally does more validation than the incorrect
baseline. These measurements do not establish production latency or accuracy.
Earlier reports are historical and retain their own source fingerprints.

Synthetic PCAP files are generated examples. Local backups, development handoff
notes, old source copies and replay logs are excluded from this review snapshot.
