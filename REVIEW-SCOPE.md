# Review scope: protocol detector v0.14

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

Verification: 239 unit tests passed on local Python 3.9.6, including overlap-oracle, capture-path and directional control-retraction regressions.
Synthetic IPv4 loopback smoke testing identified 15 sessions across 13 families
with zero reported kernel drops. No customer traffic is included.

v0.13 also fixes missing structured retractions on rejected FIN/SYN-ACK/URG/ACK
state. Offline events-only now receives the same directional invalidation as
live capture, and live event counters include it exactly once.
BENCHMARK-V013.md documents paired synthetic CPU measurements and limitations.
Ordinary cases changed by about 1% or less; the corrected control rejection
path costs about 4.8% more to publish the missing structured event. These measurements do not establish production latency or accuracy.
Earlier reports are historical and retain their own source fingerprints.

Synthetic PCAP files are generated examples. Local backups, development handoff
notes, old source copies and replay logs are excluded from this review snapshot.


v0.14 rejects compact FINs ending wholly before the retained origin instead of
interpreting them as future boundaries. It preserves zero-boundary and
origin-crossing cases. Multiple sequence epochs remain unsupported; half-range
FIN ambiguity is rejected conservatively. Five regression tests expose 17 failing
baseline subcases. BENCHMARK-V014.md has current source fingerprints and paired
measurements; earlier reports refer to their historical versions.
