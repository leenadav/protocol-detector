# Initial review: protocol detector v0.11

Review the complete current implementation, with priority on `protocol_engine/`,
`sessions.py`, `analyze_pcap.py`, `capture_stream.py` and `live_capture.py`.
The implementation supports 35 families, 31 with automatic profiles; see
PROTOCOLS.md for exact coverage and candidate requirements.

Focus on false positives, malformed/truncated inputs, ambiguous prefixes,
reassembly conflicts and lifecycle, bounded CPU/memory, and missing independent
tests. Provide concrete reproduction inputs for findings where possible.

Baseline verification: 218 unit tests passed on local Python 3.9.6. The latest
live demonstration used synthetic IPv4 loopback traffic only: 123 captured
packets, 15 identifications across 13 families, zero reported kernel drops.
These results do not establish accuracy on representative production traffic.

BENCHMARK-V011.md documents reassembly measurements, including an explicit
regression for conflicts at the first byte of a fully retained large range.
Earlier benchmark reports are historical and have distinct source fingerprints.

Synthetic PCAP files are generated examples, not captured customer traffic.
Local backups, development handoff notes, old source copies and replay logs
are excluded from this review snapshot. No runtime source files were changed
while preparing this snapshot.
