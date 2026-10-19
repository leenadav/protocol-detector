# Review scope: protocol detector v0.15

Review the complete implementation, especially protocol_engine/, sessions.py,
analyze_pcap.py, capture_stream.py and live_capture.py. It supports 35 families,
31 with automatic profiles; PROTOCOLS.md specifies the narrow supported messages
and candidate requirements. Python 3.9 and IPv4 only.

Prioritize false positives, malformed/truncated input, ambiguous prefixes,
reassembly conflicts and lifecycle, bounded CPU/memory and missing independent
tests. Provide concrete reproductions where possible.

Capture corrections validate leading overlaps, preserve offline PCAP original
length/truncation metadata with explicit retractions, reject reserved IPv4 flags,
and publish structured directional events on TCP control rejection. FIN and
payload ends use consistent origin-relative coordinates: pre-origin FINs are
rejected, harmless wholly pre-origin payload is ignored even after FIN, and
crossing payload beyond FIN is rejected. Multiple sequence epochs/endpoint
receive windows remain unsupported. The legacy read_pcap API rejects truncation;
read_pcap_records exposes metadata.

Verification: 241 tests passed on the installed Python 3.9.6 copy. These include
independent overlap and absolute FIN-coordinate oracles, wraparound, capture-gap,
malformed capture and live/offline output regressions. BENCHMARK-V015.md and its
JSON report contain current paired synthetic CPU measurements and fingerprints.
Ordinary-path p50 differences were about -1% to +3%; no statistical significance
or production latency/accuracy is established. Earlier reports are historical.
The v0.12 physical loopback smoke report covers only that earlier source version;
later changes use synthetic frame tests through the actual capture adapter.

Synthetic PCAP fixtures only; no customer traffic. Backups, development handoff
notes, old source copies, credentials and replay logs are excluded.
