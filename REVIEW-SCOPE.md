# Review scope: protocol detector v0.16

Python3.9-compatible IPv4-only bounded protocol classification. Coverage is
36 families,32 automatic, with narrow profiles documented in PROTOCOLS.md.
Review protocol_engine/, sessions.py and both capture adapters for false positives,
ambiguity, malformed lengths, reassembly/lifecycle and CPU/memory bounds.

New focus: native Git service framing and internal Git/text ambiguity routing.
Four lowercase hex bytes plus git- select a private route, not an identity.
The first bounded NUL/LF field chooses strict Git or text parsing; it is replayed
once into one parser. Explicit git hints remain strict; internal git_text cannot
be requested as a hint. Review fragmentation/consumption accounting and valid HTTP
extension methods sharing the prefix. Git paths/hosts/opaque extras are not output
as identity; offered_version is not negotiated version. No packfile, server or
Git-over-SSH/HTTPS recognition is claimed.

Earlier fixes validate leading overlaps, preserve PCAP truncation metadata with
retractions, reject reserved IPv4 flags and publish directional invalidation on
control rejection. FIN/payload ends share origin-relative coordinates. Multiple
sequence epochs and endpoint receive-window validation remain unsupported.

252 tests passed on the installed Python3.9.6 copy. Native Git interoperability
was checked with installed Git2.50.1 and a synthetic IPv4 loopback server, with
user/system Git configs disabled. The actual loopback smoke capture identified
16 streams/datagrams across14 families, including Git, with zero reported kernel
drops. Verification scripts and JSON reports have matching source fingerprints.
BENCHMARK-V016.md includes the ~10.7% cost for the deliberately ambiguous HTTP
method path; normal HTTP/TLS/SSH medians remained close in this single-host run.
None of these results establish production latency, throughput or accuracy.

Only synthetic fixtures are uploaded. Backups, development notes, credentials,
old source copies and replay logs are excluded. Provide concrete reproductions.
