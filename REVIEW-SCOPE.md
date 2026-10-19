# Review scope: protocol detector v0.17

Python 3.9-compatible IPv4-only bounded protocol classification: 37 families,
33 automatic, narrow profiles documented in PROTOCOLS.md. Review protocol_engine/,
sessions.py and both capture adapters for correctness and CPU/memory bounds.

New focus: GIOP 1.2 unfragmented KeyAddr Request/LocateRequest in either byte order.
CDR alignment is relative to the whole message, padding values are arbitrary,
and lengths/counts are bounded before slicing/iteration. Request arguments and
service contexts are opaque. No object keys/operation names/opaque payload output.
Check empty bodies versus alignment, unsupported variants, strict hints and HTTP
extension-method prefixes. No full CORBA/IDL decoding or ORB interoperability claim.

Native Git framing and its bounded private Git/text route remain part of review.
Earlier fixes validate leading overlaps, preserve PCAP truncation with retractions,
reject reserved IPv4 flags and emit directional control invalidation. FIN/payload
ends share coordinates. No multiple-epoch or endpoint receive-window validation.

261 installed tests pass, with all cuts/bytewise input, independent endian fixtures,
1,800 mutation fragmentation comparisons, negative fields, budgets and hint checks.
Actual local synthetic IPv4 capture: 145 packets,17 identifications,15 families,
zero reported kernel drops. BENCHMARK-V017.md and JSON report paired CPU costs;
ordinary existing p50 paths range approximately -1.4% to +1.9% in this run.
New GIOP work is compared to a baseline which did not identify it. No production
latency, throughput or accuracy claim. Existing Git interop report remains v0.16.

Only synthetic fixtures uploaded. Backups, development notes, credentials, old
source copies and replay logs excluded. Provide concrete reproductions.
