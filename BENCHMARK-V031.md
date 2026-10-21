# v0.31 pcapng framing: CPU cost

Python 3.13 on Linux-6.18.44-fc-v139-x86_64 (shared cloud container), same
interpreter, minimum of 7 x 50 full decodes of 240 records fed in 64 KiB chunks.

| Input | Size | µs per record |
|---|---:|---:|
| classic PCAP (unchanged path) | 19,804 B | 1.45 |
| pcapng Enhanced Packet Blocks (if_tsresol nanoseconds) | 23,824 B | 3.15 |
| pcapng Simple Packet Blocks | 19,976 B | 2.54 |

- A pcapng block costs about twice a classic record: the trailer length check,
  the interface lookup, the option walk (one `opt_endofopt` per packet in these
  fixtures) and the 64-bit timestamp division. Both are far below the
  per-packet decode and inspection cost (tens of µs), so capture format does
  not change end-to-end throughput measurably.
- The offline reader (`packets.read_pcap_records`) now streams the file
  through the same decoder in 64 KiB chunks instead of its own classic-only
  parser; `analyze_pcap` decodes frames by their link type, so raw IPv4,
  Linux cooked and loopback captures work offline as they already did live.

## Verification

415 tests pass (5 new in test_pcapng.py): byte-for-byte equivalence with the
classic decoder in both byte orders and with microsecond, nanosecond, binary
and millisecond `if_tsresol`; every split point and byte-wise feeding; Simple
Packet Blocks with and without snapshot clipping; several interfaces, several
sections (a second Section Header with the other byte order), skipped
statistics/name-resolution/custom/unknown blocks; twelve malformed documents
(byte-order magic, version, block length alignment and bounds, trailer
mismatch, unknown link type, oversized snapshot, undefined interface,
captured > snapshot, captured > original, missing section header, packet
without interface), an oversized block rejected from its header alone,
out-of-profile and truncated options, every truncation point (a cut between
blocks is a complete capture), 300 seeded single-byte mutations with a
dropped buffer after every failure, and the offline reader, `analyze` and
`live_capture --stdin` on pcapng input with identical results to classic input.
