# Protocol detector engineering and review guidance

This project is a Python 3.9-compatible, IPv4-only passive protocol classifier.
Read PROTOCOLS.md and ARCHITECTURE.md before reviewing coverage claims.
Run `python3 -B -m unittest discover -q` from the repository root.
Do not capture external or user traffic. Live smoke tests are opt-in and local
synthetic IPv4 loopback only. Ordinary tests need no capture privileges.

## Review priorities

- Report reproducible correctness and security bugs, with file/line, triggering
  input or sequence, observable consequence, and severity. Identify missing
  regression tests. Do not treat a passing suite as proof of correctness.
- A positive classification must satisfy its documented structural profile.
  Trace malformed lengths, truncated inputs, ambiguity, explicit hints and
  fragmentation. Hints select candidates; they must never establish identity.
- Reassembly must feed each contiguous byte once. Conflicting retained overlaps
  invalidate classification before admitting new bytes. Check wraparound, gaps,
  FIN/timeout/loss ordering, and both traffic directions.
- Parsing and reassembly must respect configured byte/count/depth budgets. Trace
  attacker-controlled CPU/allocation amplification, not just average performance.
  Do not recommend optimizing a hot path without preserving its error semantics.
- Do not emit payloads, credentials or opaque identifiers as application identity.
  TLS ClientHello metadata is an offer, not authenticated application identity.

## Intended limits

This is initial-message inspection, not a complete TCP stack or full-session
protocol validator. Profiles intentionally exclude features listed in PROTOCOLS.md.
Do not report those exclusions alone as bugs. Report contradictions between the
implementation and its stated contracts. Python remains required; no native
rewrite, IPv6 transport or proxy integration is in scope. Benchmarks report local
CPU work, not production SWG end-to-end latency.
