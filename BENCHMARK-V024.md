# v0.24 fingerprints: cost, and a correction to earlier benchmark methodology

Python 3.13.16 on Linux-6.18.44-fc-v139-x86_64-with-glibc2.39 (shared cloud container, 4 vCPU).

## Measurement artifact found and fixed

While comparing v0.23 and v0.24 the baseline tree (a fresh `git worktree`
checkout) ran the **same unchanged code** 50% slower than the development tree
(`ssh_flow` 132 us vs 80 us). The cause is bytecode caching: a tree without
`__pycache__` is compiled from source at import, and on this interpreter the
resulting code objects execute measurably slower than those loaded from `.pyc`
files for the whole process lifetime. Byte-compiling the baseline removed the
gap completely (80.2 us vs 80.4 us).

Consequences for the record:

- BENCHMARK-V022.md's paired table compared a byte-compiled development tree
  against an uncompiled baseline, which **understates v0.21** and overstates
  the v0.22 overhead; its separately measured per-call costs (classify about
  2 us) stand. BENCHMARK-V023.md's paired table was additionally dominated by
  host noise, as that document already states.
- `benchmark_ab.py` now byte-compiles both trees before measuring and runs the
  interpreters without `-B`. The chain below was produced with it (3
  alternations, 7 repeats of 400 flows, minimum, constructor subtracted).

## Corrected chain v0.21 -> v0.24 (microseconds per flow/datagram)

| Case | v0.21 | v0.22 | v0.23 | v0.24 (fingerprints off) | v0.24 (fingerprints on) |
|---|---:|---:|---:|---:|---:|
| http_flow | 94.4 | 102.0 | 100.4 | 101.5 | 101.6 |
| tls_flow | 108.4 | 116.4 | 118.6 | 119.2 | 185.5 |
| tls_server13 | 85.6 | 86.8 | 88.1 | 95.7 | 115.2 |
| ssh_flow | 68.2 | 77.8 | 78.4 | 73.3 | 80.8 |
| dns_datagram | 23.1 | 34.5 | 36.8 | 35.5 | 37.4 |
| dtls_datagram | 25.7 | 38.9 | 38.7 | 38.1 | 53.0 |
| udp_unknown | 12.0 | 17.1 | 17.1 | 16.5 | 17.1 |

Reading the chain:

- v0.22 (verdicts, counters, session ledger): about +8 us per TCP flow and
  +11..13 us per datagram (verdict about 2 us; flow bookkeeping, byte counters
  and the extra event field make up the rest). This is the true cost of the
  App-ID layer.
- v0.23 (signatures, retention off): within noise (-1.6..+2.3 us).
- v0.24 with fingerprints off: within noise except `tls_server13` (+7.6 us,
  the ServerHello now returns its extension order to the caller) and
  `ssh_flow` (-5 us, noise).
- v0.24 with fingerprints on: TLS ClientHello +66 us (`ClientHelloInfo`
  materialization plus JA4 and JA3: sorting, hex formatting, SHA-256 and MD5),
  DTLS +15 us (JA4 only), ServerHello +20 us (JA4S and JA3S), SSH +7.5 us for
  the KEXINIT continuation in this fixture (the banner-only flow has no
  KEXINIT, so the cost here is the continuation state and its end). Formatting
  dominates; the digests themselves are about 1 us each. A table-driven hex
  formatter is the obvious next optimization if fingerprints are left on by
  default on a busy sensor.

Fingerprints are off by default. No production latency or accuracy claim is
made; measure on target hardware with representative traffic.

## Verification

349 tests pass, 10 new in test_fingerprints.py: JA4 against an independent
computation with GREASE, ALPN edge cases and empty cipher lists; the JA4S
specification example `t130200_1301_a56c5b993250`; JA3/JA3S/HASSH/HTTP2 against
their definitions; every-37th-byte splits of a real ClientHello; server hello
and retry; DTLS protocol code; SSH banner-then-KEXINIT across all split points
with byte accounting; continuation failure, oversized packet, budget, EOF and
invalidation never downgrading the identification; fixtures unchanged with
fingerprints on; session records, live events (`updated`/`refined`) and offline
JSON carrying fingerprints.
