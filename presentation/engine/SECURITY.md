# Security policy

## Scope

This repository is a passive, bounded protocol/application classifier. Its
attack surface is the bytes it inspects: every TCP payload, UDP datagram and
PCAP record is attacker-controlled. The security goals are therefore:

1. **Bounded work**: CPU and memory per input byte are capped by `Config`
   budgets; no input may cause unbounded allocation, recursion or quadratic work.
2. **No false identity**: an identification requires the documented structural
   profile; hints, ports and ambiguous structures never establish identity.
3. **No data leakage**: payload bytes, credentials, hostnames, paths and opaque
   identifiers never appear in reasons, evidence or default live output.
4. **Integrity awareness**: conflicting reassembly, control-plane rejection and
   capture loss retract earlier labels instead of keeping a stale verdict.

Out of scope: decryption, policy enforcement, forwarding and the capture
helper's privileges (tcpdump runs separately; Python stays unprivileged).

## Supported versions

Only the latest tagged minor version on the default branch receives fixes.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository (Security →
Report a vulnerability). Include: the input (PCAP or hex), the command, the
observed consequence (crash, work amplification, wrong identification, leaked
value) and the version. Do not open a public issue for unpatched findings.

Expected handling: acknowledgement within 3 working days, a reproducing test
within 7 days, a fix or documented mitigation within 30 days for findings that
break one of the four goals above. Each fix ships with a regression test, a
PROTOCOLS.md/ARCHITECTURE.md note and, where the hot path changed, a benchmark.

## Verification you can run

```bash
make check                       # tests, lint, pins, security-requirement gate
python3 -B tools/fuzz_fixtures.py --iterations 2000
```

See SSDLC.md for the lifecycle, THREAT-MODEL.md for the threat model and
SECURITY-REQUIREMENTS.md for the requirement-to-test mapping enforced in CI.
