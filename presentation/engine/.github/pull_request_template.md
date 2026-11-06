## Summary

<!-- What changes and why. Link the PROTOCOLS.md / APPID.md section you touched. -->

## Security review checklist (SSDLC gate)

- [ ] Every new parser bounds advertised lengths and counts **before** allocation (BudgetError, not MemoryError)
- [ ] Added tests: all split points, single-byte feeds, truncation at every offset, seeded mutations
- [ ] No payload bytes, credentials, hostnames or opaque identifiers enter `reason`, evidence or live output by default
- [ ] Hints select candidates only; they never establish identity
- [ ] Ambiguity returns `unknown`, never a guess; competing budget failures block identification
- [ ] PROTOCOLS.md states the exact profile and exclusions; ARCHITECTURE.md states new invariants
- [ ] THREAT-MODEL.md updated if a trust boundary, asset or attacker capability changed
- [ ] SECURITY-REQUIREMENTS.md row added or updated with the test that verifies it
- [ ] Benchmark run recorded (BENCHMARK-Vnnn.md) when the hot path changed
- [ ] No new runtime dependency; Python 3.9 syntax only

## Threat considerations

<!-- Which attacker-controlled inputs reach the new code? What is the worst case CPU/memory per byte? -->
