# v0.30 policy evaluation: CPU cost

Python 3.13 on Linux-6.18.44-fc-v139-x86_64 (shared cloud container, 4 vCPU),
same interpreter, minimum of repeats. No engine path changed in v0.30; a policy
is evaluated once per session record and once per live classification event
only when `--policy` is given, so the default cost is zero.

| Operation | µs |
|---|---:|
| telnet/23 against the 7-rule example policy (matches rule 2) | 1.36 |
| TLS/443 against the example policy (matches rule 3) | 1.77 |
| Modbus/502 against the example policy (matches rule 5, application-default) | 2.73 |
| Modbus/5020: no match, default plus the application-default explanation (second pass) | 7.60 |
| Modbus matching the 1000th rule of a 1000-rule policy (each rule has a port list) | 727.7 |
| telnet with no match in 1000 rules (default) | 164.5 |
| `Policy.from_path` of the example file | 89.3 |

- A rule costs about 0.15-0.7 µs to reject depending on how many conditions it
  carries before the first mismatch; `apps` is tested first, so rules that name
  applications reject most verdicts in one frozenset lookup. Operators who need
  thousands of rules should put the broadest rules first; evaluation is linear
  by design (no index), which keeps ordering semantics obvious.
- The default-decision explanation re-walks application-default rules with the
  port usage forced to standard. It is skipped unless the verdict's port usage
  is nonstandard, so it costs nothing on the common path.
- `protodetect` adds one `import` of the delegated module (tens of
  milliseconds once per process) and no per-packet work.

## Verification

410 tests pass (8 new in test_policy.py): the example policy loads and lints
clean; 22 malformed documents are rejected (unknown keys, names, ports,
ranges, risk bounds, duplicate or empty names, oversized files); alias
resolution; first-match ordering and defaults; every condition kind positive
and negative; application-default semantics and the fall-through explanation;
shift-aware matching (`shifted_from`); dependency and never-matching warnings;
session records, readable output, live events and summaries carrying
decisions; and the `protodetect` subcommands through subprocesses (version,
policy lint/test with strict exit codes, risks, signatures lint, analyze with
a policy, protocols, missing command).
