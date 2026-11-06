# v0.32 S7comm after ISO-TSAP: CPU cost

Python 3.13 on Linux-6.18.44-fc-v139-x86_64 (shared cloud container), same
interpreter, minimum of 5 x 3000, Inspector constructor subtracted.

| Stream | bytes | µs |
|---|---:|---:|
| ISO-TSAP connection request alone (shift pending) | 22 | 29.1 |
| request + S7 setup-communication job (shift to s7comm) | 47 | 71.3 |
| connection confirm + S7 ack-data (shift to s7comm) | 49 | 65.7 |
| S7 job with an explicit candidate hint (no shift) | 25 | 15.5 |

- The S7 PDU itself costs about 15 µs; the shift adds the inner Inspector and
  the merged publication (about 25 µs, as measured for every v0.28 boundary).
  No dispatch or existing-family path changed, so the v0.28-v0.31 A/B numbers
  stand.

## Verification

418 tests pass (3 new in test_s7comm.py): request and confirm shifts with
every split point, verdict with `shifted_from=iso-tsap`, pending shift at
EOF, S7 header/length/function/setup/userdata/error-class rejections (each
checked both hinted and after the connection, where the carrier stays
identified), the bare-prefix exclusion, 200 seeded mutations with
fragmentation equivalence, TPKT routing of RDP versus ISO-TSAP confirms, and
confirm/request destination-reference rules.
