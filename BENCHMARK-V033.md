# v0.33 server-side CONNECT correlation: CPU cost

Python 3.13 on Linux-6.18.44-fc-v139-x86_64 (shared cloud container), same
interpreter, minimum of 5 x 3000, Inspector constructor subtracted.

| Stream | µs |
|---|---:|
| server `200 Connection established` alone | 23.5 |
| server 200, `open_shift`, then the TLS 1.3 ServerHello (shifted phase) | 98.1 |
| TLS 1.3 ServerHello alone (reference) | 33.7 |

- Reopening a direction costs about 40 µs on top of the two messages: the
  inner Inspector with a reduced-budget `Config`, the merged observation and a
  second event. It happens once per CONNECT tunnel whose answer is 2xx.
- `Analyzer._correlate_connect` runs after each identification event on a TCP
  connection: two dictionary lookups and a scan of at most a few evidence rows
  (about 1 µs), nothing on connections without an identification.

## Verification

421 tests pass (3 new in test_tunnel.py): both capture orders (request before
and after the response) reach `ssl` with `server_protocol=tls`,
`selected_tls_version` and peer-sourced shift evidence; a 403, a plain GET/200
pair and an unreadable tunnel open or identify nothing beyond the carrier;
`open_shift` preconditions (detecting, pending, already shifted, unknown,
budget below 64 bytes, bad boundary or candidate) and a restricted candidate
that rejects a non-TLS tunnel. test_shift's offline pipeline expectation now
includes the server direction's incomplete shifted phase.
