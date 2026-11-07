# Output contract (v0.34)

Every machine-readable line the tools emit conforms to a published JSON Schema
(draft-07 subset) in `schemas/`. `tools/schema_check.py` validates JSON Lines
with no dependencies and `protodetect schema NAME --validate FILE` wraps it;
the test suite validates real output of both tools under every option
combination that changes the shape (sessions, policy, heuristics,
fingerprints, hostnames, all-events).

| Schema | Produced by | Rows |
|---|---|---|
| `session` | `analyze_pcap --sessions/--policy`, `live_capture` (always) | one verdict per TCP connection or UDP flow: endpoints, timing, byte counts, `app` and catalog attributes, `port_usage`, `engine_status`, protocols per direction, `encryption`, `reasons`, `shifted_from`, `risks`; optional `fingerprints`, `certificate` (only with `--certificates`: `chain`, `version`, `self_issued`, `key`, `signature`, `lifetime_days`, `not_before`, `not_after` (calendar days), `ca`, `eku`, `san` labels, plus `validity` judged at the session's first packet when the capture clock is set; never names), `hostname` (only with `--hostnames`), `policy` |
| `live-event` | `live_capture --json`, `protodetect live --json` | `started`, `classification` (per state-change event, plus retired observations with `--all-events`), `session`, `progress`/`summary`, `capture_gap`, `error` |
| `offline-row` | `analyze_pcap --json`, `protodetect analyze --json` | per-frame rows with the direction's current classification and events (omitted with `--events-only` unless an event fired), `skipped` frames, `stream_end`, `capture_gap`, `session`, final `summary` |

Every `session` record (and every decryption row of the presentation's live
`decryption` event) also carries `layers` (schema `$defs/layers`, stage 5 of the
v0.65 architecture plan): the per-layer knowledge of one session and the one
effective answer derived from it. `outer` is the protocol and verdict seen on
the wire, `encryption` the envelope (protocol, offered ALPN, whether a server
name was asserted, negotiated version when a decoder ran), `inner` the protocol
and verdict seen in authenticated plaintext (absent without decryption),
`application` the effective name with its `basis`: `authenticated_plaintext`,
`structural`, `configured_rule`, `client_assertion` (built-in server-name
catalog) or `none`. `chain` is the display order, e.g. `["tls", "http/1.1",
"webdav"]`; `claims` lists asserted, offered and derived evidence by field,
source and strength, never by value. A failed decryption withdraws `inner`
(`authenticated: false`) and keeps the wire layer; record authentication is
never presented as peer or product identity verification (`note`).

Every `session` record, the offline summary and the live `started`,
`progress` and `summary` events carry `content: {version, digest}` (D08): the
detection content release in force and its digest, so records classified by
different catalogs can be told apart (docs/CONTENT-GOVERNANCE.md).

With `--continuation BYTES` (D07) a `session` record may also carry
`continuation`: per direction (`client`, `server`) the counts and classes the
budgeted continuation framed after the identification (`http_messages`,
`http_methods`, `http_status_classes`, `http_host_variation`, `tls_records`,
`tls_application_data`, `tls_alert`) and `ended` (`budget`, `messages`,
`records`, `framing`, `close-delimited`, `shift`; absent when the direction
ended first). It is absent when the option is off or nothing followed; the
verdict, `decision` and hostname are never changed by it (PROTOCOLS.md).

Schemas set `additionalProperties: false` on every object the tools build, so a
new field is a schema change and a review item. Values that could carry
payload are structurally excluded: `evidence[].value` is a short string from a
closed set per field (protocol names, versions, counts, classes), hostnames
appear only as asserted SNI/Host names and only where documented, and no
field holds request paths, credentials, query names or raw bytes.

```bash
python3 -B protodetect.py schema                       # list schemas
python3 -B protodetect.py schema session               # print one
python3 -B protodetect.py analyze capture.pcap --json --sessions > rows.jsonl
python3 -B protodetect.py schema offline-row --validate rows.jsonl
python3 -B live_capture.py --stdin --duration 0 --json < capture.pcap | python3 -B tools/schema_check.py live-event -
```

Compatibility: fields are added, never renamed or removed, within a major
version; enumerations (`status`, `kind`, `strength`, `port_usage`, policy
actions) are closed sets listed in the schemas. Readable (non-JSON) output is
for people and carries no compatibility promise.
