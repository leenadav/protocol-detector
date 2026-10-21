# Output contract (v0.34)

Every machine-readable line the tools emit conforms to a published JSON Schema
(draft-07 subset) in `schemas/`. `tools/schema_check.py` validates JSON Lines
with no dependencies and `protodetect schema NAME --validate FILE` wraps it;
the test suite validates real output of both tools under every option
combination that changes the shape (sessions, policy, heuristics,
fingerprints, hostnames, all-events).

| Schema | Produced by | Rows |
|---|---|---|
| `session` | `analyze_pcap --sessions/--policy`, `live_capture` (always) | one verdict per TCP connection or UDP flow: endpoints, timing, byte counts, `app` and catalog attributes, `port_usage`, `engine_status`, protocols per direction, `encryption`, `reasons`, `shifted_from`, `risks`; optional `fingerprints`, `hostname` (only with `--hostnames`), `policy` |
| `live-event` | `live_capture --json`, `protodetect live --json` | `started`, `classification` (per state-change event, plus retired observations with `--all-events`), `session`, `progress`/`summary`, `capture_gap`, `error` |
| `offline-row` | `analyze_pcap --json`, `protodetect analyze --json` | per-frame rows with the direction's current classification and events (omitted with `--events-only` unless an event fired), `skipped` frames, `stream_end`, `capture_gap`, `session`, final `summary` |

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
