# Custom application signatures — v0.23

Custom signatures name an application from fields that a completed structural
profile exposed, or from the first bytes of a stream/datagram that no profile
accepted. They play the role of custom App-IDs: the operator writes conditions
over named **contexts**, the engine evaluates them once per transaction and
reports the signature name as the application. A signature never replaces
structural validation; `http-req-*` contexts exist only after the HTTP profile
passed, `unknown-req-*` contexts only after dispatch rejected every family.

```bash
python3 -B analyze_pcap.py capture.pcap --sessions --signatures signatures-example.json
python3 -B live_capture.py -i eth0 --signatures signatures-example.json
```

```python
from protocol_engine import Config, Inspector, SignatureSet
signatures = SignatureSet.from_path("signatures-example.json")
inspector = Inspector(Config(retain_contexts=True), signatures=signatures)
```

`Config(retain_contexts=True)` is required when a non-empty set is supplied: it
lets parsers keep bounded copies of the fields below. Without it nothing is
retained and the engine behaves exactly as before.

## File format

JSON: a list, or `{"version": 1, "signatures": [...]}`. Each signature:

| Field | Meaning |
|---|---|
| `name` | 1..128 printable characters; reported as `application` |
| `category`, `subcategory`, `technology`, `risk`, `characteristics` | Catalog vocabulary (APPID.md); defaults `custom`/`custom-signature`, `client-server`, 3 |
| `parent` | Carrier application for `implicitly_uses`/`base_app`; defaults to the family that produced the contexts (`web-browsing`, `ssl`, `dns`, `unknown-tcp`, …) |
| `description` | Free text, 256 characters |
| `scope` | `transaction` (the only supported value: the initial message) |
| `conditions` | A list (implicit `and`) or one group `{"and": [...]}` / `{"or": [...]}`; groups nest to depth 4, at most 64 conditions |

Condition: `{"context": ..., "operator": ..., "pattern"|"value": ..., "negate": false, "case_insensitive": false}`.
Operators: `pattern-match` (text/raw contexts), `equal-to` (all kinds; membership for set contexts),
`less-than`, `greater-than` (integer contexts). An absent context never matches,
even with `negate`; a signature needs at least one non-negated condition.

## Contexts

| Context | Kind | Family | Value |
|---|---|---|---|
| `http-req-method`, `http-req-uri-path`, `http-req-version` | text | http | Start-line fields; path excludes the query string |
| `http-req-host-header` | text | http | Normalized ASCII host (no port, lowercase) |
| `http-req-user-agent-header` | text | http | First User-Agent value, 1024 bytes |
| `http-req-headers` | raw | http | `name: value\r\n` lines, lowercase names, 4096 bytes |
| `http-req-content-length`, `http-rsp-status` | integer | http | |
| `http-rsp-reason` | text | http | Response reason phrase |
| `ssl-req-chello-sni` | text | tls | Normalized SNI (TLS ClientHello, and QUIC Initial ClientHello since v0.25) |
| `ssl-req-alpn` | text | tls | Comma-joined ALPN offers in order |
| `ssl-req-client-hello` | raw | tls | ClientHello body (random included; never emitted) |
| `ssl-req-client-hello-ext-type`, `ssl-req-cipher-suite` | set | tls | Extension types / cipher values; `equal-to` means present |
| `ssl-req-version` | integer | tls | legacy_version, e.g. 771 (0x0303) |
| `ssh-req-banner` | text | ssh | Identification line without CRLF |
| `smtp-req-argument` | text | smtp | EHLO/HELO argument |
| `dns-req-query-name`, `dns-req-query-type` | text, integer | dns | Lowercase dotted question name; QTYPE (TCP and UDP) |
| `socks-req-target`, `socks-req-port` | text, integer | socks5 | Requested destination |
| `unknown-req-tcp-payload`, `unknown-req-tcp-payload-length` | raw, integer | unknown-tcp | First `Config.signature_bytes` (default 2000) bytes of a stream dispatch rejected |
| `unknown-req-udp-payload`, `unknown-req-udp-payload-length` | raw, integer | unknown-udp | Datagram that no validator accepted |

Contexts are internal: they never appear in `Observation.evidence`, reasons,
session records or live output. Only the signature name does.

## Pattern rules (why your pattern was rejected)

- Patterns are Python `re` syntax over bytes (`\x01\x02AGENT` for binary), Latin-1 only, at most 512 characters.
- Every pattern needs a **literal run**: 7 bytes for raw contexts, 3 for text contexts. `^GET /admin/` qualifies; `[a-z]{7}` does not. The literal run is searched with a plain substring test before the regex runs.
- No nested quantifiers (`(a+)+`), no backreferences, no lookaround, no repeat counts above 4096. These keep evaluation linear in the input.
- `case_insensitive` lowercases both anchor and input before matching.

## Evaluation semantics

- Structural profiles first: when a parser completes, its family's signatures run in file order; the first match wins and takes precedence over `RuleIndex` exact-host mappings. No match falls back to the mapping.
- Unknown TCP streams: when dispatch rejects a prefix and the set contains `unknown-req-tcp-payload*` conditions, up to `signature_bytes` are buffered (charged to the byte budget) and the signatures are evaluated after each update. A match is terminal (`scope="signature_match"`, `application_protocol=None`). A miss waits for more bytes, the buffer limit or `end()`; then the stream is `unknown`. A stream whose dispatch never resolved (too short) is evaluated once at `end()`.
- Unknown UDP datagrams: evaluated once per datagram when no validator accepted it, or when every candidate reported `unknown`.
- Verdicts (`appid.classify`) use the signature's own category/risk when the `SignatureSet` is passed; otherwise the application inherits its carrier. `base_app` is the carrier (`parent` or the family), `port_usage` uses the carrier's ports.
- Signatures also apply inside trusted decrypted plaintext (`feed_decrypted`).

## Limits

Transaction scope only: later requests, responses paired with requests and
multi-packet session conditions are not evaluated. Contexts cover the fields
the profiles already parse; there is no generic header or body search for
protocols other than HTTP. Signature evaluation cost is bounded by the number of
signatures for the family times the prefilter; keep sets small and specific.
