# Policy evaluation (v0.30)

`protocol_engine/policy.py` evaluates an ordered rule set against every session
verdict and labels it `allow`, `deny` or `alert`. The engine does not enforce
anything: the label is written into the session record (`policy`), the live
classification event (`policy`) and the live summary (`policy` counts) for the
host to act on. The vocabulary follows application-aware firewall policies
(application, category, risk, application-default) and adds this engine's
flow risks and application shifts.

## File format

```json
{
  "version": 1,
  "description": "optional",
  "default": "allow | deny | alert",
  "rules": [
    {"name": "allow-web", "action": "allow", "application_default": true,
     "description": "optional",
     "match": {
       "apps": ["web-browsing", "ssl", "quic", "msrpc", "unknown-tcp"],
       "categories": ["networking"], "subcategories": ["infrastructure"],
       "technologies": ["client-server"],
       "characteristics": ["tunnels-other-applications"],
       "risks": ["obsolete-protocol"],
       "risk_min": 1, "risk_max": 5,
       "port_usage": ["standard", "nonstandard", "unknown"],
       "transports": ["tcp", "udp"], "server_ports": ["tcp/443", "udp/53-60", "tcp/dynamic"],
       "encryption": ["none", "tls", "dtls", "quic", "wireguard", "openvpn"],
       "shifted_from": ["http-proxy", "smtp"],
       "identity_basis": ["authenticated_plaintext", "structural", "configured_rule", "client_assertion", "none"],
       "activity": ["unobserved", "http-request", "authenticated-plaintext", "none"],
       "affiliation": ["service", "provider-web", "none"],
       "decryption": ["none", "awaiting_hello", "awaiting_keys", "decrypting", "complete", "failed"],
       "capture_quality": ["intact", "degraded", "provisional"],
       "engine_status": ["identified", "correlated", "unknown", "budget_exhausted", "invalidated", "incomplete"],
       "directions": ["consistent", "conflicting", "one-direction"]
     }}
  ]
}
```

- Every `match` key is optional; a rule with no `match` matches every verdict.
  Keys are ANDed; list values are ORed (`characteristics` and `risks` match when
  any listed value is present on the verdict).
- `apps` accepts catalog names, aliases (`msrpc`, `postgres`, ...) and the
  session outcomes `unknown-tcp`, `unknown-udp`, `incomplete`,
  `insufficient-data`, `not-applicable`. Unknown names, categories, risks,
  ports or keys are errors: a policy either loads completely or not at all.
- `application_default: true` makes the rule match only when the verdict's
  `port_usage` is `standard` or `unknown` (no catalog ports). A nonstandard port
  falls through to later rules and the default; the decision's reasons then
  name the rule that would have allowed the application on its default ports.
  After an application shift the carrier's ports count (ssl after STARTTLS on
  587 is standard).
- Limits: 1024 rules, 256 entries per list, 4 MiB file, names of 1..64
  printable characters, unique rule names.

## Evidence predicates (D04)

The seven typed predicates match the session's evidence contract, not its payload and not a confidence
number (none exists). Values come from the layered view (`layers`) when the caller has one and from the
verdict otherwise; the decision reports the values it saw under `predicates`.

- `identity_basis`: how the application name was established. There is no ordering: a rule that lists
  `structural` or `authenticated_plaintext` is **not** satisfied by `client_assertion` (an SNI or Host name
  the client sent), and `authenticated_plaintext` means record AEAD with supplied secrets, not verified peer
  or product identity.
- `activity` and `affiliation` (D03): what was observed versus which provider the name affiliates with
  (`provider-web` is a marketing or documentation front, `service` a service domain).
- `decryption`: the decoder's state for the session (`none` when no decoder ran). Missing keys are
  `awaiting_keys`, a failed authentication `failed`; neither satisfies a rule that requires `complete`.
- `capture_quality`: `intact`, `degraded` (a gap or truncation retracted dependents) or `provisional`
  (a live run before stop).
- `engine_status`: the verdict's engine status (`budget_exhausted` and `invalidated` are explicit outcomes,
  never identities).
- `directions`: `conflicting` when the two directions identified different applications, `one-direction`
  when only one side was identified, `consistent` otherwise.

A rule that names a predicate never matches when the context is missing. When no rule matched because of
predicates alone, the default decision's reasons name the first rule that would have matched and which
requirement failed, so operators see "would allow, but identity is a client assertion" rather than a bare
default.

## Evaluation

`Policy.evaluate(verdict, transport, server_port, layers=None)` walks the rules in order and
returns `Decision(action, rule, reasons)` for the first match, otherwise
`Decision(default, None, reasons)`. Cost is linear in the rule count with a few
set lookups per rule (about 1 µs for the seven-rule example, about 150 µs for
a 1000-rule policy with no match); the policy is evaluated once per session
record and once per live classification event.

`Policy.lint()` returns warnings without changing the policy:

- dependency warnings: an `allow` rule names an application whose catalog
  `implicitly_uses` or `depends_on` entries the policy would deny (allowing
  `websocket` while denying `web-browsing`), mirroring the application
  dependency check of firewall rule bases;
- rules that can never match (`application_default` together with
  `port_usage: ["nonstandard"]`; outcome-only `apps` combined with catalog
  attribute conditions).

## Command line

```bash
python3 -B protodetect.py policy lint policy-example.json [--strict]
python3 -B protodetect.py policy test policy-example.json --app rdp --port 9000
python3 -B protodetect.py policy test policy-example.json --app ssl --port 8443 --shifted-from http-proxy
python3 -B protodetect.py analyze capture.pcap --policy policy-example.json --json
python3 -B protodetect.py live --interface eth0 --policy policy-example.json
```

`policy test` builds a synthetic identified verdict for the application (port
usage from the catalog ports, optional risks, encryption and carrier) and
prints the decision; it does not inspect traffic.

## What a decision is not

A decision labels a verdict, which is as strong as the evidence beneath it: an
`allow` for `ssl` means a structurally valid ClientHello/ServerHello was seen,
not that the peer is who it claims. Policies see one verdict per session, so
they cannot express "allow web-browsing only inside this application's flow";
dependency warnings exist because this engine cannot correlate flows. No
blocking, logging destination, user or zone concept exists here.
