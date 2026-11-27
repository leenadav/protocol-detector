# Child applications (enterprise App-ID model, PRO-492)

One service is split into child applications per function, as enterprise firewalls do: `gmail` has
`gmail-uploading`, `gmail-sending` and `gmail-downloading`; `dropbox` has `dropbox-uploading`, `dropbox-downloading`
and `dropbox-sharing`. The verdict names both levels: `app=gmail-uploading, container=gmail`. Request metadata never
establishes an application on its own: a child only refines what the server-name catalog already says. Go only;
the Python reference has no child applications (new detection work is Go only).

## Where it runs

Child rules match what a decrypting forward proxy (Culvert) sees of one HTTP request. The public entry point is
`go/detector`:

```go
c, err := detector.NewAppClassifier(detector.AppLimitsConfig{}) // built-in pack + child-app component
v := c.Classify(detector.HTTPRequest{SNI: sni, Host: host, Method: "POST", Path: path,
	ContentType: ct, RequestBodyBytes: up, ResponseBodyBytes: -1, WebSocket: false})
// v.App = "gmail-uploading", v.Container = "gmail", v.Basis = "request_rule", v.Rule = "gmail-uploading#0"
// v.Matches("gmail") and v.Matches("gmail-uploading") are both true
```

The record is `go/detector/app-verdict.schema.json`. A request without a matching child gets the catalog application
(`app=gmail, container=""`, basis `server_name`); an unowned host gets none (basis `none`, reason `host_unowned`).
Offline capture analysis (`protodetect analyze`) is unchanged: TLS hides the method and path there, and its output
stays equal to the reference.

## Policy

`go/internal/policy.FromJSONWithChildren` accepts child names wherever an application is named, and a Go-only match
key `containers`, which holds for the named application itself and for each of its children:

```json
{"version": 1, "default": "allow", "rules": [
  {"name": "no-uploads", "action": "deny", "match": {"apps": ["dropbox-uploading", "gmail-uploading"]}},
  {"name": "watch-dropbox", "action": "alert", "match": {"containers": ["dropbox"]}}]}
```

`FromJSON` (the reference's vocabulary, used by every parity path) still refuses `containers`, `child_status` and
child names.

### Fail closed: `child_status` (SEC-CHILD-1)

Every verdict carries `child_status`:

| Value | Meaning |
|---|---|
| `matched` | a child rule decided the function |
| `none` | every candidate rule was evaluated on the normalized request and none applies (also: no child rule names the host, so no refusal can hide a child) |
| `undetermined` | a child rule of the host could apply, but the request was refused (`path_not_canonical`), capped (any `limit`) or ambiguous (`request_ambiguous`): the verdict names the host's catalog owner and no child |
| `not_applicable` | no catalog application, so no child can be named |

A deny entry for a child alone fails open on `undetermined`. Pair it with a `child_status` rule for the owners the
child's hosts may have, its container and its `depends_on` (Gmail's API hosts belong to `google-base`):

```json
{"name": "no-gmail-upload", "action": "deny", "match": {"apps": ["gmail-uploading"]}},
{"name": "no-unknown-gmail-function", "action": "deny", "match": {"apps": ["gmail", "google-base"], "child_status": ["undetermined"]}}
```

Culvert's `go/detector` facade has `AppClassifier.MayBe(verdict, child)`, which is `Matches` plus exactly that
undetermined case; use it for deny entries and `Matches` for allow entries. Matching `containers` on the host owner
is SEC-CHILD-2.

## The data: `go/internal/childapp/childapps.json`

A component of the content data with its own release (`YYYY.MM.N`) and SHA-256 digest (`AppVerdict.child_release`).
It is kept beside the pack, not inside `pack.json`, because the frozen parity answers pin content release 2026.11.9
(docs/CONTENT-BATCHES.md, "Before the first real batch merges"); it moves into the pack when that follow-up lands.

```json
{"name": "gmail-uploading", "container": "gmail", "description": "Gmail API media upload",
 "risk": 3, "characteristics": ["widely-used", "transfers-files"], "depends_on": ["google-base"],
 "evidence": ["https://developers.google.com/workspace/gmail/api/guides/uploads"],
 "rules": [{"hosts": ["gmail.googleapis.com"], "methods": ["POST", "PUT"], "path_prefixes": ["/upload/gmail/v1/users/"]}]}
```

- **Child:** `name` starts with `<container>-` and is not a catalog name or alias; `container` is a catalog
  application. Category, subcategory and technology come from the container; `risk` and `characteristics` default to
  the container's. `implicitly_uses` is the container plus the container's own. `evidence` (1 to 8 `https://` links
  to the service's official API reference) is required.
- **Hosts:** each rule needs `hosts` (exact) or `host_suffixes` (the domain and its subdomains). Every host must be
  claimed in the server-name catalog by the container or by an application in the child's `depends_on` (Gmail's API
  is on `googleapis.com`, claimed by `google-base`). A web front or unclaimed host is refused.
- **Function conditions** (at least one; all present ones must hold):
  - `methods`: upper-case tokens;
  - `path_prefixes` and `path_patterns`: either list may hit. A pattern is `/`-separated segments: a literal, `*` or
    `{name}` for exactly one non-empty segment, a literal with `{name}` placeholders inside it (`/bot{token}/sendDocument`,
    `/v1beta/models/{model}:generateContent`, `/{owner}/{repo}.git/info/refs`; each placeholder non-empty, never two in
    a row), or a final `**` for any rest. No regular expressions; matching is linear in the path;
  - `content_types`: `type/subtype` or `type/*`, against the request Content-Type without parameters;
  - `query`: `name=v1|v2`, `name={value}` (any non-empty value) or `name` (present). Names and values are unreserved
    characters compared byte for byte, and a parameter that appears twice never satisfies a condition. Needs a
    method or path condition too;
  - `header_present`: header names that must be present (`HTTPRequest.HeaderNames`, any case);
  - `direction`: `upload` (request body at least `min_bytes`, default 1, and larger than a known response body) or
    `download` (the reverse). An unknown size never matches;
  - `websocket: true`: the request is a WebSocket upgrade.
- **Precedence: the most specific rule wins** (App Research's rule for wave 0): the rule whose matched path condition
  pins the most literal bytes, then the one with more condition kinds; on a tie the earlier rule in the file. So
  `POST /upload/gmail/v1/users/me/messages/send` is `gmail-sending` (a pattern), not `gmail-uploading` (a prefix).
- **Load limits:** 4 MiB, 4,096 children, 32 rules per child, 16,384 rules, 32 entries per list, 256 bytes per entry,
  32 pattern segments. Keys are exact and unique; anything else refuses the whole file.
- **Base children:** research's `<parent>-base` is the parent itself here: `app=<parent>`, `container` empty.

## Paths are matched only in canonical form

The fragment is ignored and the query is read only by `query` conditions. Before matching, percent escapes of
unreserved bytes (`A-Z a-z 0-9 - _ ~`, RFC 3986 section 2.3) are decoded in the path and in query names and values,
and every other escape is upper-cased (sections 6.2.2.1 and 6.2.2.2), so `/upl%6fad` matches `/upload` and
`upload%54ype=media` matches `uploadType=media`. A path with a dot segment, an empty segment, a backslash, a
control byte, a malformed escape or an encoded `/`, `\`, `.`, `%` or control byte is not matched (reason
`path_not_canonical`, `child_status` `undetermined`; the parent is still reported), so a filter and a server can
never read one path two ways.

A rule is ambiguous, and never picks a child, when it holds only for one server reading of the request: a query
parameter it reads is repeated (also through an encoded name), the content type it reads does not parse, or a path
pattern holds only without a trailing slash. If an ambiguous rule would be the most specific, the verdict is
`request_ambiguous` and `undetermined`; if a definite rule outranks it, that rule's child stands. SNI and Host of different catalog owners give no application
(`sni_host_owner_mismatch`, domain fronting); a coalesced HTTP/2 connection of one owner is classified on the Host.

## Work ceiling (never silent)

Rules are indexed by host, so a request only meets the rules of its own host and parent domains. At most
`MaxRuleEvaluations` (default 64) rules are evaluated per request, and a path longer than `MaxPathBytes`
(default 4,096) or a method or content type over 32 or 256 bytes is not matched. Hitting any of these is reported in
`limit` (`child_rule_evaluations`, `child_path_bytes`, `child_field_bytes`) with reason `work_limit` or
`field_too_long`, and the verdict then names the parent only, never a child, with `child_status` `undetermined`.

## Where the rules come from

`childapps.json` is generated, never hand-edited: `tools/child_apps_wave.py` converts App Research's cited wave file
(wave 0: PRO-495, `migration/fixtures/child-apps/wave-0.json`, a byte copy of
`research/child-apps/wave-0.json` on `claude/app-research-PRO-495-child-apps-wave0-b` at `5ebe8f5`), and `make check`
(`make child-apps`) fails when the committed rules differ from a fresh conversion. Per-child outcomes, and every
condition dropped or skipped, are in [child-apps/wave-0-rules.md](child-apps/wave-0-rules.md). The conversion is
conservative:

- only `cited` children with an `https://` citation become rules; unverified proposals never do;
- a host must be claimed in the server-name catalog, and its owner joins `depends_on` (`gmail.googleapis.com` is
  `google-base`'s, `graph.microsoft.com` `ms-base`'s); a host template such as `{box-upload-server}` is skipped;
- a placeholder named as a path (`{file_path}`, `{item-path}`) can span segments, so that pattern is skipped;
- a content type with a scope note or `*/*` drops the content-type condition (broader, recorded);
- `direction` is recorded, not enforced: a proxy often knows body sizes only after the response, and method plus
  path already name the function.

Wave 0 gives 47 children over 20 of its 30 services (the other 10 had no separable cited function; the 30 base
children map to their parents; 3 children are skipped:
`telegram-bot-downloading`, whose only path is a multi-segment variable, and the two `google-gemini-api` children,
whose parent is not yet in the pack). Most rules describe vendor APIs (`client_scope: api`): the vendors do not
publish their own web clients' request paths, so a browser session of Gmail is `gmail`, not a child.

## Adding a wave

1. App Research (wave 0, PRO-495) or Research Lab (later waves, PRO-491) delivers `research/child-apps/wave-N.json`
   with official citations.
2. Copy it to `migration/fixtures/child-apps/`, run `python3 -B tools/child_apps_wave.py <file> --version <next>
   --write`, review `docs/child-apps/wave-N-rules.md`, add example requests for the new children to
   `childapp_test.go`, and add the file to `make child-apps`.
3. `cd go && go test ./internal/childapp/ ./detector/`, `make check`, then one PR per wave of about 30 services from a
   fresh branch off `main`.
