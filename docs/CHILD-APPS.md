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

The record is `schemas/app-verdict.schema.json`. A request without a matching child gets the catalog application
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

`FromJSON` (the reference's vocabulary, used by every parity path) still refuses `containers` and child names.

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
  - `path_prefixes` and `path_patterns`: either list may hit. A pattern is `/`-separated literal segments, `*` for
    exactly one segment and a final `**` for any rest. No regular expressions;
  - `content_types`: `type/subtype` or `type/*`, against the request Content-Type without parameters;
  - `direction`: `upload` (request body at least `min_bytes`, default 1, and larger than a known response body) or
    `download` (the reverse). An unknown size never matches;
  - `websocket: true`: the request is a WebSocket upgrade.
- **Order:** rules are evaluated in file order; the first match wins. Put a narrow child before a broad one.
- **Load limits:** 4 MiB, 4,096 children, 32 rules per child, 16,384 rules, 32 entries per list, 256 bytes per entry,
  32 pattern segments. Keys are exact and unique; anything else refuses the whole file.

## Paths are matched only in canonical form

The query and fragment are ignored. A path with a dot segment, an empty segment, a backslash, a control byte or an
encoded `/`, `\`, `.`, `%` or NUL is not matched (reason `path_not_canonical`; the parent is still reported), so a
filter and a server can never read one path two ways. SNI and Host of different catalog owners give no application
(`sni_host_owner_mismatch`, domain fronting); a coalesced HTTP/2 connection of one owner is classified on the Host.

## Work ceiling (never silent)

Rules are indexed by host, so a request only meets the rules of its own host and parent domains. At most
`MaxRuleEvaluations` (default 64) rules are evaluated per request, and a path longer than `MaxPathBytes`
(default 4,096) or a method or content type over 32 or 256 bytes is not matched. Hitting any of these is reported in
`limit` (`child_rule_evaluations`, `child_path_bytes`, `child_field_bytes`) with reason `work_limit` or
`field_too_long`, and the verdict then names the parent only, never a child.

## Adding a wave

1. Take the services of the wave (Research Lab's enterprise list, PRO-491) whose container is in the catalog.
2. For each function, read the service's official API reference and write the child with its links in `evidence`.
   Skip a function the vendor does not document (consumer WhatsApp, for example) and say so in the PR.
3. `cd go && go test ./internal/childapp/ ./detector/` (load, examples, properties, schema), add example requests to
   `childapp_test.go` for the new children, raise the release version, and open one PR per wave of about 30
   services from a fresh branch off `main`.
