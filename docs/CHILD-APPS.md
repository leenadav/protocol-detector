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
key `containers`, which holds for the named application itself, for each of its children, and for each child matched
on a host it owns in the server-name catalog (`AppVerdict.host_owner`; SEC-CHILD-2). A child never moves a request
out from under its host's owner: `deny containers:[ms-base]` still denies Graph `sendMail` (outlook-sending, container
outlook-web, host owner ms-base), and `containers:[google-base]` Gmail send and Drive uploads on `googleapis.com`.
Every other rule keyed on the host owner's identity also holds on its children (SEC-CHILD-7): a child on a host
another application owns is evaluated as itself and as that owner (the owner's name, category, subcategory and
technology, both characteristic sets, the higher risk), and a rule applies when either identity satisfies it. So
`deny apps:[ms-base]`, `subcategories:[internet-utility]` or `characteristics:[pervasive]` still denies Graph
`sendMail`, and `apps:[dropbox]` still denies `dropbox-uploading` on `content.dropboxapi.com`, as before child apps
existed. The first matching rule decides, so a child-specific rule goes before a broader owner rule
(`allow apps:[ms-base]` first allows `outlook-sending` too). `AppVerdict.Matches` holds for the same three names:

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
  application. Category, subcategory and technology come from the container; `characteristics` default to the
  container's. `risk` defaults to the highest of the container's and each `depends_on` application's (the owners
  of the hosts a child may match on), and an explicit `risk` below that is refused, so a child never ranks below an
  application it is matched under (SEC-CHILD-2). `implicitly_uses` is the container plus the container's own. `evidence` (1 to 8 `https://` links
  to the service's official API reference) is required.
- **Hosts:** each rule needs `hosts` (exact) or `host_suffixes` (the domain and its subdomains). Every host must be
  claimed in the server-name catalog by the container or by an application in the child's `depends_on` (Gmail's API
  is on `googleapis.com`, claimed by `google-base`). A web front or unclaimed host is refused. A `host_suffixes` entry is also refused when
  the catalog gives a more specific domain under it to an application that is neither the container nor a `depends_on`
  (`anthropic.com`, claimed by `anthropic-claude`, covers `api.anthropic.com`, which is `anthropic-api`'s): name the
  exact hosts instead, or add that application to `depends_on` (SEC-CHILD-5). At match time a rule only fires when the request host's catalog owner
  is the container or a `depends_on` application: a `host_suffixes` rule never fires on a more specific host the
  catalog gives another application (`maps.googleapis.com` is google-maps', not google-base's).
- **Function conditions** (at least one; all present ones must hold):
  - `methods`: upper-case tokens;
  - `path_prefixes` and `path_patterns`: either list may hit. A pattern is `/`-separated segments: a literal, `*` or
    `{name}` for exactly one non-empty segment, a literal with `{name}` placeholders inside it (`/bot{token}/sendDocument`,
    `/v1beta/models/{model}:generateContent`, `/{owner}/{repo}.git/info/refs`; each placeholder non-empty, never two in
    a row), or a final `**` for any rest. No regular expressions; matching is linear in the path;
  - `path_case_insensitive: true` (needs a path condition): the path literals are compared in ASCII lower case, for
    vendors that state their path names are case-insensitive (Microsoft Graph resource names, Telegram Bot API
    methods; SEC-CHILD-3). Placeholders match as before;
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
  32 pattern segments, 256 path patterns indexed under one host or host suffix (SEC-CHILD-4). Keys are exact and
  unique; anything else refuses the whole file.
- **Base children:** research's `<parent>-base` is the parent itself here: `app=<parent>`, `container` empty.

## Paths are matched only in canonical form

The fragment is ignored and the query is read only by `query` conditions. A path with a dot segment, an empty segment, a backslash, a control byte or an
encoded `/`, `\`, `.`, `%` or NUL is not matched (reason `path_not_canonical`; the parent is still reported), so a
filter and a server can never read one path two ways. A percent-encoded letter, digit, `-`, `_`, `~`, sub-delimiter
(`$`, `!`, `&`, `'`, `(`, `)`, `*`, `+`, `,`, `;`, `=`), `:` or `@` is decoded before matching, as the server reads it
(`/v1.0/%24batch` is `/v1.0/$batch`, `/2/files/%75pload` is `/2/files/upload`; SEC-CHILD-3); any other encoding,
such as a UTF-8 file name, stays as written and a placeholder still matches it. SNI and Host of different catalog owners give no application
(`sni_host_owner_mismatch`, domain fronting); a coalesced HTTP/2 connection of one owner is classified on the Host.

## Work ceiling (never silent)

Rules are indexed by host, so a request only meets the rules of its own host and parent domains. At most
`MaxRuleEvaluations` (default 64) rules are evaluated per request, and a path longer than `MaxPathBytes`
(default 4,096) or a method or content type over 32 or 256 bytes is not matched. Hitting any of these is reported in
`limit` (`child_rule_evaluations`, `child_path_bytes`, `child_field_bytes`) with reason `work_limit` or
`field_too_long`, and the verdict then names the parent only, never a child.

Path work is linear in the path once per request, never per pattern (SEC-CHILD-4): the path is checked for dot
segments without splitting and split at most once, only when a rule with a pattern is reached and into at most 33
parts (a case-folded rule on a path with upper case splits the lower-cased path once more). Each pattern compares
the segment count first, so a 4 KiB path of 2,048 segments against the 256 patterns a host may hold costs about
10 µs and under 1 KB (`BenchmarkClassifyPatternCapLongPath`; it was 8.9 ms and 8.5 MB).

An ordinary request costs `AppClassifier.Classify` one allocation, the verdict's own `reasons` slice (PRO-522): the
matcher (`childapp.Set.Evaluate`) keeps one reason string, rule ids are built at load, header names and the query
are scanned in place (no map), host and path checks do not split, and the candidate lists and the path segments sit
in fixed stack arrays. Only an upper-case host, or an upper-case path that reaches a `path_case_insensitive` rule,
pays for its lower-cased copy. `BenchmarkAppClassifierClassify` (the Culvert lab's three requests) went from 14, 7
and 4 allocations (child, parent, unowned) to 1 each, and from about 2.2, 1.4 and 0.35 µs to 0.8, 0.7 and 0.17 µs;
`TestAppClassifierAllocationCeilings` holds the library floor for Culvert's per-request benchgate (child ≤ 8,
parent ≤ 4, unowned ≤ 2).

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

### SEC-CHILD-3 hardenings (PRO-510, release 2026.11.2)

The wave-0 rules missed real request forms. `make child-apps` therefore also reads App Research's vendor evidence
(`sec_child_3` in `migration/fixtures/child-apps/wave-1.json`, a byte copy of `research/child-apps/wave-1.json` on
`main` at `05705a3`; PRO-524), and the converter applies one hardening per verified item. Each widens what a child
matches and cites its source in the child's `evidence`:

| Item | Change |
|---|---|
| `gmail-multipart-resumable` | On Google media upload paths (`/upload/`, `/resumable/upload/` on `googleapis.com`: Gmail, Drive, YouTube) the content-type and `uploadType` conditions are dropped: Discovery's `accept` (`message/*`) is the media part's type, while a multipart upload is `multipart/related` and a resumable one starts with JSON or no body type. Gmail `drafts.update` (PUT) is added. |
| `drive-v2` | Drive v2 upload (POST `/upload/drive/v2/files`, PUT `.../files/{fileId}`, both also under `/resumable`) and download (`alt=media`, `/export`) rules beside v3's. Drive v2 sharing is not in the evidence. |
| `google-batch` | New children `gmail-batch` (POST `/batch` on `gmail.googleapis.com`) and `google-drive-batch` (POST `/batch/drive/v3`, `/batch/drive/v2`). |
| `graph-beta` | Every `graph.microsoft.com` path under `/v1.0/` also under `/beta/`. |
| `graph-case-insensitive` | Every `graph.microsoft.com` rule is `path_case_insensitive` (`/V1.0/ME/SENDMAIL` is `outlook-sending`). |
| `graph-dollar-batch` | New child `ms-base-graph-batch` (container `ms-base`, POST `/v1.0/$batch`, `/beta/$batch`, case-insensitive). |
| `telegram-case-insensitive` | `api.telegram.org` rules are `path_case_insensitive` (`SENDDOCUMENT` is `sendDocument`). |
| `discord-versions` | Every `discord.com` `/api/` path unversioned and as `v10`, `v9`, `v8`, `v7` and `v6` (v5 and older are discontinued and not matched). |
| `dropbox-arg` | On `content.dropboxapi.com` the `Dropbox-API-Arg` header and content-type conditions are dropped: the path names the function, and whether the argument may instead be an `arg` URL parameter is unverified (vendor HTTP docs blocked, `research/blocked-urls.md` row 48). |

A batch request carries several API calls in its body (up to 20 for Graph), so its inner functions are not in the
request line: the batch child is reported instead, and a policy that denies a function child should deny the
matching batch child too (`deny apps:[gmail-uploading, gmail-batch]`). Parsing batch bodies is not done (follow-up
in `migration/POST-MERGE-BACKLOG.md`). `deny containers:[ms-base]` and `containers:[google-base]` still cover them.

Wave 0 gives 47 children (50 with the three batch children) over 20 of its 30 services (the other 10 had no separable cited function; the 30 base
children map to their parents; 3 children are skipped:
`telegram-bot-downloading`, whose only path is a multi-segment variable, and the two `google-gemini-api` children,
whose parent is not yet in the pack). Most rules describe vendor APIs (`client_scope: api`): the vendors do not
publish their own web clients' request paths, so a browser session of Gmail is `gmail`, not a child.

## Adding a wave

1. App Research (wave 0, PRO-495) or Research Lab (later waves, PRO-491) delivers `research/child-apps/wave-N.json`
   with official citations.
2. Copy it to `migration/fixtures/child-apps/`, run `python3 -B tools/child_apps_wave.py <file> --evidence
   migration/fixtures/child-apps/wave-1.json --version <next> --write`, review `docs/child-apps/wave-N-rules.md`, add example requests for the new children to
   `childapp_test.go`, and add the file to `make child-apps`.
3. `cd go && go test ./internal/childapp/ ./detector/`, `make check`, then one PR per wave of about 30 services from a
   fresh branch off `main`.
