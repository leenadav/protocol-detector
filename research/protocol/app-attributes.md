# Proposed application attribute schema (ENGINE-FIELD, post-merge, Go only)

- Kind: **ENGINE-FIELD**. Post-merge, Go only (Lee's rule for engine and data-model work). Status: **PROPOSAL** for the Engine lane.
- Origin: research method v2, item 3 (Hermes for Lee, 2026-11-19). It is modelled on the shape of commercial
  application-identification catalogs: per application, its functions, dependencies, category and
  characteristics, and a risk rating. Their content is not copied; values come from this lane's primary-sourced specs.
- Today the catalog row (`protocol_engine/host_apps.py`) is: name, category, subcategory, technology, risk,
  description, characteristics, domains, web_fronts. Category, subcategory, technology, risk and the
  characteristics set already exist. This schema adds the rest, and every spec now records the values as
  data (section 11), so the engine fields can be filled when they exist.

## Fields

| Field | Type | Meaning | Rule |
|---|---|---|---|
| `id` | string | existing application id | unchanged |
| `parent` | id or null | the application this is a function of (for example `ms-teams` → `ms-office365`; `anthropic-api` → `anthropic-claude`) | set only when the functions are separated **by name** in a primary source |
| `functions` | list of `{id, kind, names}` | sub-applications: `web`, `api`, `chat`, `meetings`, `file-transfer`, `admin-console`, `sync-client`, `agent`, `media-relay` | each function lists its own host names; a function with no name of its own is not listed |
| `depends_on` | list of ids | applications this one needs and that must **not** be reported as it: identity (`google-accounts`, `azure-ad`, `okta`), CAPTCHA and bot defence (`cloudflare-challenge`), consent, telemetry, payment | from observed web-client hosts (spec section 10) and the vendor's own list; a dependency never inherits the app's identity |
| `category`, `subcategory`, `technology` | existing vocabulary | unchanged | unchanged |
| `characteristics` | set | existing vocabulary plus `supports-ech`, `consumer-variant`, `business-variant` | `supports-ech` only from a live HTTPS-record observation (`L`) or a vendor statement; never inferred |
| `variant` | `consumer` \| `business` \| `both` \| null | whether names separate consumer and business use | only when separated by name (for example `onedrive.live.com` vs `*.sharepoint.com`) |
| `risk` | 1 to 5 | existing field | with `risk_reason` |
| `risk_reason` | short text | why: the characteristics that drive the rating | written per app in spec section 11 |
| `evidence` | per host name: `N3`/`N2`/`N1`, plus `L:<date>` when live-verified and `O:<date>` when observed from the vendor's own web client | confidence input | `L` and `O` never raise a name above its primary-source level; a dead or CDN-fronted `L` result caps it |
| `reverify_by` | date | 90 days after the last verification | the change tracker (`research/tools/recheck_sources.py`) reports overdue items |

## Output rule

A gateway record shows `app` (the function's id when a function matched, otherwise the application) and may
show `parent`. `depends_on` is catalog data only. A session to a dependency host is reported as the
dependency's own id or as no application, never as the depending application.

## Test vectors the Engine lane can use

Each spec's section 6 now lists observed positives, dependency negatives and look-alike negatives. The
expected results are checked against `attribution_for_host` in scratch and recorded with the date.
