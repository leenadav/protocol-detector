# GitHub Copilot

- Content-pack id today: `github-copilot` (`githubcopilot.com`); GitHub itself is `github`
- Status: names **READY**, NAME, batch A. The plan field is **ENGINE-FIELD** (Hermes, 2026-11-18): implemented after the Go migration merge, in Go only
- Implemented: content release 2026.11.3 on `claude/go-migration` (`baa07b9`); verified in the pack at `47b2743`, 2026-11-18
- Decided (Lee via Hermes, 2026-11-18): the Copilot plan is an extra evidence field, not separate application ids
- Sources accessed: 2026-11-18

## 1. What it is

GitHub's AI coding assistant, used from IDE extensions, the CLI and github.com. It is sold as
individual plans and as Business and Enterprise plans. Detecting a *personal* plan on a corporate
network is a shadow-AI question operators ask.

## 2. Transport and ports

HTTPS on TCP 443, and WSS on TCP 443 for "Copilot on GitHub" real-time events [S1]. GitHub's
general rule is "you must allow TCP ports 22, 80, and 443 via our IP ranges for github.com" [S2].

## 3. Observable evidence

From the "Copilot allowlist reference" [S1] (hosts only; paths are not visible without decryption):

| Host (published) | Purpose (as published) |
|---|---|
| `*.githubcopilot.com` | "API service for Copilot suggestions. Allows access to authorized users regardless of Copilot plan" |
| `*.individual.githubcopilot.com` | "... via a Copilot Individual plan" |
| `*.business.githubcopilot.com` | "... via a Copilot Business plan" |
| `*.enterprise.githubcopilot.com` | "... via a Copilot Enterprise plan or the Copilot access billing model" |
| `copilot-proxy.githubusercontent.com`, `origin-tracker.githubusercontent.com` | "API service for Copilot suggestions" |
| `copilot-telemetry.githubusercontent.com` | "Copilot client telemetry" |
| `default.exp-tas.com` | "Copilot client experimentation" |
| `copilot-reports.github.com` | "Copilot usage metrics report downloads" |
| `github.com` (`/copilot/*`), `api.github.com` (`/copilot_internal/*`) | Copilot on GitHub and user management. Visible only as the host `github.com` / `api.github.com` |
| `production-copilot-host[-<region>].webpubsub.azure.com` (7 hosts listed) | "Real-time WebSocket connection used by Copilot on GitHub" |
| `copilot-reports-*.b01.azurefd.net` | report download fallback via Azure Front Door |

For data-residency customers: `*.SUBDOMAIN.ghe.com`, with per-service endpoints such as
`copilot-proxy.SUBDOMAIN.ghe.com` [S1].

GitHub calls this "subscription-based network routing". It says not to allowlist the plan-agnostic
`*.githubcopilot.com` when using it, and to leave out `*.business.githubcopilot.com` "if you want to use
subscription-based network routing to block users from using Copilot Business on your network" [S1].
GitHub's own network control therefore separates plans by host name. The routing itself is described
on a page this lane has not read yet ("Managing GitHub Copilot access to your enterprise's network");
it is cited for the host names only.

## 4. Encrypted-traffic caveats

- `webpubsub.azure.com` and `azurefd.net` are shared Azure services. GitHub itself says to "use the
  required hostnames rather than allowing every Azure Web PubSub service with *.webpubsub.azure.com" [S1].
  Only the exact published host names may be mapped.
- `github.com` and `api.github.com` carry ordinary GitHub use. Copilot on GitHub.com is a URL path
  there and is not visible.
- The plan label is client-asserted SNI, an offer, not proof of the plan. `UNVERIFIED`: how GitHub's
  servers treat a client that presents a plan host it is not entitled to; nothing read here says.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `individual.githubcopilot.com` | **N3**, Copilot, individual plan | Plan label documented by GitHub [S1] |
| SNI under `business.githubcopilot.com` / `enterprise.githubcopilot.com` | **N3**, Copilot, business/enterprise | as above |
| SNI under `githubcopilot.com`, other labels | **N3**, Copilot, plan unknown | |
| `copilot-proxy.` / `origin-tracker.` / `copilot-telemetry.githubusercontent.com` | **N3** Copilot | Today all three fall under `githubusercontent.com` and are named `github` |
| exact `production-copilot-host*.webpubsub.azure.com` | **N3** | Only these exact names. Never the parent domain |
| `default.exp-tas.com` | **N1** | Published for Copilot, but the name says nothing about Copilot. `UNVERIFIED` whether other Microsoft clients also use it, so do not map |
| `github.com`, `api.github.com` | `github` only | Copilot on github.com is not separable |

## 6. Synthetic test vectors

| # | Input | Expected |
|---|---|---|
| P1 | SNI `proxy.individual.githubcopilot.com` (synthetic first label) | Copilot, plan `individual` |
| P2 | SNI `api.business.githubcopilot.com` | Copilot, plan `business` |
| P3 | SNI `copilot-proxy.githubusercontent.com` | Copilot (today: `github`) |
| P4 | SNI `production-copilot-host-westus.webpubsub.azure.com` | Copilot |
| N1 | SNI `otherapp.webpubsub.azure.com` | no application (shared Azure service) |
| N2 | SNI `individual.githubcopilot.com.example.invalid` | no application |
| N3 | SNI `raw.githubusercontent.com` | `github` |
| N4 | `ech_outer()` with outer SNI `api.individual.githubcopilot.com` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-19 against `c08773f` plus batches D to I and retrofit R)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `github.com` | one of `github-copilot`, `github` | `github` | PASS |
| O+ | `github.githubassets.com` | one of `github-copilot`, `github` | `github` | PASS |
| D- | `images.ctfassets.net` | not github-copilot/github (third party) | no application | PASS |
| D- | `videos.ctfassets.net` | not github-copilot/github (third party) | no application | PASS |
| L- | `xgithubcopilot.com` | not github-copilot/github (label boundary) | no application | PASS |
| L- | `githubcopilot.com.example.invalid` | not github-copilot/github (suffix look-alike) | no application | PASS |
| L- | `xgithubusercontent.com` | not github-copilot/github (label boundary) | no application | PASS |
| L- | `copilot-proxy.githubusercontent.com.example.invalid` | not github-copilot/github (suffix look-alike) | no application | PASS |
| L- | `origin-tracker.githubusercontent.com.example.invalid` | not github-copilot/github (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] GitHub Docs, "Copilot allowlist reference",
  `https://docs.github.com/en/copilot/reference/copilot-allowlist-reference`, sections "Copilot on
  GitHub.com" and "Copilot on GHE.com", accessed 2026-11-18.
- [S2] GitHub Docs, "About GitHub's IP addresses",
  `https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-githubs-ip-addresses`,
  accessed 2026-11-18. The Meta API itself (`api.github.com/meta`) could not be read from this
  session (the session's GitHub API access is repository-scoped). The page states the Meta API list
  "is not intended to be an exhaustive list".

## 8. Catalog delta and recommendation

### 8a. Names (NAME-BASED, READY, batch A)

```python
("github-copilot", "business-systems", "generative-ai", "client-server", 3, "GitHub Copilot", ("transfers-files",),
 ("githubcopilot.com", "copilot-proxy.githubusercontent.com", "origin-tracker.githubusercontent.com",
  "copilot-telemetry.githubusercontent.com", "production-copilot-host.webpubsub.azure.com",
  "production-copilot-host-centralus.webpubsub.azure.com", "production-copilot-host-centralus-02.webpubsub.azure.com",
  "production-copilot-host-eastasia.webpubsub.azure.com", "production-copilot-host-austriaeast.webpubsub.azure.com",
  "production-copilot-host-westus.webpubsub.azure.com", "production-copilot-host-westus3.webpubsub.azure.com")),
```

The plan hosts need no entry of their own: they are under `githubcopilot.com`. `default.exp-tas.com`,
`github.com` and `api.github.com` are unchanged.

### 8b. Plan field (decided; ENGINE-FIELD kind, after the Go merge, Go only)

It needs engine or data-model code (verdict evidence), but no parser. Hermes made this a third kind,
ENGINE-FIELD, with the same policy as PROTOCOL: after the Go migration merge, Go only, tested with these
vectors. Specification:

- **Field**: `copilot_plan`, a closed set: `individual`, `business`, `enterprise`, `unspecified`.
- **Derivation**: from the normalized server name that named `github-copilot`, matched on whole labels,
  innermost plan label wins. `<x>.individual.githubcopilot.com` → `individual`; `<x>.business.githubcopilot.com`
  → `business`; `<x>.enterprise.githubcopilot.com` → `enterprise`; any other `githubcopilot.com` name, and the
  `githubusercontent.com` and `webpubsub.azure.com` Copilot hosts → `unspecified`.
- **Strength**: `asserted` (client-asserted SNI, like the name itself). The reason text must not include the host.
- **Never** set from anything but the SNI/Host already used for the catalog; never inferred from absence.
- **Vectors**: P1 → `individual`, P2 → `business`, `x.enterprise.githubcopilot.com` → `enterprise`,
  `api.githubcopilot.com` → `unspecified`, P3 and P4 → `unspecified`; `business.example.invalid` and
  `individual.githubcopilot.com.example.invalid` → no application and no field; ECH outer → no field.

<!-- method-v2:start -->

## 9. Live verification (L)

**BLOCKED in the research environment** (2026-11-19): its egress proxy re-terminates TLS, so a handshake would show the proxy, and direct DNS is not permitted. The tool is `research/tools/live_verify.py`; it runs from an unproxied vantage point or, DNS only, through an approved DoH resolver. No host below carries an `L` result yet.

Names to verify (catalog domains of `github-copilot`, `github`): `githubcopilot.com`, `copilot-proxy.githubusercontent.com`, `origin-tracker.githubusercontent.com`, `copilot-telemetry.githubusercontent.com`, `production-copilot-host.webpubsub.azure.com`, `production-copilot-host-centralus.webpubsub.azure.com`, `production-copilot-host-centralus-02.webpubsub.azure.com`, `production-copilot-host-eastasia.webpubsub.azure.com`, `production-copilot-host-austriaeast.webpubsub.azure.com`, `production-copilot-host-westus.webpubsub.azure.com`, `production-copilot-host-westus3.webpubsub.azure.com`, `github.com`, `githubusercontent.com`, `githubassets.com`.

## 10. Observed web-client hosts (dependency mapping)

- `https://github.com/copilot`, loaded 2026-11-19 without signing in: HTTP 200, final host `github.com`.

Pass 1 is a lower bound. The proxy refuses hosts not on the allowlist ("failed" below), so hosts that only scripts from a refused host would contact are missing.

| Host | Requests (refused) | Class | Attribution today | Note |
|---|---|---|---|---|
| `github.com` | 2 (0) | app-owned | `github` |  |
| `github.githubassets.com` | 70 (70) | app-owned | `github` |  |
| `images.ctfassets.net` | 11 (11) | third party | no application | Contentful CMS assets |
| `videos.ctfassets.net` | 2 (2) | third party | no application | Contentful CMS assets |

## 11. Attributes (App-ID model) and re-verify date

- `github-copilot`: business-systems / generative-ai, client-server; characteristics `transfers-files`; **risk 3**: moves files out of the organisation.
- `github`: business-systems / software-development, browser-based; characteristics `widely-used`, `transfers-files`; **risk 2**: widely used by enterprises; moves files out of the organisation.
- Functions separated by name: `github-copilot` (GitHub Copilot), `github` (GitHub code hosting).
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `images.ctfassets.net`, `videos.ctfassets.net`.
- Evasive (ECH, DoH, proxy modes): ECH support unknown until a live HTTPS-record check (section 9); other modes as stated in sections 2 to 4.
- Re-verify by: **2027-02-17** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
