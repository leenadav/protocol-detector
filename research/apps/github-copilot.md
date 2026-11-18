# GitHub Copilot

- Content-pack id today: `github-copilot` (`githubcopilot.com`); GitHub itself is `github`
- Status: **READY**. GitHub publishes plan-specific host names, the most useful generative-AI finding in this batch.
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

1. **Plan attribution.** Add the three plan suffixes so that the verdict can carry the plan as a
   bounded enum (`individual`, `business`, `enterprise`, `unknown`). This is new evidence vocabulary
   (closed set, no identifier) and needs a decision from the Engine lane on where it belongs:
   application id variants (`github-copilot-individual`) or an evidence field. Recommended: an
   evidence field, so that reports keep one application id.
2. Add `copilot-proxy.githubusercontent.com`, `origin-tracker.githubusercontent.com` and
   `copilot-telemetry.githubusercontent.com` → `github-copilot` (longer than `githubusercontent.com`).
3. Add the seven exact `production-copilot-host*.webpubsub.azure.com` names → `github-copilot`. They
   are exact-host entries on a shared service, which the v0.65 rule allows only because the vendor
   names them.
4. Leave `default.exp-tas.com`, `github.com` and `api.github.com` as they are.
