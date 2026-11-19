# Google generative AI: Gemini, AI Studio, Notebook

- Content-pack ids today: `google-gemini` (`gemini.google.com`), `google-ai-studio` (`aistudio.google.com`), `google-notebooklm` (`notebooklm.google.com`)
- Status: **READY**, NAME, batch C (`research/patches/batch-c-name-based.patch`): `notebook.google.com` is now sourced as the product's URL. Gemini and AI Studio are DONE. `notebooklm.google.com` stays unverified (kept)
- Sources accessed: 2026-11-18. Page "Last updated 2026-11-10 UTC"

## 1. What it is

Google's generative-AI products as listed for Google Workspace administrators: the Gemini app, Google
AI Studio (developer prompt and API console) and a notebook product [S1].

## 2. Transport and ports

Google tells Workspace administrators to open "TCP port 443 (HTTPS)" for "the main URLs for
authentication and API call" and "TCP port 80 (HTTP)" to "allow CRL and OCSP checks" [S1]. "Any of
the Google URLs specified in step 2 can use the Google IP addresses" [S1], published as `goog.json`
[S2]. The copy read here (`syncToken` 1795010697996, `creationTime` 2026-11-18T06:04:57) holds 132
IPv4 and 16 IPv6 prefixes, for all of Google, not per product.

## 3. Observable evidence

The host-name allowlist's "Generative AI" row lists, verbatim [S1]:

- `https://gemini.google.com`
- `https://notebook.google.com`
- `https://aistudio.google.com`

The same page lists the main API entry point `https://*.googleapis.com` ("where * is any string not
containing a period") for all Workspace APIs [S1]. It names no separate API host for Gemini.

No ALPN, certificate or protocol-structure information is published. `UNVERIFIED`.

## 4. Encrypted-traffic caveats

- **Shared Google front ends**: one IP range set serves every Google URL [S1, S2], so IP evidence
  says only "Google".
- **QUIC**: Google publishes nothing about QUIC on this page. Any QUIC use would leave the
  visibility-phase TCP path. Recorded here, not assessed.
- **API traffic**: Gemini API calls through `*.googleapis.com` share that wildcard with every Google
  API. Without a dedicated host, programmatic Gemini use cannot be named by SNI. `UNVERIFIED`: a
  dedicated Gemini API host name. None is on the page read.
- **Embedded Gemini** in Gmail, Docs and other apps uses those apps' hosts and cannot be separated by
  SNI (the same limit as Microsoft's in-app Copilot).

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI `gemini.google.com` | **N3** Gemini app | Personal and Workspace accounts are not distinguishable by name (no source separates them) |
| SNI `aistudio.google.com` | **N3** AI Studio | |
| SNI `notebook.google.com` | **N3** NotebookLM (Gemini Notebook) | Google's admin page links "Learn more" for the product to `https://notebook.google.com/` and states "We're renaming NotebookLM to Gemini Notebook" [S3] |
| SNI `notebooklm.google.com` (pack) | **U** | Not on the page read |
| `*.googleapis.com` | **N1** | Every Google API |
| `goog.json` ranges | **N1** | All of Google |

## 6. Synthetic test vectors

| # | Input | Expected |
|---|---|---|
| P1 | SNI `gemini.google.com`, ALPN `h2` | `google-gemini` |
| P2 | SNI `aistudio.google.com` | `google-ai-studio` |
| P3 | SNI `notebook.google.com` | the notebook application (today: falls to `google-base` via `google.com`) |
| N1 | SNI `generativelanguage.googleapis.com` | superseded in batch G: now verified as the Gemini API host and proposed as `google-gemini-api` (`apps/google-gemini-api.md`) |
| N2 | SNI `gemini.google.com.example.invalid` | no application |
| N3 | `ech_outer()` with outer SNI `gemini.google.com` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-19 against `c08773f` plus batches D to I and retrofit R)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `gemini.google.com` | one of `google-gemini`, `google-ai-studio`, `google-notebooklm` | `google-gemini` | PASS |
| D- | `gemini.gstatic.com` | not google-gemini/google-ai-studio/google-notebooklm (shared vendor infra) | `google-base` | PASS |
| D- | `ogads-pa.clients6.google.com` | not google-gemini/google-ai-studio/google-notebooklm (shared vendor infra) | `google-base` | PASS |
| D- | `play.google.com` | not google-gemini/google-ai-studio/google-notebooklm (shared vendor infra) | `google-play` | PASS |
| D- | `www.googletagmanager.com` | not google-gemini/google-ai-studio/google-notebooklm (shared vendor infra) | `google-analytics` | PASS |
| D- | `www.gstatic.com` | not google-gemini/google-ai-studio/google-notebooklm (shared vendor infra) | `google-base` | PASS |
| L- | `xgoogle.com` | not google-gemini/google-ai-studio/google-notebooklm (label boundary) | no application | PASS |
| L- | `gemini.google.com.example.invalid` | not google-gemini/google-ai-studio/google-notebooklm (suffix look-alike) | no application | PASS |
| L- | `aistudio.google.com.example.invalid` | not google-gemini/google-ai-studio/google-notebooklm (suffix look-alike) | no application | PASS |
| L- | `notebooklm.google.com.example.invalid` | not google-gemini/google-ai-studio/google-notebooklm (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Google Workspace Help, "Set up a Google Workspace host name allowlist",
  `https://knowledge.workspace.google.com/admin/getting-started/set-up-a-google-workspace-host-name-allowlist?hl=en`
  (redirected from `support.google.com/a/answer/9012184`), steps 1 to 4, "Last updated 2026-11-10 UTC",
  accessed 2026-11-18. Page text is licensed CC BY 4.0 per its footer.
- [S3] Google Workspace Help, "Turn Gemini Notebook on or off for users",
  `https://knowledge.workspace.google.com/admin/generative-ai/gemini-notebook/turn-gemini-notebook-on-or-off-for-users?hl=en`
  (redirected from the `notebooklm` path), accessed 2026-11-18: rename note and product link.
- [S2] `https://www.gstatic.com/ipranges/goog.json`, accessed 2026-11-18, `syncToken` 1795010697996
  (132 `ipv4Prefix` and 16 `ipv6Prefix` entries).

## 8. Catalog delta and recommendation

The Engine lane left `notebook.google.com` out of batch A because the allowlist source alone did not tie it
to NotebookLM. It is re-sourced from [S3] and proposed again in batch C:

```python
("google-notebooklm", "business-systems", "generative-ai", "browser-based", 3, "Google NotebookLM",
 ("transfers-files",), ("notebooklm.google.com", "notebook.google.com")),
```

- The description stays "Google NotebookLM" (neutral). Google's rename to "Gemini Notebook" [S3] is recorded
  here and can be reflected later if the Engine lane wants it.
- `notebooklm.google.com`: kept, still unverified.
- Do not map `googleapis.com` subdomains to Gemini without a primary source.

Batch G (2026-11-19): the Gemini API reference names `generativelanguage.googleapis.com` as the API host. It is
proposed as its own id, `google-gemini-api`, in `apps/google-gemini-api.md`; no other `googleapis.com` name maps to Gemini.

<!-- method-v2:start -->

## 9. Live verification (L)

**BLOCKED in the research environment** (2026-11-19): its egress proxy re-terminates TLS, so a handshake would show the proxy, and direct DNS is not permitted. The tool is `research/tools/live_verify.py`; it runs from an unproxied vantage point or, DNS only, through an approved DoH resolver. No host below carries an `L` result yet.

Names to verify (catalog domains of `google-gemini`, `google-ai-studio`, `google-notebooklm`): `gemini.google.com`, `aistudio.google.com`, `notebooklm.google.com`, `notebook.google.com`.

## 10. Observed web-client hosts (dependency mapping)

- `https://gemini.google.com/`, loaded 2026-11-19 without signing in: HTTP 200, final host `gemini.google.com`.

Pass 1 is a lower bound. The proxy refuses hosts not on the allowlist ("failed" below), so hosts that only scripts from a refused host would contact are missing.

| Host | Requests (refused) | Class | Attribution today | Note |
|---|---|---|---|---|
| `gemini.google.com` | 3 (0) | app-owned | `google-gemini` |  |
| `gemini.gstatic.com` | 2 (2) | shared vendor infra | `google-base` |  |
| `ogads-pa.clients6.google.com` | 1 (1) | shared vendor infra | `google-base` |  |
| `play.google.com` | 2 (2) | shared vendor infra | `google-play` |  |
| `www.googletagmanager.com` | 1 (1) | shared vendor infra | `google-analytics` |  |
| `www.gstatic.com` | 4 (0) | shared vendor infra | `google-base` |  |

## 11. Attributes (App-ID model) and re-verify date

- `google-gemini`: business-systems / generative-ai, browser-based; characteristics `transfers-files`; **risk 3**: moves files out of the organisation.
- `google-ai-studio`: business-systems / generative-ai, browser-based; characteristics `transfers-files`; **risk 3**: moves files out of the organisation.
- `google-notebooklm`: business-systems / generative-ai, browser-based; characteristics `transfers-files`; **risk 3**: moves files out of the organisation.
- Functions separated by name: `google-gemini` (Google Gemini), `google-ai-studio` (Google AI Studio), `google-notebooklm` (Google NotebookLM).
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `google-analytics`, `google-base`, `google-play`.
- Evasive (ECH, DoH, proxy modes): ECH support unknown until a live HTTPS-record check (section 9); other modes as stated in sections 2 to 4.
- Re-verify by: **2027-02-17** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
