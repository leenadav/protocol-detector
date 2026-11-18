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
| N1 | SNI `generativelanguage.googleapis.com` | `google-base`, never Gemini (no dedicated host verified) |
| N2 | SNI `gemini.google.com.example.invalid` | no application |
| N3 | `ech_outer()` with outer SNI `gemini.google.com` | no application |

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
