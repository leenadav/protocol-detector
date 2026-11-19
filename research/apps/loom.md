# Loom

- Content-pack id today: none
- Status: **READY**, NAME, batch F: new id `loom`
- Sources accessed: 2026-11-19. Article "Updated on April 30, 2026"

## 1. What it is

Video messaging and screen recording (an Atlassian product).

## 2. Transport and ports

`wss` and HTTPS on 443 (the article also lists 80) [S1].

## 3. Observable evidence

"Domains, Protocols and Ports required for Loom" [S1]: `*.loom.com`, `www.loom.com`, `proxy.loom.com`,
`record.loom.com`, `location.loom.com`, `cdn.loom.com`, `packages.loom.com`, `luna.loom.com`,
`loom-media-production.s3-accelerate.amazonaws.com`, `object-store.atlassian.com`, plus third parties
(`icanhazip.com`, `cdn.segment.com`, `*.intercom.io`, `*.s3.us-west-2.amazonaws.com`, `*.logs.datadoghq.com`).

## 4. Encrypted-traffic caveats

Recordings upload to S3. Only the named bucket host is proposed, never the generic regional S3 wildcard.
`object-store.atlassian.com` already resolves to `atlassian`.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `loom.com` | **N3** | |
| SNI `loom-media-production.s3-accelerate.amazonaws.com` | **N3** (exact) | Media uploads |
| `object-store.atlassian.com` | `atlassian` | Shared Atlassian storage |

## 6. Synthetic test vectors

| # | Input | Expected |
|---|---|---|
| P1 | SNI `www.loom.com`, `record.loom.com` | `loom` |
| P2 | SNI `loom-media-production.s3-accelerate.amazonaws.com` | `loom` |
| N1 | SNI `object-store.atlassian.com` | `atlassian` |

Checked in scratch (`c08773f` plus D, E and F).

## 7. Sources

- [S1] Atlassian Support (Loom), "Domains, Protocols and Ports required for Loom to work on your servers",
  `https://support.atlassian.com/loom/kb/domains-protocols-and-ports-required-for-loom-to-work-on-your-servers/`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

```python
("loom", "collaboration", "voip-video", "browser-based", 2, "Loom video messaging",
 ("transfers-files",), ("loom.com", "loom-media-production.s3-accelerate.amazonaws.com")),
```
