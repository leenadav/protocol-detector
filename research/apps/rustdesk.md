# RustDesk

- Content-pack id today: `rustdesk` (`rustdesk.com`, description "public servers"; web fronts apex and `www`)
- Status: **PARTIAL**, NAME. Low priority; research continues when the source is reachable
- Sources accessed: 2026-11-18

## 1. What it is

RustDesk. See the catalog entry for its category.

## 2. Transport and ports

See section 3.

## 3. Observable evidence

RustDesk's self-host docs give the server roles and ports: "hbbs - RustDesk ID (rendezvous / signaling) server, listen on TCP (21114 - for http in Pro only, 21115, 21116, 21118 for web socket) and UDP (21116)"; "hbbr - RustDesk relay server, listen on TCP (21117, 21119 for web socket)"; core ports "TCP 21114-21119, UDP 21116". The public server host names are not on that page, so the catalog's `rustdesk.com` mapping for public servers is `UNVERIFIED`. The ports could support a later PROTOCOL item, but the wire format is not specified on the page.

## 4. Encrypted-traffic caveats

Not assessed beyond the README's shared facts.

## 5. Confidence and false-positive risks

| Observable | Level |
|---|---|
| Current pack names | **U** (not verified by this lane) |

## 6. Synthetic test vectors

Pending a readable source.

## 7. Sources

- `https://rustdesk.com/docs/en/self-host/`, accessed 2026-11-18

## 8. Catalog delta and recommendation

None. Next: No catalog change. A PROTOCOL item would need a published wire format, and none was found.
