# Box

- Content-pack id today: `box` (`box.com`, `boxcloud.com`, `box.net`)
- Status: **BLOCKED**, NAME. Box's firewall article redirects to a sign-in page (`box.zendesk.com/access`), and this lane does not sign in to vendor portals
- Sources accessed: 2026-11-18

## 1. What it is

Enterprise cloud content management and file sharing.

## 2. Transport and ports

`UNVERIFIED`. The article that would state them could not be read.

## 3. Observable evidence

`UNVERIFIED`. The article "Configuring A Firewall For Box Applications and Services" (Box support
article 33552262497683) returned HTTP 302 to a sign-in page on 2026-11-18. Its contents are not paraphrased
here, not even from search snippets.

## 4. Encrypted-traffic caveats

Not assessed.

## 5. Confidence and false-positive risks

| Observable | Level |
|---|---|
| Current pack names | **U** |

## 6. Synthetic test vectors

Pending sources.

## 7. Sources

- [BLOCKED] `https://support.box.com/hc/en-us/articles/33552262497683-Configuring-A-Firewall-For-Box-Applications-and-Services`:
  redirect to sign-in, 2026-11-18.

## 8. Catalog delta and recommendation

None yet. **Request to Hermes**: the article text, copied by Lee from a signed-in or normal browser
session, as was done for OpenAI.
