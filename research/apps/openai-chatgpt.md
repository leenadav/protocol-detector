# OpenAI ChatGPT and OpenAI API

- Content-pack ids today: `openai-chatgpt` (`chatgpt.com`, `chat.openai.com`, `oaiusercontent.com`, `oaistatic.com`; web fronts `openai.com`, `www.openai.com`), `openai-platform` (`api.openai.com`, `platform.openai.com`)
- Status: **BLOCKED**. OpenAI's network article and its developer docs sit behind a bot challenge that this session must not bypass. No host-name claim below is verified.
- Sources accessed: 2026-11-18

## 1. What it is

OpenAI's consumer and business generative-AI assistant (ChatGPT) and its developer API. It is the
generative-AI application operators ask about most often. That is this lane's assessment of
operator value, not a sourced prevalence figure.

## 2. Transport and ports

`UNVERIFIED`. The primary article, "Network recommendations for ChatGPT errors on web and apps"
(help.openai.com article 9247338), returned a Cloudflare challenge page ("Just a moment...") to this
session, and so did `platform.openai.com`. This lane does not bypass bot challenges. The article's
content is therefore **not** paraphrased here, not even from search-result snippets.

What was read directly from OpenAI's own server:

- `https://openai.com/chatgpt-voice.json`: a JSON object with `creationTime`
  `2026-11-16T01:33:53.175979+00:00` and 411 `ipv4Prefix` entries. The file itself does not say what
  the addresses are for. The name suggests ChatGPT Voice, but this lane has not read OpenAI text
  that says so, so the **purpose is `UNVERIFIED`**.
- `chatgpt-connectors.json`, `chatgpt-user.json`, `chatgpt-actions.json`, `searchbot.json` and
  `gptbot.json` at the same origin returned HTTP 200. Their contents and purpose were not examined,
  and nothing read here documents them, so they are not used.

## 3. Observable evidence

- TLS SNI is the only evidence class available on the CONNECT path (README, shared facts). The
  current pack's names are plausible operator-owned domains. **None is verified by this lane**: they
  stay at level **U** until a primary source is read.
- ALPN, ports, WebSocket hosts and any voice/UDP transport: `UNVERIFIED`.

## 4. Encrypted-traffic caveats

Not assessed beyond the general facts in the README. Any OpenAI-specific statement (for example
about TLS inspection, WebSockets or UDP) would come from the blocked article.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| Current pack names | **U** | No primary source read |
| Destination in `chatgpt-voice.json` prefixes | **U** | Purpose not stated in the file |

Known structural risk, independent of sources: the pack treats `openai.com` as a web front
(provider affiliation only). That matches the v0.65 contract and needs no change.

## 6. Synthetic test vectors

Pending verification. Once the names are verified: SNI positives for each verified host,
`chatgpt.com.example.invalid` and `notchatgpt.com` negatives, and an `ech_outer()` negative, as in
the other specs.

## 7. Sources

- [S1] `https://openai.com/chatgpt-voice.json`, read 2026-11-18 (`creationTime`
  2026-11-16T01:33:53Z, 411 IPv4 prefixes). Purpose not stated in the file.
- [BLOCKED] `https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps`:
  Cloudflare challenge page, 2026-11-18.
- [BLOCKED] `https://platform.openai.com/docs/api-reference/introduction`: Cloudflare challenge page,
  2026-11-18.

## 8. Catalog delta and recommendation

None yet. **Request to Hermes**: a copy of the article text, which Lee or Hermes can read in a normal
browser, saved as a file or pasted into this chat, would let this lane verify the entry. The lane
would cite the article URL and the date of the copy. This is the only way forward that does not
bypass the bot challenge.
