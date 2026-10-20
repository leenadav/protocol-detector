# Handshake fingerprints — v0.24

With `Config(fingerprints=True)` (CLI `--fingerprints`) the engine derives
deterministic digests of structural handshake fields and reports them as
evidence with strength `derived`. A fingerprint characterizes a client or
server **implementation family** (a TLS library build, an SSH client); it is
not a user identity, not a product version and not authenticated. No random
bytes, session identifiers, key shares or cookies enter any digest.

| Evidence field | Where | Definition |
|---|---|---|
| `ja4` | TLS ClientHello (`t`), DTLS ClientHello (`d`), QUIC Initial ClientHello (`q`) | FoxIO JA4: `<proto><version><sni d/i><cipher count><ext count><alpn>_<sha256(sorted ciphers)[:12]>_<sha256(sorted ext without SNI/ALPN + "_" + sigalgs)[:12]>`, GREASE removed; version from `supported_versions` when present |
| `ja3` | TLS ClientHello | Salesforce JA3: md5 of `version,ciphers,extensions,groups,point_formats` (decimal, `-` joined), GREASE removed |
| `ja4s` | TLS ServerHello (not HelloRetryRequest) | `<proto><version><ext count><alpn>_<cipher hex>_<sha256(extensions in order)[:12]>`; the specification example `t130200_1301_a56c5b993250` is reproduced by the TLS 1.3 fixture |
| `ja3s` | TLS ServerHello | md5 of `version,cipher,extensions` |
| `hassh` | SSH client KEXINIT | md5 of `kex;enc_c2s;mac_c2s;comp_c2s` name-lists |
| `h2_settings` | HTTP/2 initial SETTINGS | Akamai-style `id:value;id:value` in frame order (SETTINGS portion only) |

Fingerprints are emitted on classification events (`fingerprints` object in
live JSON, `ja4=...` suffix in readable output) and collected per session in
`session["fingerprints"]`. They also feed custom signatures indirectly: the
same `ClientHelloInfo` structure backs the `ssl-req-*` contexts.

## SSH identification followed by a refinement

The SSH profile identifies on the banner. With fingerprints enabled the parser
stays attached for exactly one binary packet, which must be `SSH_MSG_KEXINIT`
(RFC 4253 7.1: length 17..35000 and within `max_bytes`, padding >= 4, cookie,
ten printable ASCII name-lists each <= 4096 bytes, `first_kex_packet_follows`
0/1, zero reserved field, no trailing bytes). The engine publishes the
identification immediately (`updated`) and a second event (`refined`) with
`hassh` when the packet completes. A malformed packet, the byte budget or
`end()` closes the continuation **without changing the identification**: the
stream stays `identified ssh` with no fingerprint. Bytes after the KEXINIT are
not consumed.

This is the first use of a general post-identification continuation in
`Inspector`: a parser that sets `continues = True` on completion keeps
receiving bytes until it clears the flag or fails; failures never downgrade a
published identification. Later releases use the same hook for application
shift at protocol-defined boundaries.

## What fingerprints are not

- Not an application identity: policy on a JA4 is policy on a client build.
- Not stable across library upgrades or TLS session-resumption variants; JA4 in
  particular is weakened by PSK/early-data extensions.
- Not computed for HelloRetryRequest, retries or encrypted QUIC packets.
- Not a privacy exemption: a fingerprint is derived from structural fields the
  observation already validated and carries no payload, hostname or cookie.
