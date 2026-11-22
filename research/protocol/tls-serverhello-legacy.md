# PROTOCOL spec: TLS ServerHello profile widening (no invalidation of valid TLS 1.0 to 1.2 servers)

- Kind: **PROTOCOL** (change to an existing parser's profile). Post-merge, Go only, with a recorded parity delta
- Status: **READY** for an Engine decision
- Origin: D09 (`research/d09-iscx-vpn2016.md` 4.3, 6): 211 TCP sessions invalidated after the server's reply;
  most frequent reason "TLS 1.2 cipher outside supported ServerHello profile"
- Primary sources: RFC 2246 (TLS 1.0), RFC 4346 (TLS 1.1), RFC 5246 (TLS 1.2), RFC 8446 (TLS 1.3), RFC 8996
  (deprecation of TLS 1.0/1.1), IANA "TLS Cipher Suites" registry (`https://www.iana.org/assignments/tls-parameters/`,
  registry updated 2026-11-05, 446 records); accessed 2026-11-19

## 1. Current behaviour (code at `claude/go-migration` `bc65e50`, `protocol_engine/tls_server.py`)

- `parse_server_hello` requires `server_version == 0x0303`, else `UnsupportedPrefix('ServerHello profile requires
  TLS 1.2 or 1.3 legacy version')`.
- For TLS 1.2 it accepts only cipher `0x002f` and `0xc023` to `0xc032`, else `UnsupportedPrefix('TLS 1.2 cipher
  outside supported ServerHello profile')`.
- Either way the session's TLS identification (from a valid ClientHello) ends invalidated (D09).

## 2. Why that is too narrow (from the registry and RFCs)

- **Common TLS 1.2 suites are rejected.** These IANA values are outside the accepted set (name and "Recommended"
  column as registered): `0x009c` TLS_RSA_WITH_AES_128_GCM_SHA256 (D), `0x009d` TLS_RSA_WITH_AES_256_GCM_SHA384 (D),
  `0x009e`/`0x009f` TLS_DHE_RSA_WITH_AES_*_GCM (D), `0x0035` TLS_RSA_WITH_AES_256_CBC_SHA (D), `0xc013`/`0xc014`
  TLS_ECDHE_RSA_WITH_AES_*_CBC_SHA (N), `0xcca8` TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (**Y**), `0xcca9`
  TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (**Y**), `0xccaa` TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (D).
  Two of them are IANA-recommended suites in current use.
- **Legacy versions are valid TLS.** TLS 1.0 uses `{ 3, 1 }` (RFC 2246) and TLS 1.1 `{ 3, 2 }` (RFC 4346) in
  `server_version`. RFC 8996 says "TLS 1.0 MUST NOT be used" and "TLS 1.1 MUST NOT be used". That makes such a
  session a **risk**, not a non-TLS session.

## 3. Proposed profile

1. Accept `server_version` ∈ {`0x0301`, `0x0302`, `0x0303`}. For `0x0301`/`0x0302`, identify TLS and add a risk
   `tls-deprecated-version-selected` (new risk id; RFC 8996). The existing `tls-legacy-version-offer` covers
   offers, not selection.
2. For TLS 1.0 to 1.2, accept any cipher value **registered** in the IANA TLS Cipher Suites registry, except
   the registered signalling cipher suite values `0x00ff` (TLS_EMPTY_RENEGOTIATION_INFO_SCSV, RFC 5746 per the
   registry) and `0x5600` (TLS_FALLBACK_SCSV, RFC 7507 per the registry). Unregistered values and values the
   registry marks "Reserved" (for example `0x0a0a`, `0x1a1a`, RFC 8701 per the registry) are malformed. This lane
   has not read RFCs 5746, 7507 and 8701, so the Engine lane should confirm that a server never selects an SCSV
   before treating V6 as malformed.
3. Derive `selected_key_exchange` from the registered name: `TLS_ECDHE_*` → ecdhe, `TLS_DHE_*` → dhe,
   `TLS_RSA_*` → static-rsa, `TLS_ECDH_*` → static-ecdh, `TLS_PSK_*`/`*_PSK_*` → psk. Set `selected_cipher_mode`
   to aead for `*_GCM_*`, `*_CCM*` and `*_CHACHA20_POLY1305_*`, else cbc or stream from the name.
4. Keep the existing risks: `tls-no-forward-secrecy` (static-rsa, static-ecdh, psk) and
   `tls-prohibited-cipher-offered`-style checks for RC4 (for example `0x0005`), 3DES (for example `0x000a`) and NULL suites,
   applied to the **selected** suite as a selected-cipher risk.
5. Ship the registry subset as a generated table with its registry date, not hand-typed ranges.

## 4. Test vectors (ServerHello bodies; the handshake header and record wrapper as in the existing fixtures)

| # | server_version | cipher | Expected |
|---|---|---|---|
| V1 | 0303 | 009c | identified TLS 1.2; key exchange static-rsa; aead; risk `tls-no-forward-secrecy` |
| V2 | 0303 | cca8 | identified TLS 1.2; ecdhe; aead |
| V3 | 0303 | c013 | identified TLS 1.2; ecdhe; cbc |
| V4 | 0301 | 0035 | identified TLS 1.0; static-rsa; cbc; risks `tls-deprecated-version-selected`, `tls-no-forward-secrecy` |
| V5 | 0302 | 002f | identified TLS 1.1; risks as V4 |
| V6 | 0303 | 00ff | malformed (SCSV selected) |
| V7 | 0303 | 0a0a | malformed (GREASE or unregistered) |
| V8 | 0300 (SSL 3.0) | 002f | outside the profile (SSL 3.0 is not TLS; RFC 7568 is not read here, so the outcome stays unknown and not invalidated) |
| V9 | existing TLS 1.2/1.3 ServerHello fixtures | | unchanged |

## 5. Parity

Changes existing behaviour: a Go-only change after the merge, with every changed case recorded in
`migration/parity/deltas.json` and justified by this spec.
