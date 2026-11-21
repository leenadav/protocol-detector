# PROTOCOL spec: Telegram MTProto over TCP (`telegram`)

- Kind: **PROTOCOL** (new parser). Post-merge, Go only, tested with these vectors, not Python parity (Lee, 2026-11-18)
- Status: **READY**, with one open point (section 6) for the Engine lane to settle from Telegram's referenced implementation
- Primary sources: Telegram, "MTProto transports", `https://core.telegram.org/mtproto/mtproto-transports.md` [T1]; "Transport protocols", `https://core.telegram.org/mtproto/transports.md` [T2]; accessed 2026-11-18
- Catalog application: `telegram` (already in the pack, by name)

## 1. Scope

The client's first bytes on a TCP connection that carries MTProto directly ("a plain TCP socket on ports 80, 443,
5222 or other" [T2]). Out of scope: WebSocket and HTTP(S) transports [T2] (they appear as HTTP or TLS), and the
obfuscated transport (section 5).

## 2. Framing (client direction, first segment), from [T1]

| Transport | Marker | First envelope |
|---|---|---|
| Abridged | first byte `0xef` | `L` (1 byte) = payload length / 4, if < 127; else `0x7f` + 3-byte little-endian (payload length / 4). Quick-ACK requests set the top bit: `L \| 0x80`, or `0xff` + 3 bytes |
| Intermediate | first int `0xeeeeeeee` | 4-byte little-endian payload length (top bit may be set for quick-ACK) + payload |
| Padded intermediate | first int `0xdddddddd` | 4-byte little-endian total length = payload + padding (0 to 15 random bytes), top bit may be set for quick-ACK |
| Full | none; the client "first packet sent is numbered 0" | `len` (4 bytes LE, counts itself: len + seqno + payload + crc), `seqno` (4 bytes, 0 for the first packet), payload, `crc` = "4 CRC32 bytes computed using length, sequence number, and payload together" |

Server-side markers: "the server **will not** send `0xef`", `0xeeeeeeee` or `0xdddddddd` as its first bytes [T1].
The profile is client-direction only.

## 3. Profile (what identifies)

Bounded by `Config.max_bytes`. Stop after the first complete envelope.

1. **Intermediate / padded intermediate**: marker, then a length field (top bit cleared) of at least 8 and at
   most `min(max_bytes, 2^24)` (the engine's bound; not from the spec). If at least 4 + length bytes have
   arrived, the envelope is complete: identified. Fewer bytes: detecting, then `incomplete` at end.
2. **Abridged**: `0xef`, then a length byte or a long header giving a payload length (×4) of at least 8. The
   envelope is complete when 1 + header + length bytes have arrived. Identify **only** if the segment is
   exactly one or more whole envelopes, or at least 64 bytes follow consistently. A one-byte marker is too
   weak alone (section 7).
3. **Full**: `len` of at least 12 and within budget, `seqno` == 0, and a CRC32 over the first `len - 4` bytes
   that equals the last 4 bytes of the envelope: identified. A CRC mismatch is never identified.
4. Evidence: `mtproto_transport` ∈ {`abridged`, `intermediate`, `padded-intermediate`, `full`}, strength
   `structural`. No payload bytes, no auth key ids and no message ids appear in evidence or reasons. The
   payload is "the MTProto payload" [T1]: its contents are not inspected.

## 4. Test vectors (hex; client direction)

| # | Input | Expected |
|---|---|---|
| P1 | `ef020001020304050607` | identified, abridged (8-byte payload; one whole envelope) |
| P2 | `ef7f800000` + 512 bytes | identified, abridged long header (payload 512) |
| P3 | `eeeeeeee10000000000102030405060708090a0b0c0d0e0f` | identified, intermediate |
| P4 | `dddddddd13000000000102030405060708090a0b0c0d0e0faabbcc` | identified, padded intermediate (16 payload + 3 padding) |
| P5 | `1c00000000000000000102030405060708090a0b0c0d0e0f21bed445` | identified, full (len 28, seqno 0, CRC-32/ISO-HDLC little-endian `0x45d4be21`; see section 6) |
| N1 | P5 with the last byte `44` | not telegram (CRC mismatch) |
| N2 | P5 with seqno `01000000` (CRC recomputed) | not telegram (first packet must be 0) |
| N3 | `eeeeeeee` + length `0x7fffffff` | `budget_exhausted` or malformed; never identified |
| N4 | `ef02` + 3 bytes then end | `incomplete` |
| N5 | 64 random bytes whose first int is none of the markers and whose bytes 4 to 8 are not zero (obfuscated init) | unknown; never telegram |
| N6 | `ef` + an inconsistent long header (length beyond the segment, more data never arrives) | `incomplete` at end; never identified |
| S1 | every split point and single-byte chunking of P1 to P5 | same final observation (contract C1) |

## 5. What cannot be identified (by design)

Transport obfuscation: "a 64-byte (512-bit) **random** initialization payload", whose first int "must not be
equal to `0xdddddddd` (padded intermediate), `0xeeeeeeee` (intermediate), `POST`, `GET `, `HEAD `", and whose
bytes 4 to 8 must not be `0x00000000` [T1]. It is required for the WebSocket transports [T2] and used through
MTProxy. A profile must never claim it. Such sessions stay unknown, which is the honest outcome.

## 6. Open point for the Engine lane

[T1] says only "CRC32", without naming the polynomial or the byte order of the `crc` field. The vector P5 assumes
the common CRC-32 (ISO-HDLC, as zlib computes it) written little-endian, like the other fields. Before merging,
confirm both against the example implementation that [T1] itself references ("tdlib ... TcpTransport.cpp", an
official Telegram project). If either differs, regenerate P5, N1 and N2.

## 7. False-positive risks

- **Abridged `0xef`**: any binary protocol whose first byte is `0xef` and whose second byte is a small number
  matches the header. Mitigated by rule 2 (whole-envelope consistency or 64 consistent bytes). Expect residual
  risk; keep abridged at a lower confidence in reasons ("abridged envelope only").
- **Intermediate and padded**: the 4-byte markers are specific. The length bound limits accidental matches.
- **Full**: the CRC makes chance matches about 2^-32 per candidate.
- **TLS on 443**: `0x16` first byte, so no overlap. **HTTP**: MTProto deliberately avoids HTTP method prefixes [T1].
