# Behaviour diff: v0.66 against v0.65 (`1d1db29`)

`python3 -B tools/compare_engine.py <v0.65 checkout>` over every fixture, every truncation and 300 seeded
mutations per fixture (seed 37): 87,461 inputs compared, 5 fixtures differ, 60 differing inputs. Every
difference is intentional and belongs to the ported v0.59 profiles:

| group | count | before (v0.65) | after (v0.66) | why |
|---|---|---|---|---|
| LIFX LAN datagrams (fixtures and mutations keeping the header valid) | 8 | unknown | identified `lifx-lan` | new automatic family |
| LIFX mutations that break a header rule | 4 | unknown | malformed | the LIFX probe now routes them; the profile rejects them explicitly |
| Tuya LAN frames | 1 | unknown | identified `tuya-lan` | new automatic family |
| Tuya mutations (bad CRC, length or suffix) | 11 | unknown | malformed | routed by the prefix probe, rejected by the profile |
| TP-Link Smart Home datagram | 1 | unknown | identified `tplink-smarthome` | new automatic family |
| TP-Link mutations | 32 | unknown or malformed | malformed | routed by the autokey probe; printable/JSON/module rules reject them (21 were already malformed by another route and now carry the TP-Link reason) |
| multicast DNS layouts (SRV-target pointer, AA on a query, reverse-mapping probe) | 3 | malformed | identified `mdns` | the DNS layout repairs (RFC 2782 RDATA names, RFC 6762 18.4 and 8.1) |

No input outside these groups changed. Inputs of every other family, including every unicast DNS, NetBIOS-NS
and LLMNR fixture and their mutations, classify exactly as on v0.65. The `malformed` outcomes above are
explicit non-identifications of inputs that now reach a profile which rejects them; none of them identifies
another family (corpus report: zero intact false negatives; the only cross-family mutation hits remain the
pre-existing netbios-ns→dns and ethernet-ip→coap sibling layouts).
