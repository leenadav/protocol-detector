# App-ID style application identification — v0.30 (introduced in v0.22)

This document maps the vocabulary of application-aware firewalls (Palo Alto
Networks App-ID is the reference model) onto this engine, states exactly what is
implemented, and names what is not. It is a product contract, not a claim of
parity with a commercial signature corpus.

## Pipeline

| App-ID stage | This engine | Where |
|---|---|---|
| Policy on the verdict (application, category, risk, application-default, risks, shift carrier) | **Implemented** as a post-verdict label (`allow`/`deny`/`alert`) with dependency warnings; detection never uses ports, enforcement is the host's (POLICY.md) | `protocol_engine/policy.py` |
| Application signatures | Bounded structural profiles per family (66 families, PROTOCOLS.md); configured exact-host mappings (`RuleIndex`) | `protocol_engine/` |
| Decryption + re-identification | TLS: not performed; `feed_decrypted()` accepts plaintext from a host TLS stack. QUIC: Initial protection (public keys) is removed to read the ClientHello | `engine.py`, `quic.py` |
| Protocol decoders / tunneled apps | Decoders per family; **application shift** at structural boundaries (CONNECT, Upgrade, STARTTLS, SSLRequest, RDP negotiation) inspects the phase after the boundary | `engine.py` |
| Heuristics for evasive traffic | **Implemented** as advisory evidence: unknown-payload entropy/printable profile and DNS name shape (`Config(heuristics=True)`); never an identification. Flow risks (RISKS.md) on every verdict | `protocol_engine/heuristics.py`, `risks.py` |
| Client/server implementation fingerprints (not an App-ID feature; nDPI-style) | **Implemented**: JA3/JA4/JA3S/JA4S/HASSH/HTTP2 (FINGERPRINTS.md) | `protocol_engine/fingerprints.py` |
| Session verdict (`web-browsing`, `ssl`, `unknown-tcp`, …) | **Implemented** | `protocol_engine/appid.py` |
| Application catalog (category, risk, characteristics, dependencies) | **Implemented**, 74 entries | `protocol_engine/applications.py` |
| application-default (standard port check) | **Implemented** as `port_usage` | `appid.py` |
| Traffic log / session record | **Implemented** as `{"type": "session"}` events | `analyze_pcap.py`, `live_capture.py` |
| Custom App-ID signatures with contexts | **Implemented** (SIGNATURES.md) | `protocol_engine/signatures.py` |

## Verdict vocabulary

A verdict names either a catalog application or a session outcome.

| Verdict | Meaning in this engine | Firewall analogue |
|---|---|---|
| `web-browsing` | HTTP/1.x or HTTP/2 initial message validated, no configured mapping | web-browsing |
| `ssl` | TLS ClientHello/ServerHello validated; SNI/ALPN are offers | ssl |
| `quic` | QUIC Initial validated; ClientHello recovered from Initial protection when possible, `h3` ALPN is an offer | quic |
| `<configured name>` | `RuleIndex` exact-host mapping on `tls_sni`/`http_host`; `base_app` names the carrier (`ssl`/`web-browsing`), `implicitly_uses` lists it | specific app implicitly using ssl/web-browsing |
| `<signature name>` | Custom signature matched (SIGNATURES.md); category/risk come from the signature, `base_app` is its `parent` or the family that exposed the contexts, including `unknown-tcp`/`unknown-udp` | custom App-ID |
| `ssh`, `dns`, `smb`, `rdp`, … | The family's structural profile passed (see catalog aliases for vendor names) | same |
| `http-proxy` | HTTP/1.x `CONNECT authority` request (the tunnel contents are inspected as a shifted phase) or an HTTP/2 CONNECT request (v0.50) | http-proxy |
| `websocket` | Frame header after an `Upgrade: websocket` boundary (or explicit candidate), or an HTTP/2 extended CONNECT with `:protocol: websocket` (v0.50) | websocket |
| `dns-over-https` | HTTP/1.x or HTTP/2 request or response whose content-type (or a request's accept) is `application/dns-message` (v0.51); an asserted header class, `implicitly_uses` web-browsing | dns-over-https |
| `portmapper`, `nfs`, `sun-rpc` | ONC RPC v2 call or reply (v0.51): program 100000 is `portmapper`; NFS, mount, NLM, NSM and NFS ACL are `nfs` (`depends_on` portmapper); other programs and every reply are `sun-rpc`, which the session merge treats as the carrier of the client's application | sun-rpc / portmapper / nfs |
| `diameter`, `zeromq`, `neo4j` | Diameter CER/CEA, ZMTP 3.x greeting, Bolt handshake (v0.51) | same |
| `xmpp` | RFC 6120 stream header, either direction (v0.52) | jabber |
| `x11`, `spice`, `afp`, `omron-fins`, `rip`, `rtcp` | X11 setup (reply with the `x11-server` hint), SPICE link header, DSI session opening, FINS/TCP exchange, RIP datagrams, hinted RTCP (v0.53) | same |
| `webdav`, `ipp`, `ocsp`, `soap` | HTTP/1.x or HTTP/2 request with a WebDAV method; POST or response with an `application/ipp` or `application/soap+xml` content class; `application/ocsp-*` in either direction (v0.52); all `implicitly_uses` web-browsing | same |
| `grpc` | Native gRPC: HTTP/2 request HEADERS decoded (v0.50) with `:method` POST and an `application/grpc` content-type class, never from HTTP/1.x (review round 1); gRPC-Web (`application/grpc-web*`, v0.51) with POST on HTTP/1.x or HTTP/2. Both are asserted headers over a structurally validated carrier; `implicitly_uses` web-browsing | grpc |
| `ssl` with `shifted_from` | TLS ClientHello/ServerHello after CONNECT (`http-proxy`; the server side is opened by direction correlation, v0.33), STARTTLS (`smtp`/`imap`/`pop3`/`ftp`), SSLRequest (`postgresql`/`mysql`) or RDP negotiation (`rdp`); the carrier is listed in `implicitly_uses` | application shift |
| `wireguard`, `openvpn` | Handshake/control framing validated; reported through `encryption`, no tunnel contents or peer identity | same |
| `ftp`, `pop3`, `smtp` with status `correlated` | Each direction alone was ambiguous (`220` greeting, `USER` command); the intersection of both candidate sets is one family (v0.27) | same |
| `unknown-tcp` / `unknown-udp` | Payload existed and every supported profile rejected it, or a budget ran out before a profile completed | unknown-tcp / unknown-udp |
| `insufficient-data` | Payload existed, inspection ended (FIN, RST, idle, EOF) while still detecting | insufficient-data |
| `incomplete` | No handshake completion observed, or handshake without any payload | incomplete |
| `not-applicable` | Observation integrity lost (conflicting overlap, control rejection, capture gap); any earlier label is retracted | not-applicable |

Rules of the session merge (`session_verdict`): an identified direction wins and
the client direction is preferred; when neither direction identified but both
carry `ambiguous_candidates` context whose intersection is exactly one family,
the verdict is that family with status `correlated` (never from one direction,
a hint or a port); a differing server identification is kept in
`reasons`, never silently dropped. Without identification, payload outside every
profile is `unknown-*`; an invalidated direction makes the session
`not-applicable`; remaining payload is `insufficient-data`; otherwise
`incomplete`. A verdict never upgrades the evidence beneath it: `ssl` is an
unauthenticated handshake, a configured mapping is an administrative label.

## Catalog attributes

Every entry carries: `category`/`subcategory` (business-systems, collaboration,
general-internet, media, networking, custom, unknown), `technology`
(network-protocol, client-server, browser-based, peer-to-peer),
`risk` 1..5, `characteristics` (evasive, excessive-bandwidth, prone-to-misuse,
transfers-files, tunnels-other-applications, used-by-malware,
has-known-vulnerabilities, widely-used, pervasive, cleartext-credentials),
`standard_ports`/`secure_ports` (`tcp/80`, `tcp/5900-5909`, `tcp/dynamic`),
`implicitly_uses`, `depends_on`, `container`, `aliases` (vendor names such as
`ms-ds-smb`, `msrpc`, `redis`, `postgres`). Risk scores and characteristics are
editorial defaults for policy authoring, not measurements; adjust them to your
environment. `python3 -B appid_catalog.py` prints the catalog, `--json` emits it.

`port_usage` compares the server port with the catalog ports: `standard`,
`nonstandard` (application-default violation) or `unknown` (no port known, no
catalog ports, or an outcome rather than an application). After an application
shift the carrier's standard ports count too (`ssl` shifted from `smtp` on
587 is `standard`); `shifted_from` names the carrier application.

## Session records

Emitted once per TCP connection (both FINs, RST, idle timeout, capture end,
rejection) and once per UDP flow (5-tuple, idle timeout or capture end; bounded
by `max_udp_flows`, default equal to the connection limit; excess flows are
counted, not tracked):

```json
{"type": "session", "transport": "tcp", "client": ["192.0.2.10", 52000], "server": ["192.0.2.20", 8080],
 "start": 1700000000.0, "end": 1700000005.0, "packets": 6, "client_bytes": 40, "server_bytes": 38,
 "end_reason": "Both TCP directions closed with FIN", "app": "web-browsing", "category": "general-internet",
 "subcategory": "internet-utility", "technology": "browser-based", "risk": 4, "characteristics": ["widely-used", "..."],
 "base_app": null, "implicitly_uses": [], "port_usage": "standard", "engine_status": "identified",
 "client_protocol": "http/1.1", "server_protocol": "http/1.1", "encryption": null, "reasons": ["..."], "shifted_from": null, "risks": ["cleartext-credential-protocol"],
 "policy": {"action": "deny", "rule": "deny-cleartext", "reasons": ["rule 'deny-cleartext' matched web-browsing"]}}
```

`risks` lists the RISKS.md flow risks derived from the verdict and both
directions' evidence (sorted, possibly empty). `policy` appears only when a
policy file was given (POLICY.md).
Byte counts are observed payload bytes per direction including retransmissions;
packets include the handshake. No hostname, path, credential or payload value is
present unless `--hostnames` is given, which adds the asserted SNI/Host name.
Classification events additionally carry `app`; live summaries carry `apps`.

```bash
python3 -B analyze_pcap.py capture.pcap --sessions --events-only
python3 -B analyze_pcap.py capture.pcap --sessions --json --hostnames
python3 -B live_capture.py -i eth0 --duration 60 --json      # session records are always emitted live
make apps
```

## Limits

- Verdicts describe the initial message scope plus one structural shift per
  direction; later requests on a kept-alive connection and the contents of a
  TLS tunnel (without `feed_decrypted`) are not inspected.
- No proprietary signature corpus, cloud lookup, machine-learned classifier or
  URL category database is included. Specific web applications require
  configured host mappings or custom signatures (SIGNATURES.md).
- Risk and characteristics are catalog metadata; they are not derived from traffic.
- UDP flows are keyed by endpoint pair only; there is no transaction matching
  or spoofing resistance.
