# tshark oracle for the Go engine (PRO-127)

`TestEngineMatchesTshark` compares what the Go engine reports with what tshark dissects, on traffic produced by
real, unmodified implementations. For each scenario:

1. **Traffic.** A real client talks to a real server on 127.0.0.1, through a relay (`relay.go`). The relay
   forwards every byte unchanged and writes it to a pcap in the test's temporary directory (`capture.go`).
   - Frames: synthetic Ethernet, IPv4 and TCP/UDP headers (a three-way handshake, the data, a FIN exchange).
   - Privileges: none needed, because nothing is captured from an interface.
   - Shaping: a scenario can split a direction into small segments, or swap segment pairs so that readers must
     reassemble out of order.
2. **Read.** gopacket (`pcapgo`, `reassembly`) reads and reassembles the pcap, independently of the engine's own
   pcap decoder (`flows.go`).
3. **Engine.** It classifies each flow with the default configuration and **no hint**.
   - TCP: the client's bytes are fed in the chunks gopacket delivered.
   - UDP: datagrams are fed one by one, with the flow as scope and a host-owned QUIC CRYPTO store, as the analyzer
     does.
4. **Oracle.** tshark runs as an external process on the same file (`tshark.go`).
   - Decode-as maps the relay's ephemeral port to TLS, HTTP or QUIC. Only tshark gets this protocol hint.
5. **Compare.** The fields below are compared per flow. tshark must also see what the client was told to send,
   so the comparison can't pass blind on two empty values.

| field | engine | tshark |
|---|---|---|
| `sni` | `hostname` (TLS or QUIC) | `tls.handshake.extensions_server_name` |
| `alpn` | `offered_alpn`, comma-joined | `tls.handshake.extensions_alpn_str` |
| `tls_version` | evidence `tls_offered_max_version` | highest known `tls.handshake.extensions.supported_version`, else `tls.handshake.version` |
| `http_host` | `hostname` from `wire:http_host` | `http.host`, without its port |
| `quic_version` | evidence `quic_version` | `quic.version` (`0x00000001` → `1`, `0x6b3343cf` → `2`) |

Names are compared in lower case.

**Mismatches.** A mismatch fails unless `allow.json` lists it as `"<scenario>/<field>": "<reason>"`. The list
is checked in both directions:
- an entry that no longer mismatches fails the run;
- an entry naming a case that no scenario compares fails the run.

The list is empty today: all 26 comparisons agree.

## Scenarios

| scenario | client → server | shape |
|---|---|---|
| s_client tls1.3 sni alpn | `openssl s_client -tls1_3 -servername a.example.test -alpn h2,http/1.1` → `openssl s_server` | one segment per read |
| s_client tls1.2 in 7-byte segments | `s_client -tls1_2 -servername b.example.test -alpn http/1.1` | 7-byte segments |
| s_client no sni out of order | `s_client -noservername` | 50-byte segments, pairs swapped |
| s_client 253-byte sni | `s_client -servername <63.63.63.example.test>` | one segment per read |
| curl https h2 | `curl https://www.example.test` (offers h2, http/1.1) → `s_server` | one segment per read |
| curl https http1.1 tls1.2 | `curl --http1.1 --tlsv1.2 --tls-max 1.2` | 100-byte segments |
| curl http host | `curl http://plain.example.test` → Go `net/http` | one segment per read |
| curl http/1.0 host header in 5-byte segments | `curl -0 -H 'Host: Mixed.Example.TEST'` | 5-byte segments |
| quic-go v1 | quic-go client (QUIC v1, `h3`) → quic-go server | one datagram per send |
| quic-go v2 | quic-go client (QUIC v2, `h3,hq-interop`) → quic-go server | one datagram per send |

Every host name ends in `.test` (RFC 6761).
- curl gets `--resolve` to 127.0.0.1 and `--noproxy '*'`. No scenario reaches the network.
- The certificates and keys are generated per run in the temporary directory.
- QUIC Initials need no key log.

## Data policy (Hermes, PRO-186)

- No capture is committed. Each pcap, certificate and key lives in the test's temporary directory and is
  removed with it.
- The traffic is synthetic IPv4 on loopback, so no third-party or user traffic is involved.
- This README replaces a `testdata/pcap/README.md`: there are no pcap files to document.

## Pinned tools and licences

The test refuses any tool version other than the one pinned here (`pinned` in `oracle_test.go`). A version
change is a reviewed bump.

| tool | pinned version | licence | how it is used |
|---|---|---|---|
| tshark (Wireshark) | 4.2.2, Debian/Ubuntu package `4.2.2-1.1build3` | GPL-2.0-or-later | external process only |
| OpenSSL | 3.0.13 (30 Jan 2024) | Apache-2.0 | external process only (`s_client`, `s_server`, `req`) |
| curl | 8.5.0 | curl (MIT-style) | external process only |

Go modules linked into this test module (`go.sum` pins every one; none is GPL or LGPL):

| module | version | licence |
|---|---|---|
| github.com/gopacket/gopacket | v1.7.7 | BSD-3-Clause |
| github.com/quic-go/quic-go | v0.65.0 | MIT |
| golang.org/x/crypto | v0.59.0 | BSD-3-Clause |
| golang.org/x/net | v0.62.0 | BSD-3-Clause |
| golang.org/x/sys | v0.50.0 | BSD-3-Clause |

**Module boundary.** This is a separate, test-only module.
- `go/go.mod` and `go/vendor` are unchanged, and no shipped package imports this one.
- It imports the engine's `internal/` packages, which Go allows here because its import path is under `go/`.
- Its Go floor and toolchain match `go/go.mod`: `go 1.27.0`, `toolchain go1.27.4`.

## Running

```sh
make pcap-oracle   # cd go/oracle && go test -count=1 ./... with the pinned Go; needs the three tools above
```

On Ubuntu 24.04, install the pinned tshark with `apt-get install tshark=4.2.2-1.1build3`. That image already
ships OpenSSL 3.0.13 and curl 8.5.0.

The module's dependencies are fetched through the Go module proxy, so a CI job builds the test in a step with
proxy access. Set `ORACLE_REPORT=<file>` to write every comparison as JSON.

`go-check` doesn't run this test, because the per-PR runner has no tshark. It is meant for a nightly job, which
belongs to the CI/CD lane.

**Limits.**
- The TCP and IP framing comes from the relay, not from a real network. Real-network reassembly edge cases are
  covered by the engine's reassembly tests and the randomized differential.
- Only the client's opening is compared. Server responses are recorded but not compared.
