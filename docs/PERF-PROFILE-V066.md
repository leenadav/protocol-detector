# Performance profile (D11)

`python3 -B tools/perf_profile.py` on Linux-6.18.44-fc-v310-x86_64-with-glibc2.39, Python 3.13.16; 200 iterations per CPU case, 300 connections for the queue measurement, 1000 for memory. Local single-process measurements on synthetic frames; not a capacity, SWG latency or long-run claim.

## CPU per flow by layer (µs, p50 / p95 / p99)

| flow | frames | payload | decode | engine | adapter path | adapter overhead p50 | CPU share decode/engine/adapter |
|---|---|---|---|---|---|---|---|
| http_small | 5 | 81 | 13.7 / 21.3 / 42.3 | 38.1 / 58.8 / 76.8 | 220.8 / 278.6 / 320.1 | 169.0 | 0.054 / 0.147 / 0.799 |
| http_fragmented_32 | 194 | 6051 | 475.0 / 570.4 / 674.9 | 497.2 / 579.4 / 715.8 | 11426.8 / 13264.4 / 14405.8 | 10454.6 | 0.04 / 0.041 / 0.919 |
| tls_client_hello | 5 | 77 | 13.5 / 18.3 / 30.9 | 26.7 / 42.3 / 60.9 | 206.1 / 286.2 / 343.0 | 165.9 | 0.058 / 0.114 / 0.828 |
| tls_client_hello_16 | 9 | 77 | 27.8 / 46.0 / 58.5 | 41.2 / 72.1 / 121.7 | 531.2 / 817.9 / 920.1 | 462.2 | 0.048 / 0.073 / 0.879 |
| unknown_payload | 5 | 224 | 17.0 / 33.2 / 78.4 | 5.4 / 7.5 / 22.4 | 197.5 / 327.8 / 419.3 | 175.2 | 0.086 / 0.027 / 0.888 |

The adapter path includes the engine and reassembly; its overhead is the difference of medians and is a property of the Python adapter, not of the parsers.

## Bytes to identification

135 fixtures identified; median shortest identifying prefix 36 bytes, maximum 247 bytes.

| family | fixtures | shortest prefix min–max | fixture bytes max | inspected max |
|---|---|---|---|---|
| afp | 3 | 16–22 | 22 | 22 |
| amqp | 1 | 69–69 | 69 | 69 |
| bgp | 1 | 33–33 | 33 | 33 |
| bittorrent | 1 | 68–68 | 68 | 68 |
| bolt | 1 | 20–20 | 20 | 20 |
| cql | 5 | 9–61 | 61 | 61 |
| dcerpc | 3 | 21–72 | 72 | 72 |
| diameter | 2 | 116–128 | 128 | 128 |
| dnp3 | 1 | 18–18 | 18 | 18 |
| dns | 1 | 35–35 | 35 | 35 |
| ethernet-ip | 1 | 28–28 | 28 | 28 |
| fastcgi | 3 | 16–49 | 49 | 49 |
| fins | 3 | 20–34 | 34 | 34 |
| ftp | 1 | 6–6 | 6 | 6 |
| giop | 3 | 20–36 | 36 | 36 |
| git | 3 | 14–154 | 154 | 154 |
| http | 9 | 77–179 | 179 | 179 |
| iec-104 | 1 | 6–6 | 6 | 6 |
| imap | 2 | 17–80 | 80 | 80 |
| irc | 6 | 12–86 | 86 | 86 |
| iso-tsap | 1 | 22–22 | 22 | 22 |
| kafka | 1 | 35–35 | 35 | 35 |
| kerberos | 3 | 99–183 | 183 | 183 |
| ldap | 8 | 14–105 | 105 | 105 |
| memcached | 3 | 27–35 | 35 | 35 |
| modbus | 3 | 9–13 | 13 | 13 |
| mqtt | 1 | 19–19 | 19 | 19 |
| nats | 2 | 97–123 | 123 | 123 |
| netbios-ss | 1 | 72–72 | 72 | 72 |
| onc-rpc | 4 | 24–92 | 92 | 92 |
| opcua | 4 | 28–74 | 74 | 74 |
| openvpn | 2 | 16–28 | 28 | 28 |
| pop3 | 2 | 6–23 | 23 | 23 |
| postgresql | 7 | 8–108 | 108 | 108 |
| pptp | 2 | 156–156 | 156 | 156 |
| rdp | 1 | 19–19 | 19 | 19 |
| rfb | 1 | 12–12 | 12 | 12 |
| rsync | 1 | 41–41 | 41 | 41 |
| rtsp | 1 | 57–57 | 57 | 57 |
| sip | 1 | 247–247 | 247 | 247 |
| smb1 | 2 | 86–93 | 93 | 93 |
| smb2 | 5 | 108–216 | 216 | 216 |
| socks5 | 2 | 12–20 | 20 | 20 |
| spice | 2 | 42–202 | 202 | 202 |
| stomp | 2 | 27–69 | 69 | 69 |
| stun | 3 | 20–64 | 64 | 64 |
| syslog | 2 | 94–96 | 96 | 96 |
| tacacs-plus | 2 | 24–29 | 29 | 29 |
| tds | 2 | 49–94 | 94 | 94 |
| telnet | 1 | 6–6 | 6 | 6 |
| tns | 5 | 8–229 | 229 | 229 |
| x11 | 2 | 12–48 | 48 | 48 |
| xmpp | 3 | 117–168 | 168 | 168 |
| zmtp | 2 | 64–64 | 64 | 64 |

The shortest prefix is the engine's own earliest identification of each fixture; a profile that needs the whole message reports the fixture length.

## Consumer-queue wait by drain cadence

| drain every | packets | events drained | depth max | wait p50 / p99 / max (capture s) | µs per packet |
|---|---|---|---|---|---|
| 1 | 1500 | 600 | 1 | 0.0001 / 0.0001 / 0.0 | 41.6 |
| 25 | 1500 | 600 | 10 | 0.01 / 0.05 / 0.012 | 36.2 |
| 250 | 1500 | 600 | 100 | 0.1 / 0.5 / 0.1245 | 32.0 |

Wait is measured on the capture clock between enqueue and drain (`queue.wait_seconds`); it grows with the consumer's cadence while the per-packet CPU does not.

## Memory per connection state (tracemalloc)

| state | connections | held bytes / connection | peak bytes / connection |
|---|---|---|---|
| syn_only | 1000 | 1012 | 1020 |
| identified_closed_both_ways | 1000 | 42 | 68 |
| identified_half_closed | 1000 | 6074 | 6095 |
| half_message_retained | 1000 | 6996 | 7013 |
| udp_flow_identified | 1000 | 36 | — |

Held bytes are what stays allocated while the connection is tracked; retired connections hold their session record only until the sink consumes it.

## Where the adapter path spends its time (cProfile, small HTTP flow)

| function | calls / flow | cumulative µs / flow | share |
|---|---|---|---|
| sessions.py:_materialize | 3.0 | 306.3 | 0.391 |
| sessions.py:_compat_rows | 3.0 | 303.3 | 0.387 |
| sessions.py:__eq__ | 1.0 | 224.7 | 0.287 |
| sessions.py:feed | 3.0 | 190.6 | 0.243 |
| sessions.py:feed | 3.0 | 170.1 | 0.217 |
| engine.py:feed | 1.0 | 159.5 | 0.204 |
| analyze_pcap.py:drop | 2.0 | 146.7 | 0.187 |
| analyze_pcap.py:_tcp_session | 1.0 | 131.7 | 0.168 |

Cumulative shares overlap (callers include callees); profiling overhead inflates absolute numbers, the ranking is the point.

These are local measurements on the named host. They are not throughput or capacity figures for any production deployment, and no long-running soak is claimed here (docs/SOAK-V065.md describes the bounded synthetic soak).
