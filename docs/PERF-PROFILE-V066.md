# Performance profile (D11)

`python3 -B tools/perf_profile.py` on Linux-6.18.44-fc-v310-x86_64-with-glibc2.39, Python 3.13.16; 200 iterations per CPU case, 300 connections for the queue measurement, 1000 for memory. Local single-process measurements on synthetic frames; not a capacity, SWG latency or long-run claim.

## CPU per flow by layer (µs, p50 / p95 / p99)

| flow | frames | payload | decode | engine | adapter path | adapter overhead p50 | CPU share decode/engine/adapter |
|---|---|---|---|---|---|---|---|
| http_small | 5 | 81 | 17.7 / 24.2 / 38.9 | 48.5 / 66.8 / 75.8 | 274.2 / 342.5 / 389.4 | 208.1 | 0.055 / 0.145 / 0.8 |
| http_fragmented_32 | 194 | 6051 | 523.9 / 871.7 / 1162.1 | 538.7 / 830.0 / 979.6 | 12202.8 / 15094.7 / 18880.8 | 11140.2 | 0.041 / 0.042 / 0.917 |
| tls_client_hello | 5 | 77 | 17.5 / 32.6 / 67.4 | 34.5 / 52.6 / 102.3 | 260.4 / 373.5 / 4387.2 | 208.4 | 0.06 / 0.115 / 0.825 |
| tls_client_hello_16 | 9 | 77 | 31.1 / 50.7 / 61.9 | 42.5 / 49.5 / 63.9 | 586.5 / 618.4 / 641.9 | 512.9 | 0.051 / 0.066 / 0.883 |
| unknown_payload | 5 | 224 | 19.2 / 25.1 / 40.5 | 6.0 / 7.2 / 11.6 | 221.5 / 261.9 / 286.7 | 196.4 | 0.081 / 0.027 / 0.892 |

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
| 1 | 1500 | 600 | 1 | 0.0001 / 0.0001 / 0.0 | 43.0 |
| 25 | 1500 | 600 | 10 | 0.01 / 0.05 / 0.012 | 39.9 |
| 250 | 1500 | 600 | 100 | 0.1 / 0.5 / 0.1245 | 40.1 |

Wait is measured on the capture clock between enqueue and drain (`queue.wait_seconds`); it grows with the consumer's cadence while the per-packet CPU does not.

## Memory per connection state (tracemalloc)

| state | connections | held bytes / connection | peak bytes / connection |
|---|---|---|---|
| syn_only | 1000 | 1012 | 1020 |
| identified_closed_both_ways | 1000 | 42 | 82 |
| identified_half_closed | 1000 | 25554 | 25565 |
| half_message_retained | 1000 | 26526 | 26537 |
| udp_flow_identified | 1000 | 38 | — |

Held bytes are what stays allocated while the connection is tracked; retired connections hold their session record only until the sink consumes it.

## Where the adapter path spends its time (cProfile, small HTTP flow)

| function | calls / flow | cumulative µs / flow | share |
|---|---|---|---|
| sessions.py:_compat_results | 3.0 | 292.2 | 0.416 |
| sessions.py:feed | 3.0 | 275.3 | 0.392 |
| sessions.py:feed | 3.0 | 254.5 | 0.362 |
| sessions.py:open_connection | 1.0 | 211.7 | 0.301 |
| sessions.py:__init__ | 2.0 | 205.3 | 0.292 |
| engine.py:feed | 1.0 | 141.3 | 0.201 |
| analyze_pcap.py:drop | 2.0 | 134.5 | 0.191 |
| analyze_pcap.py:_tcp_session | 1.0 | 120.7 | 0.172 |

Cumulative shares overlap (callers include callees); profiling overhead inflates absolute numbers, the ranking is the point.

These are local measurements on the named host. They are not throughput or capacity figures for any production deployment, and no long-running soak is claimed here (docs/SOAK-V065.md describes the bounded synthetic soak).
