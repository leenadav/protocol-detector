# Labelled-corpus report (synthetic fixtures)

Seed 72, 25 mutations per fixture. Classes: intact fixture, truncated prefixes (1, 2, 4, half, all-but-one bytes), seeded byte mutations. TP = identified as the labelled family; FN = intact fixture not identified; explicit = truncated or mutated input ended in an explicit non-identification; FP = identified as a different family. Synthetic corpus: not a real-world accuracy figure.

| family | intact TP/FN | truncated TP/explicit/FP | mutated TP/explicit/FP | FP named as |
|---|---|---|---|---|
| afp | 3/0 | 0/15/0 | 7/68/0 | — |
| amqp | 1/0 | 0/5/0 | 6/19/0 | — |
| bacnet | 1/0 | 0/0/0 | 7/18/0 | — |
| bgp | 1/0 | 0/5/0 | 7/18/0 | — |
| bittorrent | 1/0 | 0/5/0 | 17/8/0 | — |
| bolt | 1/0 | 0/5/0 | 0/25/0 | — |
| coap | 1/0 | 0/0/0 | 20/5/0 | — |
| cql | 5/0 | 0/24/0 | 12/113/0 | — |
| dcerpc | 3/0 | 0/15/0 | 13/62/0 | — |
| dhcp | 2/0 | 0/0/0 | 48/2/0 | — |
| diameter | 2/0 | 0/10/0 | 14/36/0 | — |
| dnp3 | 1/0 | 0/5/0 | 0/25/0 | — |
| dns | 5/0 | 0/5/0 | 43/82/0 | — |
| dtls | 3/0 | 0/0/0 | 22/53/0 | — |
| ethernet-ip | 2/0 | 0/5/0 | 11/36/3 | coap |
| fastcgi | 3/0 | 0/15/0 | 27/48/0 | — |
| fins | 3/0 | 0/15/0 | 8/67/0 | — |
| ftp | 1/0 | 0/5/0 | 0/25/0 | — |
| giop | 3/0 | 0/15/0 | 11/64/0 | — |
| git | 3/0 | 0/15/0 | 10/65/0 | — |
| http | 9/0 | 0/45/0 | 44/181/0 | — |
| iec-104 | 1/0 | 0/5/0 | 0/25/0 | — |
| ikev2 | 3/0 | 0/0/0 | 46/29/0 | — |
| imap | 2/0 | 0/10/0 | 6/44/0 | — |
| ipfix | 1/0 | 0/0/0 | 19/6/0 | — |
| irc | 6/0 | 0/30/0 | 42/108/0 | — |
| iso-tsap | 1/0 | 0/5/0 | 6/19/0 | — |
| kafka | 1/0 | 0/5/0 | 8/17/0 | — |
| kerberos | 7/0 | 0/15/0 | 89/86/0 | — |
| l2tp | 2/0 | 0/0/0 | 16/34/0 | — |
| ldap | 8/0 | 0/40/0 | 15/185/0 | — |
| mdns | 7/0 | 0/0/0 | 67/108/0 | — |
| memcached | 3/0 | 0/15/0 | 25/50/0 | — |
| modbus | 3/0 | 0/14/0 | 10/65/0 | — |
| mqtt | 1/0 | 0/5/0 | 2/23/0 | — |
| nats | 2/0 | 0/10/0 | 0/50/0 | — |
| netbios-ns | 10/0 | 0/0/0 | 33/192/25 | dns |
| netbios-ss | 1/0 | 0/5/0 | 0/25/0 | — |
| netflow | 2/0 | 0/0/0 | 38/12/0 | — |
| onc-rpc | 8/0 | 0/20/0 | 30/170/0 | — |
| opcua | 4/0 | 0/20/0 | 27/73/0 | — |
| openvpn | 4/0 | 0/10/0 | 76/24/0 | — |
| pop3 | 2/0 | 0/10/0 | 5/45/0 | — |
| postgresql | 7/0 | 0/33/0 | 32/143/0 | — |
| pptp | 2/0 | 0/10/0 | 25/25/0 | — |
| quic | 1/0 | 0/0/0 | 25/0/0 | — |
| rdp | 1/0 | 0/5/0 | 0/25/0 | — |
| rfb | 1/0 | 0/5/0 | 0/25/0 | — |
| rip | 3/0 | 0/0/0 | 13/62/0 | — |
| rsync | 1/0 | 0/5/0 | 2/23/0 | — |
| rtsp | 1/0 | 0/5/0 | 1/24/0 | — |
| sflow | 1/0 | 0/0/0 | 12/13/0 | — |
| sip | 2/0 | 0/5/0 | 12/38/0 | — |
| smb1 | 2/0 | 0/10/0 | 22/28/0 | — |
| smb2 | 5/0 | 0/25/0 | 47/78/0 | — |
| snmp | 8/0 | 0/0/0 | 54/146/0 | — |
| socks5 | 2/0 | 0/10/0 | 11/39/0 | — |
| spice | 2/0 | 0/10/0 | 18/32/0 | — |
| ssdp | 1/0 | 0/0/0 | 3/22/0 | — |
| stomp | 2/0 | 0/10/0 | 1/49/0 | — |
| stun | 8/0 | 0/15/0 | 80/120/0 | — |
| syslog | 3/0 | 0/10/0 | 11/64/0 | — |
| tacacs-plus | 2/0 | 0/10/0 | 15/35/0 | — |
| tds | 2/0 | 0/10/0 | 12/38/0 | — |
| telnet | 1/0 | 0/5/0 | 2/23/0 | — |
| tftp | 2/0 | 0/0/0 | 3/47/0 | — |
| tns | 5/0 | 0/24/0 | 33/92/0 | — |
| wireguard | 2/0 | 0/0/0 | 50/0/0 | — |
| x11 | 2/0 | 0/10/0 | 11/39/0 | — |
| xmpp | 3/0 | 0/15/0 | 2/73/0 | — |
| zmtp | 2/0 | 0/10/0 | 2/48/0 | — |

Totals: TP 1593, FN 0, explicit 4431, FP 28 across 71 families.
