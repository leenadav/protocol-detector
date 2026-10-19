"""Synthetic offline fixtures; no captured traffic, secrets or network activity."""
import struct

DNS = bytes.fromhex("123401000001000000000000") + b"\x03www\x07example\x03com\x00\x00\x01\x00\x01"
DNS_TCP = len(DNS).to_bytes(2, "big") + DNS
STUN = b"\x00\x01\x00\x00\x21\x12\xa4\x42" + b"0123456789ab"
_dhcp = bytearray(240)
_dhcp[:4] = b"\x01\x01\x06\x00"
_dhcp[4:8] = b"demo"
_dhcp[28:34] = b"\x02\x00\x00\x00\x00\x01"
_dhcp[236:240] = b"\x63\x82\x53\x63"
DHCP = bytes(_dhcp) + b"\x35\x01\x01\xff"
del _dhcp
COAP = b"\x41\x01\x12\x34\xaa\xb7sensors"
SYSLOG = b'<34>1 2026-10-19T12:00:00Z host.example app 123 ID47 [demo@32473 key="value"] synthetic event'
_startup = b"\x00\x03\x00\x00user\x00demo\x00database\x00example\x00\x00"
POSTGRESQL = (len(_startup) + 4).to_bytes(4, "big") + _startup
del _startup
POSTGRESQL_SSL = bytes.fromhex("0000000804d2162f")
RFB = b"RFB 003.008\n"
BITTORRENT = b"\x13BitTorrent protocol" + bytes(8) + b"h" * 20 + b"p" * 20
MEMCACHED = struct.pack("!BBHBBHIIQ", 128, 0, 3, 0, 0, 0, 3, 123, 0) + b"key"
LDAP = bytes.fromhex("300c020101600702010304008000")
SIP = (b"OPTIONS sip:server.example SIP/2.0\r\n"
       b"Via: SIP/2.0/TCP client.example;branch=z9hG4bKdemo\r\n"
       b"From: <sip:client@example.com>;tag=demo\r\n"
       b"To: <sip:server@example.com>\r\nCall-ID: synthetic@example.com\r\n"
       b"CSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n")
RTSP = b"OPTIONS rtsp://server.example/media RTSP/1.0\r\nCSeq: 1\r\n\r\n"

MQTT5 = b"\x10\x11\x00\x04MQTT\x05\x02\x00\x3c\x00\x00\x04demo"

STREAM_CASES = ((MQTT5, "mqtt/5.0"), (DNS_TCP, "dns"), (STUN, "stun"), (POSTGRESQL, "postgresql"),
                (POSTGRESQL_SSL, "postgresql"), (RFB, "rfb"), (BITTORRENT, "bittorrent"),
                (MEMCACHED, "memcached/binary"), (LDAP, "ldap/3"), (SIP, "sip/2.0"), (RTSP, "rtsp/1.0"))
DATAGRAM_CASES = ((DNS, "dns"), (STUN, "stun"), (DHCP, "dhcp/4"),
                  (COAP, "coap"), (SYSLOG, "syslog/5424"), (SIP, "sip/2.0"))

# BGP OPEN: version 4, AS 64512, hold 90, documentation router ID, route-refresh.
BGP = b'\xff' * 16 + bytes.fromhex('00210104fc00005ac00002010402020200')
_smb = bytearray(104)
_smb[:4] = b'\xfeSMB'
_smb[4:6] = (64).to_bytes(2, 'little')
_smb[64:72] = struct.pack('<HHHH', 36, 2, 1, 0)
_smb[76:92] = bytes(range(16))
_smb[100:] = struct.pack('<HH', 0x202, 0x302)
SMB2 = len(_smb).to_bytes(4, 'big') + bytes(_smb)
_smb[100:] = struct.pack('<HH', 0x302, 0x311)
_smb[92:100] = struct.pack('<IHH', 104, 1, 0)
_smb += struct.pack('<HHIHHH', 1, 6, 0, 1, 0, 1)
SMB311 = len(_smb).to_bytes(4, 'big') + bytes(_smb)
del _smb
SNMP = bytes.fromhex('302602010104067075626c6963a019020101020100020100300e300c06082b060102010101000500')
TFTP = b'\x00\x01example.txt\x00octet\x00blksize\x001428\x00'
NTP = b'\x23' + bytes(47)
NETWORK_STREAM_CASES = ((BGP, 'bgp/4'), (SMB2, 'smb2'), (SMB311, 'smb2'))
NETWORK_DATAGRAM_CASES = ((SNMP, 'snmp/2c'), (TFTP, 'tftp'))
HINTED_DATAGRAM_CASES = ((NTP, 'ntp/4', 'ntp'),)
STREAM_CASES += NETWORK_STREAM_CASES
DATAGRAM_CASES += NETWORK_DATAGRAM_CASES

STOMP = b'CONNECT\naccept-version:1.1,1.2\nhost:example.com\nheart-beat:0,10000\n\n\x00'
STOMP_SERVER = b'CONNECTED\r\nversion:1.2\r\n\r\n\x00'
NATS_INFO = (b'INFO {"server_id":"demo","version":"2.10.0","go":"go1.22",'
             b'"host":"127.0.0.1","port":4222,"max_payload":1048576,"proto":1}\r\n')
NATS_CONNECT = b'CONNECT {"verbose":false,"pedantic":false,"tls_required":false,"lang":"python","version":"1.0"}\r\n'
IMAP = b'* OK [CAPABILITY IMAP4rev1 IMAP4rev2 STARTTLS AUTH=PLAIN] Example server ready\r\n'
RDP = bytes.fromhex('030000130ee000000000000100080003000000')
SERVICE_STREAM_CASES = ((STOMP, 'stomp'), (STOMP_SERVER, 'stomp'), (NATS_INFO, 'nats'),
                        (NATS_CONNECT, 'nats'), (IMAP, 'imap'), (RDP, 'rdp'))
STREAM_CASES += SERVICE_STREAM_CASES

# Database fixtures require an explicit candidate; arbitrary length bytes do not
# enter automatic prefix routing. All values below are synthetic.
_mysql = (b'\x0a8.0.36-demo\0' + struct.pack('<I', 123) + b'abcdefgh' + b'\0'
          + struct.pack('<H', 0x8a00) + b'\x2d' + struct.pack('<HHB', 2, 8, 21)
          + bytes(10) + b'ijklmnopqrst\0' + b'caching_sha2_password\0')
MYSQL = len(_mysql).to_bytes(3, 'little') + b'\0' + _mysql
del _mysql
# {hello: 1, $db: "admin"}; OP_MSG request with one body section.
_mongo_body = b'\x10hello\0\x01\0\0\0\x02$db\0\x06\0\0\0admin\0'
_mongo_doc = struct.pack('<i', len(_mongo_body) + 5) + _mongo_body + b'\0'
MONGODB = struct.pack('<iiiiI', 21 + len(_mongo_doc), 123, 0, 2013, 0) + b'\0' + _mongo_doc
del _mongo_body, _mongo_doc
MONGODB_CHECKSUM = bytes.fromhex('380000007b00000000000000dd07000001000000001f0000001068656c6c6f000100000002246462000600000061646d696e0000433d09e1')
HINTED_STREAM_CASES = ((MYSQL, 'mysql', 'mysql'), (MONGODB, 'mongodb', 'mongodb'), (MONGODB_CHECKSUM, 'mongodb', 'mongodb'))

# FastCGI v1 responder, one synthetic parameter, explicit PARAMS EOF.
FASTCGI = bytes.fromhex('01010001000800000001010000000000') + bytes.fromhex('0104000100110000') + b'\x0e\x01REQUEST_METHODG' + bytes.fromhex('0104000100000000')
RSYNC = b'@RSYNCD: 32.0 sha512 sha256 sha1 md5 md4\n'
GATEWAY_STREAM_CASES = ((FASTCGI, 'fastcgi/1'), (RSYNC, 'rsync'))
STREAM_CASES += GATEWAY_STREAM_CASES

# RADIUS Access-Request: NAS-IP, User-Name, synthetic PAP ciphertext, NAS-Port.
# No real password or shared secret; only structural validation is claimed.
RADIUS = bytes.fromhex('017b0038') + bytes(range(16)) + bytes.fromhex('0406c00002010106') + b'demo' + bytes.fromhex('0212') + b'x' * 16 + bytes.fromhex('050600000001')
HINTED_DATAGRAM_CASES += ((RADIUS, 'radius', 'radius'),)
