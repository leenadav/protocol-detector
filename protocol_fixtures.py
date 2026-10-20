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

# Native Git request: the version field is an offer, not a negotiated result.
_git_request = b'git-upload-pack /project.git\0host=example.com\0\0version=2\0'
GIT = ('%04x' % (len(_git_request)+4)).encode('ascii') + _git_request
STREAM_CASES += ((GIT, 'git'),)
del _git_request

# GIOP 1.2, big-endian LocateRequest: request ID, KeyAddr + padding, octet key.
GIOP = bytes.fromhex('47494f500102000300000010000000010000000000000004') + b'demo'
STREAM_CASES += ((GIOP, 'giop/1.2'),)

# Synthetic DCE/RPC Bind, one context and NDR 2.0 offer; opaque interface UUID.
DCERPC = bytes.fromhex('05000b03100000004800000001000000b810b810000000000100000000000100') + bytes(range(1,17)) + bytes.fromhex('01000000045d888aeb1cc9119fe808002b10486002000000')
STREAM_CASES += ((DCERPC, 'dcerpc/5.0'),)

# Synthetic ServerHello fixtures. Key bytes are structural placeholders, not keys.
def _server_fixture(extension_bytes, cipher, retry=False):
    random = (bytes.fromhex('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c')
              if retry else bytes(range(32)))
    body = b'\x03\x03' + random + b'\0' + cipher.to_bytes(2, 'big') + b'\0'
    body += len(extension_bytes).to_bytes(2, 'big') + extension_bytes
    handshake = b'\x02' + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\x03' + len(handshake).to_bytes(2, 'big') + handshake

TLS_SERVER12 = _server_fixture(bytes.fromhex('001000050003026832'), 0xc02f)
TLS_SERVER13 = _server_fixture(bytes.fromhex('002b0002030400330024001d0020') + bytes(32), 0x1301)
TLS_RETRY = _server_fixture(bytes.fromhex('002b0002030400330002001d'), 0x1301, True)
del _server_fixture

# DTLS1.2, one complete epoch-zero ClientHello, no cookie or extensions.
_dtls_body = b'\xfe\xfd' + bytes(range(32)) + b'\0\0\0\x02\xc0\x2f\x01\0'
_dtls_handshake = b'\x01' + len(_dtls_body).to_bytes(3,'big') + bytes(5) + len(_dtls_body).to_bytes(3,'big') + _dtls_body
DTLS = b'\x16\xfe\xff' + bytes(8) + len(_dtls_handshake).to_bytes(2,'big') + _dtls_handshake
DATAGRAM_CASES += ((DTLS, 'dtls'),)
del _dtls_body, _dtls_handshake

# IKEv2 SA_INIT: AES-CBC128/HMAC-SHA256/MODP2048 offers; key/nonce placeholders.
_ike_sa=bytes.fromhex('220000300000002c010100040300000c0100000c800e00800300000802000005030000080300000c000000080400000e')
_ike_ke=bytes.fromhex('28000108000e0000')+bytes(256)
_ike_nonce=bytes.fromhex('00000024')+bytes(32)
_ike_body=_ike_sa+_ike_ke+_ike_nonce
IKEV2=bytes.fromhex('1112131415161718')+bytes(8)+bytes.fromhex('2120220800000000')+(28+len(_ike_body)).to_bytes(4,'big')+_ike_body
IKEV2_MARKER=bytes(4)+IKEV2
DATAGRAM_CASES+=((IKEV2,'ikev2'),(IKEV2_MARKER,'ikev2'))
del _ike_sa,_ike_ke,_ike_nonce,_ike_body

# RFC 9001 Appendix A.2 client Initial (QUIC v1): a published, non-secret test vector.
# Decrypting it uses only the version salt and the Destination Connection ID.
QUIC_INITIAL = bytes.fromhex(
    'c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c'
    '0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c'
    '8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89'
    'eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208'
    '4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e'
    '610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db'
    '059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7'
    '961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556'
    'be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7'
    'fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00'
    'f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf'
    '330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd'
    '14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff2'
    '8f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd'
    'c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accd'
    'd5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e'
    'fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a07'
    '1b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2'
    '162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499d'
    'bd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e'
    '8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723'
    'c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab'
    '760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905dd'
    'f3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064'
    '7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934')
DATAGRAM_CASES += ((QUIC_INITIAL, 'quic'),)
