"""Server hello framing, extension contexts and untrusted metadata boundaries."""
import random
import unittest
from dataclasses import asdict
from protocol_engine import Inspector, Config, ApplicationRule, RuleIndex
from proxy_demo import client_hello

RETRY=bytes.fromhex('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c')


def ext(kind,value):return kind.to_bytes(2,'big')+len(value).to_bytes(2,'big')+value

def record(data,version=b'\x03\x03'):return b'\x16'+version+len(data).to_bytes(2,'big')+data

def hello(extensions=None,cipher=0xc02f,random_value=bytes(range(32)),session=b'',compression=0,version=b'\x03\x03'):
    body=version+random_value+bytes([len(session)])+session+cipher.to_bytes(2,'big')+bytes([compression])
    if extensions is not None:
        values=b''.join(ext(k,v) for k,v in extensions);body+=len(values).to_bytes(2,'big')+values
    return b'\x02'+len(body).to_bytes(3,'big')+body


def server13(extra=None,**kwargs):
    if extra is None:extra=((51,b'\x00\x1d\x00\x20'+bytes(32)),)
    return hello(((43,b'\x03\x04'),)+tuple(extra),cipher=0x1301,**kwargs)


def inspect(data,config=None):
    e=Inspector(config=config);e.feed(data);return e


def evidence(e):return {x.field:x.value for x in e.observation.evidence}


class TLSServerTests(unittest.TestCase):
    def test_server12_optional_extensions_selected_not_offered(self):
        for extensions in (None,(),((0,b''),(5,b''),(23,b''),(35,b''),(65281,b'\0'),(11,b'\x03\x00\x01\x02')),
                           ((16,b'\x00\x03\x02h2'),),((16,b'\x00\x02\x01\xff'),)):
            for session in (b'',b'x'*32):
                e=inspect(record(hello(extensions,session=session)))
                self.assertEqual(e.observation.status,'identified',e.observation)
                self.assertEqual(e.observation.scope,'server_hello')
                self.assertEqual(e.observation.encryption,'tls')
                self.assertEqual(evidence(e)['selected_tls_version'],'1.2')
                self.assertEqual(e.observation.offered_alpn,())
                self.assertIsNone(e.observation.application_protocol)
                self.assertIsNone(e.observation.application)
                self.assertIsNone(e.observation.hostname)
                self.assertFalse(any(x.strength=='authenticated' for x in e.observation.evidence))
        self.assertEqual(evidence(inspect(record(hello(((16,b'\0\x03\x02h2'),)))))['selected_alpn'],'h2')

    def test_server13_psk_dhe_and_key_sizes(self):
        for extra in (((41,b'\0\x01'),),((51,b'\0\x1d\0\x20'+bytes(32)),),
                      ((41,b'\0\0'),(51,b'\0\x17\0\x41'+b'\x04'+bytes(64)))):
            e=inspect(record(server13(extra)))
            self.assertEqual(e.observation.status,'identified',e.observation)
            self.assertEqual(evidence(e)['selected_tls_version'],'1.3')
            self.assertNotIn('selected_alpn',evidence(e))
        for group,size in ((24,97),(25,133),(30,56),(256,256),(257,384),(258,512),(259,768),(260,1024)):
            key=(b'\x04'+bytes(size-1)) if group in (24,25) else bytes(size)
            e=inspect(record(server13(((51,group.to_bytes(2,'big')+size.to_bytes(2,'big')+key),))))
            self.assertEqual(e.observation.status,'identified',(group,e.observation))

    def test_retry_has_distinct_scope_and_no_completed_handshake_claim(self):
        for extra in (((51,b'\0\x1d'),),((44,b'\0\x03abc'),),((51,b'\0\x17'),(44,b'\0\x03abc'))):
            e=inspect(record(server13(extra,random_value=RETRY)))
            self.assertEqual(e.observation.status,'identified',e.observation)
            self.assertEqual(e.observation.scope,'hello_retry_request')
            self.assertNotIn('selected_group',evidence(e))
            self.assertNotIn('abc',repr(asdict(e.observation)))

    def test_every_tcp_cut_and_every_record_cut(self):
        for handshake in (hello(),hello(((16,b'\0\x03\x02h2'),)),server13(),server13(((51,b'\0\x1d'),),random_value=RETRY)):
            data=record(handshake);expected=inspect(data).observation
            for cut in range(len(data)+1):
                e=Inspector();e.feed(data[:cut]);e.feed(data[cut:]+b'later encrypted data')
                self.assertEqual(e.observation,expected,cut)
                self.assertEqual(e.metrics.bytes_inspected,len(data))
                self.assertEqual(e.metrics.candidates_selected,1)
            for cut in range(1,len(handshake)):
                split=record(handshake[:cut])+record(handshake[cut:]);e=Inspector()
                for b in split:e.feed(bytes([b]))
                self.assertEqual(e.observation,expected,cut)
                self.assertEqual(e.metrics.bytes_inspected,len(split))
            for cut in range(len(data)):
                e=inspect(data[:cut]);e.end();self.assertNotEqual(e.observation.status,'identified',cut)

    def test_bad_fixed_fields_and_cipher_profiles(self):
        for handshake in (hello(session=b'x'*33),hello(compression=1),hello(version=b'\x03\x04'),
                          hello(cipher=0),hello(cipher=0x00ff),hello(cipher=0x1301),hello(cipher=0x5600),
                          hello(((43,b'\x03\x04'),(41,b'\0\0')),cipher=0xc02f),
                          hello(random_value=RETRY)):
            self.assertNotEqual(inspect(record(handshake)).observation.status,'identified',handshake)
        for cipher in (0x002f,0xc023,0xc032):
            self.assertEqual(inspect(record(hello(cipher=cipher))).observation.status,'identified')

    def test_bad_server12_extension_values_and_contexts(self):
        for extensions in (((0,b'x'),),((23,b'x'),),((35,b'x'),),((65281,b''),),((65281,b'\x01x'),),
                           ((11,b'\0'),),((11,b'\x01\x01'),),((11,b'\x01\0x'),),
                           ((16,b'\0\0'),),((16,b'\0\x01\0'),),((16,b'\0\x06\x02h2\x02h3'),),
                           ((16,b'\0\x03\x02h2x'),),((23,b''),(23,b'')),((51,b'\0\x1d'),),((1234,b''),)):
            self.assertNotEqual(inspect(record(hello(extensions))).observation.status,'identified',extensions)

    def test_bad_server13_extension_dependencies_and_shapes(self):
        for extra in ((),((41,b'\0'),),((51,b'\0\x1d'),),((51,b'\0\x1d\0\x1f'+bytes(31)),),
                      ((51,b'\0\x17\0\x41'+bytes(65)),),((51,b'\xff\xff\0\x01x'),),
                      ((44,b'\0\x01x'),),((16,b'\0\x03\x02h2'),),((43,b'\x03\x04'),)):
            self.assertNotEqual(inspect(record(server13(extra))).observation.status,'identified',extra)
        for value in (b'',b'\x03\x03',b'\x03\x04x',b'\x03\x05'):
            self.assertNotEqual(inspect(record(hello(((43,value),(41,b'\0\0')),cipher=0x1301))).observation.status,'identified')
        for extra in ((),((41,b'\0\0'),),((44,b'\0\0'),),((44,b'\0\x02x'),),((51,b'\0\x1d\0\x20'+bytes(32)),)):
            self.assertNotEqual(inspect(record(server13(extra,random_value=RETRY))).observation.status,'identified',extra)

    def test_server13_record_boundary_version_and_interleaving(self):
        h=server13()
        for data in (record(h+b'x'),record(h,b'\x03\x01'),record(h[:2],b'\x03\x01')+record(h[2:]),
                     record(h[:2])+b'\x14\x03\x03\0\x01\x01'+record(h[2:])):
            self.assertEqual(inspect(data).observation.status,'malformed')
        # TLS 1.2 may coalesce later handshake messages, whose bytes remain uninspected.
        e=inspect(record(hello()+b'certificate bytes'))
        self.assertEqual(e.observation.status,'identified')
        self.assertEqual(e.metrics.bytes_inspected,len(hello())+5)

    def test_budgets_and_release(self):
        for data,config in ((record(hello(((0,b''),(23,b'')))),Config(max_headers=1)),
                            (record(server13()),Config(max_bytes=64))):
            e=inspect(data,config);self.assertEqual(e.observation.status,'budget_exhausted');self.assertIsNone(e._parser)
        e=inspect(record(b'\x02\xff\xff\xff'),Config(max_bytes=64))
        self.assertEqual(e.observation.status,'budget_exhausted')

    def test_selected_alpn_never_maps_an_inner_protocol_or_product(self):
        e=Inspector(rules=RuleIndex([ApplicationRule('example.com','Wrong','tls_sni')]))
        e.feed(record(hello(((0,b''),(16,b'\0\x03\x02h2')))))
        self.assertIsNone(e.observation.application_protocol);self.assertIsNone(e.observation.application)
        e.feed_decrypted(b'HTTP/1.1 200 OK\r\n\r\n')
        self.assertEqual(e.observation.application_protocol,'http/1.1')
        self.assertEqual(evidence(e)['selected_alpn'],'h2')
        self.assertEqual(e.observation.offered_alpn,())

    def test_shared_fixture_scope_and_versions(self):
        from protocol_fixtures import TLS_SERVER12, TLS_SERVER13, TLS_RETRY
        for data,version,scope in ((TLS_SERVER12,'1.2','server_hello'),
                                   (TLS_SERVER13,'1.3','server_hello'),
                                   (TLS_RETRY,'1.3','hello_retry_request')):
            e=inspect(data)
            self.assertEqual(e.observation.status,'identified')
            self.assertEqual(evidence(e)['selected_tls_version'],version)
            self.assertEqual(e.observation.scope,scope)

    def test_client_hello_behavior_preserved(self):
        e=inspect(client_hello())
        self.assertEqual(e.observation.status,'identified');self.assertEqual(e.observation.scope,'initial_message')
        self.assertNotIn('selected_alpn',evidence(e))
        self.assertNotIn('selected_tls_version',evidence(e))

    def test_mutation_fragmentation_equivalence(self):
        rng=random.Random(19019)
        for _ in range(2000):
            data=bytearray(record(rng.choice((hello(),server13(),server13(((51,b'\0\x1d'),),random_value=RETRY)))))
            for _ in range(rng.randrange(1,4)):data[rng.randrange(len(data))]=rng.randrange(256)
            data=bytes(data);whole=inspect(data);split=Inspector();pos=0
            while pos<len(data):
                n=rng.randrange(1,15);split.feed(data[pos:pos+n]);pos+=n
            whole.end();split.end();self.assertEqual(whole.observation,split.observation,data)
