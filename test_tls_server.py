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
                           ((16,b'\0\x03\x02h2x'),),((23,b''),(23,b'')),((51,b'\0\x1d'),)):
            self.assertNotEqual(inspect(record(hello(extensions))).observation.status,'identified',extensions)

    def test_ec_formats_require_ecc_cipher_in_server_hello(self):
        # RFC8422 section5.2; review4319051025. The supported RSA-only
        # cipher must reject this extension at every transport/record split.
        h=hello(((11,b'\x01\x00'),),cipher=0x002f)
        data=record(h)
        for cut in range(len(data)+1):
            e=Inspector();e.feed(data[:cut]);e.feed(data[cut:])
            self.assertEqual(e.observation.status,'malformed',cut)
            self.assertIsNone(e.observation.encryption)
        for cut in range(1,len(h)):
            self.assertEqual(inspect(record(h[:cut])+record(h[cut:])).observation.status,'malformed',cut)
        self.assertEqual(inspect(record(hello(cipher=0x002f))).observation.status,'identified')
        for cipher in range(0xc023,0xc033):
            self.assertEqual(inspect(record(hello(((11,b'\1\0'),),cipher=cipher))).observation.status,'identified',cipher)

    def test_post_quantum_hybrid_key_shares(self):
        # Integration work item #4 (2026-11-14): the hybrid groups current TLS stacks negotiate by default.
        hybrids=((4588,1120,bytes(1120)),(4587,1153,b'\x04'+bytes(1152)),(4589,1665,b'\x04'+bytes(1664)))
        for group,size,key in hybrids:
            e=inspect(record(server13(((51,group.to_bytes(2,'big')+size.to_bytes(2,'big')+key),))))
            self.assertEqual(e.observation.status,'identified',(group,e.observation))
            self.assertEqual(evidence(e)['selected_group'],str(group))
            self.assertEqual(evidence(e)['selected_key_exchange'],'hybrid')
            self.assertEqual(evidence(e)['selected_tls_version'],'1.3')
            from protocol_engine.risks import NO_FORWARD_SECRECY
            self.assertNotIn('hybrid',NO_FORWARD_SECRECY)
            # A HelloRetryRequest may ask the client for the same group.
            retry=inspect(record(server13(((51,group.to_bytes(2,'big')),),random_value=RETRY)))
            self.assertEqual(retry.observation.status,'identified',(group,retry.observation))
            self.assertEqual(evidence(retry)['requested_group'],str(group))
            # Exact length only: one byte short, one byte long, and an empty share are malformed.
            for bad in (key[:-1],key+b'\0',b''):
                e=inspect(record(server13(((51,group.to_bytes(2,'big')+len(bad).to_bytes(2,'big')+bad),))))
                self.assertEqual(e.observation.status,'malformed',(group,len(bad),e.observation))
        # The NIST-curve hybrids start with an uncompressed point; anything else is malformed. X25519MLKEM768
        # starts with the ML-KEM ciphertext, which has no fixed first byte.
        for group,size in ((4587,1153),(4589,1665)):
            for first in (0,2,3):
                key=bytes([first])+bytes(size-1)
                e=inspect(record(server13(((51,group.to_bytes(2,'big')+size.to_bytes(2,'big')+key),))))
                self.assertEqual(e.observation.status,'malformed',(group,first))

    def test_unknown_registry_values_by_position(self):
        # Integration work item #5 (2026-11-14): an unknown value is decided per field and position.
        from protocol_engine.risks import NO_FORWARD_SECRECY
        # TLS 1.3 ServerHello key_share: an unnamed group is recorded by number and gets no named exchange class
        # (0x6399 is the withdrawn X25519Kyber768Draft00 code point, 0xffff is unassigned).
        for group,key in ((0x6399,bytes(1120)),(0xffff,b'x'),(0x0200,bytes(1568))):
            e=inspect(record(server13(((51,group.to_bytes(2,'big')+len(key).to_bytes(2,'big')+key),))))
            self.assertEqual(e.observation.status,'identified',(group,e.observation))
            self.assertEqual(evidence(e)['selected_group'],str(group))
            self.assertEqual(evidence(e)['selected_key_exchange'],'unrecognized')
            self.assertNotIn('unrecognized',NO_FORWARD_SECRECY)
            # ... the key_share framing is still validated: empty share, short vector, trailing byte.
            for value in (group.to_bytes(2,'big')+b'\0\0',group.to_bytes(2,'big')+b'\0\x05abc',
                          group.to_bytes(2,'big')+b'\0\x01xy',group.to_bytes(2,'big')):
                e=inspect(record(server13(((51,value),))))
                self.assertEqual(e.observation.status,'malformed',(group,value))
            # HelloRetryRequest: the requested group is a bare number.
            retry=inspect(record(server13(((51,group.to_bytes(2,'big')),),random_value=RETRY)))
            self.assertEqual(retry.observation.status,'identified',group)
            self.assertEqual(evidence(retry)['requested_group'],str(group))
            self.assertNotIn('selected_key_exchange',evidence(retry))
        # A server never selects a GREASE value (RFC 8701), in either message.
        for group in (0x0a0a,0x8a8a,0xfafa):
            e=inspect(record(server13(((51,group.to_bytes(2,'big')+b'\0\x01x'),))))
            self.assertEqual(e.observation.status,'malformed',group)
            retry=inspect(record(server13(((51,group.to_bytes(2,'big')),),random_value=RETRY)))
            self.assertEqual(retry.observation.status,'malformed',group)
        # Known groups keep their exact lengths.
        e=inspect(record(server13(((51,b'\0\x1d\0\x1f'+bytes(31)),))))
        self.assertEqual(e.observation.status,'malformed')
        # The TLS 1.3 extension sets and cipher list stay closed.
        for extra in (((16,b'\0\x03\x02h2'),),((1234,b''),),((0x0a0a,b''),)):
            self.assertEqual(inspect(record(server13(extra+((51,b'\0\x1d\0\x20'+bytes(32)),)))).observation.status,'unknown',extra)
        # TLS 1.2 ServerHello: an extension type the profile does not interpret is skipped once framed ...
        base=evidence(inspect(record(hello(((16,b'\0\x03\x02h2'),)))))
        for extensions in (((1234,b''),),((22,b''),),((18,b'\0\x04abcd'),),((10,b'\0\x02\0\x1d'),),((1234,b'x'*300),(16,b'\0\x03\x02h2'))):
            e=inspect(record(hello(extensions+(() if any(k==16 for k,_ in extensions) else ((16,b'\0\x03\x02h2'),)))))
            self.assertEqual(e.observation.status,'identified',extensions)
            self.assertEqual(evidence(e),base,extensions)      # nothing is claimed about the skipped extension
        # ... but TLS 1.3-only and client-only types, GREASE types, duplicates and bad framing are malformed.
        for kind in (13,41,42,44,45,47,48,49,50,51,0x0a0a,0xfafa):
            self.assertEqual(inspect(record(hello(((kind,b''),)))).observation.status,'malformed',kind)
        self.assertEqual(inspect(record(hello(((1234,b''),(1234,b''))))).observation.status,'malformed')
        body=hello(((1234,b'abc'),))
        self.assertEqual(inspect(record(body[:-5]+b'\0\x04'+body[-3:])).observation.status,'malformed')   # length past the block
        # The TLS 1.2 cipher list stays closed: the key exchange and cipher mode are read from the suite.
        self.assertEqual(inspect(record(hello(((1234,b''),),cipher=0x009c))).observation.status,'unknown')

    def test_bad_server13_extension_dependencies_and_shapes(self):
        for extra in ((),((41,b'\0'),),((51,b'\0\x1d'),),((51,b'\0\x1d\0\x1f'+bytes(31)),),
                      ((51,b'\0\x17\0\x41'+bytes(65)),),((51,b'\xff\xff\0\x00'),),
                      ((44,b'\0\x01x'),),((16,b'\0\x03\x02h2'),),((43,b'\x03\x04'),)):
            self.assertNotEqual(inspect(record(server13(extra))).observation.status,'identified',extra)
        for value in (b'',b'\x03\x03',b'\x03\x04x',b'\x03\x05'):
            self.assertNotEqual(inspect(record(hello(((43,value),(41,b'\0\0')),cipher=0x1301))).observation.status,'identified')
        for extra in ((),((41,b'\0\0'),),((44,b'\0\0'),),((44,b'\0\x02x'),),((51,b'\0\x1d\0\x20'+bytes(32)),),((51,b'\x0a\x0a'),)):
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
