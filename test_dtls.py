"""DTLS wire boundaries, encryption evidence and cross-protocol isolation."""
import random
import unittest
from protocol_engine import Config, DatagramInspector
from protocol_engine.datagram import VALIDATORS
from protocol_fixtures import DTLS, DNS, DATAGRAM_CASES


def extension(kind, value):
    return kind.to_bytes(2, 'big') + len(value).to_bytes(2, 'big') + value


def hello(cookie=b'', session=b'', ciphers=b'\xc0\x2f', compression=b'\0', extensions=None, version=b'\xfe\xfd'):
    body = version + bytes(range(32)) + bytes((len(session),)) + session
    body += bytes((len(cookie),)) + cookie + len(ciphers).to_bytes(2,'big') + ciphers
    body += bytes((len(compression),)) + compression
    if extensions is not None:
        body += len(extensions).to_bytes(2,'big') + extensions
    return body


def record(body, version=b'\xfe\xff', epoch=0, sequence=0, message=0, offset=0, total=None, kind=1):
    size = len(body) if total is None else total
    header = bytes((kind,)) + size.to_bytes(3,'big') + message.to_bytes(2,'big')
    header += offset.to_bytes(3,'big') + len(body).to_bytes(3,'big')
    return b'\x16' + version + epoch.to_bytes(2,'big') + sequence.to_bytes(6,'big') + (12+len(body)).to_bytes(2,'big') + header + body


class DTLSTests(unittest.TestCase):
    def inspect(self, data, config=None, hint=None):
        return DatagramInspector(config).inspect(data, hint)

    def test_complete_hellos_cookie_retries_and_record_versions(self):
        self.assertEqual(record(hello()), DTLS)
        for version in (b'\xfe\xff',b'\xfe\xfd'):
            for cookie in (b'',b'private-cookie',bytes(range(255))):
                for session in (b'',bytes(range(32))):
                    for message, sequence in ((0,0),(1,2),(65535,2**48-1)):
                        data = record(hello(cookie,session),version=version,message=message,sequence=sequence)
                        for hint in (None,'dtls'):
                            result = self.inspect(data,hint=hint)
                            self.assertEqual((result.status,result.encryption,result.transport,result.scope),('identified','dtls','udp','datagram'),result)
                            self.assertIsNone(result.application_protocol)
                            self.assertIsNone(result.application)
                            self.assertNotIn('private-cookie',repr(result))
                            if hint: self.assertEqual(result.evidence[-1].strength,'context')

    def test_sni_alpn_are_client_assertions_only(self):
        host=b'example.com'
        names=b'\0'+len(host).to_bytes(2,'big')+host
        ext=extension(0,len(names).to_bytes(2,'big')+names)+extension(16,b'\0\x0c\x02h2\x08http/1.1')
        result=self.inspect(record(hello(extensions=ext)))
        self.assertEqual(result.status,'identified',result)
        self.assertEqual(result.hostname,'example.com')
        self.assertEqual(result.offered_alpn,('h2','http/1.1'))
        self.assertIsNone(result.application_protocol)
        self.assertIsNone(result.application)
        assertions={e.field:e for e in result.evidence if e.strength=='asserted'}
        self.assertEqual(assertions['hostname'].source,'dtls_sni')
        self.assertEqual(assertions['offered_dtls_version'].value,'1.2')
        self.assertNotIn('selected',repr(result))

    def test_every_truncation_and_datagram_no_join(self):
        inspector=DatagramInspector()
        for end in range(len(DTLS)):
            self.assertNotEqual(inspector.inspect(DTLS[:end]).status,'identified',end)
            self.assertNotEqual(inspector.inspect(DTLS[end:] if end else b'').status,'identified',end)
        self.assertEqual(inspector.inspect(DTLS).encryption,'dtls')
        self.assertEqual(inspector.inspect(DNS).application_protocol,'dns')
        empty=inspector.inspect(b'')
        self.assertEqual(empty.status,'unknown')
        self.assertIsNone(empty.encryption)
        self.assertEqual(vars(inspector).keys(),{'config','metrics','signatures','quic_assembler'})

    def test_record_and_handshake_lengths(self):
        for size in (0,11,16385,65535,len(DTLS)-14,len(DTLS)-12):
            data=DTLS[:11]+size.to_bytes(2,'big')+DTLS[13:]
            self.assertNotEqual(self.inspect(data).status,'identified',size)
        for position,width,values in ((14,3,(0,41,43,2**24-1)),(19,3,(1,42,2**24-1)),(22,3,(0,41,43,2**24-1))):
            for value in values:
                data=DTLS[:position]+value.to_bytes(width,'big')+DTLS[position+width:]
                self.assertNotEqual(self.inspect(data).status,'identified',(position,value))
        self.assertEqual(self.inspect(DTLS+DTLS).status,'unknown')
        # Two complete handshake messages in a single record must not silently
        # validate only the first (this profile requires the entire datagram).
        data=DTLS[:11]+(2*(len(DTLS)-13)).to_bytes(2,'big')+DTLS[13:]*2
        self.assertEqual(self.inspect(data).status,'unknown')

    def test_fragments_and_other_epochs_not_identified(self):
        body=hello()
        for cut in range(1,len(body)):
            for payload,offset in ((body[:cut],0),(body[cut:],cut)):
                result=self.inspect(record(payload,offset=offset,total=len(body)))
                self.assertEqual(result.status,'unknown',result)
        for epoch in (1,65535):
            self.assertEqual(self.inspect(record(body,epoch=epoch)).status,'unknown')
        for kind in (4,11,20):
            self.assertEqual(self.inspect(record(body,kind=kind)).status,'unknown')
        for kind in (2,3):   # server message types are accepted since v0.46, but not with a ClientHello body
            self.assertNotEqual(self.inspect(record(body,kind=kind)).status,'identified')

    def test_body_vectors_and_unsupported_negotiation(self):
        for body in (hello(session=bytes(33)),hello(ciphers=b''),hello(ciphers=b'x'),hello(compression=b''),hello(compression=b'\x01')):
            self.assertEqual(self.inspect(record(body)).status,'malformed')
        for body in (hello(version=b'\xfe\xff'),hello(version=b'\xfe\xfc'),hello(compression=b'\0\x01'),hello(extensions=extension(43,b'\x02\xfe\xfc'))):
            self.assertEqual(self.inspect(record(body)).status,'unknown')
        for pos,value in ((59,255),(60,255),(61,255),(62,255),(65,255)):
            data=DTLS[:pos]+bytes((value,))+DTLS[pos+1:]
            self.assertNotEqual(self.inspect(data).status,'identified',(pos,value))
        for tail in (b'\0',b'\0\x01',b'\0\x01x',b'\0\0x'):
            self.assertNotEqual(self.inspect(record(hello()+tail)).status,'identified')

    def test_extension_validation_and_count_budgets(self):
        for ext in (extension(0,b''),extension(16,b'\0\0'),extension(16,b'\0\x01\0'),extension(100,b'opaque')*2):
            self.assertEqual(self.inspect(record(hello(extensions=ext))).status,'malformed')
        opaque=extension(100,b'private-extension')
        result=self.inspect(record(hello(extensions=opaque)))
        self.assertEqual(result.status,'identified')
        self.assertNotIn('private-extension',repr(result))
        self.assertEqual(self.inspect(record(hello(extensions=opaque)),Config(max_headers=1)).status,'identified')
        ext=opaque+extension(101,b'')
        self.assertEqual(self.inspect(record(hello(extensions=ext)),Config(max_headers=1)).status,'budget_exhausted')
        ext=b''.join(extension(100+i,b'') for i in range(129))
        self.assertEqual(self.inspect(record(hello(extensions=ext)),Config(max_headers=4096)).status,'budget_exhausted')
        self.assertEqual(self.inspect(DTLS,Config(max_bytes=64)).status,'budget_exhausted')
        fragment=record(b'x',total=1000)
        self.assertEqual(self.inspect(fragment,Config(max_bytes=100)).status,'budget_exhausted')

    def test_dispatch_disjointness_and_opaque_cookie_magic(self):
        for family in VALIDATORS:
            result=self.inspect(DTLS,hint=family)
            self.assertEqual(result.status=='identified',family=='dtls',(family,result))
        for data,family in DATAGRAM_CASES:
            inspector=DatagramInspector()
            result=inspector.inspect(data)
            self.assertEqual(result.status,'identified',result)
            self.assertLessEqual(inspector.metrics.parser_calls,2)
            if family!='dtls': self.assertNotEqual(self.inspect(data,hint='dtls').status,'identified')
        # DHCP's cookie at absolute236 is opaque DTLS cookie data. A deeper
        # unrelated signature must not steal the validated DTLS prefix route.
        data=bytearray(record(hello(cookie=bytes(255))))
        data[236:240]=bytes.fromhex('63825363')
        self.assertEqual(self.inspect(bytes(data)).encryption,'dtls')

    def test_record_maximum_and_exact_config_budget(self):
        # Largest plaintext record:12 handshake bytes +16372 ClientHello bytes.
        body=hello(extensions=extension(100,b'x'*16324))
        data=record(body)
        self.assertEqual(len(data),13+16384)
        self.assertEqual(self.inspect(data,Config(max_bytes=len(data))).status,'identified')
        self.assertEqual(self.inspect(data,Config(max_bytes=len(data)-1)).status,'budget_exhausted')
        self.assertEqual(self.inspect(record(hello(extensions=extension(100,b'x'*16325)))).status,'malformed')

    def test_seeded_mutations_are_bounded_and_do_not_leak(self):
        rng=random.Random(6347)
        for _ in range(2500):
            data=bytearray(DTLS)
            for _ in range(rng.randrange(1,5)):
                pos=rng.randrange(len(data)+1)
                if pos==len(data): data.extend(rng.randbytes(rng.randrange(1,12)))
                else: data[pos]=rng.randrange(256)
            inspector=DatagramInspector()
            result=inspector.inspect(bytes(data))
            self.assertIn(result.status,('identified','unknown','malformed','budget_exhausted'))
            self.assertLessEqual(inspector.metrics.parser_calls,2)
            self.assertLessEqual(inspector.metrics.bytes_inspected,len(data))
            self.assertIsNone(result.application)
            if result.encryption=='dtls': self.assertIsNone(result.application_protocol)

    def test_offline_and_live_events_preserve_encryption(self):
        from analyze_pcap import Analyzer
        from packets import decode_packet
        from make_sample_pcap import udp_frame,A,B
        from live_capture import CaptureMonitor
        from capture_stream import CaptureRecord
        data=udp_frame(A,B,DTLS)
        analyzer=Analyzer()
        line=analyzer.process(0,decode_packet(data))
        self.assertIn('| IDENTIFIED | dtls |',line)
        self.assertIsNone(analyzer.last_events[0].observation.application_protocol)
        events=[]
        monitor=CaptureMonitor(events.append)
        monitor.accept(CaptureRecord(0,data,len(data),1),0)
        result=[e for e in events if e['type']=='classification'][0]
        self.assertEqual(result['protocol'],'dtls')
        self.assertEqual(result['transport'],'udp')
        self.assertIsNone(monitor.analyzer.last_classification.application_protocol)


if __name__=='__main__': unittest.main()
