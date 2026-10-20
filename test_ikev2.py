"""IKEv2 initial negotiation and bounded candidate ambiguity regressions."""
import itertools
import random
import unittest
from protocol_engine import Config, DatagramInspector
from protocol_engine.ikev2 import ike_probe


def transform(kind,value,attrs=b'',last=0):
    return bytes((last,0))+(8+len(attrs)).to_bytes(2,'big')+bytes((kind,0))+value.to_bytes(2,'big')+attrs


def proposal(transforms=None,number=1,last=0):
    if transforms is None:
        transforms=[transform(1,12,b'\x80\x0e\x00\x80'),transform(2,5),transform(3,12),transform(4,14)]
    body=b''.join(bytes((3 if i+1<len(transforms) else 0,))+t[1:] for i,t in enumerate(transforms))
    return bytes((last,0))+(8+len(body)).to_bytes(2,'big')+bytes((number,1,0,len(transforms)))+body


def ke(group=14, data=None):
    if data is None:data=bytes({14:256,15:384,16:512,17:768,18:1024}[group])
    return group.to_bytes(2,'big')+b'\0\0'+data


def request(payloads=None,spi=b'\x11\x12\x13\x14\x15\x16\x17\x18',marker=False,critical=0):
    if payloads is None:payloads=[(33,proposal()),(34,ke()),(40,bytes(32))]
    body=b''.join(bytes((payloads[i+1][0] if i+1<len(payloads) else 0,critical))+(4+len(v)).to_bytes(2,'big')+v for i,(_,v) in enumerate(payloads))
    data=spi+bytes(8)+bytes((payloads[0][0] if payloads else 0,32,34,8))+bytes(4)+(28+len(body)).to_bytes(4,'big')+body
    return (bytes(4) if marker else b'')+data


def notify(kind, value):return b'\0\0'+kind.to_bytes(2,'big')+value


class IKETests(unittest.TestCase):
    def inspect(self,data,config=None,hint='ikev2'):
        return DatagramInspector(config).inspect(data,hint)

    def test_published_fixture_and_capture_events(self):
        from protocol_fixtures import IKEV2,IKEV2_MARKER
        from live_capture import CaptureMonitor
        from capture_stream import CaptureRecord
        from make_sample_pcap import A,B,udp_frame
        self.assertEqual(IKEV2,request())
        self.assertEqual(IKEV2_MARKER,request(marker=True))
        events=[]
        monitor=CaptureMonitor(events.append)
        for payload in (IKEV2,IKEV2_MARKER):
            frame=udp_frame(A,B,payload)
            monitor.accept(CaptureRecord(0,frame,len(frame),1),0)
        self.assertEqual([e['protocol'] for e in events],['ikev2','ikev2'])
        self.assertEqual(monitor.counts['identified'],2)

    def test_basic_request_optional_marker_and_metadata(self):
        for marker in (False,True):
            for critical in (0,128):
                for hint in (None,'ikev2'):
                    result=self.inspect(request(marker=marker,critical=critical),hint=hint)
                    self.assertEqual((result.status,result.application_protocol),('identified','ikev2'),result)
                    self.assertIsNone(result.encryption)
                    self.assertIsNone(result.application)
                    self.assertIsNone(result.hostname)
                    self.assertEqual(result.offered_alpn,())
                    self.assertIn('no established IPsec',result.reason)
                    self.assertTrue(any(e.field=='offered_dh_group' and e.value=='14' and e.strength=='asserted' for e in result.evidence))

    def test_each_supported_cipher_prf_integrity_group(self):
        for cipher,key,prf,integ,group in itertools.product((12,18,19,20),(128,192,256),(2,5,6,7),(2,12,13,14),(14,15,16,17,18)):
            transforms=[transform(1,cipher,b'\x80\x0e'+key.to_bytes(2,'big')),transform(2,prf),transform(4,group)]
            if cipher==12:transforms.append(transform(3,integ))
            data=request([(33,proposal(transforms)),(34,ke(group)),(40,bytes(32))])
            self.assertEqual(self.inspect(data).status,'identified',(cipher,key,prf,integ,group))

    def test_payload_order_proposal_alternatives_and_cookie(self):
        required=[(33,proposal()),(34,ke()),(40,bytes(32))]
        for order in itertools.permutations(required):
            for extras in ([],[(41,notify(16388,bytes(20))),(41,notify(16389,bytes(20)))],[(43,b'private-vendor')]):
                result=self.inspect(request(list(order)+extras))
                self.assertEqual(result.status,'identified',result)
                self.assertNotIn('private-vendor',repr(result))
        for length in (1,64):
            self.assertEqual(self.inspect(request([(41,notify(16390,b'x'*length))]+required)).status,'identified')
        for length in (0,65):
            self.assertEqual(self.inspect(request([(41,notify(16390,b'x'*length))]+required)).status,'malformed')
        self.assertEqual(self.inspect(request(required+[(41,notify(16390,b'x'))])).status,'malformed')
        alternatives=proposal(last=2)+proposal([transform(1,20,b'\x80\x0e\x01\x00'),transform(2,7),transform(4,18)],number=2)
        for group in (14,18):
            self.assertEqual(self.inspect(request([(33,alternatives),(34,ke(group)),(40,bytes(32))])).status,'identified')

    def test_all_truncations_never_join_and_exact_length(self):
        for marker in (False,True):
            data=request(marker=marker)
            engine=DatagramInspector()
            for cut in range(len(data)):
                self.assertNotEqual(engine.inspect(data[:cut],'ikev2').status,'identified')
                suffix=engine.inspect(data[cut:] if cut else b'','ikev2')
                if marker and cut==4: self.assertEqual(suffix.application_protocol,'ikev2')
                else: self.assertNotEqual(suffix.status,'identified',(marker,cut))
            for suffix in (b'\0',data):self.assertNotEqual(self.inspect(data+suffix).status,'identified')
            self.assertEqual(engine.inspect(data,'ikev2').status,'identified')
            self.assertEqual(set(vars(engine)),{'metrics','config','signatures','quic_assembler'})
            start=4 if marker else 0
            for length in (0,27,len(data)-start-1,len(data)-start+1,2**32-1):
                changed=data[:start+24]+length.to_bytes(4,'big')+data[start+28:]
                self.assertNotEqual(self.inspect(changed).status,'identified')

    def test_headers_and_nested_lengths(self):
        data=request()
        for pos,value in ((8,1),(17,16),(17,33),(18,35),(19,0),(19,0x28),(19,0x18),(20,1),(29,1),(33,1),(36,2),(37,3),(38,8),(39,0),(41,1),(45,1)):
            self.assertNotEqual(self.inspect(data[:pos]+bytes((value,))+data[pos+1:]).status,'identified',(pos,value))
        self.assertEqual(self.inspect(request(spi=bytes(8))).status,'malformed')
        for pos in (30,34,42):
            for length in (0,1,3,7,65535):
                changed=data[:pos]+length.to_bytes(2,'big')+data[pos+2:]
                self.assertNotEqual(self.inspect(changed).status,'identified',(pos,length))
        for kind in (33,34,40):
            parts=[(33,proposal()),(34,ke()),(40,bytes(32))]
            self.assertEqual(self.inspect(request([p for p in parts if p[0]!=kind])).status,'malformed')
            parts.append(next(p for p in parts if p[0]==kind))
            self.assertEqual(self.inspect(request(parts)).status,'malformed')

    def test_transform_attributes_types_and_chaining(self):
        for attributes in (b'',b'\0\x0e\0\x02\0\x80',b'\x80\x0e\0\x81',b'\x80\x0e\0\x80'*2):
            transforms=[transform(1,12,attributes),transform(2,5),transform(3,12),transform(4,14)]
            self.assertEqual(self.inspect(request([(33,proposal(transforms)),(34,ke()),(40,bytes(32))])).status,'malformed')
        for kind,value in ((1,65000),(2,0),(3,0),(4,31),(5,0)):
            transforms=[transform(1,12,b'\x80\x0e\0\x80'),transform(2,5),transform(3,12),transform(4,14),transform(kind,value)]
            self.assertEqual(self.inspect(request([(33,proposal(transforms)),(34,ke()),(40,bytes(32))])).status,'unknown')
        for transforms in ([transform(1,12,b'\x80\x0e\0\x80'),transform(2,5),transform(4,14)],
                           [transform(1,20,b'\x80\x0e\0\x80'),transform(2,5),transform(3,12),transform(4,14)]):
            self.assertEqual(self.inspect(request([(33,proposal(transforms)),(34,ke()),(40,bytes(32))])).status,'malformed')
        data=bytearray(request())
        for pos,value in ((32,2),(40,0),(68,3),(39,3),(39,5)):
            changed=data.copy();changed[pos]=value
            self.assertNotEqual(self.inspect(bytes(changed)).status,'identified',(pos,value))

    def test_nonce_and_ke_cross_checks(self):
        for prf,minimum in ((2,16),(5,16),(6,24),(7,32)):
            sa=proposal([transform(1,20,b'\x80\x0e\0\x80'),transform(2,prf),transform(4,14)])
            for length in (0,15,minimum-1,minimum,256,257):
                result=self.inspect(request([(33,sa),(34,ke()),(40,bytes(length))]))
                self.assertEqual(result.status=='identified',minimum<=length<=256,(prf,length,result))
        for data in (bytes(255),bytes(257)):
            self.assertEqual(self.inspect(request([(33,proposal()),(34,ke(data=data)),(40,bytes(32))])).status,'malformed')
        self.assertEqual(self.inspect(request([(33,proposal()),(34,ke(15)),(40,bytes(32))])).status,'malformed')

    def test_notify_vendor_and_unknown_payloads(self):
        base=[(33,proposal()),(34,ke()),(40,bytes(32))]
        for code in (16388,16389):
            for length in (0,19,21):self.assertEqual(self.inspect(request(base+[(41,notify(code,bytes(length)))])).status,'malformed')
        for body in (b'',b'\1\0\x40\4'+bytes(20),b'\0\1\x40\4'+bytes(20)):
            self.assertEqual(self.inspect(request(base+[(41,body)])).status,'malformed')
        self.assertEqual(self.inspect(request(base+[(41,notify(65000,b''))])).status,'unknown')
        self.assertEqual(self.inspect(request(base+[(43,b'')])).status,'malformed')
        self.assertEqual(self.inspect(request(base+[(43,b'x'*17)]),Config(max_line=16)).status,'budget_exhausted')
        for kind in (35,46,53,250):self.assertNotEqual(self.inspect(request(base+[(kind,b'x')])).status,'identified')

    def test_aggregate_work_and_byte_budgets(self):
        data=request()
        self.assertEqual(self.inspect(data,Config(max_headers=8)).status,'identified')
        self.assertEqual(self.inspect(data,Config(max_headers=7)).status,'budget_exhausted')
        self.assertEqual(self.inspect(data,Config(max_bytes=len(data))).status,'identified')
        self.assertEqual(self.inspect(data,Config(max_bytes=len(data)-1)).status,'budget_exhausted')
        sa=b''.join(proposal(number=i+1,last=2 if i<25 else 0) for i in range(26))
        self.assertEqual(self.inspect(request([(33,sa),(34,ke()),(40,bytes(32))]),Config(max_headers=4096)).status,'budget_exhausted')

    def test_arbitrary_spi_cannot_steal_existing_prefix_routes(self):
        for spi in (b'\x16\xfe\xff'+bytes(5),b'\0\1\0\0'+bytes.fromhex('2112a442'),b'\x30'+bytes(7),b'<'+bytes(7)):
            result=self.inspect(request(spi=spi),hint=None)
            self.assertEqual(result.application_protocol,'ikev2',result)
        for marker in (False,True):
            self.assertTrue(ike_probe(request(marker=marker)))
        self.assertEqual(self.inspect(request(spi=bytes(4)+b'ABCD'),hint=None).application_protocol,'ikev2')

    def test_real_coap_and_dhcp_ambiguities_are_unknown(self):
        from protocol_engine.wire import coap,dhcp
        coap_data=request(spi=b'\x40\x01\0\0\xff\0\0\0')
        self.assertEqual(coap(coap_data,Config())[0],'coap')
        self.assertEqual(self.inspect(coap_data).application_protocol,'ikev2')
        result=self.inspect(coap_data,hint=None)
        self.assertEqual(result.status,'unknown',result)
        self.assertIn('Ambiguous',result.reason)
        data=bytearray(request(spi=b'\x01\x01\x06\0ABCD'))
        data[236:243]=bytes.fromhex('63825363350101')
        data[-1]=255
        dhcp_data=bytes(data)
        self.assertEqual(dhcp(dhcp_data,Config())[0],'dhcp/4')
        self.assertEqual(self.inspect(dhcp_data).application_protocol,'ikev2')
        self.assertEqual(self.inspect(dhcp_data,hint=None).status,'unknown')
        self.assertEqual(self.inspect(dhcp_data,Config(max_headers=2),hint=None).status,'budget_exhausted')
        self.assertEqual(self.inspect(dhcp_data,hint='dhcp').application_protocol,'dhcp/4')

    def test_three_candidates_remain_bounded(self):
        data=request(spi=bytes.fromhex('4101000000010000'))
        inspector=DatagramInspector()
        result=inspector.inspect(data)
        self.assertEqual(inspector.metrics.parser_calls,3)
        self.assertEqual(inspector.metrics.candidates_selected,3)
        self.assertIn(result.status,('identified','unknown'))

    def test_seeded_mutations_and_parser_call_ceiling(self):
        rng=random.Random(7296)
        for _ in range(3000):
            data=bytearray(request())
            for _ in range(rng.randrange(1,5)):
                pos=rng.randrange(len(data));data[pos]=rng.randrange(256)
            inspector=DatagramInspector()
            result=inspector.inspect(bytes(data))
            self.assertIn(result.status,('identified','unknown','malformed','budget_exhausted'))
            self.assertLessEqual(inspector.metrics.parser_calls,3)
            self.assertLessEqual(inspector.metrics.bytes_inspected,len(data))
            self.assertIsNone(result.application)
            self.assertIsNone(result.encryption)


if __name__=='__main__':unittest.main()
