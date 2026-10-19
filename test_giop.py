"""Independent wire builders and adversarial GIOP/CDR profile checks."""
import random
import struct
import unittest
from dataclasses import asdict
from protocol_engine import Inspector, Config
from protocol_engine.dispatch import select, LOOKAHEAD
from protocol_fixtures import GIOP, STREAM_CASES


def frame(body, order='>', kind=0):
    return b'GIOP\x01\x02' + bytes([order == '<', kind]) + struct.pack(order+'I', len(body)) + body


def request(order='>', key=b'private-object', operation=b'_is_a', contexts=(), args=b'', flags=3, pad=0xa5):
    # CDR integer fields are aligned at absolute offsets in the whole message.
    body = bytearray(struct.pack(order+'IB3xH2xI', 17, flags, 0, len(key)) + key)
    def align(n):body.extend(bytes([pad])*((-(12+len(body))) % n))
    align(4);body.extend(struct.pack(order+'I', len(operation)+1)+operation+b'\0')
    align(4);body.extend(struct.pack(order+'I', len(contexts)))
    for number, data in contexts:
        align(4);body.extend(struct.pack(order+'II',number,len(data))+data)
    if args:
        align(8);body.extend(args)
    return frame(body,order)


def locate(order='>', key=b'demo', padding=b'\xab\xcd'):
    return frame(struct.pack(order+'IH', 17, 0)+padding+struct.pack(order+'I',len(key))+key,order,3)


def inspect(data, hint=None, config=None):
    engine=Inspector(config=config,protocol_hint=hint);engine.feed(data);return engine


class GIOPTests(unittest.TestCase):
    def test_versions_endian_requests_contexts_and_opaque_arguments(self):
        for order in ('>','<'):
            for size in range(9):
                for args in (b'',b'opaque\0\xff'):
                    for flags in (0,1,3):
                        data=request(order,b'k'*size,contexts=((1,b'abc'),(9,b''),(42,b'private')),args=args,flags=flags)
                        for hint in (None,'giop'):
                            e=inspect(data,hint)
                            self.assertEqual(e.observation.status,'identified',(order,size,args,e.observation))
                            self.assertEqual(e.observation.application_protocol,'giop/1.2')
                            self.assertEqual(e.observation.scope,'request_header')
                            self.assertNotIn('private',repr(asdict(e.observation)))
                            self.assertIsNone(e.observation.application)
                            self.assertIsNone(e.observation.hostname)
                e=inspect(locate(order,b'k'*size))
                self.assertEqual(e.observation.status,'identified')
                self.assertEqual(e.observation.scope,'locate_request')

    def test_every_cut_bytewise_and_complete_frame_consumption(self):
        for data in (GIOP,locate('<'),request(),request('<',contexts=((123,b'abc'),),args=b'args')):
            expected=inspect(data).observation
            for cut in range(len(data)+1):
                e=Inspector();e.feed(data[:cut]);e.feed(data[cut:]+b'next frame ignored')
                self.assertEqual(e.observation,expected,cut)
                self.assertEqual(e.metrics.bytes_inspected,len(data))
                self.assertEqual(e.metrics.candidates_selected,1)
            e=Inspector()
            for b in data:e.feed(bytes([b]))
            self.assertEqual(e.observation,expected)
            for cut in range(len(data)):
                e=inspect(data[:cut]);e.end()
                self.assertNotEqual(e.observation.status,'identified',cut)

    def test_http_extension_methods_and_short_prefix_wait(self):
        for method in (b'G',b'GI',b'GIO',b'GIOP',b'GIOP1',b'GET'):
            data=method+b' / HTTP/1.1\r\nHost: example.com\r\n\r\n'
            for cut in range(len(data)+1):
                e=Inspector();e.feed(data[:cut]);e.feed(data[cut:])
                self.assertEqual(e.observation.application_protocol,'http/1.1',(method,cut))
        for n in range(1,5):self.assertIsNone(select(GIOP[:n]))
        self.assertEqual(select(GIOP[:5]),'giop')
        self.assertEqual(LOOKAHEAD,24)

    def test_hints_do_not_skip_validation(self):
        for data,protocol in STREAM_CASES:
            if protocol!='giop/1.2':self.assertNotEqual(inspect(data,'giop').observation.status,'identified',protocol)

    def test_unsupported_versions_flags_types_and_target(self):
        cases=[]
        for offset,values in ((4,(0,2)),(5,(0,1,3,255)),(6,(2,3,4,128)),(7,(1,2,4,5,6,7,255))):
            for value in values:
                data=bytearray(GIOP);data[offset]=value;cases.append(bytes(data))
        data=bytearray(GIOP);data[17]=1;cases.append(bytes(data))
        for flags in (2,4,255):cases.append(request(flags=flags))
        data=bytearray(request());data[17]=1;cases.append(bytes(data))
        for data in cases:self.assertNotEqual(inspect(data,'giop').observation.status,'identified',data)

    def test_bad_inner_lengths_strings_and_trailing_locate_bytes(self):
        cases=[]
        data=bytearray(GIOP);data[20:24]=struct.pack('>I',5);cases.append(bytes(data))
        cases.append(frame(GIOP[12:]+b'x',kind=3))
        for op in (b'',b'bad name',b'bad\0name',b'\xff',b'1operation'):
            cases.append(request(operation=op))
        data=bytearray(request(key=b''));data[28:32]=bytes(4);cases.append(bytes(data))
        data=bytearray(request());data[-4:]=struct.pack('>I',1);cases.append(bytes(data))
        for data in cases:self.assertNotEqual(inspect(data,'giop').observation.status,'identified',data)

    def test_empty_request_has_no_padding_and_nonempty_body_is_aligned(self):
        data=request(key=b'',operation=b'abcd')
        self.assertEqual(len(data)%8,4)
        self.assertEqual(inspect(data).observation.status,'identified')
        for n in (1,2,3,4):
            self.assertEqual(inspect(frame(data[12:]+bytes(n))).observation.status,'malformed',n)
        self.assertEqual(inspect(frame(data[12:]+b'\xff'*4+b'x')).observation.status,'identified')

    def test_bounds_stop_at_header_or_field_and_release_parser(self):
        data=bytearray(GIOP);data[8:12]=bytes.fromhex('ffffffff')
        e=inspect(bytes(data[:12]))
        self.assertEqual(e.observation.status,'budget_exhausted')
        self.assertEqual(e.metrics.bytes_inspected,12)
        for data,config in ((request(key=b'x'*33),Config(max_line=32)),
                            (request(operation=b'x'*33),Config(max_line=32)),
                            (request(contexts=((1,b''),(2,b''))),Config(max_headers=1)),
                            (request(args=b'x'*100),Config(max_bytes=64))):
            e=inspect(data,config=config)
            self.assertEqual(e.observation.status,'budget_exhausted')
            self.assertIsNone(e._parser)
        data=bytearray(request());data[-4:]=struct.pack('>I',0xffffffff)
        self.assertEqual(inspect(bytes(data)).observation.status,'budget_exhausted')

    def test_mutated_framing_and_fragmentation_are_equivalent(self):
        rng=random.Random(17017)
        seeds=(GIOP,request(),request('<',contexts=((7,b'demo'),),args=b'opaque'))
        for _ in range(1800):
            data=bytearray(rng.choice(seeds))
            for _ in range(rng.randrange(1,4)):data[rng.randrange(len(data))]=rng.randrange(256)
            data=bytes(data);whole=inspect(data);split=Inspector();pos=0
            while pos<len(data):
                n=rng.randrange(1,13);split.feed(data[pos:pos+n]);pos+=n
            whole.end();split.end()
            self.assertEqual(whole.observation,split.observation,data)
            self.assertLessEqual(split.metrics.candidates_selected,1)
