"""Independent bind builders, bounded context validation and SOCKS dispatch."""
import gc
import random
import struct
import unittest
import weakref
from dataclasses import asdict
from uuid import UUID
from protocol_engine import Inspector, Config
from protocol_engine.dispatch import select, LOOKAHEAD
from protocol_demo import SOCKS5
from protocol_fixtures import DCERPC, STREAM_CASES

NDR = '8a885d04-1ceb-11c9-9fe8-08002b104860'
NDR64 = '71710533-beba-4937-8319-b5dbef9ccc36'
INTERFACE = '12345678-1234-4321-abcd-112233445566'


def syntax(order, name, version):
    identifier=UUID(name)
    return (identifier.bytes_le if order=='<' else identifier.bytes)+struct.pack(order+'I',version)


def bind(order='<',contexts=None, flags=3, limits=(4280,4280), group=0):
    if contexts is None:contexts=((0,((NDR,2),)),)
    body=bytearray(struct.pack(order+'HHIB3x',limits[0],limits[1],group,len(contexts)))
    for context_id,offers in contexts:
        body.extend(struct.pack(order+'HBB',context_id,len(offers),0))
        body.extend(syntax(order,INTERFACE,0x00020001))
        for name,version in offers:body.extend(syntax(order,name,version))
    return bytes([5,0,11,flags,16 if order=='<' else 0,0,0,0])+struct.pack(order+'HHI',16+len(body),0,123)+body


def inspect(data,hint=None,config=None):
    e=Inspector(config=config,protocol_hint=hint);e.feed(data);return e


class DCERPCTests(unittest.TestCase):
    def test_endian_multiple_contexts_and_offers(self):
        for order in ('<','>'):
            for contexts in (((0,((NDR,2),)),),((13,((NDR64,1),)),),
                             ((0,((NDR,2),(NDR64,1))),(1,((NDR,2),)))):
                for flags in (3,7,19,23):
                    data=bind(order,contexts,flags)
                    for hint in (None,'dcerpc'):
                        e=inspect(data,hint)
                        self.assertEqual(e.observation.status,'identified',e.observation)
                        self.assertEqual(e.observation.application_protocol,'dcerpc/5.0')
                        self.assertEqual(e.observation.scope,'bind_request')
                        self.assertTrue(all(x.strength=='offered' for x in e.observation.evidence if x.field=='offered_transfer_syntax'))
                        self.assertIsNone(e.observation.hostname)
                        self.assertIsNone(e.observation.application)
                        self.assertNotIn(INTERFACE,repr(asdict(e.observation)))

    def test_all_cuts_bytewise_and_trailing_frame_consumption(self):
        for data in (DCERPC,bind('>'),bind(contexts=((1,((NDR,2),(NDR64,1))),(2,((NDR,2),))))):
            expected=inspect(data).observation
            for cut in range(len(data)+1):
                e=Inspector();e.feed(data[:cut]);e.feed(data[cut:]+b'uninspected trailing stub')
                self.assertEqual(e.observation,expected,cut)
                self.assertEqual(e.metrics.bytes_inspected,len(data))
                self.assertEqual(e.metrics.candidates_selected,1)
            e=Inspector()
            for b in data:e.feed(bytes([b]))
            self.assertEqual(e.observation,expected)
            for n in range(len(data)):
                e=inspect(data[:n]);e.end();self.assertNotEqual(e.observation.status,'identified',n)

    def test_socks_compatibility_and_two_byte_discriminator(self):
        self.assertIsNone(select(b'\x05'))
        self.assertIsNone(select(b'\x05\x00'))  # DCE/RPC minor zero or a SOCKS5 server selecting no-auth (v0.41)
        self.assertEqual(select(b'\x05\x00\x0b\x03\x10\x00'),'dcerpc')
        for count in range(1,256):
            if count==0x64:continue  # 05 64 is the DNP3 data-link start since v0.27
            self.assertEqual(select(bytes([5,count])),'socks5')
        self.assertEqual(select(b'\x05\x64'),'dnp3')
        for cut in range(len(SOCKS5)+1):
            e=Inspector();e.feed(SOCKS5[:cut]);e.feed(SOCKS5[cut:]);self.assertEqual(e.observation.application_protocol,'socks5')
        e=inspect(b'\x05\x00');self.assertEqual(e.observation.status,'detecting');e.end()
        self.assertEqual(e.observation.status,'incomplete')
        self.assertEqual(inspect(b'\x05\x00','socks5').observation.status,'detecting')  # server selection awaits its reply
        self.assertNotEqual(inspect(DCERPC,'socks5').observation.status,'identified')
        self.assertEqual(LOOKAHEAD,24)

    def test_hints_only_select_and_do_not_establish_identity(self):
        for data,protocol in STREAM_CASES:
            if protocol!='dcerpc/5.0':self.assertNotEqual(inspect(data,'dcerpc').observation.status,'identified',protocol)

    def test_unsupported_headers_flags_auth_and_representations(self):
        for offset,values in ((0,(4,6)),(1,(1,255)),(2,(0,1,12,14)),(3,(0,1,2,8,35,67,131)),
                              (4,(1,17,32)),(5,(1,255)),(6,(1,)),(7,(1,)),(10,(1,))):
            for value in values:
                data=bytearray(DCERPC);data[offset]=value
                self.assertNotEqual(inspect(bytes(data),'dcerpc').observation.status,'identified',(offset,value))

    def test_context_and_transfer_lengths_reserved_and_duplicates(self):
        cases=[]
        for offset,value in ((24,0),(24,2),(25,1),(26,1),(27,1),(30,0),(30,2),(31,1)):
            data=bytearray(DCERPC);data[offset]=value;cases.append(bytes(data))
        cases.append(bind(contexts=((3,((NDR,2),)),(3,((NDR64,1),)))))
        cases.append(bind(contexts=((0,((NDR,2),(NDR,2))),)))
        data=bytearray(DCERPC);data[32:48]=bytes(16);cases.append(bytes(data))
        data=bytearray(DCERPC+b'junk');data[8:10]=struct.pack('<H',len(data));cases.append(bytes(data))
        for data in cases:self.assertNotEqual(inspect(data).observation.status,'identified',data)

    def test_exact_standard_transfer_ids_and_versions(self):
        for offers in (((NDR,1),),((NDR,0x10002),),((NDR64,2),),((INTERFACE,2),),((NDR,2),(NDR64,1),(NDR,2))):
            self.assertNotEqual(inspect(bind(contexts=((0,offers),))).observation.status,'identified',offers)
        # Association group, call ID and interface version are opaque; zero
        # fragment-size offers retain C706's explicitly defined default encoding.
        self.assertEqual(inspect(bind(limits=(0,0),group=0xffffffff)).observation.status,'identified')

    def test_frame_size_and_count_budgets(self):
        for size in (0,16,28,71):
            data=bytearray(DCERPC);data[8:10]=struct.pack('<H',size)
            self.assertEqual(inspect(bytes(data)).observation.status,'malformed')
        data=bytearray(DCERPC[:16]);data[8:10]=struct.pack('<H',65535)
        e=inspect(bytes(data),config=Config(max_bytes=64))
        self.assertEqual(e.observation.status,'budget_exhausted');self.assertEqual(e.metrics.bytes_inspected,16)
        data=bind(contexts=((0,((NDR,2),)),(1,((NDR,2),))))
        e=inspect(data,config=Config(max_headers=1))
        self.assertEqual(e.observation.status,'budget_exhausted');self.assertIsNone(e._parser)
        data=bind(contexts=tuple((i,((NDR,2),)) for i in range(129)))
        self.assertEqual(inspect(data,config=Config(max_headers=4096)).observation.status,'budget_exhausted')

    def test_mutations_fragmentation_and_terminal_buffer_release(self):
        rng=random.Random(18018)
        for _ in range(1600):
            data=bytearray(rng.choice((DCERPC,bind('>'),bind(contexts=((7,((NDR,2),(NDR64,1))),)))))
            for _ in range(rng.randrange(1,4)):data[rng.randrange(len(data))]=rng.randrange(256)
            data=bytes(data);whole=inspect(data);split=Inspector();pos=0
            while pos<len(data):
                n=rng.randrange(1,20);split.feed(data[pos:pos+n]);pos+=n
            whole.end();split.end();self.assertEqual(whole.observation,split.observation,data)
            self.assertLessEqual(split.metrics.candidates_selected,1)
        enabled=gc.isenabled();gc.disable()
        try:
            e=inspect(DCERPC[:-1]);ref=weakref.ref(e._parser);e.feed(DCERPC[-1:])
            self.assertIsNone(ref());calls=e.metrics.parser_calls;e.feed(bytes(65536));self.assertEqual(e.metrics.parser_calls,calls)
        finally:
            if enabled:gc.enable()
