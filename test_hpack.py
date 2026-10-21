"""HPACK decoder: RFC 7541 Appendix C vectors, integer and Huffman edge cases, table and budget bounds."""
import unittest

from protocol_engine.hpack import (DEFAULT_TABLE_SIZE, HUFFMAN_CODES, STATIC_TABLE, Decoder, decode_integer,
                                   huffman_decode)
from protocol_engine.parsers import BudgetError, ParseError
from protocol_fixtures import hpack_integer, hpack_literal

REQUESTS = (  # RFC 7541 C.3 (raw) and C.4 (Huffman): three requests on one connection
    ("828684410f7777772e6578616d706c652e636f6d", "828684418cf1e3c2e5f23a6ba0ab90f4ff",
     [(b":method", b"GET"), (b":scheme", b"http"), (b":path", b"/"), (b":authority", b"www.example.com")], 57),
    ("828684be58086e6f2d6361636865", "828684be5886a8eb10649cbf",
     [(b":method", b"GET"), (b":scheme", b"http"), (b":path", b"/"), (b":authority", b"www.example.com"), (b"cache-control", b"no-cache")], 110),
    ("828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565", "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf",
     [(b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/index.html"), (b":authority", b"www.example.com"), (b"custom-key", b"custom-value")], 164),
)
RESPONSES = (  # RFC 7541 C.5 (raw) and C.6 (Huffman) with a 256-byte dynamic table
    ("4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d",
     "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
     [(b":status", b"302"), (b"cache-control", b"private"), (b"date", b"Mon, 21 Oct 2013 20:13:21 GMT"), (b"location", b"https://www.example.com")], 222),
    ("4803333037c1c0bf", "4883640effc1c0bf",
     [(b":status", b"307"), (b"cache-control", b"private"), (b"date", b"Mon, 21 Oct 2013 20:13:21 GMT"), (b"location", b"https://www.example.com")], 222),
    ("88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31",
     "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
     [(b":status", b"200"), (b"cache-control", b"private"), (b"date", b"Mon, 21 Oct 2013 20:13:22 GMT"), (b"location", b"https://www.example.com"),
      (b"content-encoding", b"gzip"), (b"set-cookie", b"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1")], 215),
)


def huffman_encode(data):
    bits = "".join(format(HUFFMAN_CODES[b][0], "0{}b".format(HUFFMAN_CODES[b][1])) for b in data)
    bits += "1" * (-len(bits) % 8)
    return int(bits, 2).to_bytes(len(bits) // 8, "big") if bits else b""


class TableTests(unittest.TestCase):
    def test_static_table_matches_appendix_a(self):
        self.assertEqual(len(STATIC_TABLE), 61)
        self.assertEqual(STATIC_TABLE[0], (b":authority", b""))
        self.assertEqual(STATIC_TABLE[1], (b":method", b"GET"))
        self.assertEqual(STATIC_TABLE[7], (b":status", b"200"))
        self.assertEqual(STATIC_TABLE[30], (b"content-type", b""))
        self.assertEqual(STATIC_TABLE[60], (b"www-authenticate", b""))

    def test_huffman_code_is_complete_and_prefix_free(self):
        self.assertEqual(len(HUFFMAN_CODES), 257)
        self.assertEqual(sum(2 ** (30 - length) for _, length in HUFFMAN_CODES), 2 ** 30)   # Kraft equality
        self.assertEqual(HUFFMAN_CODES[256], (0x3fffffff, 30))
        self.assertEqual(HUFFMAN_CODES[ord("a")], (0x3, 5))
        for code, length in HUFFMAN_CODES:
            self.assertLess(code, 1 << length)


class PrimitiveTests(unittest.TestCase):
    def test_integers_from_appendix_c1(self):
        self.assertEqual(decode_integer(b"\x0a", 0, 5), (10, 1))
        self.assertEqual(decode_integer(b"\x1f\x9a\x0a", 0, 5), (1337, 3))
        self.assertEqual(decode_integer(b"\x2a", 0, 8), (42, 1))
        self.assertEqual(decode_integer(b"\xff\x00", 0, 7), (127, 2))
        for value in (0, 1, 30, 31, 32, 127, 128, 16383, 16384, 2 ** 21 - 1, 2 ** 28 - 1):
            self.assertEqual(decode_integer(hpack_integer(value, 5), 0, 5), (value, len(hpack_integer(value, 5))), value)

    def test_integer_truncation_and_limit(self):
        with self.assertRaises(ParseError):
            decode_integer(b"\x1f", 0, 5)
        with self.assertRaises(ParseError):
            decode_integer(b"\x1f\x80\x80", 0, 5)
        with self.assertRaises(ParseError):
            decode_integer(b"\x1f\x80\x80\x80\x80\x01", 0, 5)      # five continuation bytes
        self.assertEqual(decode_integer(b"\x1f\x80\x80\x80\x01", 0, 5)[0], 31 + 2 ** 21)

    def test_huffman_round_trip_and_padding_rules(self):
        for text in (b"", b"a", b"www.example.com", b"no-cache", b"custom-key", bytes(range(256)), b"\xff" * 40):
            self.assertEqual(huffman_decode(huffman_encode(text)), text, text)
        self.assertEqual(huffman_decode(bytes.fromhex("f1e3c2e5f23a6ba0ab90f4ff")), b"www.example.com")
        for bad in (b"\x00", b"\x3f\xff\xff\xff", bytes.fromhex("f1e3c2e5f23a6ba0ab90f4fe"), huffman_encode(b"a") + b"\xff"):
            with self.assertRaises(ParseError, msg=bad):
                huffman_decode(bad)
        with self.assertRaises(ParseError):   # EOS inside the string
            huffman_decode(bytes.fromhex("ffffffff"))


class DecoderTests(unittest.TestCase):
    def decode_series(self, vectors, column, size=DEFAULT_TABLE_SIZE):
        decoder = Decoder(max_table_size=size)
        for vector in vectors:
            self.assertEqual(decoder.decode(bytes.fromhex(vector[column])), vector[2], vector[column])
            self.assertEqual(decoder.used, vector[3])
        return decoder

    def test_appendix_c_requests_and_responses(self):
        self.decode_series(REQUESTS, 0)
        self.decode_series(REQUESTS, 1)
        self.decode_series(RESPONSES, 0, 256)
        decoder = self.decode_series(RESPONSES, 1, 256)
        self.assertEqual(len(decoder.table), 3)

    def test_appendix_c2_literals(self):
        decoder = Decoder()
        self.assertEqual(decoder.decode(bytes.fromhex("400a637573746f6d2d6b65790d637573746f6d2d686561646572")), [(b"custom-key", b"custom-header")])
        self.assertEqual(decoder.used, 55)
        self.assertEqual(decoder.decode(bytes.fromhex("040c2f73616d706c652f70617468")), [(b":path", b"/sample/path")])
        self.assertEqual(decoder.decode(bytes.fromhex("100870617373776f726406736563726574")), [(b"password", b"secret")])
        self.assertEqual(decoder.used, 55)      # never-indexed and non-indexed literals leave the table alone
        self.assertEqual(decoder.decode(bytes.fromhex("82")), [(b":method", b"GET")])
        self.assertEqual(decoder.decode(bytes.fromhex("be")), [(b"custom-key", b"custom-header")])

    def test_index_errors(self):
        for block in (b"\x80", b"\xbe", b"\xff\x00", b"\x40", b"\x41", b"\x0f\x2f\x05a", b"\x7f\x01\x00", b"\x00\x00\x00"):
            with self.assertRaises(ParseError, msg=block):
                Decoder().decode(block)

    def test_dynamic_table_eviction_and_size_updates(self):
        decoder = Decoder(max_table_size=100)
        decoder.decode(hpack_literal(b"aaaa", b"bbbb").replace(b"\x00", b"\x40", 1))    # 40 bytes
        decoder.decode(hpack_literal(b"cccc", b"dddd").replace(b"\x00", b"\x40", 1))    # 80 bytes
        self.assertEqual([name for name, _ in decoder.table], [b"cccc", b"aaaa"])
        decoder.decode(hpack_literal(b"eeee", b"ffff").replace(b"\x00", b"\x40", 1))    # evicts aaaa
        self.assertEqual([name for name, _ in decoder.table], [b"eeee", b"cccc"])
        self.assertEqual(decoder.decode(b"\xbe"), [(b"eeee", b"ffff")])
        self.assertEqual(decoder.decode(b"\xbf"), [(b"cccc", b"dddd")])
        decoder.decode(b"\x40\x05wwwww" + b"\x7f\x01" + b"x" * 128)                      # larger than the table: clears it
        self.assertEqual((len(decoder.table), decoder.used), (0, 0))
        decoder.decode(hpack_literal(b"aaaa", b"bbbb").replace(b"\x00", b"\x40", 1))
        decoder.decode(b"\x20\x82")                                                     # size update to 0 then indexed field
        self.assertEqual((len(decoder.table), decoder.table_size), (0, 0))
        decoder.decode(b"\x3f\x45")                                                     # back to 100
        self.assertEqual(decoder.table_size, 100)
        with self.assertRaises(ParseError):
            decoder.decode(b"\x3f\x46")                                                 # 101 > acknowledged maximum
        with self.assertRaises(ParseError):
            decoder.decode(b"\x82\x20")                                                 # update after a field
        with self.assertRaises(ParseError):
            decoder.decode(b"\x20\x20\x20")                                             # three updates

    def test_budgets(self):
        decoder = Decoder(max_fields=2)
        with self.assertRaises(BudgetError):
            decoder.decode(b"\x82\x86\x84")
        decoder = Decoder(max_string=4)
        with self.assertRaises(BudgetError):
            decoder.decode(hpack_literal(b"abcde", b"x"))
        self.assertEqual(Decoder(max_string=4).decode(hpack_literal(b"abcd", b"x")), [(b"abcd", b"x")])
        decoder = Decoder(max_list_size=100)
        with self.assertRaises(BudgetError):
            decoder.decode(hpack_literal(b"name", b"x" * 65))
        with self.assertRaises(ParseError):
            Decoder().decode(hpack_literal(b"", b"x"))
        with self.assertRaises(ParseError):
            Decoder().decode(b"\x00\x05abc")                                            # truncated string
        with self.assertRaises(ParseError):
            Decoder().decode(b"\x00\x85" + huffman_encode(b"ab"))                        # truncated Huffman string

    def test_decoder_never_grows_past_its_maximum(self):
        decoder = Decoder(max_table_size=4096)
        for i in range(400):
            decoder.decode(b"\x40\x08" + ("name{:04d}".format(i)).encode() + b"\x20" + b"v" * 32)
        self.assertLessEqual(decoder.used, 4096)
        self.assertLessEqual(len(decoder.table), 4096 // 72)


if __name__ == "__main__":
    unittest.main()
