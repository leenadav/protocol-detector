"""Data infrastructure handshakes: Kafka requests, Cassandra CQL STARTUP/OPTIONS, RTP (hint only)."""
import struct
from .framing import FrameParser
from .parsers import BudgetError, ParseError
from .extended import UnsupportedPrefix

_KAFKA_FIRST = {18: 4, 3: 12, 0: 10, 1: 16, 17: 1, 36: 2, 32: 4}  # api key -> highest version in this profile


def kafka_probe(prefix):
    """Eight-byte request header start: non-negative size >= 10, known api key, version within range."""
    if len(prefix) < 8 or prefix[0] & 0x80:
        return False
    key, version = struct.unpack("!hh", prefix[4:8])
    return key in _KAFKA_FIRST and 0 <= version <= _KAFKA_FIRST[key] and int.from_bytes(prefix[:4], "big") >= 10


class KafkaParser(FrameParser):
    """Kafka request header v1/v2: size, api key, version, correlation id, nullable client id."""
    header_size = 10
    protocol_name = "kafka"
    scope = "request_header"

    def frame_size(self, header):
        if not kafka_probe(header):
            raise ParseError("Kafka request header outside first-request profile")
        size = int.from_bytes(header[:4], "big")
        if size > 65536:
            raise BudgetError("Kafka request exceeds profile size")
        return 4 + size

    def validate(self, data):
        key, version = struct.unpack("!hh", data[4:8])
        client_length = struct.unpack("!h", data[12:14])[0]
        pos = 14
        if client_length < -1 or client_length > 256:
            raise ParseError("Kafka client id length outside profile")
        if client_length > 0:
            client = data[pos:pos + client_length]
            if len(client) != client_length or any(byte < 32 or byte > 126 for byte in client):
                raise ParseError("Kafka client id must be printable ASCII")
            pos += client_length
        if key == 18 and version >= 3:
            if pos >= len(data) or data[pos] != 0:
                raise ParseError("Kafka ApiVersions v3 requires empty header tagged fields")
            pos += 1
            name_length = data[pos] - 1 if pos < len(data) else -1
            if name_length < 1 or pos + 1 + name_length > len(data):
                raise ParseError("Kafka ApiVersions client software name invalid")
        self.extra_evidence = (("kafka_api_key", str(key), "request_header", "structural"),)
        self.reason = "Kafka request header validated; topics, records and authentication not decoded"


class CQLParser(FrameParser):
    """Cassandra native protocol v4 request frame: STARTUP or OPTIONS."""
    header_size = 9
    protocol_name = "cql/4"
    scope = "protocol_header"

    def frame_size(self, header):
        if header[0] != 0x04:
            raise UnsupportedPrefix("CQL profile covers protocol version 4 requests")
        if header[1] & 0xf0:
            raise ParseError("CQL flags reserved bits set")
        if header[4] not in (0x01, 0x05):
            raise UnsupportedPrefix("CQL profile covers STARTUP and OPTIONS requests")
        size = int.from_bytes(header[5:9], "big")
        if header[4] == 0x05 and size:
            raise ParseError("CQL OPTIONS carries no body")
        if header[4] == 0x01 and not 2 <= size <= 4096:
            raise ParseError("CQL STARTUP body length outside profile")
        return 9 + size

    def validate(self, data):
        if data[4] == 0x01:
            count = int.from_bytes(data[9:11], "big")
            if not 1 <= count <= 16:
                raise ParseError("CQL STARTUP string map count outside profile")
            pos = 11
            keys = set()
            for _ in range(count):
                for _ in range(2):
                    if pos + 2 > len(data):
                        raise ParseError("Truncated CQL string map")
                    size = int.from_bytes(data[pos:pos + 2], "big")
                    value = data[pos + 2:pos + 2 + size]
                    if len(value) != size or any(byte < 32 or byte > 126 for byte in value):
                        raise ParseError("CQL string map entry outside printable ASCII")
                    pos += 2 + size
                    if len(keys) < 32:
                        keys.add(value.upper())
            if pos != len(data):
                raise ParseError("Trailing bytes after CQL STARTUP map")
            if b"CQL_VERSION" not in keys:
                raise ParseError("CQL STARTUP requires CQL_VERSION")
        self.reason = "Cassandra native protocol v4 request validated; authentication and queries unverified"


def rtp(data, config):
    """RTP header (RFC 3550) with a candidate hint only; the fixed header is too weak for automatic selection."""
    if len(data) < 12:
        raise ParseError("RTP header shorter than 12 bytes")
    if data[0] >> 6 != 2:
        raise UnsupportedPrefix("RTP profile requires version 2")
    csrc = data[0] & 15
    payload_type = data[1] & 127
    if 72 <= payload_type <= 76:
        raise UnsupportedPrefix("Payload type collides with RTCP packet types")
    pos = 12 + 4 * csrc
    if pos > len(data):
        raise ParseError("RTP CSRC list exceeds datagram")
    if data[0] & 0x10:
        if pos + 4 > len(data):
            raise ParseError("Truncated RTP header extension")
        pos += 4 + 4 * int.from_bytes(data[pos + 2:pos + 4], "big")
        if pos > len(data):
            raise ParseError("RTP header extension exceeds datagram")
    if data[0] & 0x20:
        if pos >= len(data) or data[-1] == 0 or data[-1] > len(data) - pos:
            raise ParseError("RTP padding count invalid")
    return "rtp", "RTP fixed header, CSRC and extension framing validated with a candidate hint; media not decoded"
