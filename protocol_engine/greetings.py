"""Fixed-size binary greetings: ZeroMQ ZMTP 3.x and the Neo4j Bolt handshake.

Both are complete, self-delimiting opening messages whose every byte is
constrained; nothing beyond them (frames, authentication, queries) is read.
"""
from .extended import UnsupportedPrefix
from .framing import FrameParser
from .parsers import ParseError

ZMTP_MECHANISMS = {b"NULL": "null", b"PLAIN": "plain", b"CURVE": "curve", b"GSSAPI": "gssapi"}
_MECHANISM_BYTES = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
BOLT_MAGIC = b"\x60\x60\xb0\x17"
BOLT_HANDSHAKE = 20
_BOLT_MAX_MINOR = {1: 0, 2: 0, 3: 0, 4: 4, 5: 15}   # protocol versions Neo4j has published


def _bolt_version_ok(major, minor):
    return major in _BOLT_MAX_MINOR and minor <= _BOLT_MAX_MINOR[major]


class ZMTPParser(FrameParser):
    """ZMTP 3.0/3.1 greeting (64 bytes): signature, version, mechanism, as-server flag, zero filler."""
    header_size = 64
    protocol_name = "zmtp/3"

    def frame_size(self, data):
        if data[0] != 0xff or data[9] != 0x7f:
            raise UnsupportedPrefix("ZMTP signature expected")
        if data[10] != 3 or data[11] > 1:
            raise UnsupportedPrefix("Only ZMTP 3.0 and 3.1 greetings are supported")
        return 64

    def validate(self, data):
        mechanism = data[12:32]
        end = mechanism.find(b"\x00")
        name = mechanism if end < 0 else mechanism[:end]
        if not name or any(byte not in _MECHANISM_BYTES for byte in name) or (end >= 0 and any(mechanism[end:])):
            raise ParseError("ZMTP mechanism must be an upper-case name padded with zero bytes")
        if data[32] > 1 or any(data[33:64]):
            raise ParseError("ZMTP as-server flag or filler outside the specification")
        self.extra_evidence = (("zmtp_mechanism", ZMTP_MECHANISMS.get(name, "other"), "greeting", "structural"),
                               ("zmtp_role", "server" if data[32] else "client", "greeting", "structural"))
        self.reason = "ZMTP 3.x greeting validated; handshake commands and frames not inspected"


class BoltParser(FrameParser):
    """Client handshake: magic plus four version ranges. The four-byte server choice only with the bolt hint."""
    header_size = 4
    protocol_name = "bolt"

    def frame_size(self, data):
        if data == BOLT_MAGIC:
            self.handshake = True
            return BOLT_HANDSHAKE
        if data[:2] != b"\x00\x00":
            raise UnsupportedPrefix("Bolt magic or version response expected")
        self.handshake = False
        return 4

    def validate(self, data):
        if self.handshake:
            versions, ended = [], False
            for offset in range(4, BOLT_HANDSHAKE, 4):
                reserved, span, minor, major = data[offset:offset + 4]
                if reserved or span > minor or (major and not _bolt_version_ok(major, minor)):
                    raise ParseError("Bolt version range outside the published versions")
                if not major:
                    if minor or span:
                        raise ParseError("Bolt version zero must be all zero")
                    ended = True
                    continue
                if ended:
                    raise ParseError("Bolt version after an empty slot")
                versions.append((major, minor))
            if not versions:
                raise ParseError("Bolt handshake without a version proposal")
            major, minor = versions[0]
            self.extra_evidence = (("bolt_message", "handshake", "handshake", "structural"),
                                   ("bolt_version", "{}.{}".format(major, minor), "handshake", "offered"))
            self.reason = "Bolt handshake magic and version proposals validated; messages not inspected"
            return
        minor, major = data[2], data[3]
        if (major or minor) and not _bolt_version_ok(major, minor):
            raise ParseError("Bolt selected version outside the published versions")
        self.extra_evidence = (("bolt_message", "version-response", "handshake", "structural"),
                               ("bolt_version", "{}.{}".format(major, minor) if major else "none", "handshake", "asserted"))
        self.scope = "negotiation_response"
        self.reason = "Bolt version response validated with caller hint; four bytes alone never select this family"
