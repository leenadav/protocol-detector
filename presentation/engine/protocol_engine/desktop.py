"""Remote desktop greetings: X11 connection setup and the SPICE link header.

X11: the client's setup request (byte order, protocol 11.0, authorization
protocol name and data lengths) is automatic; the server's setup reply is
accepted only with the `x11-server` hint because its first byte is 0, 1 or 2.
SPICE: the 16-byte link header in both directions, followed by the client
SpiceLinkMess or the server SpiceLinkReply with their capability counts. Cookie
data, vendor strings and the server public key are never emitted.
"""
from .extended import UnsupportedPrefix
from .framing import FrameParser
from .parsers import ParseError

X11_MAJOR = 11
MAX_AUTH_NAME = 64
MAX_AUTH_DATA = 1024
_AUTH_NAMES = {b"MIT-MAGIC-COOKIE-1": "mit-magic-cookie-1", b"XDM-AUTHORIZATION-1": "xdm-authorization-1", b"SUN-DES-1": "sun-des-1",
               b"MIT-KERBEROS-5": "mit-kerberos-5"}
SPICE_MAGIC = b"REDQ"
SPICE_CHANNELS = {1: "main", 2: "display", 3: "inputs", 4: "cursor", 5: "playback", 6: "record", 7: "tunnel", 8: "smartcard",
                  9: "usbredir", 10: "port", 11: "webdav"}
SPICE_LINK_ERRORS = ("ok", "error", "invalid-magic", "invalid-data", "version-mismatch", "need-secured", "need-unsecured",
                     "permission-denied", "bad-connection-id", "channel-not-available")
SPICE_PUBLIC_KEY = 162
MAX_SPICE_CAPS = 32


def _pad4(value):
    return (value + 3) & ~3


class X11Parser(FrameParser):
    """Client connection setup (X Window System Protocol, chapter 8)."""
    header_size = 12
    protocol_name = "x11"

    def frame_size(self, data):
        if data[0] == 0x42:
            self.order = "big"
        elif data[0] == 0x6c:
            self.order = "little"
        else:
            raise UnsupportedPrefix("X11 setup requires the byte-order byte B or l")
        if data[1]:
            raise ParseError("X11 setup unused byte must be zero")
        major = int.from_bytes(data[2:4], self.order)
        minor = int.from_bytes(data[4:6], self.order)
        if major != X11_MAJOR or minor:
            raise UnsupportedPrefix("Only X11 protocol 11.0 is supported")
        name_length = int.from_bytes(data[6:8], self.order)
        data_length = int.from_bytes(data[8:10], self.order)
        if name_length > MAX_AUTH_NAME or data_length > MAX_AUTH_DATA:
            raise ParseError("X11 authorization lengths outside the profile")
        if not name_length and data_length:
            raise ParseError("X11 authorization data without a protocol name")
        self.lengths = (name_length, data_length)
        return 12 + _pad4(name_length) + _pad4(data_length)

    def validate(self, data):
        name_length, data_length = self.lengths
        name = data[12:12 + name_length]
        if any(not 0x20 <= byte < 0x7f for byte in name):
            raise ParseError("X11 authorization protocol name must be printable")
        label = _AUTH_NAMES.get(name, "other") if name_length else "none"
        self.extra_evidence = (("x11_message", "setup-request", "setup", "structural"),
                               ("x11_byte_order", "msb" if self.order == "big" else "lsb", "setup", "structural"),
                               ("x11_authorization", label, "setup", "asserted"))
        self.reason = "X11 connection setup request validated; authorization data not emitted, requests not inspected"


class X11ReplyParser(FrameParser):
    """Server setup reply (Failed, Success or Authenticate); hint only, since the first byte is 0, 1 or 2."""
    header_size = 8
    protocol_name = "x11"
    scope = "negotiation_response"

    def frame_size(self, data):
        if data[0] > 2:
            raise UnsupportedPrefix("X11 setup reply status must be 0, 1 or 2")
        if data[2:4] == b"\x00\x0b":
            self.order = "big"
        elif data[2:4] == b"\x0b\x00":
            self.order = "little"
        else:
            raise UnsupportedPrefix("X11 setup reply requires protocol major 11")
        if int.from_bytes(data[4:6], self.order):
            raise UnsupportedPrefix("Only X11 protocol 11.0 is supported")
        self.status = data[0]
        words = int.from_bytes(data[6:8], self.order)
        if self.status == 1 and words < 8:
            raise ParseError("X11 setup success reply too short for its fixed fields")
        if self.status != 1 and (self.status == 0 and words < (data[1] + 3) // 4):
            raise ParseError("X11 setup failure reason exceeds the reply")
        if self.status == 2 and data[1]:
            raise ParseError("X11 authenticate reply unused byte must be zero")
        return 8 + 4 * words

    def validate(self, data):
        if self.status == 1:
            order = self.order
            vendor_length = int.from_bytes(data[24:26], order)
            roots, formats = data[28], data[29]
            if data[30] > 1 or data[31] > 1 or data[32] not in (8, 16, 32) or data[33] not in (8, 16, 32):
                raise ParseError("X11 setup image byte order, bit order or scanline fields outside the specification")
            if data[34] < 8 or data[35] < data[34]:
                raise ParseError("X11 keycode range outside the specification")
            if not roots or not formats or 40 + _pad4(vendor_length) + 8 * formats + 40 * roots > len(data):
                raise ParseError("X11 setup vendor, format and screen sizes exceed the reply")
            label = "setup-success"
        else:
            reason = data[8:8 + data[1]] if self.status == 0 else data[8:]
            if any(not 0x20 <= byte < 0x7f for byte in reason.rstrip(b"\x00")):
                raise ParseError("X11 setup reason must be printable")
            label = "setup-failed" if self.status == 0 else "setup-authenticate"
        self.extra_evidence = (("x11_message", label, "setup", "structural"),
                               ("x11_byte_order", "msb" if self.order == "big" else "lsb", "setup", "structural"))
        self.reason = "X11 setup reply validated with caller hint; vendor, reason and screen details not emitted"


class SPICEParser(FrameParser):
    """SpiceLinkHeader followed by SpiceLinkMess (client) or SpiceLinkReply (server)."""
    header_size = 16
    protocol_name = "spice"

    def frame_size(self, data):
        if data[:4] != SPICE_MAGIC:
            raise UnsupportedPrefix("SPICE link magic expected")
        major = int.from_bytes(data[4:8], "little")
        minor = int.from_bytes(data[8:12], "little")
        if major != 2 or minor > 2:
            raise UnsupportedPrefix("Only SPICE link protocol 2.x is supported")
        size = int.from_bytes(data[12:16], "little")
        if size < 18 or size > 16 + SPICE_PUBLIC_KEY + 12 + 8 * MAX_SPICE_CAPS:
            raise ParseError("SPICE link message size outside the profile")
        return 16 + size

    def validate(self, data):
        body = data[16:]
        if len(body) < 18:
            raise ParseError("SPICE link message shorter than its fixed fields")
        # The client layout is tried first: a reply can never satisfy it, because the bytes a
        # client layout reads as the capability offset (body[14:18]) fall inside the reply's
        # DER-encoded RSA public key, whose fixed object identifier never encodes 18. A client
        # message whose trailing capability word happens to equal the reply's offset must
        # therefore not be read as a reply (review finding, round 1).
        channel_type = body[4]                      # body[5] is the channel id, not emitted
        common = int.from_bytes(body[6:10], "little")
        channel = int.from_bytes(body[10:14], "little")
        offset = int.from_bytes(body[14:18], "little")
        if (channel_type and offset == 18 and common <= MAX_SPICE_CAPS and channel <= MAX_SPICE_CAPS
                and len(body) == 18 + 4 * (common + channel)):
            if channel_type != 1 and not int.from_bytes(body[:4], "little"):
                raise ParseError("SPICE secondary channel without a connection id")
            self.extra_evidence = (("spice_message", "link-message", "link_header", "structural"),
                                   ("spice_channel", SPICE_CHANNELS.get(channel_type, "other"), "link_message", "structural"))
            self.reason = "SPICE link message validated; connection id and capabilities not emitted"
            return
        if len(body) < SPICE_PUBLIC_KEY + 16 or int.from_bytes(body[SPICE_PUBLIC_KEY + 12:SPICE_PUBLIC_KEY + 16], "little") != SPICE_PUBLIC_KEY + 16:
            raise ParseError("SPICE link message fields outside the profile")
        error = int.from_bytes(body[:4], "little")
        common = int.from_bytes(body[SPICE_PUBLIC_KEY + 4:SPICE_PUBLIC_KEY + 8], "little")
        channel = int.from_bytes(body[SPICE_PUBLIC_KEY + 8:SPICE_PUBLIC_KEY + 12], "little")
        if error >= len(SPICE_LINK_ERRORS):
            raise ParseError("SPICE link error outside the specification")
        if common > MAX_SPICE_CAPS or channel > MAX_SPICE_CAPS or len(body) != SPICE_PUBLIC_KEY + 16 + 4 * (common + channel):
            raise ParseError("SPICE link reply capability counts disagree with its size")
        self.scope = "negotiation_response"
        self.extra_evidence = (("spice_message", "link-reply", "link_header", "structural"),
                               ("spice_link_error", SPICE_LINK_ERRORS[error], "link_reply", "structural"))
        self.reason = "SPICE link reply validated; public key and capabilities not emitted"
