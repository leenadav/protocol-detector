"""OPC UA TCP transport connection messages (OPC 10000-6 section 7.1): HEL, ACK, ERR, RHE.

The profile covers the connection-protocol messages that precede the secure
channel. Endpoint URLs, server URIs and error reasons are checked for framing
(length bounds, printable ASCII, opc.tcp scheme) and never emitted. Secure
channel messages (OPN/MSG/CLO), chunking and security are outside the profile.
"""
from .framing import FrameParser
from .parsers import ParseError, BudgetError
from .extended import UnsupportedPrefix

OPCUA_MAGICS = (b"HELF", b"ACKF", b"ERRF", b"RHEF")
_KINDS = {b"HEL": "hello", b"ACK": "acknowledge", b"ERR": "error", b"RHE": "reverse-hello"}
MAX_STRING = 4096         # Part 6 7.1.2.3: EndpointUrl and Reason shall be at most 4096 bytes
MIN_BUFFER = 8192         # Part 6 7.1.2.3/7.1.2.4: buffer sizes shall be at least 8192 bytes
MAX_MESSAGE = 8 + 4 + MAX_STRING + 4 + MAX_STRING


def opcua_probe(prefix):
    """Magic plus a little-endian message size of 8..MAX_MESSAGE; needs 8 bytes."""
    return (len(prefix) >= 8 and prefix[:4] in OPCUA_MAGICS and prefix[6] == 0 and prefix[7] == 0
            and 8 <= int.from_bytes(prefix[4:8], "little") <= MAX_MESSAGE)


def _string(data, pos, what, scheme=None):
    """OPC UA String: Int32 length (-1 null) then bytes; returns the position after it."""
    if pos + 4 > len(data):
        raise ParseError(what + " length field truncated")
    length = int.from_bytes(data[pos:pos + 4], "little", signed=True)
    pos += 4
    if length == -1:
        if scheme is not None:
            raise ParseError(what + " must not be null")
        return pos
    if not 0 <= length <= MAX_STRING or pos + length > len(data):
        raise ParseError(what + " length outside the message or the 4096-byte bound")
    text = data[pos:pos + length]
    if any(byte < 0x20 or byte > 0x7e for byte in text):
        raise ParseError(what + " is not printable ASCII")
    if scheme is not None and not text.startswith(scheme):
        raise UnsupportedPrefix(what + " does not use the opc.tcp scheme")
    return pos + length


class OPCUAParser(FrameParser):
    header_size = 8
    protocol_name = "opcua"
    scope = "negotiation_request"

    def frame_size(self, header):
        if not opcua_probe(header):
            raise ParseError("OPC UA connection message header invalid")
        size = int.from_bytes(header[4:8], "little")
        if size > MAX_MESSAGE:
            raise BudgetError("OPC UA connection message exceeds the profile size")
        return size

    def validate(self, data):
        kind = _KINDS[bytes(data[:3])]
        evidence = [("opcua_message", kind, "header", "structural")]
        if kind in ("hello", "acknowledge"):
            if len(data) < 28:
                raise ParseError("OPC UA hello/acknowledge shorter than its fixed fields")
            version = int.from_bytes(data[8:12], "little")
            receive = int.from_bytes(data[12:16], "little")
            send = int.from_bytes(data[16:20], "little")
            if receive < MIN_BUFFER or send < MIN_BUFFER:
                raise ParseError("OPC UA buffer sizes must be at least 8192 bytes")
            if kind == "hello":
                end = _string(data, 28, "OPC UA endpoint URL", b"opc.tcp://")
                self.reason = "OPC UA Hello validated; endpoint URL not emitted, secure channel unverified"
            else:
                end = 28
                self.scope = "negotiation_response"
                self.reason = "OPC UA Acknowledge validated; negotiated limits unauthenticated"
            evidence.append(("opcua_protocol_version", str(version), "header", "asserted"))
        elif kind == "error":
            if len(data) < 16:
                raise ParseError("OPC UA error shorter than its fixed fields")
            if not data[11] & 0x80:
                raise ParseError("OPC UA error message must carry a Bad status code")
            end = _string(data, 12, "OPC UA error reason")
            self.scope = "negotiation_response"
            self.reason = "OPC UA Error validated; status code and reason not emitted"
        else:
            end = _string(data, 8, "OPC UA server URI")
            end = _string(data, end, "OPC UA endpoint URL", b"opc.tcp://")
            self.reason = "OPC UA ReverseHello validated; server URI and endpoint URL not emitted"
        if end != len(data):
            raise ParseError("OPC UA message size disagrees with its fields")
        self.extra_evidence = tuple(evidence)
