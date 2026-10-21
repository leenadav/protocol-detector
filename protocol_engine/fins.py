"""Omron FINS/TCP: the node address exchange and the first FINS frame.

Every FINS/TCP message starts with the ASCII magic FINS, a big-endian length
of the rest, a command (0 node address data send from the client, 1 the
server's answer, 2 a FINS frame) and an error code. Node addresses and the
FINS command header (ICF, GCT, network and node fields) are validated for
range; memory areas, addresses and data are never read.
"""
from .extended import UnsupportedPrefix
from .framing import FrameParser
from .parsers import ParseError

MAGIC = b"FINS"
NODE_REQUEST, NODE_REPLY, FRAME = 0, 1, 2
MAX_FRAME = 2048


class FINSParser(FrameParser):
    header_size = 16
    protocol_name = "fins"

    def frame_size(self, data):
        if data[:4] != MAGIC:
            raise UnsupportedPrefix("FINS/TCP magic expected")
        length = int.from_bytes(data[4:8], "big")
        command = int.from_bytes(data[8:12], "big")
        error = int.from_bytes(data[12:16], "big")
        if command not in (NODE_REQUEST, NODE_REPLY, FRAME):
            raise UnsupportedPrefix("FINS/TCP command outside node address exchange and frame send")
        if command == NODE_REQUEST and (length != 12 or error):
            raise ParseError("FINS node address request must carry one node address without error")
        if command == NODE_REPLY and length != 16:
            raise ParseError("FINS node address reply must carry two node addresses")
        if command == FRAME and not 8 + 12 <= length <= MAX_FRAME:
            raise ParseError("FINS frame length outside the profile")
        if error > 0x1f:
            raise ParseError("FINS/TCP error code outside the specification")
        self.command = command
        return 8 + length

    def validate(self, data):
        body = data[16:]
        if self.command != FRAME:
            if any(int.from_bytes(body[at:at + 4], "big") > 254 for at in range(0, len(body), 4)):
                raise ParseError("FINS node address outside 0..254")
            reply = self.command == NODE_REPLY
            self.extra_evidence = (("fins_message", "node-address-reply" if reply else "node-address-request", "header", "structural"),)
            if reply:
                self.scope = "negotiation_response"
            self.reason = "FINS/TCP node address exchange validated; node numbers not emitted"
            return
        icf = body[0]
        if icf & 0x3f or body[1] or body[2] > 7:
            raise ParseError("FINS frame ICF, reserved or gateway count outside the specification")
        if body[3] > 127 or body[6] > 127 or body[5] > 15 or body[8] > 15:
            raise ParseError("FINS frame network or unit address outside the specification")
        response = bool(icf & 0x40)
        if response and len(body) < 14:
            raise ParseError("FINS response frame shorter than its command and end codes")
        self.extra_evidence = (("fins_message", "frame", "header", "structural"),
                               ("fins_frame", "response" if response else "command", "fins_header", "structural"))
        if response:
            self.scope = "response_header"
        self.reason = "FINS/TCP frame header validated; command code, addresses and data not emitted"
