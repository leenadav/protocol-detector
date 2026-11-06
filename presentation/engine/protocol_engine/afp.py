"""Apple Filing Protocol over DSI (Data Stream Interface): the session opening messages.

DSI header: flags (0 request, 1 reply), command, request id, data offset
(requests) or error code (replies), total data length, four reserved zero
bytes. The profile covers DSIGetStatus and DSIOpenSession in both directions:
OpenSession options are walked (type, length, value); the server information
block answering GetStatus is bounded but not decoded. Nothing from the payload
is emitted.
"""
from .extended import UnsupportedPrefix
from .framing import FrameParser
from .parsers import ParseError

GET_STATUS, OPEN_SESSION = 3, 4
_COMMANDS = {GET_STATUS: "get-status", OPEN_SESSION: "open-session"}
MAX_OPTIONS = 64
MAX_STATUS = 4096
_OPTION_TYPES = {0: 4, 1: 4, 2: 4}      # attention quantum, server request quantum, replay cache size: all four bytes


class DSIParser(FrameParser):
    header_size = 16
    protocol_name = "afp"

    def frame_size(self, data):
        flags, command = data[0], data[1]
        if flags > 1 or command not in _COMMANDS:
            raise UnsupportedPrefix("DSI profile covers GetStatus and OpenSession requests and replies")
        if any(data[12:16]):
            raise ParseError("DSI reserved bytes must be zero")
        self.reply = flags == 1
        if not self.reply and any(data[4:8]):
            raise ParseError("DSI request data offset must be zero")
        if self.reply and data[4] not in (0, 0xff):
            raise ParseError("DSI reply error code outside the AFP result range")
        if self.reply and any(data[4:8]) and data[4] == 0 and any(data[5:8]):
            raise ParseError("DSI reply error code outside the AFP result range")
        length = int.from_bytes(data[8:12], "big")
        limit = MAX_STATUS if (command == GET_STATUS and self.reply) else MAX_OPTIONS
        if length > limit:
            raise ParseError("DSI payload length outside the profile")
        if command == GET_STATUS and not self.reply and length:
            raise ParseError("DSIGetStatus request carries no data")
        if command == GET_STATUS and self.reply and not any(data[4:8]) and not length:
            raise ParseError("DSIGetStatus reply without server information")
        self.command = command
        return 16 + length

    def validate(self, data):
        payload = data[16:]
        if self.command == OPEN_SESSION:
            pos = 0
            while pos < len(payload):
                if len(payload) - pos < 2:
                    raise ParseError("Truncated DSI option")
                kind, length = payload[pos], payload[pos + 1]
                if kind not in _OPTION_TYPES or length != _OPTION_TYPES[kind] or pos + 2 + length > len(payload):
                    raise ParseError("DSI OpenSession option outside the profile")
                pos += 2 + length
        self.extra_evidence = (("dsi_message", "reply" if self.reply else "request", "dsi_header", "structural"),
                               ("afp_command", _COMMANDS[self.command], "dsi_header", "structural"))
        if self.reply:
            self.scope = "negotiation_response"
        self.reason = ("DSI reply validated; server information and option values not emitted" if self.reply
                       else "DSI request validated; option values not emitted, AFP commands not inspected")
