"""Protocols that only start after an HTTP Upgrade boundary: WebSocket frame headers (RFC 6455 5.2).

A WebSocket stream is never selected from a bare prefix; the Inspector reaches
this parser through the websocket-upgrade shift (or an explicit candidate hint)
and validates exactly one frame header. Payload bytes are not read.
"""
from .parsers import ParseError
from .extended import UnsupportedPrefix

_OPCODES = {1: "text", 2: "binary", 8: "close", 9: "ping", 10: "pong"}


class WebSocketParser:
    protocol_name = "websocket"
    scope = "frame_header"

    def __init__(self, config):
        self.config = config
        self.buffer = bytearray()
        self.done = False
        self.shift = None
        self.extra_evidence = ()
        self.reason = "Waiting for a WebSocket frame header"

    def feed(self, data):
        pos = 0
        while not self.done and pos < len(data):
            self.buffer.append(data[pos])
            pos += 1
            if len(self.buffer) < 2:
                continue
            first, second = self.buffer[0], self.buffer[1]
            if first & 0x70:
                raise ParseError("WebSocket RSV bits set without a negotiated extension")
            opcode = first & 0x0f
            if opcode == 0:
                raise UnsupportedPrefix("A WebSocket continuation frame cannot open a stream")
            if opcode not in _OPCODES:
                raise ParseError("WebSocket reserved opcode")
            masked, short = bool(second & 0x80), second & 0x7f
            extra = 2 if short == 126 else 8 if short == 127 else 0
            needed = 2 + extra + (4 if masked else 0)
            if len(self.buffer) < needed:
                continue
            if extra == 2:
                length = int.from_bytes(self.buffer[2:4], "big")
                if length < 126:
                    raise ParseError("WebSocket 16-bit length must be minimal")
            elif extra == 8:
                length = int.from_bytes(self.buffer[2:10], "big")
                if length >> 63 or length < 65536:
                    raise ParseError("WebSocket 64-bit length must be minimal with the high bit clear")
            else:
                length = short
            if opcode >= 8 and (not first & 0x80 or length > 125):
                raise ParseError("WebSocket control frames must be unfragmented and at most 125 bytes")
            self.done = True
            self.extra_evidence = (("websocket_opcode", _OPCODES[opcode], "frame_header", "structural"),
                                   ("websocket_masked", "true" if masked else "false", "frame_header", "structural"))
            self.reason = "WebSocket frame header validated after the upgrade boundary; payload not decoded"
        return pos
