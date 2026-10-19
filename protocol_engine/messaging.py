"""Bounded initial-message recognizers for MQTT, RESP requests and AMQP headers.

Recognition is structural evidence, not server/application authentication.
Credentials and message bodies are never included in observations or errors.
"""
import re
from .parsers import BudgetError, ParseError
from .extended import UnsupportedPrefix


class _Fields:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, size):
        end = self.pos + size
        if end > len(self.data):
            raise ParseError("Truncated MQTT CONNECT field")
        result = self.data[self.pos:end]
        self.pos = end
        return result

    def vector(self, utf8=False):
        value = self.take(int.from_bytes(self.take(2), "big"))
        if not utf8:
            return value
        try:
            text = value.decode("utf-8")
        except UnicodeError:
            raise ParseError("Invalid MQTT UTF-8 field") from None
        if "\x00" in text:
            raise ParseError("NUL in MQTT UTF-8 field")
        return text


    def varint(self):
        value = 0
        for index in range(4):
            byte = self.take(1)[0]
            value |= (byte & 127) << (7 * index)
            if byte < 128:
                if index and byte == 0:
                    raise ParseError("Nonminimal MQTT variable integer")
                return value
        raise ParseError("MQTT variable integer exceeds four bytes")


_CONNECT_PROPERTIES = frozenset((0x11, 0x21, 0x27, 0x22, 0x19, 0x17, 0x26, 0x15, 0x16))
_WILL_PROPERTIES = frozenset((0x18, 0x01, 0x02, 0x03, 0x08, 0x09, 0x26))


def _properties(fields, will=False):
    block = _Fields(fields.take(fields.varint()))
    allowed = _WILL_PROPERTIES if will else _CONNECT_PROPERTIES
    seen, count, payload_format = set(), 0, 0
    while block.pos < len(block.data):
        count += 1
        if count > 128:
            raise BudgetError("MQTT property count exceeds inspection limit")
        code = block.varint()
        if code not in allowed or (code in seen and code != 0x26):
            raise ParseError("Unknown, misplaced or duplicate MQTT CONNECT/Will property")
        seen.add(code)
        if code in (0x01, 0x17, 0x19):
            value = block.take(1)[0]
            if value not in (0, 1):
                raise ParseError("Invalid MQTT boolean property")
            if code == 1:
                payload_format = value
        elif code in (0x21, 0x22):
            value = int.from_bytes(block.take(2), "big")
            if code == 0x21 and value == 0:
                raise ParseError("MQTT Receive Maximum must be nonzero")
        elif code in (0x11, 0x27, 0x18, 0x02):
            value = int.from_bytes(block.take(4), "big")
            if code == 0x27 and value == 0:
                raise ParseError("MQTT Maximum Packet Size must be nonzero")
        elif code in (0x15, 0x03, 0x08):
            value = block.vector(utf8=True)
            if code == 0x08 and (not value or "+" in value or "#" in value):
                raise ParseError("Invalid MQTT Response Topic")
        elif code in (0x16, 0x09):
            block.vector()
        else:
            block.vector(utf8=True)
            block.vector(utf8=True)
    if not will and 0x16 in seen and 0x15 not in seen:
        raise ParseError("MQTT Authentication Data requires Authentication Method")
    return payload_format


class MQTTParser:
    """MQTT 3.1.1/5.0 CONNECT; no subsequent packet or broker-state inspection."""
    protocol_name = "mqtt/3.1.1"

    def __init__(self, config):
        self.config = config
        self.started = False
        self.length = 0
        self.length_bytes = 0
        self.body_ready = False
        self.body = bytearray()
        self.done = False
        self.reason = "Waiting for complete MQTT CONNECT"

    def feed(self, data):
        pos = 0
        if not self.started and data:
            if data[0] != 0x10:
                raise ParseError("Invalid MQTT CONNECT control byte")
            self.started, pos = True, 1
        while not self.body_ready and pos < len(data):
            byte = data[pos]
            pos += 1
            self.length |= (byte & 127) << (7 * self.length_bytes)
            self.length_bytes += 1
            if byte & 128:
                if self.length_bytes == 4:
                    raise ParseError("MQTT Remaining Length exceeds four bytes")
                continue
            if self.length_bytes > 1 and byte == 0:
                raise ParseError("Nonminimal MQTT Remaining Length (strict profile)")
            if self.length < 12:
                raise ParseError("MQTT CONNECT body is too short")
            if 1 + self.length_bytes + self.length > self.config.max_bytes:
                raise BudgetError("MQTT CONNECT exceeds byte budget")
            self.body_ready = True
        if self.body_ready:
            amount = min(self.length - len(self.body), len(data) - pos)
            self.body.extend(data[pos:pos + amount])
            pos += amount
            if len(self.body) == self.length:
                self._validate()
                self.done = True
                self.reason = self.protocol_name.upper() + " CONNECT fields validated; broker reply and later packets not inspected"
                self.body.clear()
        return pos

    def _validate(self):
        fields = _Fields(self.body)
        if fields.vector() != b"MQTT":
            raise UnsupportedPrefix("Unsupported MQTT protocol name")
        level, flags = fields.take(2)
        if level not in (4, 5):
            raise UnsupportedPrefix("Only MQTT protocol levels 4 and 5 are supported")
        self.protocol_name = "mqtt/3.1.1" if level == 4 else "mqtt/5.0"
        will = bool(flags & 4)
        qos = (flags >> 3) & 3
        if flags & 1 or qos == 3 or (not will and flags & 0x38) or (level == 4 and flags & 64 and not flags & 128):
            raise ParseError("Invalid MQTT CONNECT flags")
        fields.take(2)  # Keep Alive: any unsigned 16-bit value.
        if level == 5:
            _properties(fields)
        client_id = fields.vector(utf8=True)
        if level == 4 and not client_id and not flags & 2:
            raise ParseError("Empty MQTT ClientId requires Clean Session")
        if will:
            payload_format = _properties(fields, will=True) if level == 5 else 0
            topic = fields.vector(utf8=True)
            if not topic or "+" in topic or "#" in topic:
                raise ParseError("Invalid MQTT Will Topic")
            payload = fields.vector()
            if payload_format:
                try:
                    payload.decode("utf-8")
                except UnicodeError:
                    raise ParseError("MQTT Will Payload violates declared UTF-8 format") from None
        if flags & 128:
            fields.vector(utf8=True)
        if flags & 64:
            fields.vector()  # Password is binary in MQTT 3.1.1.
        if fields.pos != len(self.body):
            raise ParseError("Extra bytes inside MQTT CONNECT")


class RESPParser:
    """One command array of non-null bulk strings (RESP2/3 request format).

    Arguments are counted/skipped, never retained. First bulk must be an ASCII
    command token. Inline requests, nested arrays and server replies unsupported.
    RESP identifies a wire format shared by Redis-compatible implementations.
    """
    protocol_name = "resp"
    MAX_ARGUMENTS = 1024
    MAX_COMMAND = 128

    def __init__(self, config):
        self.config = config
        self.stage = "array"
        self.line = bytearray()
        self.command = bytearray()
        self.remaining_items = None
        self.first = True
        self.remaining_bytes = 0
        self.trailer = 0
        self.total = 0
        self.done = False
        self.reason = "Waiting for a complete RESP command array"

    def _header(self):
        marker = b"*" if self.stage == "array" else b"$"
        line = bytes(self.line)
        self.line.clear()
        if not line.startswith(marker) or not line.endswith(b"\r\n") or not line[1:-2].isdigit():
            raise ParseError("Invalid RESP request length header")
        number = int(line[1:-2])
        if self.stage == "array":
            if not number:
                raise ParseError("RESP command array must not be empty")
            if number > self.MAX_ARGUMENTS:
                raise BudgetError("RESP argument count exceeds inspection limit")
            self.remaining_items = number
            self.stage = "bulk"
        else:
            if self.total + number + 2 > self.config.max_bytes:
                raise BudgetError("RESP bulk string exceeds byte budget")
            if self.first and not 1 <= number <= self.MAX_COMMAND:
                raise UnsupportedPrefix("RESP command token outside supported length")
            self.remaining_bytes = number
            self.stage = "data" if number else "trailer"

    def feed(self, data):
        pos = 0
        while pos < len(data) and not self.done:
            if self.stage in ("array", "bulk"):
                # Numeric headers only; 24-byte cap bounds int conversion/work.
                end = data.find(b"\n", pos, pos + 24 - len(self.line))
                amount = end + 1 - pos if end >= 0 else min(24 - len(self.line), len(data) - pos)
                self.line.extend(data[pos:pos + amount])
                pos += amount
                self.total += amount
                if end >= 0:
                    self._header()
                elif len(self.line) == 24:
                    raise BudgetError("RESP numeric header exceeds inspection limit")
            elif self.stage == "data":
                amount = min(self.remaining_bytes, len(data) - pos)
                if self.first:
                    self.command.extend(data[pos:pos + amount])
                pos += amount
                self.total += amount
                self.remaining_bytes -= amount
                if not self.remaining_bytes:
                    if self.first and not re.fullmatch(rb"[A-Za-z][A-Za-z0-9_.-]*", self.command):
                        raise UnsupportedPrefix("RESP first bulk string is not a supported command token")
                    self.stage = "trailer"
            else:
                if data[pos] != b"\r\n"[self.trailer]:
                    raise ParseError("Invalid RESP bulk string terminator")
                pos += 1
                self.total += 1
                self.trailer += 1
                if self.trailer == 2:
                    self.remaining_items -= 1
                    self.first = False
                    self.command.clear()
                    self.trailer = 0
                    if not self.remaining_items:
                        self.done = True
                        self.reason = "RESP command array framing validated; compatible server identity and command semantics unverified"
                    else:
                        self.stage = "bulk"
        return pos


class AMQPParser:
    """Eight-byte plain AMQP version header, not the handshake or frame stream."""
    scope = "protocol_header"
    VERSIONS = {b"AMQP\x00\x00\x09\x01": "amqp/0-9-1", b"AMQP\x00\x01\x00\x00": "amqp/1.0"}

    def __init__(self, config):
        self.header = bytearray()
        self.done = False
        self.reason = "Waiting for complete AMQP version header"

    def feed(self, data):
        amount = min(8 - len(self.header), len(data))
        self.header.extend(data[:amount])
        if len(self.header) == 8:
            self.protocol_name = self.VERSIONS.get(bytes(self.header))
            if self.protocol_name is None:
                raise UnsupportedPrefix("Unsupported AMQP protocol version header")
            self.done = True
            self.reason = "AMQP version header validated; negotiation, frames and peer identity unverified"
        return amount
