"""RFC 5424 version-1 UDP message framing; no RFC 3164 guessing."""
import datetime
import re
from .parsers import BudgetError, ParseError


def syslog(data, config):
    parts = data.split(b" ", 6)
    if len(parts) != 7:
        raise ParseError("Incomplete RFC5424 header")
    priority = re.fullmatch(rb"<(0|[1-9][0-9]{0,2})>1", parts[0])
    if not priority or int(priority[1]) > 191:
        raise ParseError("Invalid syslog priority/version")
    timestamp = parts[1]
    if timestamp != b"-":
        if not re.fullmatch(rb"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])", timestamp):
            raise ParseError("Invalid syslog timestamp framing")
        try:
            datetime.datetime.fromisoformat(timestamp.decode().replace("Z", "+00:00"))
        except ValueError:
            raise ParseError("Invalid syslog timestamp value") from None
    for value, limit in zip(parts[2:6], (255, 48, 128, 32)):
        if not 1 <= len(value) <= limit or any(byte < 33 or byte > 126 for byte in value):
            raise ParseError("Invalid syslog header field")
    sd = parts[6]
    if sd == b"-" or sd.startswith(b"- "):
        return "syslog/5424", "RFC5424 header and NIL structured-data framing validated; log content unverified"
    pos, count, ids = 0, 0, set()
    while pos < len(sd) and sd[pos] == 91:
        pos += 1
        start = pos
        while pos < len(sd) and sd[pos] not in (32, 93):
            pos += 1
        identifier = sd[start:pos]
        if not re.fullmatch(rb'[^=\]"\x00-\x20\x7f-\xff]{1,32}', identifier) or identifier in ids:
            raise ParseError("Invalid or duplicate syslog SD-ID")
        ids.add(identifier)
        names = set()
        while pos < len(sd) and sd[pos] == 32:
            count += 1
            if count > 128:
                raise BudgetError("Syslog structured-data field budget exhausted")
            pos += 1
            start = pos
            while pos < len(sd) and sd[pos] != 61:
                pos += 1
            name = sd[start:pos]
            if not re.fullmatch(rb'[^=\]"\x00-\x20\x7f-\xff]{1,32}', name) or name in names:
                raise ParseError("Invalid or duplicate syslog parameter name")
            names.add(name)
            if sd[pos:pos + 2] != b'="':
                raise ParseError("Syslog parameter requires quoted value")
            pos += 2
            value = bytearray()
            while pos < len(sd) and sd[pos] != 34:
                byte = sd[pos]
                pos += 1
                if byte == 92:
                    # RFC5424 receivers treat other escape sequences as a
                    # literal backslash followed by the original character.
                    if pos < len(sd) and sd[pos] in (34, 92, 93):
                        byte = sd[pos]
                        pos += 1
                elif byte == 93:
                    raise ParseError("Unescaped syslog closing bracket")
                value.append(byte)
            if pos == len(sd):
                raise ParseError("Unterminated syslog parameter")
            try:
                value.decode("utf-8")
            except UnicodeError:
                raise ParseError("Invalid syslog structured-data UTF-8") from None
            pos += 1
        if pos == len(sd) or sd[pos] != 93:
            raise ParseError("Unterminated syslog structured-data element")
        pos += 1
        if len(ids) > 128:
            raise BudgetError("Syslog element budget exhausted")
    if not ids or (pos < len(sd) and sd[pos] != 32):
        raise ParseError("Invalid syslog structured-data boundary")
    return "syslog/5424", "RFC5424 header and structured-data framing validated; log content unverified"


class SyslogStreamParser:
    """RFC 6587 TCP framing: octet counting (MSG-LEN SP SYSLOG-MSG) or non-transparent (SYSLOG-MSG LF).

    One complete RFC 5424 message is validated by the datagram profile above;
    the framing kind is reported, the message content is never emitted.
    """
    protocol_name = "syslog/5424"
    MAX_MESSAGE = 8192

    def __init__(self, config):
        self.config = config
        self.limit = min(config.max_line, self.MAX_MESSAGE)
        self.buffer = bytearray()
        self.counting = None
        self.length = None
        self.done = False
        self.shift = None
        self.extra_evidence = ()
        self.reason = "Waiting for one complete framed syslog message"

    def feed(self, data):
        pos = 0
        while not self.done and pos < len(data):
            if self.counting is None:
                self.counting = data[pos] != 0x3c          # '<' starts a non-transparent frame
            if self.counting:
                if self.length is None:
                    pos = self._length(data, pos)
                    if self.length is None:
                        return pos
                amount = min(self.length - len(self.buffer), len(data) - pos)
                self.buffer.extend(data[pos:pos + amount])
                pos += amount
                if len(self.buffer) == self.length:
                    self._message(bytes(self.buffer))
            else:
                newline = data.find(b"\n", pos)
                end = len(data) if newline < 0 else newline + 1
                if len(self.buffer) + end - pos > self.limit:
                    raise BudgetError("Syslog message exceeds the line budget")
                self.buffer.extend(data[pos:end])
                pos = end
                if newline >= 0:
                    message = bytes(self.buffer[:-1])
                    self._message(message[:-1] if message.endswith(b"\r") else message)
        return pos

    def _length(self, data, pos):
        while pos < len(data):
            byte = data[pos]
            pos += 1
            if byte == 0x20:
                if not self.buffer:
                    raise ParseError("Syslog octet count missing")
                length = int(self.buffer)
                self.buffer.clear()
                if length < 16:
                    raise ParseError("Syslog octet count below the shortest RFC 5424 header")
                if length > self.limit:
                    raise BudgetError("Syslog octet count exceeds the line budget")
                self.length = length
                return pos
            if not 0x30 <= byte <= 0x39 or len(self.buffer) >= 5 or (not self.buffer and byte == 0x30):
                raise ParseError("Invalid syslog octet count")
            self.buffer.append(byte)
        return pos

    def _message(self, message):
        protocol, reason = syslog(message, self.config)
        self.protocol_name = protocol
        self.done = True
        framing = "octet-counting" if self.counting else "non-transparent"
        self.extra_evidence = (("syslog_framing", framing, "frame", "structural"),)
        self.reason = reason + "; TCP " + framing + " framing"
