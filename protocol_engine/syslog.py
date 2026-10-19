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
