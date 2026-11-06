"""Shared header validation for SIP and RTSP; bodies are outside this scope."""
import re
from .parsers import BudgetError, ParseError, TOKEN

START = re.compile(rb"(?:[A-Z_]+ [\x21-\x7e]+ (?:SIP/2\.0|RTSP/[12]\.0)|(?:SIP/2\.0|RTSP/[12]\.0) [1-6][0-9]{2} [\x20-\x7e]*)")


class ControlHeaders:
    def __init__(self, line, config):
        self.config = config
        self.request = not line.startswith((b"SIP/", b"RTSP/"))
        self.method = line.split(b" ", 1)[0] if self.request else None
        version = line.rsplit(b" ", 1)[-1] if self.request else line.split(b" ", 1)[0]
        self.protocol_name = version.decode("ascii").lower()
        self.family = "sip" if version.startswith(b"SIP") else "rtsp"
        if not self.request and self.family == "rtsp" and int(line.split(b" ", 2)[1]) >= 600:
            raise ParseError("Invalid RTSP response status class")
        self.fields = {}
        self.count = 0
        self.done = False
        self.reason = "Waiting for control-protocol headers"

    def consume_line(self, line):
        if not line:
            fields = self.fields
            if self.family == "sip":
                required = {b"via", b"from", b"to", b"call-id", b"cseq"}
                if self.request:
                    required.add(b"max-forwards")
                if not required <= fields.keys():
                    raise ParseError("SIP required headers missing")
                if not re.fullmatch(rb"SIP/2\.0/[A-Z]+ [\x21-\x7e]+", fields[b"via"]):
                    raise ParseError("Invalid SIP Via framing")
                match = re.fullmatch(rb"([0-9]{1,10}) ([A-Z_]+)", fields[b"cseq"])
                if not match or int(match[1]) >= 2 ** 31 or (self.request and match[2] != self.method):
                    raise ParseError("Invalid SIP CSeq or request-method mismatch")
                if self.request and (not re.fullmatch(rb"[0-9]{1,3}", fields[b"max-forwards"])
                                     or int(fields[b"max-forwards"]) > 255):
                    raise ParseError("Invalid SIP Max-Forwards")
            elif b"cseq" not in fields or not re.fullmatch(rb"[0-9]{1,10}", fields[b"cseq"]) or int(fields[b"cseq"]) >= 2 ** 31:
                raise ParseError("RTSP requires a valid CSeq")
            self.done = True
            self.reason = "SIP/RTSP start-line and required header framing validated; URI semantics, body and dialogue unverified"
            return
        self.count += 1
        if self.count > self.config.max_headers:
            raise BudgetError("Control-protocol header count exceeded")
        name, colon, value = line.partition(b":")
        if not colon or not re.fullmatch(TOKEN, name) or any(c < 32 and c != 9 or c == 127 for c in value):
            raise ParseError("Invalid control-protocol header")
        name, value = name.lower(), value.strip(b" \t")
        if self.family == "sip":
            name = {b"v": b"via", b"f": b"from", b"t": b"to", b"i": b"call-id", b"l": b"content-length"}.get(name, name)
        if name in (b"via", b"from", b"to", b"call-id", b"cseq", b"max-forwards", b"content-length"):
            if not value or (name in self.fields and name != b"via"):
                raise ParseError("Empty or duplicate singleton control header")
            if name == b"content-length" and not re.fullmatch(rb"[0-9]{1,20}", value):
                raise ParseError("Invalid control-protocol Content-Length")
            if name not in self.fields:
                self.fields[name] = value
