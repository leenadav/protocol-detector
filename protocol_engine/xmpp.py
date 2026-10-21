"""XMPP (RFC 6120) initial stream header in either direction.

The profile is the optional XML declaration followed by the complete
`<stream:stream ...>` open tag: content namespace jabber:client,
jabber:server or jabber:component:accept, the streams namespace, a numeric
version, and `to` (initiating entity) or `id`/`from` (receiving entity). The
domain in `to` or `from` becomes an asserted hostname; stream ids, language
and every other attribute are read for framing only. Features, STARTTLS and
stanzas are not inspected.
"""
import re
from .extended import UnsupportedPrefix
from .model import normalize_hostname
from .parsers import BudgetError, ParseError

MAX_HEADER = 4096
MAX_ATTRIBUTES = 16
STREAM_TAG = b"<stream:stream"
STREAMS_NAMESPACE = b"http://etherx.jabber.org/streams"
NAMESPACES = {b"jabber:client": "client", b"jabber:server": "server", b"jabber:component:accept": "component"}
_PROLOG = re.compile(rb"<\?xml[ \t\r\n]+version[ \t\r\n]*=[ \t\r\n]*(['\"])1\.[0-9]\1(?:[ \t\r\n]+encoding[ \t\r\n]*=[ \t\r\n]*(['\"])[Uu][Tt][Ff]-8\2)?"
                     rb"(?:[ \t\r\n]+standalone[ \t\r\n]*=[ \t\r\n]*(['\"])(?:yes|no)\3)?[ \t\r\n]*\?>")
_ATTRIBUTE = re.compile(rb"[ \t\r\n]+([A-Za-z_][A-Za-z0-9_.:-]{0,63})[ \t\r\n]*=[ \t\r\n]*(?:'([^'<&\x00-\x08\x0b\x0c\x0e-\x1f]{0,1023})'|\"([^\"<&\x00-\x08\x0b\x0c\x0e-\x1f]{0,1023})\")")
_VERSION = re.compile(rb"[0-9]{1,2}\.[0-9]{1,2}")


class XMPPParser:
    protocol_name = "xmpp"
    host_source = "xmpp_stream"

    def __init__(self, config):
        self.config = config
        self.limit = min(config.max_line, MAX_HEADER)
        self.buffer = bytearray()
        self.quote = None                       # open quote byte while scanning an attribute value
        self.done = False
        self.shift = None
        self.host = None
        self.extra_evidence = ()
        self.scope = "initial_message"
        self.reason = "Waiting for the complete XMPP stream header"

    def feed(self, data):
        pos = 0
        while not self.done and pos < len(data):
            close = self._tag_end(data, pos)
            end = len(data) if close < 0 else close + 1
            piece = data[pos:end]
            if len(self.buffer) + len(piece) > self.limit:
                raise BudgetError("XMPP stream header exceeds the line budget")
            self.buffer.extend(piece)
            pos = end
            if close >= 0:
                self._tag_closed()
        return pos

    def _tag_end(self, data, pos):
        """Index of the first '>' outside quotes from pos, or -1; the quote state spans feeds."""
        quote = self.quote
        for index in range(pos, len(data)):
            byte = data[index]
            if quote is not None:
                if byte == quote:
                    quote = None
            elif byte in (0x22, 0x27):
                quote = byte
            elif byte == 0x3e:
                self.quote = None
                return index
        self.quote = quote
        return -1

    def _tag_closed(self):
        text = bytes(self.buffer).lstrip(b" \t\r\n")
        if text.startswith(b"<?xml"):
            prolog = _PROLOG.match(text)
            if prolog is None:
                if b"?>" in text:
                    raise UnsupportedPrefix("XML declaration outside the XMPP profile")
                return                      # a '>' inside the declaration's quotes; keep reading
            text = text[prolog.end():].lstrip(b" \t\r\n")
            if not text:
                return                      # declaration complete; the stream tag follows
        if not text.startswith(STREAM_TAG) or text[len(STREAM_TAG):len(STREAM_TAG) + 1] not in (b" ", b"\t", b"\r", b"\n", b">", b"/"):
            if STREAM_TAG.startswith(text):
                return
            raise UnsupportedPrefix("XMPP profile requires a stream:stream open tag")
        if not text.endswith(b">"):
            return                          # the '>' belonged to the declaration
        if text.endswith(b"/>"):
            raise ParseError("XMPP stream header must not be self-closing")
        self._header(text[len(STREAM_TAG):-1])

    def _header(self, attributes):
        pos, found = 0, {}
        while pos < len(attributes):
            match = _ATTRIBUTE.match(attributes, pos)
            if match is None:
                if not attributes[pos:].strip(b" \t\r\n"):
                    break
                raise ParseError("Invalid XMPP stream header attribute")
            name = match.group(1)
            if name in found:
                raise ParseError("Duplicate XMPP stream header attribute")
            if len(found) >= MAX_ATTRIBUTES:
                raise BudgetError("XMPP stream header attribute count exceeds budget")
            found[name] = match.group(2) if match.group(2) is not None else match.group(3)
            pos = match.end()
        namespace = NAMESPACES.get(found.get(b"xmlns", b""))
        if namespace is None:
            raise UnsupportedPrefix("XMPP content namespace outside client, server and component streams")
        if found.get(b"xmlns:stream") != STREAMS_NAMESPACE:
            raise ParseError("XMPP stream header requires the streams namespace")
        version = found.get(b"version")
        if version is not None and not _VERSION.fullmatch(version):
            raise ParseError("Invalid XMPP stream version")
        response = b"id" in found
        if response and not found[b"id"]:
            raise ParseError("Empty XMPP stream id")
        domain = found.get(b"from") if response else found.get(b"to")
        if domain:
            try:
                self.host = normalize_hostname(domain.decode("ascii"))
            except UnicodeDecodeError:
                raise ParseError("XMPP stream address must be ASCII") from None
            except ValueError:
                if not all(byte in b"0123456789." for byte in domain):
                    raise ParseError("Invalid XMPP stream address") from None
        self.extra_evidence = (("xmpp_stream", "response" if response else "initiating", "stream_header", "structural"),
                               ("xmpp_namespace", namespace, "stream_header", "structural"),
                               ("xmpp_version", "1.0" if version is not None and version.startswith(b"1.") else ("legacy" if version is None else "other"),
                                "stream_header", "structural"))
        self.scope = "negotiation_response" if response else "initial_message"
        self.done = True
        self.reason = ("XMPP receiving-entity stream header validated; stream id, features and stanzas not inspected" if response
                       else "XMPP initiating stream header validated; features, STARTTLS, authentication and stanzas not inspected")
