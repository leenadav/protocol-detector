"""Additional bounded initial-message recognizers; no port-based inference."""
import ipaddress
import re
from .model import normalize_hostname
from .control import ControlHeaders, START
from .parsers import BudgetError, LineParser, ParseError, TOKEN
from .service_text import nats, imap_capability
from .session_text import command_line, imap_command, pop3_greeting

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
_NATS_START = re.compile(rb'(INFO|CONNECT)[ \t]+(.+)', re.I)


class UnsupportedPrefix(ParseError):
    """An ambiguous or unsupported structure, not proof of a malformed protocol."""


class AmbiguousPrefix(UnsupportedPrefix):
    """Valid for several families at once; carries the candidate set for session correlation."""

    def __init__(self, message, candidates):
        super().__init__(message)
        self.candidates = tuple(candidates)


class TextParser(LineParser):
    """Share first-line framing for HTTP, SSH and SMTP instead of rescanning.

    In particular, EHLO can be a syntactically valid HTTP extension method;
    its first word alone must not select SMTP.
    """
    def __init__(self, config):
        super().__init__(config, "http")
        self.family = "text"
        self.extra_evidence = ()
        self.control = None

    def feed(self, data):
        if self.continues:
            return LineParser.feed(self, data)
        return super().feed(data)

    def consume_line(self, line):
        if self.first and not line.endswith((b"HTTP/1.0", b"HTTP/1.1")) and START.fullmatch(line):
            self.control = ControlHeaders(line, self.config)
            self.family, self.protocol_name = self.control.family, self.control.protocol_name
            self.scope = "initial_headers"
            self.first = False
            self._line_handler = TextParser._consume_control
            return
        if not self.first:
            return super().consume_line(line)
        command, separator, identity = line.partition(b" ")
        potentially_special = line.startswith(b"SSH-") or command.upper() in (b"EHLO", b"HELO")
        potentially_special = potentially_special or line[:1] in (b'I', b'i', b'C', b'c', b'*')
        if potentially_special and re.fullmatch(TOKEN + rb" [\x21-\x7e]+ HTTP/1\.[01]", line):
            self.family = "http"
            self._line_handler = LineParser.consume_line
            return self._line_handler(self, line)
        if line.startswith(b"SSH-"):
            self.family = self.protocol = "ssh"
            if len(line) + 2 > 255:
                raise ParseError("SSH identification exceeds 255 bytes")
            if self.contexts is not None:
                self.contexts["ssh-req-banner"] = line
            return super().consume_line(line)
        if command.upper() in (b"EHLO", b"HELO"):
            self.family = "smtp"
            if len(line) + 2 > 512:
                raise ParseError("SMTP command exceeds 512 bytes")
            if not separator or not identity:
                raise ParseError("SMTP greeting needs a domain or address literal")
            try:
                text = identity.decode("ascii")
                if text.startswith("[") and text.endswith("]"):
                    address = text[1:-1]
                    if address.lower().startswith("ipv6:"):
                        ipaddress.IPv6Address(address[5:])
                    else:
                        ipaddress.IPv4Address(address)
                else:
                    normalize_hostname(text)
            except (ValueError, UnicodeError):
                raise ParseError("Invalid SMTP greeting identity") from None
            self.protocol_name = "smtp"
            self.done = True
            self.reason = "SMTP client EHLO/HELO syntax validated; server exchange and message body not inspected"
            self.extra_evidence = (("smtp_client_identity", text, "smtp_greeting", "asserted"),)
            if self.contexts is not None:
                self.contexts["smtp-req-argument"] = identity
            return
        if line[:1] in (b'I', b'i', b'C', b'c'):
            match = _NATS_START.fullmatch(line)
            if match:
                nats(match.group(1).upper(), match.group(2), self.config)
                self.family = self.protocol_name = 'nats'
                self.scope = 'protocol_header'
                self.done = True
                self.reason = 'NATS INFO/CONNECT JSON structure validated; authentication and later messages unverified'
                return
        if line.startswith(b'* '):
            if not imap_capability(line, self.config):
                raise AmbiguousPrefix('Untagged text without explicit IMAP revision capabilities is ambiguous', ('imap',))
            self.family = self.protocol_name = 'imap'
            self.scope = 'protocol_header'
            self.done = True
            self.reason = 'IMAP server capability syntax validated; revision capabilities, authentication and later messages unverified'
            return
        if re.match(rb"220(?:[ -]|$)", line):
            raise AmbiguousPrefix("A 220 server greeting alone is ambiguous between SMTP and FTP; a client command is required", ("smtp", "ftp"))
        is_http = re.fullmatch(TOKEN + rb" [\x21-\x7e]+ HTTP/1\.[01]", line) or re.fullmatch(rb"HTTP/1\.[01] [1-5][0-9]{2} .*", line)
        if not is_http:
            if line[:1] in (b'+', b'-') and pop3_greeting(line):
                self.family = self.protocol_name = 'pop3'
                self.scope = 'protocol_header'
                self.done = True
                self.reason = 'POP3 server status line validated; mailbox and authentication unverified'
                return
            if imap_command(line, self.config):
                self.family = self.protocol_name = 'imap'
                self.scope = 'initial_message'
                self.done = True
                self.reason = 'IMAP tagged client command validated; arguments and credentials are not inspected or emitted'
                return
            classified = command_line(line)
            if classified is not None:
                family, candidates = classified
                if family is None:
                    raise AmbiguousPrefix("Command shared by FTP and POP3; the server greeting decides", candidates)
                self.family = self.protocol_name = family
                self.scope = 'initial_message'
                self.done = True
                self.reason = ('FTP client command syntax validated; arguments are not emitted, transfers unverified' if family == 'ftp'
                               else 'POP3 client command syntax validated; credentials are not emitted, mailbox unverified')
                return
        self.family = "http"
        # First-line framing has resolved the family. Later HTTP headers need
        # no shared-text dispatch, regardless of how many protocols are added.
        self._line_handler = LineParser.consume_line
        return self._line_handler(self, line)

    def _consume_control(self, line):
        self.control.consume_line(line)
        self.done, self.reason = self.control.done, self.control.reason


class HTTP2Parser:
    """Client preface AND complete initial SETTINGS; no HPACK or stream decoding."""
    protocol_name = "http/2"

    def __init__(self, config):
        self.config = config
        self.prefix_position = 0
        self.header = bytearray()
        self.payload = bytearray()
        self.length = None
        self.done = False
        self.fingerprints = ()
        self.reason = "Waiting for complete HTTP/2 client preface and initial SETTINGS"

    def feed(self, data):
        pos = 0
        if self.prefix_position < len(H2_PREFACE):
            amount = min(len(H2_PREFACE) - self.prefix_position, len(data))
            if data[:amount] != H2_PREFACE[self.prefix_position:self.prefix_position + amount]:
                raise ParseError("Invalid HTTP/2 client preface")
            self.prefix_position += amount
            pos += amount
            if self.prefix_position < len(H2_PREFACE):
                return pos
        if len(self.header) < 9:
            amount = min(9 - len(self.header), len(data) - pos)
            self.header.extend(data[pos:pos + amount])
            pos += amount
            if len(self.header) < 9:
                return pos
            self.length = int.from_bytes(self.header[:3], "big")
            stream = int.from_bytes(self.header[5:9], "big") & 0x7fffffff
            if self.header[3] != 4 or self.header[4] & 1 or stream:
                raise ParseError("Initial HTTP/2 frame must be non-ACK SETTINGS on stream zero")
            if self.length > 16384 or self.length % 6:
                raise ParseError("Invalid initial SETTINGS payload length")
            if 33 + self.length > self.config.max_bytes:
                raise BudgetError("Initial HTTP/2 SETTINGS exceeds byte budget")
        amount = min(self.length - len(self.payload), len(data) - pos)
        self.payload.extend(data[pos:pos + amount])
        pos += amount
        if len(self.payload) == self.length:
            settings = []
            for offset in range(0, self.length, 6):
                setting = int.from_bytes(self.payload[offset:offset + 2], "big")
                value = int.from_bytes(self.payload[offset + 2:offset + 6], "big")
                settings.append((setting, value))
                if setting == 2 and value not in (0, 1):
                    raise ParseError("Invalid SETTINGS_ENABLE_PUSH")
                if setting == 4 and value > 0x7fffffff:
                    raise ParseError("Invalid SETTINGS_INITIAL_WINDOW_SIZE")
                if setting == 5 and not 16384 <= value <= 0xffffff:
                    raise ParseError("Invalid SETTINGS_MAX_FRAME_SIZE")
                # Unknown setting identifiers and repeated settings are allowed.
            if self.config.fingerprints:
                from .fingerprints import h2_settings_fingerprint
                self.fingerprints = (("h2_settings", h2_settings_fingerprint(settings), "settings_frame"),)
            self.done = True
            self.reason = "HTTP/2 client preface and initial SETTINGS validated; headers, HPACK and later frames not inspected"
        return pos


class Socks5Parser:
    """Client greeting offering no-auth, followed by a complete client request.

    Client-direction bytes only. The intervening server method-selection is not
    observed here; no claim is made that authentication or the tunnel succeeded.
    Authentication subnegotiation and server-only streams are unsupported.
    """
    protocol_name = "socks5"

    def __init__(self, config):
        self.config = config
        self.buffer = bytearray()
        self.stage = "greeting"
        self.needed = 2
        self.command = None
        self.atyp = None
        self.address = None
        self.extra_evidence = ()
        self.contexts = None
        self.done = False
        self.reason = "Waiting for SOCKS5 client greeting and request"

    def feed(self, data):
        pos = 0
        while pos < len(data) and not self.done:
            amount = min(self.needed - len(self.buffer), len(data) - pos)
            self.buffer.extend(data[pos:pos + amount])
            pos += amount
            if len(self.buffer) < self.needed:
                break
            field = bytes(self.buffer)
            self.buffer.clear()
            if self.stage == "greeting":
                if field[0] != 5 or field[1] == 0:
                    raise ParseError("Invalid SOCKS5 client greeting version/method count")
                self.stage, self.needed = "methods", field[1]
            elif self.stage == "methods":
                if 255 in field:
                    raise ParseError("No-acceptable-methods is a server response, not a client method")
                if 0 not in field:
                    raise UnsupportedPrefix("SOCKS5 authentication subnegotiation is not supported")
                self.stage, self.needed = "request", 4
            elif self.stage == "request":
                if field[0] != 5 or field[1] not in (1, 2, 3) or field[2] != 0 or field[3] not in (1, 3, 4):
                    raise ParseError("Invalid SOCKS5 request header")
                self.command, self.atyp = field[1], field[3]
                self.stage = "domain_length" if self.atyp == 3 else "address"
                self.needed = {1: 4, 3: 1, 4: 16}[self.atyp]
            elif self.stage == "domain_length":
                if field[0] == 0:
                    raise ParseError("Empty SOCKS5 destination name")
                self.stage, self.needed = "address", field[0]
            elif self.stage == "address":
                try:
                    self.address = (normalize_hostname(field.decode("ascii")) if self.atyp == 3
                                    else str(ipaddress.ip_address(field)))
                except (ValueError, UnicodeError):
                    raise ParseError("Invalid or unsupported SOCKS5 destination") from None
                self.stage, self.needed = "port", 2
            else:
                port = int.from_bytes(field, "big")
                self.done = True
                self.reason = "SOCKS5 client greeting and request validated; method selection, server reply and tunneled protocol unverified"
                self.extra_evidence = (
                    ("socks_command", {1: "CONNECT", 2: "BIND", 3: "UDP_ASSOCIATE"}[self.command], "socks_request", "asserted"),
                    ("socks_target", self.address, "socks_request", "asserted"),
                    ("socks_port", str(port), "socks_request", "asserted"),
                )
                if self.config.retain_contexts:
                    self.contexts = {"socks-req-target": self.address.encode("ascii"), "socks-req-port": port}
        return pos
