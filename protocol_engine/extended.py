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
    SMTP_COMMANDS = frozenset((b"EHLO", b"HELO", b"MAIL", b"RCPT", b"DATA", b"RSET", b"NOOP", b"QUIT", b"VRFY", b"EXPN",
                               b"HELP", b"AUTH", b"BDAT", b"STARTTLS"))

    def __init__(self, config):
        super().__init__(config, "http")
        self.family = "text"
        self.extra_evidence = ()
        self.control = None
        self.watched = 0

    def feed(self, data):
        if self.continues:
            return LineParser.feed(self, data)
        return super().feed(data)

    def _consume_smtp(self, line):
        """After EHLO: watch a bounded number of client commands for STARTTLS (RFC 3207)."""
        self.watched += 1
        if len(line) + 2 > 512:
            raise ParseError("SMTP command exceeds 512 bytes")
        verb = line.split(b" ", 1)[0].upper()
        if verb not in self.SMTP_COMMANDS:
            raise ParseError("Unexpected SMTP command")
        if verb == b"STARTTLS":
            if line.upper() != b"STARTTLS":
                raise ParseError("STARTTLS takes no parameters")
            self.shift = ("starttls", "tls")
            self.continues = False
            return
        if verb != b"NOOP" or self.watched >= min(self.config.max_headers, 8):
            self.continues = False  # MAIL/AUTH/... begin the plaintext session; stop watching

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
            # Keep reading commands for STARTTLS; the identification stands either way.
            self.continues = True
            self._line_handler = TextParser._consume_smtp
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
                if line.split(b" ")[1].upper() == b"STARTTLS":
                    self.shift = ("starttls", "tls")
                return
            classified = command_line(line)
            if classified is not None:
                family, candidates, shift = classified
                if family is None:
                    raise AmbiguousPrefix("Command shared by FTP and POP3; the server greeting decides", candidates)
                self.family = self.protocol_name = family
                self.scope = 'initial_message'
                self.done = True
                self.shift = shift
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


class HTTP2ServerParser(HTTP2Parser):
    """Server side of an h2c upgrade: the first frame is SETTINGS without any preface (RFC 7540 3.2).

    Reached only through the h2c-upgrade shift of a 101 response or an explicit
    candidate; the SETTINGS fingerprint is a client characteristic and is not
    derived for a server.
    """

    def __init__(self, config):
        super().__init__(config)
        self.prefix_position = len(H2_PREFACE)
        self.reason = "Waiting for the server's initial HTTP/2 SETTINGS after the h2c upgrade"

    def feed(self, data):
        consumed = super().feed(data)
        if self.done:
            self.fingerprints = ()
            self.reason = "HTTP/2 server SETTINGS after the h2c upgrade validated; headers, HPACK and later frames not inspected"
        return consumed


class Socks5Parser:
    """SOCKS5 initial exchange of one direction.

    Client: greeting offering no-auth followed by the complete request (CONNECT,
    BIND or UDP ASSOCIATE with an IPv4, IPv6 or domain destination). Server
    (v0.41): method selection (no-auth or username/password) followed by the
    complete reply. Neither direction claims that authentication or the tunnel
    succeeded; subnegotiation bytes are outside the profile.
    """
    protocol_name = "socks5"
    MAX_BYTES = 2 + 255 + 4 + 1 + 255 + 2      # longest client exchange
    _REPLIES = ("succeeded", "general-failure", "not-allowed", "network-unreachable", "host-unreachable",
                "connection-refused", "ttl-expired", "command-not-supported", "address-type-not-supported")

    def __init__(self, config):
        self.config = config
        self.buffer = bytearray()
        self.scope = "initial_message"
        self.extra_evidence = ()
        self.contexts = None
        self.done = False
        self.reason = "Waiting for SOCKS5 greeting and request"

    def feed(self, data):
        if self.done:
            return 0
        before = len(self.buffer)
        self.buffer.extend(data[:self.MAX_BYTES - before])
        end = self._parse(self.buffer)
        if end is None:
            if len(self.buffer) >= self.MAX_BYTES:
                raise ParseError("SOCKS5 exchange exceeds its maximum size")
            return len(self.buffer) - before
        self.done = True
        self.buffer = bytearray()
        return end - before

    def _parse(self, buf):
        """Return the exchange length once complete, None while bytes are missing."""
        if len(buf) < 2:
            return None
        if buf[0] != 5:
            raise ParseError("Invalid SOCKS5 version")
        second = buf[1]
        if second == 0 or (second == 2 and len(buf) >= 5 and buf[2] == 5 and buf[4] == 0):
            return self._server(buf)
        if second == 2 and len(buf) < 5:
            return None          # a client offering two methods or a server selecting username/password
        return self._client(buf)

    def _address(self, buf, pos, what):
        """Return (atyp, address text or None, position after the port) or None when incomplete."""
        if pos + 1 > len(buf):
            return None
        atyp = buf[pos - 1]
        if atyp == 3:
            length = buf[pos]
            if length == 0:
                raise ParseError("Empty SOCKS5 " + what)
            pos += 1
        else:
            length = 4 if atyp == 1 else 16
        if pos + length + 2 > len(buf):
            return None
        field = bytes(buf[pos:pos + length])
        try:
            address = normalize_hostname(field.decode("ascii")) if atyp == 3 else str(ipaddress.ip_address(field))
        except (ValueError, UnicodeError):
            raise ParseError("Invalid or unsupported SOCKS5 " + what) from None
        return atyp, address, pos + length + 2

    def _client(self, buf):
        count = buf[1]
        if len(buf) < 2 + count:
            return None
        methods = buf[2:2 + count]
        if 255 in methods:
            raise ParseError("No-acceptable-methods is a server response, not a client method")
        if 0 not in methods:
            raise UnsupportedPrefix("SOCKS5 authentication subnegotiation is not supported")
        request = 2 + count
        if len(buf) < request + 4:
            return None
        if buf[request] != 5 or buf[request + 1] not in (1, 2, 3) or buf[request + 2] != 0 or buf[request + 3] not in (1, 3, 4):
            raise ParseError("Invalid SOCKS5 request header")
        parsed = self._address(buf, request + 4, "destination")
        if parsed is None:
            return None
        _, address, end = parsed
        port = int.from_bytes(buf[end - 2:end], "big")
        self.reason = "SOCKS5 client greeting and request validated; method selection, server reply and tunneled protocol unverified"
        self.extra_evidence = (
            ("socks_command", {1: "CONNECT", 2: "BIND", 3: "UDP_ASSOCIATE"}[buf[request + 1]], "socks_request", "asserted"),
            ("socks_target", address, "socks_request", "asserted"),
            ("socks_port", str(port), "socks_request", "asserted"),
        )
        if self.config.retain_contexts:
            self.contexts = {"socks-req-target": address.encode("ascii"), "socks-req-port": port}
        return end

    def _server(self, buf):
        if len(buf) < 6:
            return None
        if buf[2] != 5 or buf[3] > 8 or buf[4] != 0 or buf[5] not in (1, 3, 4):
            raise ParseError("Invalid SOCKS5 server reply header")
        parsed = self._address(buf, 6, "bound address")
        if parsed is None:
            return None
        _, _, end = parsed
        self.scope = "negotiation_response"
        self.reason = "SOCKS5 server method selection and reply validated; bound address not emitted, tunneled protocol unverified"
        self.extra_evidence = (("socks_method", "no-authentication" if buf[1] == 0 else "username-password", "socks_reply", "structural"),
                               ("socks_reply", self._REPLIES[buf[3]], "socks_reply", "asserted"))
        return end
