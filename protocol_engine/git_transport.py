"""Native Git request framing; no repository identity or packfile interpretation.

Sources: git-scm.com/docs/pack-protocol and /docs/protocol-common.
"""
import ipaddress
import re
from .framing import FrameParser
from .parsers import BudgetError, ParseError
from .extended import TextParser, UnsupportedPrefix
from .model import normalize_hostname

HEX = frozenset(b'0123456789abcdef')
COMMANDS = (b'git-upload-pack', b'git-receive-pack', b'git-upload-archive')


class GitParser(FrameParser):
    header_size = 4
    family = 'git'
    protocol_name = 'git'
    scope = 'service_request'

    def frame_size(self, header):
        if any(byte not in HEX for byte in header):
            raise ParseError('Invalid lowercase Git pkt-line length')
        size = int(header, 16)
        if not 5 <= size <= 65520:
            raise ParseError('Git request requires a data packet within pkt-line limits')
        return size

    def validate(self, data):
        body = data[4:]
        if not body.endswith(b'\0'):
            raise ParseError('Git service request must end with NUL')
        if body.count(b'\0') > min(self.config.max_headers, 16) + 3:
            raise BudgetError('Git request field count exceeds budget')
        fields = body.split(b'\0')[:-1]
        command, separator, path = fields[0].partition(b' ')
        if command not in COMMANDS or not separator or not path:
            raise ParseError('Invalid Git service command or empty pathname')
        if len(fields[0]) + 5 > self.config.max_line:
            raise BudgetError('Git initial request field exceeds line budget')
        if any(byte < 32 or byte == 127 for byte in path):
            raise UnsupportedPrefix('Control characters in Git pathname outside supported profile')
        rest = fields[1:]
        if rest and rest[0].startswith(b'host='):
            authority = rest.pop(0)[5:]
            if len(authority) > 260:
                raise BudgetError('Git virtual host exceeds profile budget')
            try:
                host, colon, port = authority.decode('ascii').partition(':')
                if colon and (not port.isascii() or not port.isdecimal() or len(port) > 5 or not 1 <= int(port) <= 65535):
                    raise ValueError()
                try:
                    normalize_hostname(host)
                except ValueError:
                    ipaddress.IPv4Address(host)
            except (UnicodeError, ValueError):
                raise ParseError('Invalid Git ASCII DNS/IPv4 virtual host or port') from None
        version = None
        if rest:
            if rest.pop(0) != b'' or not rest:
                raise ParseError('Git extra parameters require a NUL separator and fields')
            if len(rest) > min(self.config.max_headers, 16):
                raise BudgetError('Git extra parameter count exceeds budget')
            keys = set()
            for parameter in rest:
                if len(parameter) > min(self.config.max_line, 512):
                    raise BudgetError('Git extra parameter exceeds width budget')
                if not re.fullmatch(rb'[A-Za-z0-9][A-Za-z0-9_-]*(?:=[\x21-\x7e]+)?', parameter):
                    raise UnsupportedPrefix('Git extra parameter outside supported ASCII profile')
                key, separator, value = parameter.partition(b'=')
                if len(key) > 64:
                    raise BudgetError('Git parameter key exceeds budget')
                if key in keys:
                    raise UnsupportedPrefix('Duplicate Git extra parameter outside supported profile')
                keys.add(key)
                if key == b'version':
                    if not separator or value not in (b'1', b'2'):
                        raise UnsupportedPrefix('Unsupported Git protocol version offer')
                    version = value.decode('ascii')
        self.extra_evidence = (() if version is None else
                               (('offered_version', version, 'service_request', 'offered'),))
        self.reason = 'Native Git service request framing validated; repository, server, version negotiation and packfile unverified'


class GitTextParser:
    """Resolve ASCII pkt-line/HTTP-method overlap without running both parsers.

    Scan new bytes once for the first NUL or LF. Buffer at most max_line bytes,
    replay that bounded field once into the selected parser, then delegate.
    This route is internal; an explicit git hint always uses GitParser directly.
    """
    def __init__(self, config):
        self.config = config
        self.pending = bytearray()
        self.child = None

    @property
    def done(self):
        return self.child is not None and self.child.done

    def __getattr__(self, name):
        if self.child is None:
            raise AttributeError(name)
        return getattr(self.child, name)

    def feed(self, data):
        if self.child is not None:
            return self.child.feed(data)
        previous = len(self.pending)
        allowance = self.config.max_line - previous
        nul = data.find(b'\0', 0, allowance)
        lf = data.find(b'\n', 0, allowance)
        ends = [index for index in (nul, lf) if index >= 0]
        amount = min(ends) + 1 if ends else min(len(data), allowance)
        self.pending.extend(data[:amount])
        if not ends:
            if len(data) > amount or len(self.pending) >= self.config.max_line:
                raise BudgetError('Git/text discriminator exceeds line budget')
            return amount
        self.child = GitParser(self.config) if nul == amount-1 else TextParser(self.config)
        consumed = self.child.feed(bytes(self.pending))
        self.pending.clear()
        current = max(0, consumed - previous)
        if not self.child.done:
            current += self.child.feed(data[amount:])
        return current
