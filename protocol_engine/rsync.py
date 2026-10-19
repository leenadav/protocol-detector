"""Bounded rsync daemon greeting profile; no file transfer or authentication."""
import re
from .parsers import BudgetError, ParseError
from .extended import UnsupportedPrefix

_GREETING = re.compile(rb'@RSYNCD: ([0-9]{2})(?:\.([0-9]{1,3}))?(?: ([a-z0-9-]+(?: [a-z0-9-]+)*))?\n')


class RsyncParser:
    protocol_name = 'rsync'
    scope = 'protocol_header'

    def __init__(self, config):
        self.config = config
        self.line = bytearray()
        self.done = False
        self.reason = 'Waiting for complete rsync daemon greeting'

    def feed(self, data):
        newline = data.find(b'\n')
        amount = len(data) if newline < 0 else newline + 1
        if len(self.line) + amount > min(self.config.max_line, 512):
            raise BudgetError('Rsync daemon greeting exceeds line budget')
        self.line.extend(data[:amount])
        if newline < 0:
            return amount
        match = _GREETING.fullmatch(self.line)
        if match is None:
            raise ParseError('Invalid rsync daemon greeting framing')
        version, sub, digests = match.groups()
        version = int(version)
        if not 27 <= version <= 32 or (sub is not None and int(sub) != 0):
            raise UnsupportedPrefix('Rsync profile supports final daemon protocols 27 through 32')
        if version >= 30 and sub is None:
            raise ParseError('Rsync protocol 30 and above require subprotocol')
        if version >= 32 and digests is None:
            raise ParseError('Rsync protocol 32 requires authentication digest offers')
        if digests is not None:
            names = digests.split(b' ')
            if len(names) > min(self.config.max_headers, 16) or any(len(name) > 32 for name in names):
                raise BudgetError('Rsync digest offer count or width exceeds budget')
            if len(set(names)) != len(names):
                raise UnsupportedPrefix('Duplicate rsync digest offers outside conservative profile')
        self.extra_evidence = (('rsync_protocol', str(version), 'daemon_greeting', 'offered'),)
        self.line.clear()
        self.done = True
        self.reason = 'Rsync daemon greeting validated; version/digest offers only, no authentication or file transfer validation'
        return amount
