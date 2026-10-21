"""GIOP 1.2 unfragmented KeyAddr Request / LocateRequest structural profiles."""
import re
from .cdr import CDRCursor
from .framing import FrameParser
from .parsers import BudgetError, ParseError
from .extended import UnsupportedPrefix

_OPERATION = re.compile(rb'[A-Za-z_][A-Za-z0-9_]*\Z')


_REPLY_STATUS = ('no-exception', 'user-exception', 'system-exception', 'location-forward', 'location-forward-perm', 'needs-addressing-mode')
_LOCATE_STATUS = ('unknown-object', 'object-here', 'object-forward', 'object-forward-perm', 'loc-system-exception', 'loc-needs-addressing-mode')


class GIOPParser(FrameParser):
    header_size = 12
    protocol_name = 'giop/1.2'
    scope = 'request_header'

    def frame_size(self, data):
        if data[:4] != b'GIOP':
            raise ParseError('Invalid GIOP magic')
        if data[4:6] != b'\x01\x02':
            raise UnsupportedPrefix('GIOP profile supports version 1.2 only')
        if data[6] & ~1:
            raise UnsupportedPrefix('Fragmented GIOP and reserved flags outside profile')
        if data[7] not in (0, 1, 3, 4):
            raise UnsupportedPrefix('GIOP profile requires Request, Reply, LocateRequest or LocateReply')
        self.byteorder = 'little' if data[6] else 'big'
        size = int.from_bytes(data[8:12], self.byteorder)
        if size < {0: 24, 1: 12, 3: 12, 4: 8}[data[7]]:
            raise ParseError('GIOP body too short for supported message header')
        return size + 12

    def validate(self, data):
        cursor = CDRCursor(data, self.byteorder)
        cursor.uint(4)  # Request ID is opaque and never emitted.
        if data[7] in (1, 4):
            return self._reply(data, cursor)
        request = data[7] == 0
        if request:
            if cursor.uint(1) not in (0, 1, 3):
                raise UnsupportedPrefix('Unsupported GIOP response flags')
            if cursor.take(3) != bytes(3):
                raise UnsupportedPrefix('GIOP profile requires zero reserved request bytes')
        if cursor.uint(2) != 0:
            raise UnsupportedPrefix('GIOP profile requires KeyAddr target')
        cursor.sequence(self.config.max_line)  # Opaque object key, including empty.
        if request:
            operation = cursor.string(self.config.max_line)
            if not _OPERATION.fullmatch(operation):
                raise UnsupportedPrefix('GIOP operation outside ASCII identifier profile')
            count = cursor.uint(4)
            if count > min(self.config.max_headers, 128):
                raise BudgetError('GIOP service-context count exceeds budget')
            # Each context needs at least its ID and sequence length; preflight
            # even a malicious count before iterating. Context contents stay opaque.
            if count > (len(data) - cursor.pos) // 8:
                raise ParseError('Truncated GIOP service-context list')
            for _ in range(count):
                cursor.uint(4)
                cursor.sequence(self.config.max_bytes)
            if cursor.pos < len(data):
                cursor.align(8)
                if cursor.pos == len(data):
                    raise ParseError('GIOP empty request body must not have padding')
                # Argument layout requires the IDL. Only framing is asserted.
            self.reason = 'GIOP 1.2 KeyAddr request header validated; arguments, contexts and server unverified'
        else:
            if cursor.pos != len(data):
                raise ParseError('Unexpected bytes after GIOP LocateRequest')
            self.scope = 'locate_request'
            self.reason = 'GIOP 1.2 KeyAddr LocateRequest validated; object identity and server unverified'
        self.extra_evidence = (('giop_message', 'request' if request else 'locate-request', 'header', 'structural'),)

    def _reply(self, data, cursor):
        """Reply (status, service contexts, opaque body) or LocateReply (status, opaque body) (v0.47)."""
        status = cursor.uint(4)
        if data[7] == 1:
            if status > 5:
                raise ParseError('GIOP reply status outside 0..5')
            count = cursor.uint(4)
            if count > min(self.config.max_headers, 128):
                raise BudgetError('GIOP service-context count exceeds budget')
            if count > (len(data) - cursor.pos) // 8:
                raise ParseError('Truncated GIOP service-context list')
            for _ in range(count):
                cursor.uint(4)
                cursor.sequence(self.config.max_bytes)
            if cursor.pos < len(data):
                cursor.align(8)
                if cursor.pos == len(data):
                    raise ParseError('GIOP empty reply body must not have padding')
            label, name = _REPLY_STATUS[status], 'reply'
            self.scope = 'reply_header'
            self.reason = 'GIOP 1.2 Reply header validated; status reported, body and contexts opaque'
        else:
            if status > 5:
                raise ParseError('GIOP locate status outside 0..5')
            if status in (0, 1) and cursor.pos != len(data):
                raise ParseError('GIOP LocateReply without a body for UNKNOWN_OBJECT/OBJECT_HERE')
            label, name = _LOCATE_STATUS[status], 'locate-reply'
            self.scope = 'locate_reply'
            self.reason = 'GIOP 1.2 LocateReply validated; status reported, forwarded reference opaque'
        self.extra_evidence = (('giop_message', name, 'header', 'structural'), ('giop_status', label, 'header', 'asserted'))
