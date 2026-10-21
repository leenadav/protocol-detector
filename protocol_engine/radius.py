"""Explicit-candidate RADIUS Access-Request structural profile (RFC2865).

No shared secrets, password recovery, HMAC verification or response correlation.
Only the listed legacy attributes plus Message-Authenticator framing are covered.
"""
from .datagram_result import DatagramMatch
from .model import Evidence
from .parsers import BudgetError, ParseError
from .extended import UnsupportedPrefix

_FIXED_FOUR = frozenset((4, 5, 6, 7, 8, 9, 12, 13, 14, 61, 62))
_STRINGS = frozenset((1, 19, 24, 30, 31, 32, 33, 60))
_REPEATABLE = frozenset((13, 14, 26, 33))
_SUPPORTED = _FIXED_FOUR | _STRINGS | frozenset((2, 3, 26, 80))
# Responses (RFC 2865 4.2-4.4): attributes a server may return, per code.
_RESPONSE_FOUR = frozenset((6, 7, 8, 9, 12, 13, 14, 27, 28, 29, 85))
_RESPONSE_STRINGS = frozenset((11, 18, 24, 25, 79, 87))
_RESPONSE_SUPPORTED = _RESPONSE_FOUR | _RESPONSE_STRINGS | frozenset((26, 33, 80))
_REJECT_ALLOWED = frozenset((18, 26, 33, 79, 80))
_CHALLENGE_ALLOWED = frozenset((18, 24, 26, 27, 28, 33, 79, 80))
_CODES = {1: "access-request", 2: "access-accept", 3: "access-reject", 11: "access-challenge"}


def radius(data, config):
    if len(data) < 20:
        raise ParseError('Truncated RADIUS header')
    if data[0] not in _CODES:
        raise UnsupportedPrefix('RADIUS profile supports Access-Request, Accept, Reject and Challenge')
    length = int.from_bytes(data[2:4], 'big')
    if not 20 <= length <= 4096 or length > len(data):
        raise ParseError('Invalid RADIUS packet length')
    if length != len(data):
        raise UnsupportedPrefix('RADIUS trailing datagram padding outside conservative profile')
    if data[0] != 1:
        return _response(data, length, config)
    pos, count, seen = 20, 0, set()
    while pos < length:
        count += 1
        if count > min(config.max_headers, 128):
            raise BudgetError('RADIUS attribute count exceeds budget')
        if pos + 2 > length:
            raise ParseError('Truncated RADIUS attribute header')
        kind, size = data[pos], data[pos + 1]
        if size < 2 or pos + size > length:
            raise ParseError('Invalid RADIUS attribute boundary')
        if kind not in _SUPPORTED:
            raise UnsupportedPrefix('RADIUS attribute outside supported Access-Request profile')
        if kind in seen and kind not in _REPEATABLE:
            raise ParseError('Duplicate singleton RADIUS attribute')
        seen.add(kind)
        value_size = size - 2
        if kind in _FIXED_FOUR and value_size != 4:
            raise ParseError('RADIUS address/integer attribute must contain four bytes')
        if kind in _STRINGS and not value_size:
            raise ParseError('RADIUS string attribute cannot be empty')
        if kind == 2 and (not 16 <= value_size <= 128 or value_size % 16):
            raise ParseError('Invalid RADIUS User-Password ciphertext length')
        if kind == 3 and value_size != 17:
            raise ParseError('RADIUS CHAP-Password must contain identifier and sixteen-byte response')
        if kind == 26 and (value_size < 5 or data[pos + 2] != 0):
            raise ParseError('Invalid RADIUS vendor identifier or empty vendor payload')
        if kind == 80 and value_size != 16:
            raise ParseError('RADIUS Message-Authenticator must contain sixteen bytes')
        pos += size
    if not ({4, 32} & seen):
        raise ParseError('RADIUS Access-Request requires NAS address or identifier')
    if not ({2, 3, 24} & seen):
        raise UnsupportedPrefix('RADIUS profile requires PAP, CHAP or State authentication fields')
    if 2 in seen and 3 in seen:
        raise ParseError('RADIUS Access-Request cannot combine User-Password and CHAP-Password')
    return DatagramMatch('RADIUS Access-Request and supported attributes structurally validated; '
                         'authenticators, password values, vendor contents and authorization unverified',
                         application_protocol='radius', evidence=_evidence('access-request'))


def _evidence(code):
    return (Evidence('application_protocol', 'radius', 'wire', 'structural'), Evidence('radius_code', code, 'wire', 'structural'))


def _response(data, length, config):
    """Access-Accept/Reject/Challenge: attribute framing per code; values never emitted (v0.46)."""
    code = data[0]
    allowed = _RESPONSE_SUPPORTED if code == 2 else (_REJECT_ALLOWED if code == 3 else _CHALLENGE_ALLOWED)
    pos, count, seen = 20, 0, set()
    while pos < length:
        count += 1
        if count > min(config.max_headers, 128):
            raise BudgetError('RADIUS attribute count exceeds budget')
        if pos + 2 > length:
            raise ParseError('Truncated RADIUS attribute header')
        kind, size = data[pos], data[pos + 1]
        if size < 2 or pos + size > length:
            raise ParseError('Invalid RADIUS attribute boundary')
        if kind not in allowed:
            raise UnsupportedPrefix('RADIUS attribute outside the response profile for this code')
        if kind in seen and kind not in _REPEATABLE and kind not in (18, 79, 25):
            raise ParseError('Duplicate singleton RADIUS attribute')
        seen.add(kind)
        value_size = size - 2
        if kind in _RESPONSE_FOUR and value_size != 4:
            raise ParseError('RADIUS address/integer attribute must contain four bytes')
        if kind in _RESPONSE_STRINGS and not value_size:
            raise ParseError('RADIUS string attribute cannot be empty')
        if kind == 26 and (value_size < 5 or data[pos + 2] != 0):
            raise ParseError('Invalid RADIUS vendor identifier or empty vendor payload')
        if kind == 80 and value_size != 16:
            raise ParseError('RADIUS Message-Authenticator must contain sixteen bytes')
        pos += size
    if code == 11 and 24 not in seen:
        raise ParseError('RADIUS Access-Challenge requires a State attribute')
    return DatagramMatch('RADIUS {} attribute framing validated; authenticator, values and authorization unverified'.format(_CODES[code]),
                         application_protocol='radius', evidence=_evidence(_CODES[code]))
