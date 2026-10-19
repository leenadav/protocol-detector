"""Bounded NATS and IMAP first-line validation, called after shared framing.

No credentials, peer identities or arbitrary JSON values escape into evidence.
Unknown extension fields are accepted only within the same syntax/resource bounds.
"""
import json
import math
import re
from .parsers import BudgetError, ParseError


def _integer(value):
    if len(value.lstrip('-')) > 20:
        raise BudgetError("JSON integer exceeds 20-digit profile")
    return int(value)


def _float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ParseError("Non-finite JSON number")
    return number


def _constant(value):
    raise ParseError("Non-standard JSON constant")


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ParseError("Duplicate JSON member")
        result[key] = value
    return result


def bounded_json(data, max_fields):
    # Preflight BEFORE json.loads: Python 3.9 has no integer digit limit, and
    # the JSON decoder would otherwise recurse on arbitrarily deep input.
    depth = tokens = 0
    quoted = escaped = False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            tokens += 1
            if depth > 16:
                raise BudgetError("JSON nesting exceeds 16 levels")
        elif byte in (93, 125):
            depth -= 1
        elif byte in (44, 58):
            tokens += 1
        if tokens > max_fields * 4:
            raise BudgetError("JSON structure exceeds field budget")
    try:
        value = json.loads(data.decode('utf-8'), object_pairs_hook=_object,
                           parse_int=_integer, parse_float=_float, parse_constant=_constant)
    except (UnicodeError, json.JSONDecodeError):
        raise ParseError("Invalid UTF-8 JSON object") from None
    if not isinstance(value, dict):
        raise ParseError("Expected JSON object")
    pending = [value]
    nodes = 0
    while pending:
        node = pending.pop()
        nodes += 1
        if nodes > max_fields * 4:
            raise BudgetError("JSON values exceed field budget")
        if isinstance(node, dict):
            if len(node) > max_fields:
                raise BudgetError("JSON member count exceeds field budget")
            pending.extend(node.keys())
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
        elif isinstance(node, str):
            try:
                node.encode('utf-8')
            except UnicodeError:
                raise ParseError("Unpaired surrogate in JSON string") from None
    return value


def nats(command, data, config):
    obj = bounded_json(data, min(config.max_headers, 128))
    required = ({'server_id': str, 'version': str, 'go': str, 'host': str,
                 'port': int, 'max_payload': int} if command == b'INFO' else
                {'verbose': bool, 'pedantic': bool, 'tls_required': bool,
                 'lang': str, 'version': str})
    for key, kind in required.items():
        if key not in obj or type(obj[key]) is not kind or kind is str and not obj[key]:
            raise ParseError("Missing or invalid NATS handshake field")
    if command == b'INFO':
        if not 1 <= obj['port'] <= 65535 or not 0 < obj['max_payload'] <= 0x7fffffffffffffff:
            raise ParseError("NATS server limits outside supported range")
    for key in ('verbose', 'pedantic', 'tls_required', 'auth_required', 'tls_verify',
                'tls_available', 'echo', 'headers', 'no_responders', 'ldm', 'jetstream'):
        if key in obj and type(obj[key]) is not bool:
            raise ParseError("Invalid NATS boolean field")
    for key in ('proto', 'protocol'):
        if key in obj and (type(obj[key]) is not int or obj[key] not in (0, 1)):
            raise ParseError("Unsupported NATS protocol level")
    for key in ('server_id', 'server_name', 'version', 'go', 'host', 'lang', 'name',
                'user', 'pass', 'auth_token', 'sig', 'jwt', 'nkey', 'nonce', 'cluster', 'domain'):
        if key in obj and type(obj[key]) is not str:
            raise ParseError("Invalid NATS string field")
    for key in ('connect_urls', 'ws_connect_urls'):
        if key in obj and (type(obj[key]) is not list or any(type(item) is not str for item in obj[key])):
            raise ParseError("Invalid NATS endpoint list")


_IMAP_GREETING = re.compile(rb'\* (?:OK|PREAUTH) \[CAPABILITY ([^\]]+)\] (.+)', re.I)
_IMAP_CAPABILITY = re.compile(rb'\* CAPABILITY (.+)', re.I)
_IMAP_ATOM = re.compile(rb'[^\x00-\x20\x7f-\xff(){%*"\\\]]+')


def imap_capability(line, config):
    match = _IMAP_GREETING.fullmatch(line) or _IMAP_CAPABILITY.fullmatch(line)
    if match is None:
        return False
    capabilities = match.group(1).split(b' ')
    if len(capabilities) > min(config.max_headers, 128):
        raise BudgetError("IMAP capability count exceeds budget")
    if any(not _IMAP_ATOM.fullmatch(item) for item in capabilities):
        raise ParseError("Invalid IMAP capability atom")
    if len(match.groups()) == 2:
        # Greeting text is UTF-8 in rev2; no literal, CR, LF or NUL framing.
        text = match.group(2)
        if any(byte < 32 or byte == 127 for byte in text):
            raise ParseError("Invalid IMAP greeting text")
        try:
            text.decode('utf-8')
        except UnicodeError:
            raise ParseError("Invalid IMAP greeting encoding") from None
    return any(item.upper() in (b'IMAP4REV1', b'IMAP4REV2') for item in capabilities)
