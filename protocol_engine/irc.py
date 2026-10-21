"""IRC (RFC 1459/2812) first-line profiles: client registration lines and ':'-prefixed server lines.

Only the message grammar is validated: an optional ':'-prefixed origin, a command
that is either letters or three digits, at most 15 middle parameters and one
trailing parameter, all within 512 bytes. Nicknames, user names, channel names,
server names, passwords and message text are checked for shape and never emitted;
only the closed command class is reported. Registration (PASS/NICK/USER/CAP) and
the server's NOTICE/PING/numeric replies are the initial messages; the IRC
session itself (JOIN, PRIVMSG, modes, CTCP, DCC) is outside the profile.
"""
import re
from .parsers import BudgetError, LineParser, ParseError, UnsupportedPrefix

IRC_LINE_LIMIT = 512                                   # RFC 2812 2.3: 510 characters plus CRLF
_NICK = re.compile(rb"[A-Za-z\[\]\\`_^{|}][A-Za-z0-9\[\]\\`_^{|}\-]{0,63}")
_USER = re.compile(rb"[^\x00\x0a\x0d\x20@]{1,64}")
_HOST = re.compile(rb"[A-Za-z0-9](?:[A-Za-z0-9\-.:_/]{0,254})")
_MIDDLE = re.compile(rb"[^\x00\x0a\x0d\x20:][^\x00\x0a\x0d\x20]{0,509}")
_TRAILING = re.compile(rb"[^\x00\x0a\x0d]{0,510}")
_CAP_SUBCOMMANDS = frozenset((b"LS", b"LIST", b"REQ", b"ACK", b"NAK", b"END", b"NEW", b"DEL"))
_CLIENT_COMMANDS = {b"NICK": "nick", b"USER": "user", b"CAP": "cap", b"PASS": "pass"}
_SERVER_COMMANDS = {b"NOTICE": "notice", b"PING": "ping", b"ERROR": "error", b"CAP": "cap", b"PONG": "pong",
                    b"MODE": "mode", b"PRIVMSG": "privmsg", b"NICK": "nick", b"JOIN": "join", b"AUTHENTICATE": "authenticate"}
MAX_PARAMS = 15


def split_message(line):
    """(prefix or None, command, params) for one IRC line without CRLF; raises ParseError on grammar faults."""
    if not line or len(line) > IRC_LINE_LIMIT - 2:
        raise ParseError("IRC line empty or longer than 510 bytes")
    if any(byte in (0, 10, 13) for byte in line):
        raise ParseError("IRC line contains NUL, CR or LF")
    prefix = None
    rest = line
    if rest[:1] == b":":
        prefix, separator, rest = rest[1:].partition(b" ")
        if not separator or not prefix:
            raise ParseError("IRC prefix must be followed by a command")
        if not _valid_prefix(prefix):
            raise ParseError("IRC prefix is neither a server name nor nick!user@host")
    if not rest or rest[:1] == b" ":
        raise ParseError("IRC command missing or preceded by extra space")
    command, separator, rest = rest.partition(b" ")
    if not (re.fullmatch(rb"[A-Za-z]{1,20}", command) or re.fullmatch(rb"[0-9]{3}", command)):
        raise ParseError("IRC command must be letters or three digits")
    params = []
    while separator:
        if rest[:1] == b":":
            if not _TRAILING.fullmatch(rest[1:]):
                raise ParseError("IRC trailing parameter outside its profile")
            params.append(rest[1:])
            break
        middle, separator, rest = rest.partition(b" ")
        if not _MIDDLE.fullmatch(middle):
            raise ParseError("IRC parameter empty or outside its profile")
        params.append(middle)
        if len(params) > MAX_PARAMS:
            raise BudgetError("IRC message exceeds 15 parameters")
    return prefix, command.upper(), params


def _valid_prefix(prefix):
    if b"!" in prefix or b"@" in prefix:
        nick, _, rest = prefix.partition(b"!")
        user, at, host = rest.partition(b"@")
        if not _NICK.fullmatch(nick) or not at or not _USER.fullmatch(user) or not _HOST.fullmatch(host):
            return False
        return True
    return bool(_HOST.fullmatch(prefix) or _NICK.fullmatch(prefix))


def irc_client_line(line):
    """Classify one registration line a client sends first. Returns an irc_message label or None when not IRC.

    NICK and CAP are IRC-only verbs. USER with the four RFC 2812 parameters is
    validated here but reported by the text route as ambiguous with FTP, whose
    USER argument is a free-form string that may contain spaces (RFC 959); POP3
    takes a single space-free argument and is excluded. One-argument USER never
    reaches this function's IRC rules.
    """
    if not 4 <= len(line) <= IRC_LINE_LIMIT - 2 or line[:1] == b":":
        return None
    verb = line.split(b" ", 1)[0].upper()
    if verb not in (b"NICK", b"USER", b"CAP"):
        return None
    if verb == b"USER" and len(line.split(b" ")) < 5:
        return None
    _, command, params = split_message(line)
    if command == b"NICK":
        if len(params) != 1 or not _NICK.fullmatch(params[0]):
            raise ParseError("IRC NICK takes one nickname of up to 64 nickname characters")
    elif command == b"USER":
        if len(params) != 4 or not _USER.fullmatch(params[0]) or not re.fullmatch(rb"[0-9]{1,3}|[^\x20]{1,64}", params[1]) \
                or not re.fullmatch(rb"\*|[^\x20]{1,255}", params[2]) or len(params[3]) > 255:
            raise ParseError("IRC USER takes user, mode, unused and realname parameters")
    else:
        if not params or params[0].upper() not in _CAP_SUBCOMMANDS or len(params) > 3:
            raise ParseError("IRC CAP needs a subcommand LS/LIST/REQ/ACK/NAK/END/NEW/DEL")
        if params[0].upper() == b"LS" and len(params) == 2 and not re.fullmatch(rb"[0-9]{3}", params[1]):
            raise ParseError("IRC CAP LS version must be three digits")
    return _CLIENT_COMMANDS[command]


def irc_server_notice(line):
    """A server's unprefixed NOTICE/PING opening line (NOTICE AUTH/* ..., PING :token); label or None."""
    verb = line.split(b" ", 1)[0].upper()
    if verb not in (b"NOTICE", b"PING"):
        return None
    _, command, params = split_message(line)
    if command == b"NOTICE":
        if len(params) != 2 or params[0].upper() not in (b"AUTH", b"*"):
            raise ParseError("Unprefixed IRC NOTICE before registration targets AUTH or *")
        return "notice"
    if not 1 <= len(params) <= 2:
        raise ParseError("IRC PING takes one or two parameters")
    return "ping"


class IRCParser(LineParser):
    """':'-prefixed server line (numeric reply, NOTICE, PING, CAP) or, with the irc hint, any registration line."""

    def __init__(self, config):
        super().__init__(config, "irc")
        self.family = "irc"
        self.extra_evidence = ()

    def consume_line(self, line):
        prefix, command, params = split_message(line)
        if prefix is None:
            label = irc_client_line(line) or irc_server_notice(line)
            if label is None and command == b"PASS" and len(params) == 1:
                label = "pass"      # PASS alone is ambiguous with FTP/POP3; only the irc hint reaches this parser with it
            if label is None:
                raise UnsupportedPrefix("Only IRC registration and server opening lines are supported")
            self.scope = "initial_message" if label in ("nick", "user", "cap", "pass") else "protocol_header"
        else:
            if command.isdigit():
                if not params or not _NICK.fullmatch(params[0]) and params[0] != b"*":
                    raise ParseError("IRC numeric reply must name its target nickname or *")
                label = "numeric"
            elif command in _SERVER_COMMANDS:
                label = _SERVER_COMMANDS[command]
                if command in (b"NOTICE", b"PRIVMSG") and len(params) != 2:
                    raise ParseError("IRC NOTICE/PRIVMSG take a target and a text parameter")
                if command == b"PING" and not 1 <= len(params) <= 2:
                    raise ParseError("IRC PING takes one or two parameters")
                if command == b"CAP" and (len(params) < 2 or params[1].upper() not in _CAP_SUBCOMMANDS):
                    raise ParseError("IRC CAP reply needs a target and a subcommand")
            else:
                raise UnsupportedPrefix("Prefixed IRC command outside the opening-line profile")
            self.scope = "protocol_header"
        self.protocol_name = "irc"
        self.done = True
        self.extra_evidence = (("irc_message", label, "irc_line", "structural"),)
        self.reason = "IRC message grammar validated ({}); nicknames, hosts, channels and text are never emitted".format(label)
