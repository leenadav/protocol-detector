"""First-line profiles for FTP, POP3 and IMAP client/server text, plus Telnet negotiation.

Text commands shared by several protocols (USER, PASS, QUIT, NOOP, STAT, LIST,
RETR, DELE, AUTH) are reported as ambiguous with the candidate set, never as a
guess; the session verdict can intersect both directions' candidates. Arguments
(user names, passwords, paths) are validated for framing and never emitted.
"""
import re
from .parsers import BudgetError, ParseError

_ARGUMENT = re.compile(rb"[\x20-\x7e]{1,512}")
FTP_ONLY = frozenset((b"ACCT", b"CWD", b"CDUP", b"SMNT", b"REIN", b"PORT", b"PASV", b"TYPE", b"STRU", b"MODE", b"STOR",
                      b"STOU", b"APPE", b"ALLO", b"REST", b"RNFR", b"RNTO", b"ABOR", b"RMD", b"MKD", b"PWD", b"NLST", b"SITE",
                      b"SYST", b"HELP", b"FEAT", b"OPTS", b"PBSZ", b"PROT", b"EPSV", b"EPRT", b"MLSD", b"MLST", b"SIZE", b"MDTM",
                      b"CCC", b"CLNT", b"XPWD", b"XCWD", b"XMKD", b"XRMD"))
POP3_ONLY = frozenset((b"APOP", b"CAPA", b"STLS", b"UIDL", b"TOP", b"RSET"))
SHARED = frozenset((b"USER", b"PASS", b"QUIT", b"NOOP", b"STAT", b"LIST", b"RETR", b"DELE", b"AUTH"))
NO_ARGUMENT = frozenset((b"QUIT", b"NOOP", b"STAT", b"PWD", b"XPWD", b"SYST", b"FEAT", b"PASV", b"EPSV", b"CDUP", b"REIN",
                         b"ABOR", b"CAPA", b"STLS", b"UIDL", b"RSET", b"LIST", b"NLST", b"MLSD", b"CCC"))
IMAP_COMMANDS = frozenset((b"CAPABILITY", b"NOOP", b"LOGOUT", b"STARTTLS", b"AUTHENTICATE", b"LOGIN", b"ID", b"ENABLE", b"SELECT",
                           b"EXAMINE", b"CREATE", b"DELETE", b"RENAME", b"SUBSCRIBE", b"UNSUBSCRIBE", b"LIST", b"LSUB", b"NAMESPACE",
                           b"STATUS", b"APPEND", b"IDLE", b"CHECK", b"CLOSE", b"UNSELECT", b"EXPUNGE", b"SEARCH", b"FETCH", b"STORE",
                           b"COPY", b"MOVE", b"UID", b"XLIST", b"GETQUOTAROOT", b"COMPRESS"))
_IMAP_TAG = re.compile(rb"[A-Za-z0-9.\-_]{1,32}")


def command_line(line):
    """Classify one client command line. Returns (family, candidates, shift) or None when not a command.

    family is 'ftp', 'pop3' or None (ambiguous between the candidates); shift is
    the (boundary, expected family) announced by STLS / AUTH TLS, else None.
    """
    if not 3 <= len(line) <= 520 or any(byte < 32 or byte > 126 for byte in line):
        return None
    verb, separator, argument = line.partition(b" ")
    verb = verb.upper()
    if not re.fullmatch(rb"[A-Z]{3,4}", verb):
        return None
    if separator and not _ARGUMENT.fullmatch(argument):
        raise ParseError("Command argument outside printable profile")
    if verb in NO_ARGUMENT and separator and argument:
        if verb not in (b"LIST", b"NLST", b"MLSD", b"STAT", b"UIDL", b"TOP", b"PASV"):
            raise ParseError("Command does not take an argument")
    if verb in FTP_ONLY:
        if verb in (b"PORT", b"EPRT", b"TYPE", b"CWD", b"MKD", b"RMD", b"STOR", b"APPE", b"RNFR", b"RNTO", b"SIZE", b"MDTM", b"OPTS") and not argument:
            raise ParseError("FTP command requires an argument")
        if verb == b"TYPE" and argument.upper()[:1] not in (b"A", b"I", b"E", b"L"):
            raise ParseError("FTP TYPE argument invalid")
        if verb == b"PORT" and not re.fullmatch(rb"(\d{1,3},){5}\d{1,3}", argument):
            raise ParseError("FTP PORT argument invalid")
        return "ftp", ("ftp",), None
    if verb in POP3_ONLY:
        if verb == b"APOP" and len(argument.split(b" ")) != 2:
            raise ParseError("POP3 APOP requires name and digest")
        if verb == b"TOP" and not re.fullmatch(rb"\d{1,10} \d{1,10}", argument):
            raise ParseError("POP3 TOP requires two numbers")
        return "pop3", ("pop3",), (("starttls", "tls") if verb == b"STLS" else None)
    if verb in SHARED:
        if verb in (b"USER", b"PASS", b"AUTH") and not argument:
            raise ParseError("Command requires an argument")
        if verb in (b"RETR", b"DELE") and not argument:
            raise ParseError("Command requires an argument")
        if verb == b"AUTH" and argument.upper() in (b"TLS", b"SSL", b"TLS-C", b"TLS-P"):
            return "ftp", ("ftp",), ("auth-tls", "tls")  # RFC 4217 security mechanism names are FTP-only
        return None, ("ftp", "pop3"), None
    return None


def pop3_greeting(line):
    """Server +OK/-ERR line; returns True for a POP3 status line."""
    if line[:3] == b"+OK" or line[:4] == b"-ERR":
        rest = line[3:] if line[:1] == b"+" else line[4:]
        if rest and (rest[:1] != b" " or not _ARGUMENT.fullmatch(rest[1:] or b" ")):
            if rest != b" ":
                raise ParseError("POP3 status line text outside printable profile")
        return True
    return False


def imap_command(line, config):
    """Tagged IMAP client command: tag SP command [SP arguments]. Returns True when it matches."""
    parts = line.split(b" ", 2)
    if len(parts) < 2 or not _IMAP_TAG.fullmatch(parts[0]) or parts[0].upper() in (b"OK", b"NO", b"BAD"):
        return False
    command = parts[1].upper()
    if command not in IMAP_COMMANDS:
        return False
    if len(line) > config.max_line:
        raise BudgetError("IMAP command exceeds line budget")
    if any(byte < 32 or byte > 126 for byte in line):
        raise ParseError("IMAP command outside printable profile")
    if command in (b"LOGIN", b"AUTHENTICATE", b"SELECT", b"EXAMINE", b"FETCH", b"STORE", b"SEARCH", b"COPY", b"MOVE", b"STATUS") and len(parts) < 3:
        raise ParseError("IMAP command requires arguments")
    if command in (b"CAPABILITY", b"NOOP", b"LOGOUT", b"STARTTLS", b"IDLE", b"CHECK", b"CLOSE", b"EXPUNGE", b"NAMESPACE") and len(parts) > 2:
        raise ParseError("IMAP command does not take arguments")
    return True


class TelnetParser:
    """Telnet option negotiation (RFC 854/855): IAC WILL/WONT/DO/DONT option, IAC SB ... IAC SE.

    Two complete commands identify the stream; a non-IAC byte before that is a
    plain data byte and ends the profile without identification.
    """
    protocol_name = "telnet"
    scope = "negotiation_request"

    def __init__(self, config):
        self.config = config
        self.buffer = bytearray()
        self.commands = 0
        self.done = False
        self.reason = "Waiting for Telnet option negotiation"

    def feed(self, data):
        pos = 0
        while pos < len(data) and not self.done:
            self.buffer.extend(data[pos:pos + 1])
            pos += 1
            if len(self.buffer) > 64:
                raise BudgetError("Telnet command exceeds 64-byte profile")
            if self.buffer[0] != 255:
                raise ParseError("Telnet negotiation requires IAC")
            if len(self.buffer) < 2:
                continue
            kind = self.buffer[1]
            if kind in (251, 252, 253, 254):
                if len(self.buffer) == 3:
                    self._complete()
            elif kind == 250:
                if self.buffer[-2:] == b"\xff\xf0" and len(self.buffer) >= 5:
                    self._complete()
            elif kind in (241, 242, 243, 244, 245, 246, 247, 248, 249, 255):
                self._complete()
            else:
                raise ParseError("Telnet command byte outside negotiation profile")
        return pos

    def _complete(self):
        self.buffer.clear()
        self.commands += 1
        if self.commands >= 2:
            self.done = True
            self.reason = "Telnet option negotiation validated; terminal data and credentials not inspected"
