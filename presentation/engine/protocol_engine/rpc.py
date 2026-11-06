"""ONC RPC version 2 (RFC 5531): CALL and REPLY messages over TCP record marking and UDP.

The profile validates the RPC header and both opaque_auth structures (AUTH_NONE,
AUTH_SYS fully; AUTH_SHORT, AUTH_DH and RPCSEC_GSS by flavor and bounded
length). Program numbers are reported as closed labels; procedure arguments and
results are not decoded, and machine names, uids, gids and GSS tokens are
never emitted.
"""
from .datagram_result import DatagramMatch
from .extended import UnsupportedPrefix
from .framing import FrameParser
from .model import Evidence
from .parsers import ParseError

PROTOCOL = "onc-rpc/2"
PROGRAMS = {100000: "portmap", 100003: "nfs", 100005: "mount", 100021: "nlm", 100024: "nsm", 100227: "nfs-acl", 100011: "rquota"}
_PROGRAM_VERSIONS = {100000: (2, 3, 4), 100003: (2, 3, 4), 100005: (1, 2, 3), 100021: (1, 2, 3, 4), 100024: (1,), 100227: (2, 3), 100011: (1, 2)}
_ACCEPT = ("success", "prog-unavail", "prog-mismatch", "proc-unavail", "garbage-args", "system-err")
_FLAVORS = {0: "auth-none", 1: "auth-sys", 2: "auth-short", 3: "auth-dh", 6: "rpcsec-gss"}
MAX_AUTH = 400          # RFC 5531: opaque_auth body limit
MAX_GIDS = 16
MIN_MESSAGE = 20        # denied REPLY: xid, type, reply_stat, reject_stat, auth_stat; every other message is longer


def _u32(data, pos):
    if pos + 4 > len(data):
        raise ParseError("Truncated RPC message")
    return int.from_bytes(data[pos:pos + 4], "big"), pos + 4


def _auth_sys(body):
    pos = 4                                            # stamp
    length, pos = _u32(body, pos)
    if length > 255:
        raise ParseError("AUTH_SYS machine name too long")
    padded = (length + 3) & ~3
    if pos + padded > len(body):
        raise ParseError("Truncated AUTH_SYS machine name")
    name = body[pos:pos + padded]
    if any(not 0x20 <= byte < 0x7f for byte in name[:length]) or any(name[length:]):
        raise ParseError("AUTH_SYS machine name must be printable with zero padding")
    pos += padded + 8                                  # uid, gid
    count, pos = _u32(body, pos)
    if count > MAX_GIDS:
        raise ParseError("AUTH_SYS gid list exceeds the specification limit")
    if pos + 4 * count != len(body):
        raise ParseError("AUTH_SYS body length disagrees with its gid count")


def _opaque_auth(data, pos, verifier=False):
    flavor, pos = _u32(data, pos)
    length, pos = _u32(data, pos)
    if flavor not in _FLAVORS or (verifier and flavor == 1):
        raise UnsupportedPrefix("RPC authentication flavor outside the profile")
    if length > MAX_AUTH or length % 4:
        raise ParseError("RPC opaque_auth length outside the specification")
    if pos + length > len(data):
        raise ParseError("Truncated RPC opaque_auth")
    if flavor == 0 and length:
        raise ParseError("AUTH_NONE carries no body")
    if flavor == 1:
        _auth_sys(data[pos:pos + length])
    return flavor, pos + length


def message(data):
    """Validate one RPC message; return (end of the RPC header, evidence rows, reason, scope, trailing allowed)."""
    if len(data) < 12:
        raise ParseError("RPC message shorter than its header")
    kind, pos = _u32(data, 4)
    if kind == 0:
        version, pos = _u32(data, pos)
        if version != 2:
            raise UnsupportedPrefix("Only RPC version 2 is supported")
        program, pos = _u32(data, pos)
        program_version, pos = _u32(data, pos)
        procedure, pos = _u32(data, pos)
        name = PROGRAMS.get(program)
        if name is not None:
            if program_version not in _PROGRAM_VERSIONS[program]:
                raise UnsupportedPrefix("RPC program version outside the known range")
        elif not program or program_version > 255:
            raise ParseError("RPC program or version outside the profile")
        if procedure > 65535:
            raise ParseError("RPC procedure number outside the profile")
        credential, pos = _opaque_auth(data, pos)
        _, pos = _opaque_auth(data, pos, verifier=True)
        rows = (("rpc_message", "call", "rpc_header", "structural"),
                ("rpc_program", name or "other", "rpc_header", "structural"),
                ("rpc_program_version", str(program_version), "rpc_header", "structural"),
                ("rpc_credential", _FLAVORS[credential], "rpc_header", "asserted"))
        return pos, rows, "ONC RPC v2 call header and authentication structures validated; arguments not decoded", "initial_message", True
    if kind != 1:
        raise UnsupportedPrefix("RPC message type outside CALL/REPLY")
    status, pos = _u32(data, pos)
    if status == 0:
        _, pos = _opaque_auth(data, pos, verifier=True)
        accepted, pos = _u32(data, pos)
        if accepted > 5:
            raise ParseError("RPC accept status outside the specification")
        if accepted == 2:
            low, pos = _u32(data, pos)
            high, pos = _u32(data, pos)
            if low > high:
                raise ParseError("RPC version range inverted")
        rows = (("rpc_message", "reply", "rpc_header", "structural"), ("rpc_reply", "accepted", "rpc_header", "structural"),
                ("rpc_accept_status", _ACCEPT[accepted], "rpc_header", "structural"))
        return pos, rows, "ONC RPC v2 accepted reply validated; results not decoded", "response_header", accepted == 0
    if status != 1:
        raise ParseError("RPC reply status outside the specification")
    rejected, pos = _u32(data, pos)
    if rejected == 0:
        low, pos = _u32(data, pos)
        high, pos = _u32(data, pos)
        if low > high:
            raise ParseError("RPC version range inverted")
    elif rejected == 1:
        auth_status, pos = _u32(data, pos)
        if not 1 <= auth_status <= 14:
            raise ParseError("RPC authentication status outside the specification")
    else:
        raise ParseError("RPC reject status outside the specification")
    rows = (("rpc_message", "reply", "rpc_header", "structural"), ("rpc_reply", "denied", "rpc_header", "structural"),
            ("rpc_reject_status", "rpc-mismatch" if rejected == 0 else "auth-error", "rpc_header", "structural"))
    return pos, rows, "ONC RPC v2 denied reply validated", "response_header", False


def _check_trailing(data, end, trailing_allowed):
    if end != len(data) and not trailing_allowed:
        raise ParseError("Bytes after an RPC message that carries no results")


class RPCParser(FrameParser):
    """TCP record marking (RFC 5531 section 11): one last-fragment record carrying a complete message."""
    header_size = 4
    protocol_name = PROTOCOL

    def frame_size(self, data):
        mark = int.from_bytes(data[:4], "big")
        if not mark & 0x80000000:
            raise UnsupportedPrefix("Multi-fragment RPC records are outside the profile")
        size = mark & 0x7fffffff
        if size < MIN_MESSAGE:
            raise ParseError("RPC record too short for a message")
        return 4 + size

    def validate(self, data):
        body = data[4:]
        end, rows, reason, scope, trailing_allowed = message(body)
        _check_trailing(body, end, trailing_allowed)
        self.extra_evidence = rows
        self.reason = reason
        self.scope = scope


def onc_rpc(data, config):
    """UDP datagram: one complete RPC message."""
    if len(data) < MIN_MESSAGE:
        raise ParseError("RPC datagram too short for a message")
    end, rows, reason, _, trailing_allowed = message(data)
    _check_trailing(data, end, trailing_allowed)
    return DatagramMatch(reason, application_protocol=PROTOCOL,
                         evidence=(Evidence("application_protocol", PROTOCOL, "wire", "structural"),)
                         + tuple(Evidence(field, value, "wire:" + provenance, strength) for field, value, provenance, strength in rows))
