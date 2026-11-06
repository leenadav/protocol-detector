"""VPN control channels: WireGuard, OpenVPN, PPTP and L2TPv2 first messages.

All profiles are plaintext framing checks. None of them proves that a tunnel is
established or inspects what it carries. Keys, cookies, session identifiers and
hostnames inside the messages are never emitted.
"""
import struct
from .datagram_result import DatagramMatch
from .framing import FrameParser
from .model import Evidence
from .parsers import BudgetError, ParseError
from .extended import UnsupportedPrefix

_WIREGUARD = {1: (148, "handshake_initiation"), 2: (92, "handshake_response"), 3: (64, "cookie_reply")}
_OPENVPN_HMAC = (0, 16, 20, 28, 32, 48, 64)


def wireguard_probe(data):
    return len(data) >= 4 and data[1:4] == b"\0\0\0" and data[0] in _WIREGUARD and len(data) == _WIREGUARD[data[0]][0]


def wireguard(data, config):
    if not wireguard_probe(data):
        raise UnsupportedPrefix("Outside WireGuard handshake message sizes")
    kind = _WIREGUARD[data[0]][1]
    if data[0] == 1 and data[4:8] == bytes(4):
        raise ParseError("WireGuard sender index must be nonzero")
    return DatagramMatch(encryption="wireguard", evidence=(Evidence("encryption", "wireguard", "wire", "structural"),
                                                            Evidence("message_type", kind, "wire", "structural")),
                         reason="WireGuard handshake message size and reserved bytes validated; keys and MACs unverified, no tunnel claim")


def _openvpn_control(data):
    """Validate a hard-reset control packet (client V2/V3, server V2); returns (tls-auth HMAC width, role) or raises."""
    if len(data) < 14:
        raise ParseError("OpenVPN control packet too short")
    opcode, key_id = data[0] >> 3, data[0] & 7
    if opcode not in (7, 8, 10):
        raise UnsupportedPrefix("OpenVPN profile covers client and server hard-reset control packets")
    if key_id:
        raise ParseError("OpenVPN initial key id must be zero")
    if data[1:9] == bytes(8):
        raise ParseError("OpenVPN session id must be nonzero")
    role = "server" if opcode == 8 else "client"
    for width in _OPENVPN_HMAC:
        offset = 9 + width + (8 if width else 0)  # tls-auth adds HMAC, packet id and timestamp
        if offset + 5 > len(data):
            continue
        if opcode == 8:
            # Server reset acknowledges the client's packet: 1..8 acked ids, the remote session id, then its own id.
            acked = data[offset]
            if 1 <= acked <= 8 and len(data) == offset + 1 + 4 * acked + 8 + 4 and data[offset + 1 + 4 * acked:offset + 1 + 4 * acked + 8] != bytes(8):
                return width, role
            continue
        if data[offset] == 0 and len(data) == offset + 5:  # empty ACK array then message packet id
            return width, role
        if opcode == 10 and data[offset] == 0 and len(data) > offset + 5:
            return width, role  # V3 carries tls-crypt-v2 client key material after the packet id
    raise ParseError("OpenVPN control framing does not match plain or tls-auth layouts")


def openvpn(data, config):
    width, role = _openvpn_control(data)
    return DatagramMatch(encryption="openvpn", evidence=(Evidence("encryption", "openvpn", "wire", "structural"),
                                                          Evidence("tls_auth", "present" if width else "absent", "wire", "structural"),
                                                          Evidence("openvpn_control", role + "-hard-reset", "wire", "structural")),
                         reason="OpenVPN {} hard-reset control packet validated; no key exchange or tunnel claim".format(role))


class OpenVPNParser(FrameParser):
    """OpenVPN over TCP: two-byte length then the same control packet."""
    header_size = 2
    protocol_name = "openvpn"

    def frame_size(self, header):
        size = int.from_bytes(header, "big")
        if not 14 <= size <= 1500:
            raise ParseError("OpenVPN TCP frame length outside control profile")
        return 2 + size

    def validate(self, data):
        width, role = _openvpn_control(data[2:])
        self.extra_evidence = (("tls_auth", "present" if width else "absent", "control_packet", "structural"),
                               ("openvpn_control", role + "-hard-reset", "control_packet", "structural"))
        if role == "server":
            self.scope = "negotiation_response"
        self.reason = "OpenVPN TCP {} hard-reset control packet validated; no key exchange or tunnel claim".format(role)


_PPTP_RESULTS = {1: "ok", 2: "general-error", 3: "already-connected", 4: "not-authorized", 5: "bad-version"}


class PPTPParser(FrameParser):
    """PPTP Start-Control-Connection-Request (RFC 2637 2.1), 156 bytes."""
    header_size = 12
    protocol_name = "pptp"
    scope = "negotiation_request"

    def frame_size(self, header):
        length, kind, cookie, control = struct.unpack("!HHIH", header[:10])
        if cookie != 0x1a2b3c4d or kind != 1:
            raise ParseError("PPTP control header magic or message type invalid")
        if control not in (1, 2):
            raise UnsupportedPrefix("PPTP profile covers Start-Control-Connection-Request and -Reply")
        if length != 156:
            raise ParseError("PPTP SCCRQ/SCCRP must be 156 bytes")
        return 156

    def validate(self, data):
        control = int.from_bytes(data[8:10], "big")
        if control == 2:
            reserved0, version, result, error, framing, bearer, channels, firmware = struct.unpack("!HHBBIIHH", data[10:28])
            if reserved0 or version != 0x0100 or not 1 <= result <= 5 or error > 6 or (result != 2 and error):
                raise ParseError("PPTP SCCRP reserved field, version, result or error code invalid")
        else:
            reserved0, version, reserved1, framing, bearer, channels, firmware = struct.unpack("!HHHIIHH", data[10:28])
            if reserved0 or reserved1 or version != 0x0100:
                raise ParseError("PPTP SCCRQ reserved fields or protocol version invalid")
        if framing & ~3 or bearer & ~3:
            raise ParseError("PPTP capability bits outside RFC 2637")
        for field in (data[28:92], data[92:156]):
            end = field.find(b"\0")
            text = field if end < 0 else field[:end]
            if any(byte < 32 or byte > 126 for byte in text):
                raise ParseError("PPTP host/vendor name outside printable ASCII")
        if control == 2:
            self.scope = "negotiation_response"
            self.extra_evidence = (("pptp_message", "sccrp", "control", "structural"),
                                   ("pptp_result", _PPTP_RESULTS[result], "control", "asserted"))
            self.reason = "PPTP start-control-connection reply validated; names are not emitted, no call or tunnel claim"
            return
        self.extra_evidence = (("pptp_message", "sccrq", "control", "structural"),)
        self.reason = "PPTP start-control-connection request validated; names are not emitted, no call or tunnel claim"


def l2tp(data, config):
    """L2TPv2 control message SCCRQ (RFC 2661 6.1) with mandatory message-type AVP first."""
    if len(data) < 20:
        raise ParseError("L2TP control message too short")
    flags = int.from_bytes(data[:2], "big")
    if flags & 0x8000 == 0 or flags & 0x000f != 2:
        raise UnsupportedPrefix("L2TP profile covers version 2 control messages")
    if flags & 0x4000 == 0 or flags & 0x0800 == 0 or flags & 0x3030:
        raise ParseError("L2TP control messages require L and S bits and zero reserved bits")
    pos = 2
    length = int.from_bytes(data[pos:pos + 2], "big")
    pos += 2
    if length != len(data):
        raise ParseError("L2TP length disagrees with datagram")
    tunnel, session = struct.unpack("!HH", data[pos:pos + 4])
    pos += 4 + 4  # Ns, Nr
    if flags & 0x0200:
        pos += 2  # offset size present
    count = 0
    first = None
    while pos < length:
        count += 1
        if count > min(config.max_headers, 64):
            raise BudgetError("L2TP AVP count exceeds budget")
        if pos + 6 > length:
            raise ParseError("Truncated L2TP AVP")
        avp_flags_length = int.from_bytes(data[pos:pos + 2], "big")
        avp_length = avp_flags_length & 0x3ff
        if avp_flags_length & 0x3c00 or avp_length < 6 or pos + avp_length > length:
            raise ParseError("L2TP AVP reserved bits or length invalid")
        vendor, attribute = struct.unpack("!HH", data[pos + 2:pos + 6])
        if first is None:
            if vendor or attribute != 0 or avp_length != 8 or not avp_flags_length & 0x8000:
                raise ParseError("L2TP first AVP must be the mandatory Message Type")
            first = int.from_bytes(data[pos + 6:pos + 8], "big")
            if first not in (1, 2):
                raise UnsupportedPrefix("L2TP profile covers SCCRQ and SCCRP as the first control messages")
            if session or (first == 1 and tunnel) or (first == 2 and not tunnel):
                raise ParseError("L2TP SCCRQ requires zero identifiers; SCCRP carries the peer's assigned tunnel id")
        pos += avp_length
    if first is None:
        raise ParseError("L2TP control message without AVPs")
    name = "sccrq" if first == 1 else "sccrp"
    return DatagramMatch("L2TPv2 {} control framing and AVP boundaries validated; tunnel establishment unverified".format(name.upper()),
                         application_protocol="l2tp/2",
                         evidence=(Evidence("application_protocol", "l2tp/2", "wire", "structural"), Evidence("l2tp_message", name, "wire", "structural")))
