"""Industrial and building protocols: Modbus/TCP, DNP3, BACnet/IP, ISO-TSAP (RFC 1006), EtherNet/IP, IEC 60870-5-104."""
import struct
from .framing import FrameParser
from .parsers import ParseError
from .extended import UnsupportedPrefix

_MODBUS_FIXED = {1: 4, 2: 4, 3: 4, 4: 4, 5: 4, 6: 4, 7: 0, 8: 4, 11: 0, 12: 0, 17: 0}


def modbus_probe(prefix):
    """MBAP header: protocol id 0, length 2..254, unit id, function code; transaction id arbitrary."""
    if len(prefix) < 8 or prefix[2:4] != b"\0\0":
        return False
    length = int.from_bytes(prefix[4:6], "big")
    return 2 <= length <= 254 and 1 <= prefix[7] <= 127


class ModbusParser(FrameParser):
    header_size = 8
    protocol_name = "modbus"
    scope = "request_header"

    def frame_size(self, header):
        if not modbus_probe(header):
            raise ParseError("Invalid Modbus/TCP MBAP header")
        return 6 + int.from_bytes(header[4:6], "big")

    def validate(self, data):
        function, pdu = data[7], data[8:]
        if function in _MODBUS_FIXED:
            if len(pdu) != _MODBUS_FIXED[function]:
                raise ParseError("Modbus request PDU length does not match the function code")
            if function in (1, 2, 3, 4):
                quantity = int.from_bytes(pdu[2:4], "big")
                if not 1 <= quantity <= (2000 if function in (1, 2) else 125):
                    raise ParseError("Modbus read quantity outside specification")
            if function == 5 and pdu[2:4] not in (b"\0\0", b"\xff\0"):
                raise ParseError("Modbus write-single-coil value must be 0x0000 or 0xff00")
        elif function in (15, 16):
            if len(pdu) < 5 or len(pdu) != 5 + pdu[4]:
                raise ParseError("Modbus multiple-write byte count disagrees with PDU")
        elif function in (20, 21, 22, 23, 24, 43):
            if not pdu:
                raise ParseError("Modbus request PDU empty")
        else:
            raise UnsupportedPrefix("Modbus function code outside the public function profile")
        self.reason = "Modbus/TCP MBAP header and request PDU shape validated; register semantics unverified"


def _dnp3_crc(data):
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xa6bc if crc & 1 else crc >> 1
    return (~crc) & 0xffff


class DNP3Parser(FrameParser):
    """DNP3 data link frame (IEEE 1815): 0x0564, length, control, destination, source, CRC-checked blocks."""
    header_size = 10
    protocol_name = "dnp3"
    scope = "protocol_header"

    def frame_size(self, header):
        if header[:2] != b"\x05\x64":
            raise ParseError("Invalid DNP3 start bytes")
        length = header[2]
        if length < 5:
            raise ParseError("DNP3 length below header size")
        if _dnp3_crc(header[:8]) != int.from_bytes(header[8:10], "little"):
            raise ParseError("DNP3 header CRC mismatch")
        user = length - 5
        blocks = (user + 15) // 16
        return 10 + user + 2 * blocks

    def validate(self, data):
        control = data[3]
        if control & 0x0f not in (0, 1, 2, 3, 4, 9, 11, 0x0f) and control & 0x0f != 0xb:
            raise UnsupportedPrefix("DNP3 link function code outside profile")
        pos, remaining = 10, data[2] - 5
        while remaining > 0:
            chunk = min(16, remaining)
            if _dnp3_crc(data[pos:pos + chunk]) != int.from_bytes(data[pos + chunk:pos + chunk + 2], "little"):
                raise ParseError("DNP3 data block CRC mismatch")
            pos += chunk + 2
            remaining -= chunk
        self.reason = "DNP3 link frame header and block CRCs validated; application fragments not decoded"


def bacnet_probe(data):
    return len(data) >= 4 and data[0] == 0x81 and data[1] <= 0x0c and int.from_bytes(data[2:4], "big") == len(data)


def bacnet(data, config):
    """BACnet/IP BVLC (ASHRAE 135 Annex J) with NPDU version 1 for NPDU-carrying functions."""
    if not bacnet_probe(data):
        raise UnsupportedPrefix("Outside BACnet/IP BVLC framing")
    function = data[1]
    if function in (0x0a, 0x0b, 0x04, 0x09):
        offset = 4 if function in (0x0a, 0x0b) else 10
        if len(data) < offset + 2 or data[offset] != 1:
            raise ParseError("BACnet NPDU version must be 1")
        control = data[offset + 1]
        if control & 0x50:
            raise ParseError("BACnet NPDU reserved control bits set")
        pos = offset + 2
        for present in (control & 0x20, control & 0x08):
            if present:
                if pos + 3 > len(data):
                    raise ParseError("Truncated BACnet NPDU address")
                pos += 3 + data[pos + 2]
        if control & 0x20:
            pos += 1  # hop count follows a destination specifier
        if control & 0x80:
            if pos + 1 > len(data):
                raise ParseError("Truncated BACnet network message type")
        elif pos >= len(data):
            raise ParseError("BACnet NPDU without APDU")
        elif data[pos] >> 4 > 7:
            raise ParseError("BACnet APDU type reserved")
    elif function in (0x00, 0x03, 0x06, 0x08):
        if len(data) != 6 and function != 0x08:
            raise ParseError("BACnet BVLC result/entry length invalid")
    return "bacnet", "BACnet/IP BVLC and NPDU framing validated; objects and services not decoded"


class COTPParser(FrameParser):
    """ISO transport over TCP (RFC 1006 TPKT) with an X.224 connection request carrying TSAP parameters."""
    header_size = 4
    protocol_name = "iso-tsap"
    scope = "negotiation_request"

    def frame_size(self, header):
        if header[:2] != b"\x03\x00":
            raise ParseError("Invalid TPKT version")
        size = int.from_bytes(header[2:4], "big")
        if not 11 <= size <= 1024:
            raise ParseError("TPKT length outside connection request profile")
        return size

    def validate(self, data):
        if data[4] != len(data) - 5 or data[5] != 0xe0 or data[6:8] != b"\0\0" or data[10] & 0xf0 not in (0, 0x10, 0x20, 0x30, 0x40):
            raise ParseError("Invalid X.224 connection request header")
        pos, codes = 11, set()
        while pos < len(data):
            if pos + 2 > len(data):
                raise ParseError("Truncated X.224 parameter")
            code, size = data[pos], data[pos + 1]
            if pos + 2 + size > len(data):
                raise ParseError("X.224 parameter exceeds request")
            if code in codes:
                raise ParseError("Duplicate X.224 parameter")
            codes.add(code)
            if code == 0xc0 and (size != 1 or not 7 <= data[pos + 2] <= 13):
                raise ParseError("X.224 TPDU size parameter invalid")
            if code in (0xc1, 0xc2) and not 1 <= size <= 32:
                raise ParseError("X.224 TSAP parameter length outside profile")
            pos += 2 + size
        if not codes & {0xc1, 0xc2}:
            raise UnsupportedPrefix("X.224 request without TSAP parameters is outside the ISO-TSAP profile")
        self.reason = "TPKT/X.224 connection request with TSAP parameters validated; upper protocol (for example S7comm) unverified"


_ENIP_COMMANDS = {0x0004: "list_services", 0x0063: "list_identity", 0x0064: "list_interfaces", 0x0065: "register_session",
                  0x0066: "unregister_session", 0x006f: "send_rr_data", 0x0070: "send_unit_data"}


def enip_probe(prefix):
    return len(prefix) >= 8 and prefix[1] == 0 and prefix[0] in (0x04, 0x63, 0x64, 0x65, 0x66, 0x6f, 0x70) and prefix[3] == 0 and prefix[2] <= 0xff


class ENIPParser(FrameParser):
    """EtherNet/IP encapsulation header (24 bytes) with a RegisterSession or list request."""
    header_size = 24
    protocol_name = "ethernet-ip"
    scope = "protocol_header"

    def frame_size(self, header):
        command, length, session, status = struct.unpack("<HHII", header[:12])
        if command not in _ENIP_COMMANDS:
            raise UnsupportedPrefix("EtherNet/IP command outside profile")
        if status or header[20:24] != bytes(4):
            raise ParseError("EtherNet/IP request requires zero status and options")
        if command == 0x0065 and (length != 4 or session):
            raise ParseError("EtherNet/IP RegisterSession requires a four-byte body and zero session handle")
        if command in (0x0004, 0x0063, 0x0064) and length:
            raise ParseError("EtherNet/IP list requests carry no data")
        if command in (0x006f, 0x0070) and (length < 6 or not session):
            raise ParseError("EtherNet/IP data commands require a session handle and CPF body")
        if length > 65511:
            raise ParseError("EtherNet/IP length outside encapsulation limit")
        return 24 + length

    def validate(self, data):
        command = int.from_bytes(data[:2], "little")
        if command == 0x0065 and data[24:28] != b"\x01\x00\x00\x00":
            raise ParseError("EtherNet/IP RegisterSession protocol version must be 1 with zero options")
        self.extra_evidence = (("enip_command", _ENIP_COMMANDS[command], "encapsulation_header", "structural"),)
        self.reason = "EtherNet/IP encapsulation header validated; CIP payload not decoded"


class IEC104Parser(FrameParser):
    """IEC 60870-5-104 APCI: start 0x68, length 4..253, control field format I/S/U."""
    header_size = 6
    protocol_name = "iec-104"
    scope = "protocol_header"

    def frame_size(self, header):
        if header[0] != 0x68:
            raise ParseError("Invalid IEC 104 start byte")
        length = header[1]
        if not 4 <= length <= 253:
            raise ParseError("IEC 104 APDU length outside 4..253")
        control = header[2]
        if control & 3 == 3:
            if length != 4 or header[3] or header[4] or header[5]:
                raise ParseError("IEC 104 U-format frame must be four bytes with zero reserved octets")
            if bin(control >> 2).count("1") != 1:
                raise ParseError("IEC 104 U-format must carry exactly one function bit")
        elif control & 3 == 1:
            if length != 4 or header[3]:
                raise ParseError("IEC 104 S-format frame invalid")
        elif length < 6:
            raise ParseError("IEC 104 I-format frame requires an ASDU")
        return 2 + length

    def validate(self, data):
        self.reason = "IEC 60870-5-104 APCI validated; ASDU contents not decoded"


class TPKTParser(FrameParser):
    """Automatic TPKT route: RDP connection requests versus ISO-TSAP connection requests."""
    header_size = 4
    scope = "negotiation_request"

    def __init__(self, config):
        super().__init__(config)
        self.child = None

    def frame_size(self, header):
        if header[:2] != b"\x03\x00":
            raise ParseError("Invalid TPKT version or reserved byte")
        size = int.from_bytes(header[2:4], "big")
        if not 11 <= size <= 1024:
            raise ParseError("TPKT length outside connection request profile")
        return size

    def validate(self, data):
        from .remote import RDPParser
        rest = data[11:]
        rdp = rest.startswith(b"Cookie: mstshash=") or rest[:1] == b"\x01" or not rest or data[5] == 0xd0
        child = RDPParser(self.config) if rdp else COTPParser(self.config)
        child.validate(data)
        self.child = child
        self.protocol_name = child.protocol_name
        self.reason = child.reason
        self.scope = child.scope
        self.shift = child.shift
        self.extra_evidence = getattr(child, "extra_evidence", ())
        self.family = child.protocol_name
