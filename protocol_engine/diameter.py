"""Diameter base protocol (RFC 6733) capabilities exchange: CER and CEA.

Header, command flags, every AVP header (flags, length, padding, vendor id) and
the mandatory AVPs of the exchange are validated. Origin-Host, Origin-Realm,
Host-IP-Address, Product-Name and every other value are read for framing only
and never emitted; the result code is reported as a class.
"""
from .extended import UnsupportedPrefix
from .framing import FrameParser
from .parsers import BudgetError, ParseError

CAPABILITIES_EXCHANGE = 257
_REQUEST, _PROXIABLE, _ERROR, _RETRANSMIT = 0x80, 0x40, 0x20, 0x10
_AVP_VENDOR, _AVP_MANDATORY, _AVP_PROTECTED = 0x80, 0x40, 0x20
ORIGIN_HOST, ORIGIN_REALM, HOST_IP, VENDOR_ID, PRODUCT_NAME, RESULT_CODE = 264, 296, 257, 266, 269, 268
_UNSIGNED32 = frozenset((258, 259, 265, 266, 267, 268, 278, 299))     # application ids, vendor ids, firmware, result, state, security
_IDENTITIES = frozenset((ORIGIN_HOST, ORIGIN_REALM))
_ONCE = frozenset((ORIGIN_HOST, ORIGIN_REALM, VENDOR_ID, PRODUCT_NAME, RESULT_CODE, 267, 278))
_REQUIRED = frozenset((ORIGIN_HOST, ORIGIN_REALM, HOST_IP, VENDOR_ID, PRODUCT_NAME))
MAX_AVPS = 128


def result_class(code):
    return {1: "informational", 2: "success", 3: "protocol-error", 4: "transient-failure", 5: "permanent-failure"}.get(code // 1000, "other") \
        if 1000 <= code <= 5999 else "other"


class DiameterParser(FrameParser):
    header_size = 20
    protocol_name = "diameter"

    def frame_size(self, data):
        if data[0] != 1:
            raise UnsupportedPrefix("Diameter profile requires protocol version 1")
        size = int.from_bytes(data[1:4], "big")
        flags = data[4]
        if size < 20 or size % 4:
            raise ParseError("Diameter message length must be a multiple of four, at least the header")
        if flags & 0x0f:
            raise ParseError("Reserved Diameter command flags set")
        if int.from_bytes(data[5:8], "big") != CAPABILITIES_EXCHANGE or any(data[8:12]):
            raise UnsupportedPrefix("Diameter profile covers the capabilities exchange on the base application only")
        if flags & _PROXIABLE:
            raise ParseError("Capabilities exchange messages are never proxiable")
        if flags & _REQUEST and flags & _ERROR:
            raise ParseError("Diameter request with the error flag")
        if flags & _RETRANSMIT and not flags & _REQUEST:
            raise ParseError("Diameter answer with the retransmission flag")
        self.request = bool(flags & _REQUEST)
        return size

    def validate(self, data):
        pos, seen, codes, result = 20, 0, set(), None
        while pos < len(data):
            if len(data) - pos < 8:
                raise ParseError("Truncated Diameter AVP header")
            code = int.from_bytes(data[pos:pos + 4], "big")
            flags = data[pos + 4]
            length = int.from_bytes(data[pos + 5:pos + 8], "big")
            if flags & 0x1f:
                raise ParseError("Reserved Diameter AVP flags set")
            header = 12 if flags & _AVP_VENDOR else 8
            padded = (length + 3) & ~3
            if length < header or pos + padded > len(data):
                raise ParseError("Diameter AVP length outside its message")
            if any(data[pos + length:pos + padded]):
                raise ParseError("Diameter AVP padding must be zero")
            seen += 1
            if seen > min(self.config.max_headers, MAX_AVPS):
                raise BudgetError("Diameter AVP count exceeds budget")
            value = data[pos + header:pos + length]
            if not flags & _AVP_VENDOR:
                if code in _ONCE and code in codes:
                    raise ParseError("Repeated Diameter AVP that may appear once")
                result = self._avp(code, flags, value, result)
                codes.add(code)
            pos += padded
        missing = _REQUIRED - codes
        if missing or (not self.request and RESULT_CODE not in codes):
            raise ParseError("Diameter capabilities exchange lacks a mandatory AVP")
        rows = [("diameter_message", "cer" if self.request else "cea", "header", "structural")]
        if not self.request:
            rows.append(("diameter_result", result_class(result), "avp", "structural"))
        self.extra_evidence = tuple(rows)
        self.scope = "negotiation_request" if self.request else "negotiation_response"
        self.reason = ("Diameter CER header and mandatory AVPs validated; identities, addresses and product name not emitted" if self.request
                       else "Diameter CEA header, result code and mandatory AVPs validated; identities, addresses and product name not emitted")

    @staticmethod
    def _avp(code, flags, value, result):
        if code in _UNSIGNED32:
            if len(value) != 4:
                raise ParseError("Diameter Unsigned32 AVP with the wrong length")
            if code == RESULT_CODE:
                result = int.from_bytes(value, "big")
                if result_class(result) == "other":
                    raise ParseError("Diameter Result-Code outside the specification ranges")
        elif code in _IDENTITIES or code == PRODUCT_NAME:
            if not 1 <= len(value) <= 255 or any(byte < 0x20 or byte == 0x7f for byte in value):
                raise ParseError("Diameter identity or name outside the profile")
            if code in _IDENTITIES and any(byte == 0x20 for byte in value):
                raise ParseError("DiameterIdentity must not contain spaces")
        elif code == HOST_IP:
            family = int.from_bytes(value[:2], "big") if len(value) >= 2 else 0
            if (family, len(value)) not in ((1, 6), (2, 18)):
                raise ParseError("Host-IP-Address must be an IPv4 or IPv6 Address AVP")
        if code in (ORIGIN_HOST, ORIGIN_REALM, VENDOR_ID, PRODUCT_NAME) and not flags & _AVP_MANDATORY:
            raise ParseError("Mandatory Diameter AVP without the M flag")
        return result
