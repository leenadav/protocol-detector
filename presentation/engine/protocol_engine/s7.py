"""Siemens S7comm (S7 protocol over ISO-TSAP/COTP): one complete PDU after the COTP connection.

The engine reaches this parser through the cotp-connect shift announced by the
ISO-TSAP connection request/confirm (or an explicit candidate hint); it is
never selected from a bare prefix because every message starts with the TPKT
header that also carries RDP and ISO-TSAP connection requests. The profile is
the public S7 header (protocol id 0x32, ROSCTR, parameter and data lengths that
fill the PDU exactly) plus the well-known function codes of the first
parameter byte; Setup Communication is validated field by field. Variable
addresses, values and block contents are not decoded or emitted.
"""
from .framing import FrameParser
from .parsers import ParseError
from .extended import UnsupportedPrefix

_ROSCTR = {1: "job", 2: "ack", 3: "ack_data", 7: "userdata"}
_FUNCTIONS = {0x00: "cpu_services", 0x04: "read_var", 0x05: "write_var", 0x1a: "request_download", 0x1b: "download_block",
              0x1c: "download_ended", 0x1d: "start_upload", 0x1e: "upload", 0x1f: "end_upload", 0x28: "plc_control",
              0x29: "plc_stop", 0xf0: "setup_communication"}
_PDU_SIZES = frozenset((240, 480, 960, 1920, 2048, 4096, 8192))


class S7Parser(FrameParser):
    header_size = 7
    protocol_name = "s7comm"
    scope = "protocol_header"

    def frame_size(self, header):
        if header[:2] != b"\x03\x00":
            raise ParseError("Invalid TPKT header before S7 PDU")
        size = int.from_bytes(header[2:4], "big")
        if header[4:7] != b"\x02\xf0\x80":
            raise UnsupportedPrefix("S7comm requires a COTP data TPDU (class 0, single TPDU) after the connection")
        if not 17 <= size <= 8192:
            raise ParseError("TPKT length outside the S7 PDU profile")
        return size

    def validate(self, data):
        pdu = data[7:]
        if pdu[0] != 0x32:
            raise UnsupportedPrefix("S7 protocol id must be 0x32")
        rosctr = pdu[1]
        if rosctr not in _ROSCTR:
            raise ParseError("S7 ROSCTR outside job/ack/ack-data/userdata")
        if pdu[2:4] != b"\x00\x00":
            raise ParseError("S7 reserved field must be zero")
        parameters, payload = int.from_bytes(pdu[6:8], "big"), int.from_bytes(pdu[8:10], "big")
        header = 12 if rosctr in (2, 3) else 10
        if header + parameters + payload != len(pdu):
            raise ParseError("S7 parameter and data lengths disagree with the PDU")
        function = None
        if rosctr in (1, 3):
            if parameters < 1:
                raise ParseError("S7 job/ack-data requires a parameter block")
            function = pdu[header]
            if function not in _FUNCTIONS:
                raise UnsupportedPrefix("S7 function code outside the public profile")
            if function == 0xf0:
                if parameters != 8 or pdu[header + 1] != 0:
                    raise ParseError("S7 setup communication parameter must be eight bytes")
                calling, called, length = (int.from_bytes(pdu[header + 2:header + 4], "big"),
                                           int.from_bytes(pdu[header + 4:header + 6], "big"),
                                           int.from_bytes(pdu[header + 6:header + 8], "big"))
                if not 1 <= calling <= 255 or not 1 <= called <= 255 or length not in _PDU_SIZES:
                    raise ParseError("S7 setup communication queues or PDU length outside profile")
            if rosctr == 3 and pdu[10] > 0x8f:
                raise ParseError("S7 error class outside profile")
        elif rosctr == 7 and parameters < 8:
            raise ParseError("S7 userdata parameter block too short")
        self.extra_evidence = (("s7_rosctr", _ROSCTR[rosctr], "s7_header", "structural"),)
        if function is not None:
            self.extra_evidence += (("s7_function", _FUNCTIONS[function], "s7_header", "structural"),)
        self.reason = "S7comm PDU header and parameter framing validated; addresses, values and blocks not decoded"
