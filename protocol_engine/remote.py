"""RDP connection negotiation, without security selection or session decoding."""
from functools import lru_cache

from .framing import FrameParser
from .parsers import ParseError
from .extended import UnsupportedPrefix

# MS-RDPBCGR 2.2.1.1.1 requestedProtocols / 2.2.1.2.1 selectedProtocol bits, as closed labels (v0.60).
SECURITY_PROTOCOLS = ((0x01, "tls"), (0x02, "credssp"), (0x04, "rdstls"), (0x08, "credssp-early-user-auth"), (0x10, "aad"))
_SELECTED = {0: "standard-rdp", **{bit: label for bit, label in SECURITY_PROTOCOLS}}
# RDP_NEG_REQ flags: RESTRICTED_ADMIN_MODE_REQUIRED, REDIRECTED_AUTHENTICATION_MODE_REQUIRED (CORRELATION_INFO_PRESENT is framing).
CREDENTIAL_MODES = ((0x01, "restricted-admin"), (0x02, "remote-credential-guard"))
# RDP_NEG_RSP flags (NEGRSP_FLAG_RESERVED 0x04 carries no meaning and is not reported).
SERVER_SUPPORTS = ((0x01, "extended-client-data"), (0x02, "gfx-pipeline"), (0x08, "restricted-admin"), (0x10, "remote-credential-guard"))
# RDP_NEG_FAILURE failureCode 1..6.
FAILURES = {1: "ssl-required", 2: "ssl-not-allowed", 3: "ssl-certificate-missing", 4: "inconsistent-flags",
            5: "hybrid-required", 6: "ssl-with-user-auth-required"}



@lru_cache(maxsize=None)
def _request_rows(offered, modes):
    """Evidence rows for one RDP_NEG_REQ; at most 32 x 4 distinct inputs once validated."""
    rows = [('rdp_security_flags', str(offered), 'negotiation_request', 'offered')]
    rows.extend(('rdp_offered_security', label, 'negotiation_request', 'offered') for bit, label in SECURITY_PROTOCOLS if offered & bit)
    if not offered:
        rows.append(('rdp_offered_security', 'standard-rdp', 'negotiation_request', 'offered'))
    rows.extend(('rdp_credential_mode', label, 'negotiation_request', 'offered') for bit, label in CREDENTIAL_MODES if modes & bit)
    return tuple(rows)


@lru_cache(maxsize=None)
def _response_rows(selected, flags):
    """Evidence rows for one RDP_NEG_RSP; at most 6 x 32 distinct inputs once validated."""
    return (('rdp_selected_protocol', str(selected), 'negotiation_response', 'asserted'),
            ('rdp_selected_security', _SELECTED[selected], 'negotiation_response', 'asserted')) + tuple(
        ('rdp_server_supports', label, 'negotiation_response', 'asserted') for bit, label in SERVER_SUPPORTS if flags & bit)


class RDPParser(FrameParser):
    header_size = 4
    protocol_name = 'rdp'
    scope = 'negotiation_request'

    def frame_size(self, header):
        if header[:2] != b'\x03\x00':
            raise ParseError("Invalid TPKT version or reserved byte")
        size = int.from_bytes(header[2:4], 'big')
        if not 11 <= size <= 260:
            raise ParseError("TPKT length outside X.224 connection request profile")
        return size

    def validate(self, data):
        if data[4] == len(data) - 5 and data[5] == 0xd0:
            return self._confirm(data)
        if data[4] != len(data) - 5 or data[5] != 0xe0 or data[6:8] != b'\0\0' or data[10] != 0:
            raise ParseError("Invalid X.224 class-zero connection request")
        pos = 11
        if data.startswith(b'Cookie: mstshash=', pos):
            end = data.find(b'\r\n', pos)
            if end < 0 or any(byte < 32 or byte == 127 for byte in data[pos:end]):
                raise ParseError("Invalid RDP cookie framing")
            pos = end + 2
        if pos == len(data):
            raise UnsupportedPrefix("X.224 request alone does not identify RDP; negotiation required")
        if data[pos] != 1:
            raise UnsupportedPrefix("Unsupported X.224 routing token or negotiation type")
        neg = data[pos:pos + 8]
        if len(neg) != 8 or neg[1] & ~0x0b or neg[2:4] != b'\x08\x00':
            raise ParseError("Invalid RDP negotiation header")
        offered = int.from_bytes(neg[4:8], 'little')
        if offered & ~0x1f:
            raise UnsupportedPrefix("Unsupported RDP security offer flags")
        pos += 8
        if neg[1] & 8:
            correlation = data[pos:pos + 36]
            if len(correlation) != 36 or correlation[:4] != b'\x06\x00\x24\x00' or any(correlation[20:]):
                raise ParseError("Invalid RDP correlation structure")
            pos += 36
        if pos != len(data):
            raise ParseError("Unexpected bytes after RDP negotiation")
        self.reason = 'RDP connection request and security offers validated; selected security and session unverified'
        self.extra_evidence = _request_rows(offered, neg[1] & 3)
        if offered:
            # Every offered protocol other than standard RDP security (TLS, CredSSP, RDSTLS, AAD) starts with TLS
            # once the server confirms; if the server selects standard RDP security the shifted bytes stay unknown.
            self.shift = ('rdp-negotiation', 'tls')

    def _confirm(self, data):
        """Server X.224 Connection Confirm with RDP_NEG_RSP or RDP_NEG_FAILURE (MS-RDPBCGR 2.2.1.2)."""
        if data[6:8] == b'\0\0' or data[10] != 0:
            raise ParseError("Invalid X.224 connection confirm")
        neg = data[11:]
        if not neg:
            raise UnsupportedPrefix("X.224 confirm alone does not identify RDP; negotiation response required")
        if len(neg) != 8 or neg[2:4] != b'\x08\x00':
            raise ParseError("Invalid RDP negotiation response header")
        self.scope = 'negotiation_response'
        if neg[0] == 2:
            if neg[1] & ~0x1f:
                raise ParseError("Invalid RDP negotiation response flags")
            selected = int.from_bytes(neg[4:8], 'little')
            if selected not in (0, 1, 2, 4, 8, 16):
                raise ParseError("RDP server must select exactly one security protocol")
            self.extra_evidence = _response_rows(selected, neg[1])
            self.reason = 'RDP connection confirm and selected security protocol validated; session unverified'
            if selected:
                self.shift = ('rdp-negotiation', 'tls')
            return
        if neg[0] == 3:
            code = int.from_bytes(neg[4:8], 'little')
            if neg[1] or code not in FAILURES:
                raise ParseError("Invalid RDP negotiation failure")
            self.extra_evidence = (('rdp_negotiation', 'failure', 'negotiation_response', 'structural'),
                                   ('rdp_failure', FAILURES[code], 'negotiation_response', 'structural'))
            self.reason = 'RDP connection confirm with negotiation failure validated'
            return
        raise UnsupportedPrefix("Unsupported X.224 confirm negotiation type")
