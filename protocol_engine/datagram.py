"""One complete UDP payload per inspect(); boundaries are never concatenated.

No automatic lifetime bypass: UDP associations may carry different message types.
Candidate hints restrict validation; they never cause an identification themselves.
"""
from types import MappingProxyType
from .model import Config, Evidence, Metrics, Observation
from .parsers import BudgetError, ParseError
from .extended import TextParser, UnsupportedPrefix
from .syslog import syslog
from .network import ntp, snmp, tftp
from .radius import radius
from .wire import coap, dhcp, dns, dns_probe, stun

def _sip_probe(data, limit):
    if not data or not 65 <= data[0] <= 90:
        return False
    end = data.find(b"\r\n", 0, limit)
    if end < 0:
        return False
    return data.startswith(b"SIP/2.0 ") or data[max(0, end - 8):end] == b" SIP/2.0"


def sip(data, config):
    parser = TextParser(config)
    consumed = parser.feed(data)
    if not parser.done or parser.family != "sip":
        raise ParseError("Incomplete or invalid SIP datagram headers")
    length = parser.control.fields.get(b"content-length")
    if length is not None and int(length) != len(data) - consumed:
        raise ParseError("SIP datagram body disagrees with Content-Length")
    return "sip/2.0", "SIP required header framing and datagram body length validated; body/dialogue semantics unverified"


VALIDATORS = MappingProxyType({"radius": radius, "ntp": ntp, "snmp": snmp, "tftp": tftp, "dns": dns, "stun": stun, "dhcp": dhcp, "coap": coap, "sip": sip, "syslog": syslog})


class DatagramInspector:
    def __init__(self, config=None):
        self.config = config if config is not None else Config()
        if not isinstance(self.config, Config):
            raise TypeError("Expected Config")
        self.metrics = Metrics()

    def inspect(self, data, protocol_hint=None):
        if not isinstance(data, bytes):
            raise TypeError("inspect expects one complete UDP payload as bytes")
        if protocol_hint is not None and protocol_hint not in VALIDATORS:
            raise ValueError("Unsupported UDP candidate hint")
        self.metrics.bytes_received += len(data)
        self.metrics.updates += 1
        base = {"transport": "udp", "scope": "datagram"}
        if len(data) > self.config.max_bytes:
            return Observation(status="budget_exhausted", reason="Datagram exceeds byte budget", **base)
        if protocol_hint:
            candidates = (protocol_hint,)
        elif len(data) >= 8 and data[4:8] == b"\x21\x12\xa4\x42":
            candidates = ("stun",)
        elif len(data) >= 240 and data[236:240] == b"\x63\x82\x53\x63":
            candidates = ("dhcp",)
        elif data.startswith(b"<"):
            candidates = ("syslog",)
        elif _sip_probe(data, self.config.max_line):
            candidates = ("sip",)
        else:
            candidates = []
            if data.startswith(b"\x30"):
                candidates.append("snmp")
            elif data[:2] in (b"\x00\x01", b"\x00\x02"):
                candidates.append("tftp")
            if dns_probe(data):
                candidates.append("dns")
            # Tiny empty CoAP messages are too weak for automatic selection.
            if len(data) >= 4 and len(data) > 4 + (data[0] & 15) and data[0] >> 6 == 1 and data[0] & 15 <= 8:
                candidates.append("coap")
        if not candidates:
            return Observation(status="unknown", reason="No supported datagram structure selected", **base)
        self.metrics.bytes_inspected += len(data)
        matches, errors = [], []
        for candidate in candidates:  # bounded by two preselected families, not registry size
            self.metrics.candidates_selected += 1
            self.metrics.parser_calls += 1
            try:
                matches.append(VALIDATORS[candidate](data, self.config))
            except BudgetError as error:
                errors.append(("budget_exhausted", str(error)))
            except UnsupportedPrefix as error:
                errors.append(("unknown", str(error)))
            except ParseError as error:
                errors.append(("malformed", str(error)))
        if len(matches) > 1:
            return Observation(status="unknown", reason="Ambiguous datagram matches multiple supported structures", **base)
        if matches and any(status == "budget_exhausted" for status, _ in errors):
            return Observation(status="budget_exhausted", reason="A competing datagram candidate exhausted its budget", **base)
        if matches:
            protocol, reason = matches[0]
            return Observation(status="identified", application_protocol=protocol, reason=reason,
                               evidence=(Evidence("application_protocol", protocol, "wire", "structural"),)
                               + ((Evidence("candidate_hint", protocol_hint, "caller", "context"),) if protocol_hint else ()), **base)
        status, reason = next((item for item in errors if item[0] == "budget_exhausted"), errors[0])
        return Observation(status=status, reason=reason, **base)
