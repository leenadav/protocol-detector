"""One complete UDP payload per inspect(); boundaries are never concatenated.

No automatic lifetime bypass: UDP associations may carry different message types.
Candidate hints restrict validation; they never cause an identification themselves.
"""
from types import MappingProxyType
from .datagram_result import DatagramMatch
from .rpc import onc_rpc
from .rip import rip, rtcp
from .dtls import dtls
from .ikev2 import ikev2, ike_probe
from .quic import QuicAssembler, quic, quic_probe
from .vpn import l2tp, openvpn, wireguard, wireguard_probe
from .telemetry import netflow, netflow_probe, sflow, ssdp, ssdp_probe
from .ics import ENIPParser, bacnet, bacnet_probe, enip_probe
from .windows import kerberos, kerberos_probe
from .datainfra import rtp
from .model import Config, Evidence, Metrics, Observation
from .parsers import BudgetError, ParseError
from .signatures import SignatureSet
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


def enip_datagram(data, config):
    parser = ENIPParser(config)
    consumed = parser.feed(data)
    if not parser.done or consumed != len(data):
        raise ParseError("EtherNet/IP datagram must contain exactly one encapsulation message")
    return parser.protocol_name, parser.reason


def dns_with_contexts(data, config):
    if not config.retain_contexts and not config.heuristics:
        return dns(data, config)
    from .wire import dns_details, dns_message_evidence, dns_query_type_evidence
    protocol, reason, qname, qtype = dns_details(data, config)
    contexts = {"dns-req-query-name": qname, "dns-req-query-type": qtype} if config.retain_contexts else None
    evidence = (Evidence("application_protocol", protocol, "wire", "structural"),) + dns_message_evidence(data) + dns_query_type_evidence(qname, qtype)
    if config.heuristics:
        evidence += dns_name_shape(qname)
    return DatagramMatch(reason, application_protocol=protocol, contexts=contexts, signature_family="dns", evidence=evidence)


def dns_name_shape(qname):
    """Heuristic evidence about a query name's shape; the name itself is never emitted.

    suspicious: a label of 40+ bytes, a total name of 150+ bytes, or a label of
    16+ bytes whose byte entropy is >= 4.0 bits (RISKS.md).
    """
    from .heuristics import label_entropy
    labels = [label for label in qname.rstrip(b".").split(b".") if label]
    longest = max((len(label) for label in labels), default=0)
    entropy = max((label_entropy(label.lower()) for label in labels if len(label) >= 16), default=0.0)
    shape = "suspicious" if longest >= 40 or len(qname) >= 150 or entropy >= 4.0 else "ordinary"
    return (Evidence("dns_query_shape", shape, "wire:heuristic", "heuristic"),
            Evidence("dns_query_labels", str(len(labels)), "wire:heuristic", "heuristic"),
            Evidence("dns_query_longest_label", str(longest), "wire:heuristic", "heuristic"),
            Evidence("dns_label_entropy", "{:.2f}".format(entropy), "wire:heuristic", "heuristic"))


VALIDATORS = MappingProxyType({"quic": quic, "wireguard": wireguard, "openvpn": openvpn, "l2tp": l2tp, "ssdp": ssdp, "netflow": netflow,
                               "sflow": sflow, "bacnet": bacnet, "kerberos": kerberos, "ethernet-ip": enip_datagram, "rtp": rtp,
                               "ikev2": ikev2, "dtls": dtls, "radius": radius, "ntp": ntp, "snmp": snmp, "tftp": tftp, "dns": dns_with_contexts, "stun": stun, "dhcp": dhcp, "coap": coap, "sip": sip, "syslog": syslog, "onc-rpc": onc_rpc, "rip": rip, "rtcp": rtcp})


class DatagramInspector:
    def __init__(self, config=None, signatures=None, quic_assembler=None):
        self.config = config if config is not None else Config()
        if not isinstance(self.config, Config):
            raise TypeError("Expected Config")
        if signatures is not None and not isinstance(signatures, SignatureSet):
            raise TypeError("Expected a SignatureSet")
        if signatures is not None and len(signatures) and not self.config.retain_contexts:
            raise ValueError("Signatures require Config(retain_contexts=True)")
        if quic_assembler is not None and not isinstance(quic_assembler, QuicAssembler):
            raise TypeError("Expected a QuicAssembler")
        self.signatures = signatures
        self.quic_assembler = quic_assembler  # optional bounded cross-datagram CRYPTO store owned by the host
        self.metrics = Metrics()

    def _unknown(self, data, base, reason, protocol_hint):
        """Unknown datagram: custom unknown-udp signatures may still name an application."""
        if self.signatures is not None and self.signatures.wants("unknown-udp"):
            match = self.signatures.match("unknown-udp", {"unknown-req-udp-payload": data[:self.config.signature_bytes],
                                                          "unknown-req-udp-payload-length": len(data)})
            if match is not None:
                evidence = (Evidence("application", match.name, "signature:unknown-udp", "configured_signature"),)
                if protocol_hint:
                    evidence += (Evidence("candidate_hint", protocol_hint, "caller", "context"),)
                return Observation(status="identified", application=match.name, evidence=evidence, scope="signature_match",
                                   reason="Custom signature matched an unknown datagram; no protocol profile validated",
                                   transport="udp")
        evidence = ()
        if self.config.heuristics:
            from .heuristics import heuristic_evidence
            evidence = heuristic_evidence(data, "wire", self.config.heuristic_bytes)
        return Observation(status="unknown", reason=reason, evidence=evidence, **base)

    def _signature_evidence(self, protocol, contexts):
        if self.signatures is None or contexts is None:
            return None
        family = protocol.split("/", 1)[0]
        match = self.signatures.match(family, contexts)
        if match is None:
            return None
        return match.name, (Evidence("application", match.name, "signature:" + family, "configured_signature"),)

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
        elif quic_probe(data):
            candidates = ("quic",)
        elif wireguard_probe(data):
            candidates = ("wireguard",)
        elif ssdp_probe(data):
            candidates = ("ssdp",)
        elif data[:3] in (b"\x16\xfe\xff", b"\x16\xfe\xfd"):
            candidates = ("dtls",)
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
            elif data[:2] in (b"\x00\x01", b"\x00\x02", b"\x00\x06"):
                candidates.append("tftp")   # ERROR (00 05) is too weak for automatic selection: NetFlow v5 shares its first bytes
            if dns_probe(data):
                candidates.append("dns")
            # Tiny empty CoAP messages are too weak for automatic selection.
            if len(data) >= 4 and len(data) > 4 + (data[0] & 15) and data[0] >> 6 == 1 and data[0] & 15 <= 8:
                candidates.append("coap")
            if netflow_probe(data):
                candidates.append("netflow")
            if data[:4] == b"\0\0\0\x05" and len(data) >= 28:
                candidates.append("sflow")
            if bacnet_probe(data):
                candidates.append("bacnet")
            if kerberos_probe(data):
                candidates.append("kerberos")
            if len(data) >= 14 and data[0] in (0x38, 0x40, 0x50):
                candidates.append("openvpn")
            if len(data) >= 20 and data[0] & 0xcb == 0xc8:
                candidates.append("l2tp")
            if enip_probe(data) and len(data) >= 24:
                candidates.append("ethernet-ip")
            if len(data) >= 20 and (data[4:12] == b"\x00\x00\x00\x00\x00\x00\x00\x02" or (data[4:8] == b"\x00\x00\x00\x01" and data[8:12] in (b"\x00\x00\x00\x00", b"\x00\x00\x00\x01"))):
                candidates.append("onc-rpc")   # CALL with RPC version 2, or a REPLY with a valid reply_stat (v0.51)
            if len(data) >= 24 and data[0] in (1, 2) and data[1] in (1, 2) and data[2:4] == b"\x00\x00" and (len(data) - 4) % 20 == 0:
                candidates.append("rip")
        # SPI bytes are arbitrary and may also satisfy a different protocol's
        # probe. Keep that competitor; at most one extra fixed-position route.
        if not protocol_hint and ike_probe(data):
            candidates = (*candidates, "ikev2")
        if not candidates:
            return self._unknown(data, base, "No supported datagram structure selected", protocol_hint)
        self.metrics.bytes_inspected += len(data)
        matches, errors = [], []
        for candidate in candidates:  # bounded by three preselected families, not registry size
            self.metrics.candidates_selected += 1
            self.metrics.parser_calls += 1
            try:
                if candidate == "quic":
                    matches.append(quic(data, self.config, self.quic_assembler))
                else:
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
            match = matches[0]
            if isinstance(match, DatagramMatch):
                application, extra = None, ()
                if match.contexts is not None and match.signature_family and self.signatures is not None:
                    found = self.signatures.match(match.signature_family, match.contexts)
                    if found is not None:
                        application = found.name
                        extra = (Evidence("application", found.name, "signature:" + match.signature_family, "configured_signature"),)
                return Observation(status="identified", encryption=match.encryption,
                                   application_protocol=match.application_protocol, application=application,
                                   hostname=match.hostname, offered_alpn=match.offered_alpn,
                                   evidence=match.evidence + extra + ((Evidence("candidate_hint", protocol_hint, "caller", "context"),) if protocol_hint else ()),
                                   reason=match.reason, **base)
            protocol, reason = match[0], match[1]
            application, extra = None, ()
            if len(match) > 2 and match[2] is not None:
                found = self._signature_evidence(protocol, match[2])
                if found is not None:
                    application, extra = found
            return Observation(status="identified", application_protocol=protocol, application=application, reason=reason,
                               evidence=(Evidence("application_protocol", protocol, "wire", "structural"),) + extra
                               + ((Evidence("candidate_hint", protocol_hint, "caller", "context"),) if protocol_hint else ()), **base)
        status, reason = next((item for item in errors if item[0] == "budget_exhausted"), errors[0])
        if status == "unknown" and not protocol_hint and len(errors) == len(candidates):
            # A hint restricts validation to its candidate; it never opens unknown-payload signatures.
            return self._unknown(data, base, reason, protocol_hint)
        return Observation(status=status, reason=reason, **base)
