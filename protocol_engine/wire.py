"""Complete-message validators shared by stream framing and datagram inspection.

No ports, I/O, application attribution or payload values in diagnostic messages.
"""
import struct
import zlib
from .datagram_result import DatagramMatch
from .model import Evidence
from .parsers import BudgetError, ParseError, UnsupportedPrefix


def dns_probe(data):
    """DNS message layout (v0.55): the QUERY opcode with 1..8 questions, or zero questions for a response that
    carries answers (multicast DNS announcement), or the NetBIOS name service opcodes 5..8 (registration,
    release, WACK, refresh) with at most one question; the Z bit stays clear."""
    if len(data) < 12 or data[3] & 0x40:
        return False
    opcode = data[2] & 0x78
    questions = int.from_bytes(data[4:6], "big")
    if opcode == 0 and questions == 1:
        return True
    # The multicast and NetBIOS layouts are rarer: their section counts must also be plausible
    # (RFC 6762 answers, RFC 1002 one additional record) and the first name must start with a
    # label of 1..63 bytes, so other datagrams (RIP entries, DTLS records) never become candidates.
    if len(data) <= 12 or not 1 <= data[12] <= 63:
        return False
    total = sum(struct.unpack("!4H", data[4:12]))
    if not 1 <= total <= 32:
        return False
    if opcode == 0:
        if questions == 0:
            return bool(data[2] & 0x80) and data[6:8] != b"\x00\x00"
        return questions <= 8
    return opcode in (0x28, 0x30, 0x38, 0x40) and questions <= 1


_DNS_RCODES = ("noerror", "formerr", "servfail", "nxdomain", "notimp", "refused", "yxdomain", "yxrrset", "nxrrset", "notauth", "notzone")
# Evidence rows are immutable; the sixteen possible header outcomes are built once (hot UDP path).
_DNS_QUERY_EVIDENCE = (Evidence("dns_message", "query", "wire", "structural"),)
_DNS_RESPONSE_EVIDENCE = tuple((Evidence("dns_message", "response", "wire", "structural"),
                                Evidence("dns_rcode", _DNS_RCODES[code] if code < len(_DNS_RCODES) else "other", "wire", "structural"))
                               for code in range(16))
DNS_FAMILIES = ("dns", "mdns", "netbios-ns", "llmnr")
_DNS_PROTOCOL_EVIDENCE = {name: (Evidence("application_protocol", name, "wire", "structural"),) for name in DNS_FAMILIES}
_NBNS_OPCODES = {0: "query", 5: "registration", 6: "release", 7: "wack", 8: "refresh"}
_NBNS_OPCODE_EVIDENCE = {label: (Evidence("nbns_opcode", label, "wire", "structural"),) for label in _NBNS_OPCODES.values()}
_MDNS_PROFILE_EVIDENCE = {label: (Evidence("mdns_profile", label, "wire", "structural"),)
                          for label in ("announcement", "probe", "known-answer", "unicast-requested", "plain")}
_LLMNR_FLAG_EVIDENCE = {label: (Evidence("llmnr_flags", label, "wire", "structural"),) for label in ("none", "conflict", "tentative")}
_DNS_REASONS = {
    "dns": "DNS question and record framing validated; unknown RDATA semantics and DNSSEC unverified",
    "mdns": "Multicast DNS framing validated (.local names, QU or cache-flush bits, question count); names and records never emitted",
    "llmnr": "LLMNR header and single question validated with the llmnr hint (opcode zero, zero Z field); names never emitted",
}


_DNS_QTYPES = {1: "a", 2: "ns", 5: "cname", 6: "soa", 12: "ptr", 15: "mx", 16: "txt", 28: "aaaa", 33: "srv", 35: "naptr", 43: "ds",
               46: "rrsig", 48: "dnskey", 64: "svcb", 65: "https", 255: "any", 32: "nb"}
_NETBIOS_LABEL = frozenset(b"ABCDEFGHIJKLMNOPabcdefghijklmnop")   # question names are expanded lowercase
_DNS_QTYPE_EVIDENCE = {label: (Evidence("dns_query_type", label, "wire", "structural"),) for label in list(_DNS_QTYPES.values()) + ["nbstat", "other"]}


def _netbios_name(qname):
    first = qname.split(b".", 1)[0] if qname else b""
    return len(first) == 32 and all(byte in _NETBIOS_LABEL for byte in first)


def dns_query_type_class(qname, qtype):
    """Closed label for the question type; NetBIOS name service queries (NB 0x20, NBSTAT 0x21) are told from DNS SRV by their 32-byte first-level encoded label."""
    netbios = _netbios_name(qname)
    if qtype == 33 and netbios:
        return "nbstat"
    if qtype == 32:
        return "nb" if netbios else "other"
    return _DNS_QTYPES.get(qtype, "other")


def dns_query_type_evidence(qname, qtype):
    return _DNS_QTYPE_EVIDENCE[dns_query_type_class(qname, qtype)]


def dns_message_evidence(header):
    """(dns_message, dns_rcode) evidence rows for a validated header; query or response, no names."""
    if not header[2] & 0x80:
        return _DNS_QUERY_EVIDENCE
    return _DNS_RESPONSE_EVIDENCE[header[3] & 0x0f]


def dns_protocol_evidence(protocol):
    return _DNS_PROTOCOL_EVIDENCE[protocol]


def dns(data, config):
    protocol, reason, _, _, evidence = dns_details(data, config)
    return DatagramMatch(reason, application_protocol=protocol, evidence=_DNS_PROTOCOL_EVIDENCE[protocol] + evidence)


def llmnr(data, config):
    """Hint-only: LLMNR shares the DNS layout and only its header semantics differ (RFC 4795 2.1.1)."""
    protocol, reason, _, _, evidence = dns_details(data, config, llmnr=True)
    return DatagramMatch(reason, application_protocol=protocol, evidence=_DNS_PROTOCOL_EVIDENCE[protocol] + evidence)


def dns_details(data, config, llmnr=False):
    """Validate one DNS-layout message.

    Returns (protocol, reason, qname bytes, qtype, evidence rows) where protocol is
    `dns`, `mdns` (multicast DNS markers: a `.local` name, a QU or cache-flush bit,
    several questions or an unsolicited announcement), `netbios-ns` (NB/NBSTAT
    question with a 32-byte first-level encoded name, or the NetBIOS opcodes 5..8)
    or, with llmnr=True (hint only), `llmnr`. The evidence rows exclude the
    application_protocol row; names are returned for signature contexts only.
    """
    if llmnr:
        if len(data) < 12 or data[2] & 0x78 or data[3] & 0xf0 or data[4:6] != b"\x00\x01":
            raise UnsupportedPrefix("LLMNR requires opcode zero, one question and a zero Z field")
    elif not dns_probe(data):
        raise UnsupportedPrefix("DNS layout requires the QUERY or a NetBIOS name service opcode and a bounded question count")
    if data[2] & 2:
        raise UnsupportedPrefix("Truncated DNS messages require transport retry")
    response = bool(data[2] & 0x80)
    opcode = (data[2] >> 3) & 15
    rcode = data[3] & 0x0f
    counts = struct.unpack("!4H", data[4:12])
    if sum(counts) > 128:
        raise BudgetError("DNS record count exceeds inspection limit")
    steps = 0
    boundaries = set()

    def name(start):
        nonlocal steps
        pos, end, size = start, None, 1
        visited = set()
        while True:
            steps += 1
            if steps > config.max_bytes:
                raise BudgetError("DNS name work budget exhausted")
            if pos >= len(data) or pos in visited:
                raise ParseError("Truncated or cyclic DNS name")
            visited.add(pos)
            length = data[pos]
            if length & 0xc0 == 0xc0:
                if pos + 1 >= len(data):
                    raise ParseError("Truncated DNS compression pointer")
                target = ((length & 63) << 8) | data[pos + 1]
                if target >= pos or target not in boundaries:
                    raise ParseError("DNS pointer must reference an earlier parsed name boundary")
                if end is None:
                    end = pos + 2
                pos = target
                continue
            if length & 0xc0 or pos + 1 + length > len(data):
                raise ParseError("Invalid DNS label length")
            boundaries.add(pos)
            pos += 1
            if not length:
                return end if end is not None else pos
            size += 1 + length
            if size > 255:
                raise ParseError("DNS expanded name exceeds 255 bytes")
            pos += length

    pos = 12
    qname, qtype = b"", 0
    unicast_requested = local = False
    netbios = opcode != 0
    for index in range(counts[0]):
        start = pos
        pos = name(pos)
        if pos + 4 > len(data):
            raise ParseError("Truncated DNS question")
        expanded = _expand_name(data, start, pos)
        kind, klass = struct.unpack("!HH", data[pos:pos + 4])
        if not kind or klass & 0x7fff not in (1, 255):
            raise UnsupportedPrefix("Unsupported DNS question type/class profile")
        pos += 4
        if index == 0:
            qname, qtype = expanded, kind
            netbios = netbios or (kind in (32, 33) and _netbios_name(expanded))
        unicast_requested = unicast_requested or bool(klass & 0x8000)
        local = local or expanded.endswith(b"local") and (expanded == b"local" or expanded.endswith(b".local"))
    cache_flush = False
    for section, count in enumerate(counts[1:]):
        for _ in range(count):
            start = pos
            pos = name(pos)
            if pos + 10 > len(data):
                raise ParseError("Truncated DNS resource record")
            kind, klass, _, size = struct.unpack("!HHIH", data[pos:pos + 10])
            pos += 10
            end = pos + size
            if end > len(data):
                raise ParseError("DNS RDATA exceeds message")
            if not counts[0] and not qtype:
                qname, qtype = _expand_name(data, start, pos - 10), kind
                netbios = netbios or (kind in (32, 33) and _netbios_name(qname))
            if section != 1 and klass & 0x8000 and kind != 41:
                cache_flush = True
            if kind in (1, 28) and size != (4 if kind == 1 else 16):
                raise ParseError("Invalid DNS address record size")
            if kind in (2, 5, 12) and name(pos) != end:
                raise ParseError("Invalid DNS name RDATA length")
            if kind == 15 and (size < 3 or name(pos + 2) != end):
                raise ParseError("Invalid DNS MX RDATA")
            if kind == 6 and name(name(pos)) + 20 != end:
                raise ParseError("Invalid DNS SOA RDATA")
            if kind == 16:
                cursor = pos
                while cursor < end:
                    cursor += 1 + data[cursor]
                if cursor != end:
                    raise ParseError("Invalid DNS TXT RDATA")
            if kind == 41:
                cursor = pos
                while cursor < end:
                    if cursor + 4 > end:
                        raise ParseError("Truncated EDNS option")
                    cursor += 4 + int.from_bytes(data[cursor + 2:cursor + 4], "big")
                if cursor != end:
                    raise ParseError("Invalid EDNS option length")
            if kind == 32 and netbios and size != 2 and size % 6:
                raise ParseError("NetBIOS NB record data must be a WACK flag word or 6-byte address entries")
            pos = end
    if pos != len(data):
        raise ParseError("Trailing bytes after DNS sections")
    evidence = dns_message_evidence(data) + dns_query_type_evidence(qname, qtype)
    if llmnr:
        # RFC 4795 2.1.1: C (conflict) sits where DNS keeps AA, T (tentative) where DNS keeps RD; the Z nibble was checked.
        conflict, tentative = bool(data[2] & 0x04), bool(data[2] & 0x01)
        if not response and (rcode or counts[1] or counts[2] or tentative):
            raise ParseError("LLMNR query must not carry answers, authority records, a response code or the T bit")
        if netbios or local:
            raise UnsupportedPrefix("NetBIOS or .local names are not LLMNR")
        label = "conflict" if conflict else ("tentative" if tentative else "none")
        return "llmnr", _DNS_REASONS["llmnr"], qname, qtype, evidence + _LLMNR_FLAG_EVIDENCE[label]
    if netbios:
        if opcode not in _NBNS_OPCODES or not _netbios_name(qname):
            raise UnsupportedPrefix("NetBIOS name service needs an encoded name with a query, registration, release, WACK or refresh opcode")
        if not response:
            if rcode or counts[1] or counts[2] or (opcode and (counts[0] != 1 or counts[3] != 1)):
                raise ParseError("NetBIOS name service request sections outside RFC 1002")
        elif counts[0] > 1 or counts[1] > 1 or counts[2] or counts[3]:
            raise ParseError("NetBIOS name service response sections outside RFC 1002")
        label = _NBNS_OPCODES[opcode]
        reason = "NetBIOS name service {} framing validated; names, addresses and node status are never emitted".format(label)
        return "netbios-ns", reason, qname, qtype, evidence + _NBNS_OPCODE_EVIDENCE[label]
    if not counts[0] or unicast_requested or cache_flush or local:
        # Multicast DNS (RFC 6762): QU questions, cache-flush answers, .local names, known-answer and probe
        # queries carrying records, unsolicited announcements without questions.
        if not counts[0] and not (local or cache_flush):
            raise ParseError("DNS response without a question")
        if response and (rcode or not data[2] & 0x04):
            raise ParseError("Multicast DNS responses carry the AA bit and a zero response code")
        if not response and (rcode or data[2] & 0x04):
            raise ParseError("Multicast DNS queries carry neither the AA bit nor a response code")
        if not counts[0]:
            profile = "announcement"
        elif not response and counts[2]:
            profile = "probe"
        elif not response and counts[1]:
            profile = "known-answer"
        elif unicast_requested:
            profile = "unicast-requested"
        else:
            profile = "plain"
        return "mdns", _DNS_REASONS["mdns"], qname, qtype, evidence + _MDNS_PROFILE_EVIDENCE[profile]
    if counts[0] != 1:
        raise UnsupportedPrefix("Several questions without multicast DNS markers are outside the DNS profile")
    if not response and (data[2] & 0x04 or rcode or counts[1] or counts[2]):
        raise ParseError("DNS query must not carry the AA bit, answers, authority records or a response code")
    return "dns", _DNS_REASONS["dns"], qname, qtype, evidence


def _expand_name(data, start, end):
    """Lowercase dotted question name from already validated labels (no pointers in a question start)."""
    labels, pos = [], start
    while pos < end:
        length = data[pos]
        if length & 0xc0:
            break  # compressed question names are validated but not expanded for contexts
        pos += 1
        if not length:
            break
        labels.append(data[pos:pos + length].lower())
        pos += length
    return b".".join(labels)


_STUN_METHODS = {1: "binding", 3: "allocate", 4: "refresh", 6: "send", 7: "data", 8: "create-permission", 9: "channel-bind",
                 10: "connect", 11: "connection-bind", 12: "connection-attempt"}
_STUN_CLASSES = ("request", "indication", "success-response", "error-response")
_STUN_INDICATION_ONLY = frozenset((6, 7, 12))       # Send, Data, ConnectionAttempt never have requests or responses
_STUN_ADDRESS_ATTRIBUTES = frozenset((0x0001, 0x0020, 0x0012, 0x0016, 0x8020))   # MAPPED, XOR-MAPPED, XOR-PEER, XOR-RELAYED, legacy XOR
_STUN_FIXED_SIZES = {0x0019: 4, 0x000d: 4, 0x000c: 4, 0x0018: 1, 0x0022: 8, 0x8022: None}
_STUN_TEXT_LIMITS = {0x0006: 513, 0x0014: 763, 0x0015: 763, 0x8022: 763}


def stun(data, config):
    if len(data) < 20 or data[0] & 0xc0 or data[4:8] != b"\x21\x12\xa4\x42":
        raise ParseError("Invalid STUN header")
    length = int.from_bytes(data[2:4], "big")
    kind = int.from_bytes(data[:2], "big")
    method = (kind & 15) | ((kind >> 1) & 0x70) | ((kind >> 2) & 0xf80)
    klass = ((kind >> 7) & 2) | ((kind >> 4) & 1)
    if method not in _STUN_METHODS:
        raise UnsupportedPrefix("STUN method outside Binding and the TURN methods")
    if (method in _STUN_INDICATION_ONLY) != (klass == 1) and method != 1:
        raise ParseError("STUN class inconsistent with its method (Send/Data/ConnectionAttempt are indications only)")
    if length % 4 or length + 20 != len(data):
        raise ParseError("Invalid STUN message length")
    pos, count = 20, 0
    while pos < len(data):
        count += 1
        if count > 128:
            raise BudgetError("STUN attribute count exceeds inspection limit")
        if pos + 4 > len(data):
            raise ParseError("Truncated STUN attribute")
        tag, size = struct.unpack("!HH", data[pos:pos + 4])
        end = pos + 4 + size
        padded = pos + 4 + ((size + 3) & ~3)
        if padded > len(data):
            raise ParseError("STUN attribute exceeds message")
        if tag in _STUN_ADDRESS_ATTRIBUTES:
            value = data[pos + 4:end]
            if size not in (8, 20) or value[0] != 0 or (value[1], size) not in ((1, 8), (2, 20)):
                raise ParseError("Invalid STUN address attribute")
        elif tag in _STUN_FIXED_SIZES and _STUN_FIXED_SIZES[tag] is not None:
            if size != _STUN_FIXED_SIZES[tag]:
                raise ParseError("TURN attribute size outside the specification")
            value = data[pos + 4:end]
            if tag == 0x0019 and (value[0] not in (6, 17) or any(value[1:])):
                raise ParseError("TURN REQUESTED-TRANSPORT must name UDP or TCP with zero reserved bytes")
            if tag == 0x000c and (value[0] & 0xc0 != 0x40 or any(value[2:])):
                raise ParseError("TURN CHANNEL-NUMBER outside 0x4000..0x7FFF")
            if tag == 0x0018 and value[0] & 0x7f:
                raise ParseError("TURN EVEN-PORT reserved bits set")
        elif tag in _STUN_TEXT_LIMITS:
            if size > _STUN_TEXT_LIMITS[tag]:
                raise ParseError("STUN text attribute exceeds its specified length")
        elif tag == 0x0009:
            value = data[pos + 4:end]
            if size < 4 or size > 4 + 763 or value[0] or value[1] or not 3 <= value[2] <= 6 or value[3] > 99:
                raise ParseError("Invalid STUN ERROR-CODE attribute")
        if tag == 0x0008 and size != 20:
            raise ParseError("Invalid STUN MESSAGE-INTEGRITY size")
        if tag == 0x001c and (size < 16 or size > 32 or size % 4):
            raise ParseError("Invalid STUN SHA256 integrity size")
        if tag == 0x8028:
            if size != 4 or padded != len(data):
                raise ParseError("STUN FINGERPRINT must be the last four-byte attribute")
            expected = (zlib.crc32(data[:pos]) & 0xffffffff) ^ 0x5354554e
            if int.from_bytes(data[pos + 4:end], "big") != expected:
                raise ParseError("STUN FINGERPRINT mismatch")
        pos = padded
    name = _STUN_METHODS[method]
    reason = ("STUN Binding framing validated; optional fingerprint checked, HMAC and peer identity unverified" if method == 1
              else "TURN {} framing validated; relayed addresses, credentials, realm and nonce not emitted, HMAC unverified".format(name))
    return DatagramMatch(reason, application_protocol="stun",
                         evidence=(Evidence("application_protocol", "stun", "wire", "structural"),
                                   Evidence("stun_method", name, "wire", "structural"),
                                   Evidence("stun_class", _STUN_CLASSES[klass], "wire", "structural")))


_DHCP_MESSAGES = {1: "discover", 2: "offer", 3: "request", 4: "decline", 5: "ack", 6: "nak", 7: "release", 8: "inform"}


def dhcp(data, config):
    if len(data) < 241 or data[236:240] != b"\x63\x82\x53\x63":
        raise ParseError("Invalid DHCPv4 fixed header/cookie")
    if data[0] not in (1, 2) or not 1 <= data[2] <= 16 or data[1] == 0:
        raise ParseError("Invalid DHCPv4 operation or hardware address length")
    if int.from_bytes(data[10:12], "big") & 0x7fff:
        raise ParseError("Reserved DHCPv4 flags set")
    pos, message_type, count = 240, None, 0
    while pos < len(data):
        code = data[pos]
        pos += 1
        if code == 0:
            continue
        if code == 255:
            if message_type is None or any(data[pos:]):
                raise ParseError("Missing DHCP message type or non-padding after END")
            expected = 1 if message_type in (1, 3, 4, 7, 8) else 2
            if data[0] != expected:
                raise ParseError("DHCP message type conflicts with operation")
            return DatagramMatch("DHCPv4 header and option framing validated; lease state and option semantics unverified",
                                 application_protocol="dhcp/4",
                                 evidence=(Evidence("application_protocol", "dhcp/4", "wire", "structural"),
                                           Evidence("dhcp_operation", "request" if expected == 1 else "reply", "wire", "structural"),
                                           Evidence("dhcp_message", _DHCP_MESSAGES[message_type], "wire", "structural")))
        count += 1
        if count > 128:
            raise BudgetError("DHCP option count exceeds inspection limit")
        if pos >= len(data) or pos + 1 + data[pos] > len(data):
            raise ParseError("Truncated DHCP option")
        size = data[pos]
        value = data[pos + 1:pos + 1 + size]
        pos += 1 + size
        if code == 52:
            raise UnsupportedPrefix("DHCP overloaded option fields are outside this profile")
        if code == 53:
            if size != 1 or message_type is not None or not 1 <= value[0] <= 8:
                raise ParseError("Invalid or duplicate DHCP message type")
            message_type = value[0]
    raise ParseError("DHCP options require END")


def coap(data, config):
    if len(data) < 4 or data[0] >> 6 != 1 or (data[0] & 15) > 8:
        raise ParseError("Invalid CoAP v1 header/token length")
    token = data[0] & 15
    kind, code = (data[0] >> 4) & 3, data[1]
    if not code:
        if token or len(data) != 4 or kind == 1:
            raise ParseError("Invalid CoAP empty message")
        return "coap", "CoAP empty-message framing only; no peer authentication"
    if code >> 5 not in (0, 2, 4, 5) or (code >> 5 == 0 and not 1 <= code <= 4):
        raise UnsupportedPrefix("Unsupported CoAP code profile")
    if kind == 3 or (code < 32 and kind not in (0, 1)):
        raise ParseError("CoAP code conflicts with message type")
    pos = 4 + token
    if pos > len(data):
        raise ParseError("Truncated CoAP token")
    option, count = 0, 0

    def extended(value, offset):
        if value < 13:
            return value, offset
        if value == 15:
            raise ParseError("Reserved CoAP option nibble")
        width = 1 if value == 13 else 2
        if offset + width > len(data):
            raise ParseError("Truncated CoAP extended option")
        return int.from_bytes(data[offset:offset + width], "big") + (13 if width == 1 else 269), offset + width

    while pos < len(data):
        if data[pos] == 255:
            if pos + 1 == len(data):
                raise ParseError("CoAP payload marker without payload")
            break
        count += 1
        if count > 128:
            raise BudgetError("CoAP option count exceeds inspection limit")
        byte = data[pos]
        delta, pos = extended(byte >> 4, pos + 1)
        size, pos = extended(byte & 15, pos)
        option += delta
        if option > 65535 or pos + size > len(data):
            raise ParseError("CoAP option outside message or number range")
        pos += size
    return "coap", "CoAP v1 token/options framing validated; option semantics and payload unverified"
