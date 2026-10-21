"""Direction coverage matrix: which side of each family the fixtures prove the engine identifies.

Every stream and datagram fixture (and the demo examples) is classified; an
identified observation is attributed to the client or the server side by its
scope or, for datagrams, by the evidence it carries (DIRECTION_RULES). The
table lists per family the transports, the sides proven, and the evidence
fields emitted. PROTOCOLS.md carries the generated table between markers;
`--check` fails when the document drifts from the fixtures, `--write` updates
it. Fixture bytes, not documentation, are the source of truth.
"""
import argparse
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol_engine import Config, DatagramInspector, Inspector, supported_protocols  # noqa: E402
from protocol_demo import examples  # noqa: E402
import protocol_fixtures as fixtures  # noqa: E402

START, END = "<!-- coverage-matrix:start -->", "<!-- coverage-matrix:end -->"
SERVER_SCOPES = frozenset(("negotiation_response", "server_hello", "hello_retry_request", "reply_header", "locate_reply",
                           "response_header", "bind_response"))
# Datagram observations share the scope "datagram"; these evidence values mark the server side.
DIRECTION_RULES = (
    ("dns_message", lambda value: value == "response"),
    ("snmp_pdu", lambda value: value in ("response", "trap", "report")),
    ("handshake", lambda value: value in ("server_hello", "hello_verify_request")),
    ("radius_code", lambda value: value != "access-request"),
    ("openvpn_control", lambda value: value == "server-hard-reset"),
    ("exchange", lambda value: value == "ike_sa_init_response"),
    ("kerberos_message", lambda value: value in ("as-rep", "tgs-rep", "error")),
    ("tls_handshake", lambda value: value in ("server_hello", "hello_retry_request")),
)
HIDDEN_FIELDS = frozenset(("application_protocol", "encryption", "candidate_hint"))
# Fixtures that live outside the generic case lists (name, hint, transport).
EXTRA = (
    ("TLS_SERVER12", None, "tcp"), ("TLS_SERVER13", None, "tcp"), ("TLS_RETRY", None, "tcp"),
    ("TLS_SERVER12_CERTIFICATE", None, "tcp"), ("TLS_ECH_HELLO", None, "tcp"), ("CONNECT_RESPONSE", None, "tcp"), ("H2C_101", None, "tcp"),
    ("RDP_CONFIRM", None, "tcp"), ("ISO_TSAP_CONFIRM", None, "tcp"), ("HTTP_RESPONSE", None, "tcp"),
    ("H2_SERVER_SETTINGS", "http2-server", "tcp"), ("WEBSOCKET_FRAME", "websocket", "tcp"), ("WEBSOCKET_SERVER_FRAME", "websocket", "tcp"),
    ("S7COMM", "s7comm", "tcp"), ("S7COMM_ACK", "s7comm", "tcp"), ("RTP", "rtp", "udp"),
)
# Fixtures whose bytes are a server message although their scope and evidence do not say so.
SERVER_FIXTURE_NAMES = ("TLS_SERVER12", "TLS_SERVER13", "TLS_RETRY", "TLS_SERVER12_CERTIFICATE", "CONNECT_RESPONSE", "H2C_101",
                        "RDP_CONFIRM", "ISO_TSAP_CONFIRM", "H2_SERVER_SETTINGS", "WEBSOCKET_SERVER_FRAME", "S7COMM_ACK",
                        "STOMP_SERVER", "NATS_INFO", "POP3_SERVER", "MYSQL", "IMAP", "HTTP_RESPONSE")
# Families whose initial message has the same shape in both directions (one fixture proves both),
# and families that only ever flow one way (exporter to collector, client to broker).
SYMMETRIC = frozenset(("bgp", "ssh", "telnet", "dnp3", "iec-104", "bacnet", "ethernet-ip", "stun", "sip", "rtsp", "ssdp", "rtp", "bittorrent", "coap"))
ONE_WAY = frozenset(("netflow", "ipfix", "sflow", "syslog"))


def family_of(observation):
    name = observation.application_protocol or observation.encryption
    if name is None:
        return None
    return "http2" if name == "http/2" else name.split("/", 1)[0]


def _server_bytes():
    return {bytes(getattr(fixtures, name)) for name in SERVER_FIXTURE_NAMES if hasattr(fixtures, name)}


def side_of(observation, data=None, server_bytes=frozenset()):
    """'server' or 'client' for an identified observation."""
    if data is not None and bytes(data) in server_bytes:
        return "server"
    if observation.scope in SERVER_SCOPES:
        return "server"
    values = {evidence.field: evidence.value for evidence in observation.evidence}
    for field, predicate in DIRECTION_RULES:
        if field in values and predicate(values[field]):
            return "server"
    return "client"


def _inputs():
    yield from ((data, None, "tcp") for data, _ in fixtures.STREAM_CASES)
    yield from ((data, hint, "tcp") for data, _, hint in fixtures.HINTED_STREAM_CASES)
    yield from ((data, None, "udp") for data, _ in fixtures.DATAGRAM_CASES)
    yield from ((data, hint, "udp") for data, _, hint in fixtures.HINTED_DATAGRAM_CASES)
    yield from ((data, None, "tcp") for _, data in examples())
    for name, hint, transport in EXTRA:
        data = getattr(fixtures, name, None)
        if data is not None:
            yield data, hint, transport


def build(config=None):
    """Return {family: {"transports": set, "sides": set, "fields": set}} from every fixture."""
    config = config or Config(certificates=True)
    server_bytes = _server_bytes()
    table = defaultdict(lambda: {"transports": set(), "sides": set(), "fields": set()})
    for data, hint, transport in _inputs():
        if transport == "tcp":
            inspector = Inspector(config, protocol_hint=hint)
            inspector.feed(data)
            observation = inspector.observation
        else:
            observation = DatagramInspector(config).inspect(data, hint)
        if observation.status != "identified":
            continue
        family = family_of(observation)
        if family is None:
            continue
        row = table[family]
        row["transports"].add(transport)
        row["sides"].add(side_of(observation, data, server_bytes))
        row["fields"].update(evidence.field for evidence in observation.evidence if evidence.field not in HIDDEN_FIELDS)
    return table


def render(table=None):
    table = table if table is not None else build()
    catalog = {entry.family: entry for entry in supported_protocols()}
    lines = ["| Family | Transports | Client | Server | Evidence fields |", "|---|---|---|---|---|"]
    for family in sorted(catalog):
        row = table.get(family)
        transports = "/".join(catalog[family].transports)
        if row is None:
            lines.append("| {} | {} | - | - | (no fixture) |".format(family, transports))
            continue
        client = "yes" if "client" in row["sides"] else "-"
        if "server" in row["sides"]:
            server = "yes"
        elif family in SYMMETRIC:
            server = "same shape"
        elif family in ONE_WAY:
            server = "n/a (one-way)"
        else:
            server = "-"
        fields = ", ".join("`{}`".format(field) for field in sorted(row["fields"])) or "-"
        lines.append("| {} | {} | {} | {} | {} |".format(family, transports, client, server, fields))
    both = sum(1 for family, row in table.items() if "server" in row["sides"] or family in SYMMETRIC)
    pending = sorted(family for family in catalog if family not in SYMMETRIC and family not in ONE_WAY
                     and "server" not in table.get(family, {"sides": set()})["sides"])
    summary = ("{} families in the catalog, {} with fixtures, {} proven on both sides (or symmetric), {} one-way; "
               "server side still unproven: {}.".format(len(catalog), len(table), both, len(ONE_WAY & set(catalog)),
                                                          ", ".join(pending) if pending else "none"))
    return "\n".join(lines) + "\n\n" + summary + "\n"


def splice(document, table_text):
    start, end = document.index(START), document.index(END)
    return document[:start + len(START)] + "\n" + table_text + document[end:]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write", metavar="PATH", help="Replace the table between the markers in PATH")
    parser.add_argument("--check", metavar="PATH", help="Exit 1 when PATH's table differs from the fixtures")
    args = parser.parse_args(argv)
    text = render()
    if args.write:
        with open(args.write, encoding="utf-8") as handle:
            document = handle.read()
        with open(args.write, "w", encoding="utf-8") as handle:
            handle.write(splice(document, text))
        print("coverage matrix written to", args.write)
        return 0
    if args.check:
        with open(args.check, encoding="utf-8") as handle:
            document = handle.read()
        if START not in document or END not in document:
            print("coverage matrix markers missing in", args.check)
            return 1
        if splice(document, text) != document:
            print("coverage matrix drift: run tools/coverage_matrix.py --write", args.check)
            return 1
        print("coverage matrix ok")
        return 0
    print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
