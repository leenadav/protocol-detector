"""PRO-448 (kidcarmi PoC, forwarded by Lee, 2026-11-25): the Python reference with the Go-only analyze additions
modelled, for analyze_diff.py.

Go's `analyze` reports what a full table turned away and what a UDP flow's first identification hid; the frozen
reference does neither (Go only; the Python engine is being retired):

- the summary counter and the summary's input quality carry `udp_flow_limit` (UDP datagrams inspected while the
  flow table was full: the reference already counts them in Analyzer.counts, but never prints them) and
  `tcp_connection_limit` (connection openings answered "LIMIT: too many tracked connections"), always, after
  the reference's keys; the text summary names each only when it is not 0;
- each UDP session record ends with `mixed_outcomes` and `datagram_outcomes`: the flow's distinct identified
  (protocol, application) labels, the ones Analyzer._decided records, in first-seen order with datagram counts,
  at most MAX_OUTCOMES, the identified datagrams beyond them counted in `beyond_limit`.

`modelled()` adds exactly that to the reference's output and changes nothing else about it. The harness compares
the Go binary with the modelled output byte for byte, so every other difference still fails.
"""

import contextlib
import io
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from protocol_adapters import analyze_pcap  # noqa: E402

LABEL = "PRO-448"
MAX_OUTCOMES = 8                     # go/internal/session MaxDatagramOutcomes
LIMIT = "LIMIT: too many tracked connections"


def _outcomes(state):
    outcomes, beyond = state.get("pro448_outcomes", []), state.get("pro448_beyond", 0)
    distinct = [{"protocol": label[0] or "", "application": label[1], "datagrams": count} for label, count in outcomes]
    return len(outcomes) > 1 or beyond > 0, {"distinct": distinct, "beyond_limit": beyond}


def summary_line(line, udp_limit, tcp_limit, json_output):
    """The reference's last line with the two counters added as Go writes them."""
    if json_output:
        row = json.loads(line)
        for part in (row["summary"], row["input_quality"]):
            part["udp_flow_limit"], part["tcp_connection_limit"] = udp_limit, tcp_limit
        return json.dumps(row)
    return line + ("; udp_flow_limit: {}".format(udp_limit) if udp_limit else "") + (
        "; tcp_connection_limit: {}".format(tcp_limit) if tcp_limit else "")


@contextlib.contextmanager
def modelled(created):
    """The reference's Analyzer with the PRO-448 session fields and the TCP limit count; each Analyzer that
    processes a packet is appended to created. Restored on exit."""
    analyzer_class = analyze_pcap.Analyzer
    original_decided, original_record, original_process = analyzer_class._decided, analyzer_class._record, analyzer_class.process

    def decided(self, state, label):
        original_decided(self, state, label)
        if "fin" in state:               # a TCP state; UDP flows carry no FIN table
            return
        outcomes = state.setdefault("pro448_outcomes", [])
        for entry in outcomes:
            if entry[0] == label:
                entry[1] += 1
                return
        if len(outcomes) >= MAX_OUTCOMES:
            state["pro448_beyond"] = state.get("pro448_beyond", 0) + 1
        else:
            outcomes.append([label, 1])

    def record(self, transport, client, server, state, verdict, reason, observations, inspectors=(None, None)):
        sink = self.on_session
        if transport != "udp" or sink is None:
            return original_record(self, transport, client, server, state, verdict, reason, observations, inspectors)

        def extended(session):
            session["mixed_outcomes"], session["datagram_outcomes"] = _outcomes(state)
            sink(session)
        self.on_session = extended
        try:
            return original_record(self, transport, client, server, state, verdict, reason, observations, inspectors)
        finally:
            self.on_session = sink

    def process(self, timestamp, packet):
        if not created or created[-1] is not self:
            created.append(self)
        before = self.counts["pro448_tcp_limit"]
        message = original_process(self, timestamp, packet)
        # A midstream restart re-enters process: count the LIMIT once, where it was decided.
        if message == LIMIT and self.counts["pro448_tcp_limit"] == before:
            self.counts["pro448_tcp_limit"] += 1
        return message

    analyzer_class._decided, analyzer_class._record, analyzer_class.process = decided, record, process
    try:
        yield
    finally:
        analyzer_class._decided, analyzer_class._record, analyzer_class.process = original_decided, original_record, original_process


def analyze(path, json_output=False, **options):
    """analyze_pcap.analyze with the PRO-448 output, printed to the current standard output. An exception
    leaves the rows printed before it, as the reference does (there is no summary then)."""
    created, output = [], io.StringIO()
    try:
        with modelled(created), contextlib.redirect_stdout(output):
            counts = analyze_pcap.analyze(path, json_output=json_output, **options)
    except BaseException:
        sys.stdout.write(output.getvalue())
        raise
    lines = output.getvalue().split("\n")    # the summary is the last line; "" follows its newline
    analyzer = created[-1] if created else None
    udp_limit = analyzer.counts["udp_flow_limit"] if analyzer else 0
    tcp_limit = analyzer.counts["pro448_tcp_limit"] if analyzer else 0
    lines[-2] = summary_line(lines[-2], udp_limit, tcp_limit, json_output)
    sys.stdout.write("\n".join(lines))
    return counts


def _frame(protocol, source, destination, header, payload):
    """Ethernet II + IPv4 (valid header checksum) around a transport header and payload."""
    ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(header) + len(payload), 0, 0, 64, protocol, 0,
                               bytes(source), bytes(destination)))
    total = sum(struct.unpack("!10H", bytes(ip)))
    while total > 0xffff:
        total = (total & 0xffff) + (total >> 16)
    ip[10:12] = struct.pack("!H", ~total & 0xffff)
    return b"\xff" * 6 + b"\x00\x00\x00\x00\x00\x01\x08\x00" + bytes(ip) + header + payload


def _udp(source, destination, ports, payload):
    return _frame(17, source, destination, struct.pack("!HHHH", ports[0], ports[1], 8 + len(payload), 0), payload)


def _syn(source, destination, ports, sequence):
    return _frame(6, source, destination, struct.pack("!HHIIBBHHH", ports[0], ports[1], sequence, 0, 5 << 4, 0x02, 65535, 0, 0), b"")


def _write_pcap(path, records):
    """A classic little-endian PCAP of Ethernet frames (no import of analyze_diff, which imports this module)."""
    with open(path, "wb") as capture:
        capture.write(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
        for timestamp, data, _ in records:
            seconds = int(timestamp)
            capture.write(struct.pack("<IIII", seconds, int(round((timestamp - seconds) * 1000000)) % 1000000, len(data), len(data)) + data)


def self_test():
    """The model is still needed (the reference prints neither addition), adds exactly the documented keys with
    the counts the Go tests expect, and leaves nothing patched behind."""
    import tempfile
    dns = bytes.fromhex("12340100000100000000000007" + "6578616d706c65" + "03636f6d0000010001")
    stun = bytes.fromhex("000100002112a442" + "0102030405060708090a0b0c")
    client, server = (198, 51, 100, 7), (192, 0, 2, 9)
    records = [[1700000000.0, _udp(client, server, (40000, 3478), dns), False],
               [1700000000.1, _udp(client, server, (40000, 3478), stun), False],
               [1700000000.2, _udp(client, server, (40000, 3478), dns), False]]
    records += [[1700000000.3 + i / 1000, _udp((198, 51, 101, i), server, (40000, 53), dns), False] for i in range(40)]
    records += [[1700000000.5 + i / 1000, _syn((198, 51, 102, i), server, (40000, 80), 1000 * i + 1), False] for i in range(40)]

    def run(path, model, json_output):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            (analyze if model else analyze_pcap.analyze)(str(path), json_output=json_output, sessions=True)
        return output.getvalue().splitlines()
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "capture.pcap"
        _write_pcap(path, records)
        plain, model, text = run(path, False, True), run(path, True, True), run(path, True, False)
    if any("udp_flow_limit" in line or "mixed_outcomes" in line for line in plain):
        raise AssertionError("the reference now prints the PRO-448 keys; the model is stale")
    if len(plain) != len(model):
        raise AssertionError("the PRO-448 model added or removed a row")
    udp_sessions = 0
    for before, after in zip(plain[:-1], model[:-1]):
        row, extended = json.loads(before), json.loads(after)
        if row.get("type") == "session" and row["transport"] == "udp":
            udp_sessions += 1
            mixed, outcomes = extended.pop("mixed_outcomes"), extended.pop("datagram_outcomes")
            if udp_sessions == 1 and (mixed is not True or [(o["protocol"], o["datagrams"]) for o in outcomes["distinct"]] != [("dns", 2), ("stun", 1)]):
                raise AssertionError("the PRO-448 mixed flow is wrong: {}".format(after))
            if udp_sessions > 1 and mixed is not False:
                raise AssertionError("a single-protocol flow is marked: {}".format(after))
        if row != extended or list(row) != list(extended):
            raise AssertionError("the PRO-448 model changed a row it does not own: {}".format(after))
    summary = json.loads(model[-1])
    # 32 flows: the mixed flow and 31 DNS flows; 9 datagrams turned away. 32 connections; 8 SYNs turned away.
    if udp_sessions != 32 or [summary[part].get(key) for part in ("summary", "input_quality")
                              for key in ("udp_flow_limit", "tcp_connection_limit")] != [9, 8, 9, 8]:
        raise AssertionError("the PRO-448 summary model is wrong: {} ({} UDP sessions)".format(model[-1], udp_sessions))
    if not text[-1].endswith("; sessions: 64; udp_flow_limit: 9; tcp_connection_limit: 8"):
        raise AssertionError("the PRO-448 text summary model is wrong: {}".format(text[-1]))
    if analyze_pcap.Analyzer.process.__name__ != "process" or analyze_pcap.Analyzer._decided.__name__ != "_decided" or \
            analyze_pcap.Analyzer._record.__name__ != "_record":
        raise AssertionError("the PRO-448 model leaked out of its context")
    return summary


if __name__ == "__main__":
    self_test()
    print("pro448 model: ok")
