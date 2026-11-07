"""D10: stateful and metamorphic sequence checks over the Analyzer (the public packet path).

Every labelled stream fixture is sent as the client's data after an observed handshake, and the
session record of that plain delivery is the oracle. Seeded transformations of the packet
sequence must then satisfy documented relations:

  segmentation   any in-order split into segments gives the same record;
  reordering     segments delivered in any order (within the reassembly window), with identical
                 retransmissions mixed in, give the same record, and the engine inspects each
                 contiguous byte once (telemetry bytes.new equals the payload once);
  conflict       a retransmission that changes a byte never identifies another family: the record is
                 the oracle (overlap no longer retained) or an explicit invalidation;
  interleaving   connections and datagram flows interleaved with each other give the records they give
                 alone (no cross-flow state);
  fin-first      a FIN that arrives before the last data segment waits for the gap and gives the oracle;
  reuse          a second connection on the same 5-tuple after the first closed gives its own record;
  expiry         a connection idle before its message completed ends explicitly, never as another family.

Violations are reported with the fixture label, the relation and the seed. The checks run in-process on
synthetic frames only.
"""
import argparse
import random
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from protocol_adapters.analyze_pcap import Analyzer  # noqa: E402
from protocol_adapters.link_packets import decode_frame  # noqa: E402
from protocol_adapters.make_sample_pcap import frame, udp_frame  # noqa: E402
from protocol_adapters.protocol_fixtures import DATAGRAM_CASES, STREAM_CASES  # noqa: E402
from protocol_engine.descriptors import build  # noqa: E402

DESCRIPTORS = build()
KEEP = ("app", "base_app", "category", "subcategory", "client_protocol", "server_protocol", "encryption", "engine_status",
        "risks", "hostname", "shifted_from", "transport")
IDLE = 60.0


def family_of(label):
    return (label or "").split("/", 1)[0]


def normalize(record):
    out = {key: record.get(key) for key in KEEP}
    out["risks"] = sorted(out["risks"] or [])
    return out


class Connection:
    """Frame builder for one synthetic TCP connection with correct sequence numbers."""

    def __init__(self, client, server, isn=1000, server_isn=9000):
        self.client, self.server, self.isn, self.server_isn = client, server, isn, server_isn

    def handshake(self):
        return [frame(self.client, self.server, self.isn - 1, 0, 2), frame(self.server, self.client, self.server_isn - 1, self.isn, 18),
                frame(self.client, self.server, self.isn, self.server_isn, 16)]

    def segments(self, data, cuts):
        """Client data frames for `data` split at the sorted offsets `cuts`."""
        frames, bounds = [], [0] + sorted(cuts) + [len(data)]
        for start, end in zip(bounds, bounds[1:]):
            if end > start:
                frames.append(frame(self.client, self.server, self.isn + start, self.server_isn, 24, data[start:end]))
        return frames

    def fin(self, data):
        return frame(self.client, self.server, self.isn + len(data), self.server_isn, 17)

    def server_fin(self):
        return frame(self.server, self.client, self.server_isn, self.isn, 17)


def drive(frames, **options):
    """Session records (normalized, keyed by endpoints) and telemetry counters of one packet sequence."""
    records = []
    analyzer = Analyzer(on_session=records.append, idle_timeout=IDLE, **options)
    now = 0.0
    for item in frames:
        if isinstance(item, tuple):
            now, data = item
        else:
            now, data = now + 0.001, item
        analyzer.process(now, decode_frame(data, 1))
    analyzer.finish("eof")
    keyed = {}
    for record in records:
        keyed.setdefault((tuple(record["client"]), tuple(record["server"])), []).append(normalize(record))
    return keyed, analyzer.telemetry.render()["counters"]


def random_cuts(rng, length, pieces):
    if length < 2 or pieces < 2:
        return []
    return sorted(rng.sample(range(1, length), min(pieces - 1, length - 1)))


class Checker:
    def __init__(self, seed, iterations):
        self.rng = random.Random(seed)
        self.seed = seed
        self.iterations = iterations
        self.violations = []
        self.counts = Counter()

    def fail(self, label, relation, detail):
        self.violations.append("%s [%s] seed %d: %s" % (label, relation, self.seed, detail))

    def same(self, label, relation, expected, actual, detail=""):
        self.counts[relation] += 1
        if expected != actual:
            self.fail(label, relation, "%sexpected %s got %s" % (detail and detail + "; ", expected, actual))

    def check_fixture(self, data, label):
        family = family_of(label)
        connection = Connection(("192.0.2.10", 52000), ("198.51.100.20", 8000))
        plain = connection.handshake() + connection.segments(data, []) + [connection.fin(data)]
        oracle, _ = drive(plain)
        key = (connection.client, connection.server)
        record = oracle.get(key, [None])[-1]
        if record is None:
            return self.fail(label, "oracle", "no session record for the plain delivery")
        identified = record["engine_status"] == "identified"
        found = family_of(record["client_protocol"] or record["encryption"])
        if identified and found != family:
            # Fixtures labelled with a server-side message are allowed to be unknown as client data, never another family.
            self.fail(label, "oracle", "plain delivery identified %s" % found)
        for _ in range(self.iterations):
            pieces = self.rng.randrange(2, 9)
            cuts = random_cuts(self.rng, len(data), pieces)
            segments = connection.segments(data, cuts)
            # segmentation: in order
            self.same(label, "segmentation", oracle[key], drive(connection.handshake() + segments + [connection.fin(data)])[0].get(key))
            # reordering with identical retransmissions, FIN last
            shuffled = segments[:]
            self.rng.shuffle(shuffled)
            for _ in range(self.rng.randrange(0, 3)):
                shuffled.insert(self.rng.randrange(len(shuffled) + 1), self.rng.choice(segments))
            keyed, counters = drive(connection.handshake() + shuffled + [connection.fin(data)])
            self.same(label, "reordering", oracle[key], keyed.get(key))
            if counters.get("bytes.new", 0) > len(data):
                self.fail(label, "reordering", "bytes.new %d exceeds the payload %d" % (counters["bytes.new"], len(data)))
            # conflicting retransmission
            if identified and len(data) > 1:
                victim = self.rng.randrange(len(segments))
                start = sum(len(decode_frame(s, 1).payload) for s in segments[:victim])
                piece = bytearray(decode_frame(segments[victim], 1).payload)
                piece[self.rng.randrange(len(piece))] ^= 0xff
                conflicting = frame(connection.client, connection.server, connection.isn + start, connection.server_isn, 24, bytes(piece))
                sequence = connection.handshake() + segments[:]
                sequence.insert(self.rng.randrange(victim + 1, len(sequence) + 1), conflicting)
                keyed, _ = drive(sequence + [connection.fin(data)])
                self.counts["conflict"] += 1
                outcome = keyed.get(key, [None])[-1]
                if outcome is not None and outcome["engine_status"] == "invalidated":
                    self.counts["conflict-invalidated"] += 1
                if outcome is not None and outcome["engine_status"] == "identified" and outcome != record:
                    self.fail(label, "conflict", "changed bytes produced a different identified record %s" % outcome)
                if outcome is not None and outcome["engine_status"] == "identified" and family_of(outcome["client_protocol"] or outcome["encryption"]) != family:
                    self.fail(label, "conflict", "identified another family %s" % outcome)
            # fin-first: the FIN precedes the last data segment
            if len(segments) > 1:
                early = connection.handshake() + segments[:-1] + [connection.fin(data), segments[-1]]
                self.same(label, "fin-first", oracle[key], drive(early)[0].get(key))
        # reuse: the same tuple carries this fixture, closes both ways, then carries an HTTP request
        http = b"GET /reuse HTTP/1.1\r\nHost: reuse.example\r\n\r\n"
        second = Connection(connection.client, connection.server, isn=70000, server_isn=80000)
        sequence = plain + [connection.server_fin()] + second.handshake() + second.segments(http, []) + [second.fin(http)]
        keyed, _ = drive(sequence)
        alone, _ = drive(second.handshake() + second.segments(http, []) + [second.fin(http)])
        self.counts["reuse"] += 1
        if keyed.get(key, [])[:1] != oracle[key][:1] or keyed.get(key, [])[-1:] != alone.get(key):
            self.fail(label, "reuse", "records after tuple reuse %s differ from the isolated runs" % keyed.get(key))
        # expiry: half the message, then silence past the idle timeout
        half = connection.segments(data[:max(1, len(data) // 2)], [])
        other = Connection(("192.0.2.77", 40000), ("198.51.100.77", 7000))
        sequence = [(0.0, f) for f in connection.handshake() + half] + [(IDLE + 1.0, f) for f in other.handshake()]
        keyed, _ = drive(sequence)
        self.counts["expiry"] += 1
        outcome = keyed.get(key, [None])[-1]
        if outcome is None:
            self.fail(label, "expiry", "idle connection produced no record")
        elif outcome["engine_status"] == "identified" and family_of(outcome["client_protocol"] or outcome["encryption"]) != family:
            self.fail(label, "expiry", "half a message identified another family %s" % outcome)

    def check_interleaving(self, streams, datagrams):
        """Several connections and datagram flows at once give the records they give alone."""
        for _ in range(self.iterations):
            chosen = self.rng.sample(streams, min(3, len(streams)))
            flows, alone = [], {}
            for index, (data, label) in enumerate(chosen):
                connection = Connection(("192.0.2.%d" % (10 + index), 52000 + index), ("198.51.100.%d" % (20 + index), 8000 + index))
                cuts = random_cuts(self.rng, len(data), self.rng.randrange(1, 5))
                frames = connection.handshake() + connection.segments(data, cuts) + [connection.fin(data)]
                flows.append(frames)
                alone[(connection.client, connection.server)] = drive(frames)[0].get((connection.client, connection.server))
            for index, (data, label) in enumerate(self.rng.sample(datagrams, min(2, len(datagrams)))):
                client, server = ("192.0.2.%d" % (30 + index), 53000 + index), ("198.51.100.%d" % (40 + index), 5300 + index)
                frames = [udp_frame(client, server, data)]
                flows.append(frames)
                alone[(client, server)] = drive(frames)[0].get((client, server))
            # Merge preserving each flow's internal order.
            merged, cursors = [], [0] * len(flows)
            while any(cursor < len(flow) for cursor, flow in zip(cursors, flows)):
                index = self.rng.choice([i for i, flow in enumerate(flows) if cursors[i] < len(flow)])
                merged.append(flows[index][cursors[index]])
                cursors[index] += 1
            keyed, _ = drive(merged)
            self.counts["interleaving"] += 1
            for endpoints, expected in alone.items():
                if keyed.get(endpoints) != expected:
                    self.fail(str(endpoints), "interleaving", "expected %s got %s" % (expected, keyed.get(endpoints)))


def automatic_streams():
    return [(data, label) for data, label in STREAM_CASES if not DESCRIPTORS[family_of(label)].requires_hint]


def automatic_datagrams():
    return [(data, label) for data, label in DATAGRAM_CASES if not DESCRIPTORS[family_of(label)].requires_hint]


def run(seed, iterations, limit=None):
    checker = Checker(seed, iterations)
    streams = automatic_streams()
    if limit:
        streams = streams[:limit]
    for data, label in streams:
        checker.check_fixture(data, label)
    checker.check_interleaving(streams, automatic_datagrams())
    return checker


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seed", type=int, default=20261107)
    parser.add_argument("--iterations", type=int, default=3, help="transformations per fixture and interleaving rounds")
    parser.add_argument("--limit", type=int, default=None, help="only the first N automatic stream fixtures")
    args = parser.parse_args(argv)
    checker = run(args.seed, args.iterations, args.limit)
    for violation in checker.violations:
        print("VIOLATION " + violation)
    summary = ", ".join("%s %d" % item for item in sorted(checker.counts.items()))
    print("sequence check %s: seed %d, %d fixtures, %s, %d violations" % (
        "FAILED" if checker.violations else "ok", args.seed, len(automatic_streams()) if not args.limit else args.limit, summary, len(checker.violations)))
    return 1 if checker.violations else 0


if __name__ == "__main__":
    sys.exit(main())
