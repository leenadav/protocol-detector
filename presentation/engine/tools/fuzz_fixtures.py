"""Seeded mutation fuzzing of every fixture through both inspection APIs.

Exit status 1 on any crash, status outside the documented set, more than one
candidate selected per stream, or inspected bytes exceeding the input. This is
the nightly extension of the bounded mutation tests that run in `make test`.
"""
import argparse
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol_engine import Config, DatagramInspector, Inspector  # noqa: E402
from protocol_engine.datagram import VALIDATORS  # noqa: E402
from protocol_engine.registry import PARSERS  # noqa: E402
from protocol_fixtures import DATAGRAM_CASES, HINTED_DATAGRAM_CASES, HINTED_STREAM_CASES, STREAM_CASES  # noqa: E402
from proxy_demo import client_hello  # noqa: E402

STATUSES = {"identified", "unknown", "malformed", "budget_exhausted", "incomplete", "invalidated", "detecting"}


def mutate(rng, data):
    data = bytearray(data)
    for _ in range(rng.randrange(1, 6)):
        choice = rng.random()
        if choice < .6 and data:
            data[rng.randrange(len(data))] = rng.randrange(256)
        elif choice < .8:
            pos = rng.randrange(len(data) + 1)
            data[pos:pos] = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 9)))
        elif data:
            pos = rng.randrange(len(data))
            del data[pos:pos + rng.randrange(1, 9)]
    return bytes(data)


def stream_case(rng, data, hint, config):
    whole = Inspector(config, protocol_hint=hint)
    whole.feed(data)
    whole.end()
    split = Inspector(config, protocol_hint=hint)
    pos = 0
    while pos < len(data):
        width = rng.randrange(1, 32)
        split.feed(data[pos:pos + width])
        pos += width
    split.end()
    for inspector in (whole, split):
        if inspector.observation.status not in STATUSES:
            raise AssertionError("undocumented status " + inspector.observation.status)
        if inspector.metrics.candidates_selected > 1 or inspector.metrics.bytes_inspected > len(data):
            raise AssertionError("work bound violated")
    if whole.observation != split.observation:
        raise AssertionError("fragmentation changed the observation")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=20261020)
    args = parser.parse_args()
    rng = random.Random(args.seed)
    config = Config()
    streams = [(data, None) for data, _ in STREAM_CASES] + [(data, hint) for data, _, hint in HINTED_STREAM_CASES]
    streams.append((client_hello(), None))
    datagrams = [(data, None) for data, _ in DATAGRAM_CASES] + [(data, hint) for data, _, hint in HINTED_DATAGRAM_CASES]
    start = time.monotonic()
    executed = 0
    try:
        for data, hint in streams:
            for _ in range(args.iterations):
                stream_case(rng, mutate(rng, data), hint, config)
                executed += 1
        udp = DatagramInspector(config)
        for data, hint in datagrams:
            for _ in range(args.iterations):
                result = udp.inspect(mutate(rng, data), hint)
                if result.status not in STATUSES or udp.metrics.parser_calls < 0:
                    raise AssertionError("undocumented datagram status")
                executed += 1
        for _ in range(args.iterations):
            noise = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 600)))
            for hint in (None, *PARSERS):
                stream_case(rng, noise, hint, config)
            for hint in (None, *VALIDATORS):
                udp.inspect(noise, hint)
            executed += 1
    except Exception as error:  # noqa: BLE001 - any exception is a finding
        print("FUZZ FINDING after {} cases (seed {}): {!r}".format(executed, args.seed, error))
        return 1
    print("fuzz ok: {} cases, seed {}, {:.1f}s".format(executed, args.seed, time.monotonic() - start))
    return 0


if __name__ == "__main__":
    sys.exit(main())
