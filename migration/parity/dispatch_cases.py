"""Migration M4: the bounded prefix classifier's decisions as a language-neutral table.

`protocol_engine.dispatch.select(prefix)` maps 1..24 leading bytes to a family, "unknown", or None (wait
for more bytes). It is pure, so the Go port is checked against every prefix length of every labelled
stream fixture plus seeded mutations: migration/fixtures/dispatch.json maps hex prefix -> decision.
"""
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from protocol_adapters.protocol_fixtures import HINTED_STREAM_CASES, STREAM_CASES  # noqa: E402
from protocol_engine.dispatch import LOOKAHEAD, select  # noqa: E402


def generate(seed=4):
    rng = random.Random(seed)
    table = {}
    sources = [data for data, _ in STREAM_CASES] + [data for data, _, _ in HINTED_STREAM_CASES]
    for data in sources:
        variants = [data]
        for _ in range(3):
            mutated = bytearray(data[:LOOKAHEAD])
            if mutated:
                mutated[rng.randrange(len(mutated))] = rng.randrange(256)
            variants.append(bytes(mutated))
        variants.append(bytes([rng.randrange(256) for _ in range(LOOKAHEAD)]))
        for variant in variants:
            for length in range(1, min(LOOKAHEAD, len(variant)) + 1):
                prefix = variant[:length]
                table[prefix.hex()] = select(prefix)
    return table


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", default=str(ROOT / "migration/fixtures/dispatch.json"))
    args = parser.parse_args(argv)
    table = generate()
    Path(args.write).write_text(json.dumps({"schema": 1, "lookahead": LOOKAHEAD, "decisions": table}, indent=0, sort_keys=True) + "\n", encoding="utf-8")
    print("dispatch decisions written: {} prefixes".format(len(table)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
