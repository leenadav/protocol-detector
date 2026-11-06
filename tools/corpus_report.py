"""Labelled-corpus accuracy report (stage 7, A15): true/false outcomes by profile and input class.

The corpus is the repository's synthetic fixture set (every labelled stream and datagram fixture), which is
authorized by construction: no captured traffic. Input classes: `intact` (the fixture as labelled),
`truncated` (prefixes), `mutated` (seeded byte mutations). Per family the report counts true positives
(identified as the labelled family), false negatives (intact fixture not identified as its family), explicit
non-identifications, and false positives (an input of one class identified as a different family). It is an
accuracy report over a synthetic corpus, not a real-world accuracy or latency claim.
"""
import argparse
import random
import sys
from collections import OrderedDict, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from protocol_engine import Config, DatagramInspector, Inspector  # noqa: E402
from protocol_engine.descriptors import build  # noqa: E402
from protocol_engine.registry import PARSERS  # noqa: E402
from protocol_adapters.protocol_fixtures import DATAGRAM_CASES, STREAM_CASES  # noqa: E402

DESCRIPTORS = build()


def family_of(label):
    return (label or "").split("/", 1)[0]


def stream_outcome(data, family):
    hint = family if DESCRIPTORS[family].requires_hint and family in PARSERS else None
    inspector = Inspector(Config(), protocol_hint=hint)
    inspector.feed(data)
    observation = inspector.observation
    return observation.status, family_of(observation.application_protocol or observation.encryption)


def datagram_outcome(data, family):
    hint = family if DESCRIPTORS[family].requires_hint else None
    observation = DatagramInspector().inspect(data, hint)
    return observation.status, family_of(observation.application_protocol or observation.encryption)


def tally(table, family, cls, status, found):
    row = table[family][cls]
    if status == "identified":
        if found == family:
            row["tp"] += 1
        else:
            row["fp"] += 1
            table[family]["fp_as"].add(found)
    elif cls == "intact":
        row["fn"] += 1
    else:
        row["explicit"] += 1


def run(seed, mutations):
    rng = random.Random(seed)
    table = defaultdict(lambda: {"intact": defaultdict(int), "truncated": defaultdict(int), "mutated": defaultdict(int), "fp_as": set()})
    for cases, outcome in ((STREAM_CASES, stream_outcome), (DATAGRAM_CASES, datagram_outcome)):
        for data, label in cases:
            family = family_of(label)
            tally(table, family, "intact", *outcome(data, family))
            if outcome is stream_outcome:
                for cut in sorted({1, 2, 4, len(data) // 2, max(1, len(data) - 1)}):
                    tally(table, family, "truncated", *outcome(data[:cut], family))
            for _ in range(mutations):
                mutated = bytearray(data)
                for _ in range(rng.randrange(1, 4)):
                    mutated[rng.randrange(len(mutated))] = rng.randrange(256)
                tally(table, family, "mutated", *outcome(bytes(mutated), family))
    return OrderedDict(sorted(table.items()))


def render(table, seed, mutations):
    lines = ["# Labelled-corpus report (synthetic fixtures)", "",
             "Seed %d, %d mutations per fixture. Classes: intact fixture, truncated prefixes (1, 2, 4, half, all-but-one bytes), "
             "seeded byte mutations. TP = identified as the labelled family; FN = intact fixture not identified; explicit = truncated or "
             "mutated input ended in an explicit non-identification; FP = identified as a different family. Synthetic corpus: "
             "not a real-world accuracy figure." % (seed, mutations), "",
             "| family | intact TP/FN | truncated TP/explicit/FP | mutated TP/explicit/FP | FP named as |", "|---|---|---|---|---|"]
    totals = defaultdict(int)
    for family, rows in table.items():
        i, t, m = rows["intact"], rows["truncated"], rows["mutated"]
        for cls in (i, t, m):
            for key in ("tp", "fn", "fp", "explicit"):
                totals[key] += cls[key]
        lines.append("| %s | %d/%d | %d/%d/%d | %d/%d/%d | %s |" % (family, i["tp"], i["fn"], t["tp"], t["explicit"], t["fp"],
                                                                   m["tp"], m["explicit"], m["fp"], ", ".join(sorted(rows["fp_as"])) or "—"))
    lines += ["", "Totals: TP %d, FN %d, explicit %d, FP %d across %d families." % (totals["tp"], totals["fn"], totals["explicit"], totals["fp"], len(table))]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=72)
    parser.add_argument("--mutations", type=int, default=25)
    parser.add_argument("--write", help="write the Markdown report to this path")
    parser.add_argument("--max-fn", type=int, default=0, help="fail when intact false negatives exceed this")
    args = parser.parse_args(argv)
    table = run(args.seed, args.mutations)
    report = render(table, args.seed, args.mutations)
    if args.write:
        Path(args.write).write_text(report)
    print(report.splitlines()[-1])
    fn = sum(rows["intact"]["fn"] for rows in table.values())
    fp_intact = sum(rows["intact"]["fp"] for rows in table.values())
    if fn > args.max_fn or fp_intact:
        print("corpus FAILED: %d intact false negatives, %d intact false positives" % (fn, fp_intact))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
