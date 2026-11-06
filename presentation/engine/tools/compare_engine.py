"""Behaviour diff of the whole classification engine against another source tree.

Usage: python3 -B tools/compare_engine.py BASELINE_TREE [--iterations N] [--seed S]
                                          [--report FILE] [--report-only]

The working tree generates one input set from its fixtures: every stream and
datagram fixture, every truncation of each fixture, a 3-byte fragmentation and
N seeded single-byte mutations per fixture. Each tree then classifies the whole
set in its own interpreter (a worker process with that tree first on sys.path,
so lazy imports inside the engine resolve to the same tree) and reports the
terminal observation per input: status, protocol, encryption, hostname, scope,
reason and evidence rows, or the exception that escaped. Differences are listed per fixture
family so a reviewer can tell an intended profile change from an accidental
one. Exit status is 1 when differences exist unless --report-only is given
(the CI job publishes the report for review without failing the build).
"""
import argparse
import json
import random
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

WORKER = r'''
import json, sys
root, path = sys.argv[1], sys.argv[2]
sys.path.insert(0, root)
from protocol_engine import DatagramInspector, Inspector
cases = json.load(open(path))
def summary(observation):
    evidence = sorted((e.field, e.value, e.strength) for e in observation.evidence)
    return [observation.status, observation.application_protocol, observation.encryption, observation.hostname, observation.scope, observation.reason, evidence]
out = []
for kind, hint, fragments, data_hex in cases:
    data = bytes.fromhex(data_hex)
    try:
        if kind == "stream":
            try:
                inspector = Inspector(protocol_hint=hint)
            except (ValueError, TypeError):
                out.append(["unsupported-hint"]); continue
            if fragments:
                for pos in range(0, len(data), fragments):
                    inspector.feed(data[pos:pos + fragments])
            else:
                inspector.feed(data)
            inspector.end()
            out.append(summary(inspector.observation))
        else:
            out.append(summary(DatagramInspector().inspect(data, hint)))
    except Exception as error:
        out.append(["exception", type(error).__name__, str(error)])
print(json.dumps(out))
'''


def build_cases(iterations, seed):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    import protocol_fixtures as fixtures
    rng = random.Random(seed)
    cases, names = [], []
    streams = [(data, name, None) for data, name in fixtures.STREAM_CASES] + [(data, name, hint) for data, name, hint in fixtures.HINTED_STREAM_CASES]
    for data, name, hint in streams:
        variants = [(data, None)] + [(data[:cut], None) for cut in range(1, len(data))] + [(data, 3)]
        for _ in range(iterations):
            changed = bytearray(data)
            changed[rng.randrange(len(changed))] = rng.randrange(256)
            variants.append((bytes(changed), None))
        for variant, fragments in variants:
            cases.append(("stream", hint, fragments, variant.hex()))
            names.append(name)
    datagrams = [(data, name, None) for data, name in fixtures.DATAGRAM_CASES] + [(data, name, hint) for data, name, hint in fixtures.HINTED_DATAGRAM_CASES]
    for data, name, hint in datagrams:
        variants = [data] + [data[:cut] for cut in range(1, len(data))]
        for _ in range(iterations):
            changed = bytearray(data)
            changed[rng.randrange(len(changed))] = rng.randrange(256)
            variants.append(bytes(changed))
        for variant in variants:
            cases.append(("datagram", hint, None, variant.hex()))
            names.append(name)
    return cases, names


def classify_in_tree(root, cases_path):
    result = subprocess.run([sys.executable, "-B", "-c", WORKER, str(root), str(cases_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1800)
    if result.returncode:
        raise RuntimeError("worker failed in {}: {}".format(root, result.stderr.decode("utf-8", "replace")[-2000:]))
    return json.loads(result.stdout.decode("utf-8"))


def compare(baseline_root, iterations, seed):
    cases, names = build_cases(iterations, seed)
    current_root = Path(__file__).resolve().parent.parent
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(cases, handle)
    try:
        before = classify_in_tree(baseline_root, handle.name)
        after = classify_in_tree(current_root, handle.name)
    finally:
        Path(handle.name).unlink()
    differences = defaultdict(list)
    for (kind, hint, fragments, data_hex), name, old, new in zip(cases, names, before, after):
        if old != new:
            differences[name].append((data_hex[:48], old, new))
    return len(cases), differences


def render(baseline_root, cases, differences, iterations, seed):
    lines = ["# Engine behaviour diff", "", "Baseline tree: `{}`".format(baseline_root), "",
             "{} inputs compared ({} seeded mutations per fixture, seed {}); {} fixtures differ.".format(
                 cases, iterations, seed, len(differences)), ""]
    for name in sorted(differences):
        items = differences[name]
        lines.append("## {} ({} differing inputs)".format(name, len(items)))
        lines.append("")
        lines.append("| input prefix (hex) | baseline | current |")
        lines.append("|---|---|---|")
        for prefix, old, new in items[:12]:
            lines.append("| `{}` | {} | {} |".format(prefix, " / ".join(str(part) for part in old[:3]), " / ".join(str(part) for part in new[:3])))
        if len(items) > 12:
            lines.append("")
            lines.append("... {} more".format(len(items) - 12))
        lines.append("")
    if not differences:
        lines.append("No behaviour differences.")
        lines.append("")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("baseline", help="Path to another checkout of this repository")
    parser.add_argument("--iterations", type=int, default=300, help="Seeded mutations per fixture (default 300)")
    parser.add_argument("--seed", type=int, default=37)
    parser.add_argument("--report", help="Write the Markdown report to this file as well as printing a summary")
    parser.add_argument("--report-only", action="store_true", help="Exit 0 even when differences exist")
    args = parser.parse_args(argv)
    root = Path(args.baseline).resolve()
    if not (root / "protocol_engine" / "__init__.py").is_file():
        print("not a protocol-detector tree: {}".format(root))
        return 2
    cases, differences = compare(root, max(0, args.iterations), args.seed)
    report = render(root, cases, differences, args.iterations, args.seed)
    if args.report:
        Path(args.report).write_text(report, encoding="utf-8")
    print(report if not args.report else report.splitlines()[4])
    return 0 if (not differences or args.report_only) else 1


if __name__ == "__main__":
    sys.exit(main())
