"""Differential check of parse_hello against another source tree.

Usage: python3 -B tools/compare_client_hello.py /path/to/baseline-tree [iterations]

Loads protocol_engine.parsers from the baseline tree under a temporary module
alias and compares, for every truncation and thousands of seeded mutations of
three synthetic ClientHellos, the (hostname, alpn, ClientHelloInfo fields)
result or the exception type and message. Used to show that a hot-path
rewrite preserved error semantics (BENCHMARK-V035.md). Exit status 1 when any
case differs.
"""
import importlib
import random
import sys
from pathlib import Path


def load_baseline(root):
    saved = {name: module for name, module in sys.modules.items() if name == "protocol_engine" or name.startswith("protocol_engine.")}
    for name in saved:
        del sys.modules[name]
    sys.path.insert(0, str(root))
    try:
        module = importlib.import_module("protocol_engine.parsers")
    finally:
        sys.path.pop(0)
        for name in list(sys.modules):
            if name == "protocol_engine" or name.startswith("protocol_engine."):
                del sys.modules[name]
        sys.modules.update(saved)
    return module


def outcome(module, body):
    info = module.ClientHelloInfo()
    try:
        result = module.parse_hello(body, info)
    except Exception as error:  # noqa: BLE001 - any exception type is part of the compared behaviour
        return ("error", type(error).__name__, str(error))
    return ("ok", result, info.version, info.ciphers, info.extensions, info.hostname, info.alpn, info.groups,
            info.signature_algorithms, info.point_formats, info.supported_versions)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print(__doc__)
        return 2
    root = Path(argv[0]).resolve()
    iterations = int(argv[1]) if len(argv) > 1 else 4000
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    current = importlib.import_module("protocol_engine.parsers")
    baseline = load_baseline(root)
    from proxy_demo import client_hello
    from test_fingerprints import hello
    bodies = [raw[9:] for raw in (client_hello(),
                                  hello([0x1301, 0x1302], [(0, b"\x00\x0c\x00\x00\x09localhost"), (43, b"\x02\x03\x04"), (16, b"\x00\x05\x02h2\x00")]),
                                  hello([0x002f], []))]
    rng = random.Random(35)
    cases, differences = 0, []
    for body in bodies:
        variants = [body[:n] for n in range(len(body) + 1)] + [body + b"\x00", body + b"\x00\x00"]
        for _ in range(iterations):
            changed = bytearray(body)
            for _ in range(rng.choice((1, 1, 2, 3))):
                changed[rng.randrange(len(changed))] = rng.randrange(256)
            variants.append(bytes(changed))
        for variant in variants:
            cases += 1
            before, after = outcome(baseline, variant), outcome(current, variant)
            if before != after:
                differences.append((variant[:16].hex(), before[:3], after[:3]))
    print("{} cases compared against {}: {} differences".format(cases, root, len(differences)))
    for item in differences[:10]:
        print(item)
    return 1 if differences else 0


if __name__ == "__main__":
    sys.exit(main())
