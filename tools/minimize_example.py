"""D12: explain one payload's non-identification and shrink it to a minimal example with the same outcome.

    python3 -B tools/minimize_example.py --hex 474554202f20485454502f312e310d0a...   [--udp] [--hint FAMILY] [--minimize]
    python3 -B tools/minimize_example.py --file payload.bin --minimize --json

The outcome signature is (status, code, family[, candidates]); the minimizer is a bounded delta-debugging
pass (ddmin on byte ranges, then single bytes) that keeps the signature equal to the original's. Its result
is the smallest input the search found, not a proven minimum. The payload is the caller's input and is
echoed back only as the minimized hex; nothing else is stored.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from protocol_engine import Config, DatagramInspector, Inspector  # noqa: E402
from protocol_engine.registry import PARSERS  # noqa: E402
from protocol_engine.unknown import explain  # noqa: E402

MAX_INPUT = 65536
MAX_STEPS = 20000


def outcome(data, transport="tcp", hint=None, config=None):
    """(observation, structured reason) of one payload through a fresh inspector."""
    config = config or Config()
    if transport == "udp":
        observation = DatagramInspector(config).inspect(data, hint)
        return observation, explain(observation)
    inspector = Inspector(config, protocol_hint=hint if hint in PARSERS else None)
    inspector.feed(data)
    inspector.end("Capture ended before initial message completed")
    return inspector.observation, explain(inspector.observation, inspector=inspector)


def signature(observation, reason, strict=True):
    """What a minimized example must preserve: status, code, family, candidates and, when strict, the engine's sentence."""
    if reason is None:
        return ("identified", observation.application_protocol or observation.encryption, observation.application)
    detail = reason["detail"] if strict else None
    return (observation.status, reason["code"], reason["family"], tuple(reason.get("candidates", ())), detail)


def minimize(data, transport="tcp", hint=None, config=None, max_steps=MAX_STEPS, strict=True):
    """Shrink `data` while the outcome signature stays the same; returns (minimized, steps, target signature)."""
    target = signature(*outcome(data, transport, hint, config), strict=strict)
    steps = 0

    def same(candidate):
        nonlocal steps
        steps += 1
        return signature(*outcome(candidate, transport, hint, config), strict=strict) == target

    current = bytes(data)
    # 1. shortest prefix with the same signature (binary search over the prefix length is unsafe when the
    #    outcome is not monotone, so walk down in halves and confirm each step).
    size = len(current)
    while size > 1 and steps < max_steps:
        half = size // 2
        if same(current[:half]):
            current, size = current[:half], half
        else:
            break
    low, high = 1, len(current)
    while low < high and steps < max_steps:
        mid = (low + high) // 2
        if same(current[:mid]):
            high = mid
        else:
            low = mid + 1
    current = current[:high]
    # 2. ddmin over interior ranges, then single bytes.
    granularity = 2
    while len(current) >= 2 and steps < max_steps:
        chunk = max(1, len(current) // granularity)
        reduced = False
        start = 0
        while start < len(current) and steps < max_steps:
            candidate = current[:start] + current[start + chunk:]
            if candidate and same(candidate):
                current = candidate
                reduced = True
            else:
                start += chunk
        if not reduced:
            if chunk == 1:
                break
            granularity = min(len(current), granularity * 2)
    return current, steps, target


def report(data, transport, hint, do_minimize, config=None, strict=True):
    observation, reason = outcome(data, transport, hint, config)
    out = {"transport": transport, "hint": hint, "input_bytes": len(data), "status": observation.status,
           "reason": observation.reason, "structured": reason,
           "identification": None if reason is not None else {"protocol": observation.application_protocol or observation.encryption,
                                                                "application": observation.application}}
    if do_minimize:
        minimized, steps, target = minimize(data, transport, hint, config, strict=strict)
        out["minimized"] = {"bytes": len(minimized), "hex": minimized.hex(), "steps": steps, "strict": strict,
                            "signature": {"status": target[0], "code": target[1], "family": target[2], "candidates": list(target[3]), "detail": target[4]}
                            if len(target) > 3 else {"identified": list(target)},
                            "reproduce": "Inspector().feed(bytes.fromhex(%r))" % minimized.hex() if transport == "tcp"
                            else "DatagramInspector().inspect(bytes.fromhex(%r), %r)" % (minimized.hex(), hint)}
    return out


def render(out):
    lines = ["%s payload, %d bytes%s" % (out["transport"], out["input_bytes"], " (hint %s)" % out["hint"] if out["hint"] else ""),
             "status: %s" % out["status"], "reason: %s" % out["reason"]]
    if out["structured"] is None:
        lines.append("identified: %s" % out["identification"])
    else:
        item = out["structured"]
        lines.append("code: %s (stage %s, family %s%s)" % (item["code"], item["stage"], item["family"],
                                                           ", candidates " + ",".join(item["candidates"]) if item.get("candidates") else ""))
    if "minimized" in out:
        m = out["minimized"]
        lines += ["minimized: %d bytes after %d steps, same %s" % (m["bytes"], m["steps"], "outcome and sentence" if m["strict"] else "status, code and family"),
                  "hex: " + m["hex"], "reproduce: " + m["reproduce"]]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--hex", help="payload as hex")
    source.add_argument("--file", help="payload file (raw bytes)")
    parser.add_argument("--udp", action="store_true", help="treat the payload as one datagram")
    parser.add_argument("--hint", help="candidate hint (a family name)")
    parser.add_argument("--minimize", action="store_true", help="shrink to a minimal example with the same outcome")
    parser.add_argument("--loose", action="store_true", help="with --minimize: keep only status, code and family, not the engine's sentence")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        data = bytes.fromhex(args.hex) if args.hex else Path(args.file).read_bytes()
    except (ValueError, OSError) as error:
        parser.exit(2, "payload error: {}\n".format(error))
    if not data or len(data) > MAX_INPUT:
        parser.exit(2, "payload must be 1..{} bytes\n".format(MAX_INPUT))
    transport = "udp" if args.udp else "tcp"
    if args.hint and transport == "tcp" and args.hint not in PARSERS:
        parser.exit(2, "unknown TCP hint {}\n".format(args.hint))
    out = report(data, transport, args.hint, args.minimize, strict=not args.loose)
    print(json.dumps(out, indent=2) if args.json else render(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
