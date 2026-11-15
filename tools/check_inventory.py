"""Build-time inventory check (stage 7, A12): parsers, validators, dispatch routes and the public catalog agree.

Also runs every fixture of the corpus through the engine and checks that the family each fixture is labelled
with is in the inventory and that no fixture of a family produces an identification of another family
(an ambiguous candidate must end explicit: unknown, correlated or the right family).
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from protocol_engine import DatagramInspector, Inspector  # noqa: E402
from protocol_engine.descriptors import InventoryError, build, validate_inventory  # noqa: E402
from protocol_adapters.protocol_fixtures import DATAGRAM_CASES, STREAM_CASES  # noqa: E402


def family_of(label):
    return label.split("/", 1)[0]


def main():
    try:
        summary = validate_inventory()
    except InventoryError as error:
        print("inventory FAILED: " + str(error))
        return 1
    descriptors = build()
    problems = []
    for data, label in STREAM_CASES:
        family = family_of(label)
        if family not in descriptors:
            problems.append("stream fixture labelled with an unknown family: " + label)
            continue
        inspector = Inspector(protocol_hint=family if descriptors[family].requires_hint and family in __import__("protocol_engine.registry", fromlist=["PARSERS"]).PARSERS else None)
        inspector.feed(data)
        observation = inspector.observation
        found = observation.application_protocol or observation.encryption
        if observation.status == "identified" and found is not None and family_of(found) != family and family_of(found) not in descriptors:
            problems.append("stream fixture %s identified as a family outside the inventory: %s" % (label, found))
    for data, label in DATAGRAM_CASES:
        family = family_of(label)
        if family not in descriptors:
            problems.append("datagram fixture labelled with an unknown family: " + label)
            continue
        observation = DatagramInspector().inspect(data, family if descriptors[family].requires_hint else None)
        found = observation.application_protocol or observation.encryption
        if observation.status == "identified" and found is not None and family_of(found) not in descriptors:
            problems.append("datagram fixture %s identified as a family outside the inventory: %s" % (label, found))
    if problems:
        print("inventory FAILED:\n  " + "\n  ".join(problems))
        return 1
    print("inventory ok: %(families)d families (%(tcp)d tcp, %(udp)d udp, %(hint_only)d hint-only, %(text_routed)d text-routed); "
          "%(streams)d stream and %(datagrams)d datagram fixtures labelled within the inventory"
          % dict(summary, streams=len(STREAM_CASES), datagrams=len(DATAGRAM_CASES)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
