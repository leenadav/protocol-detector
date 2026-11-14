"""Migration M0/M5: the capability inventory, counted from the registry rather than from prose.

Writes migration/CAPABILITIES.json: one entry per public protocol family with its transports, selection
per transport (prefix/text/hint/peer/datagram), observation modes, hint requirement, scope, the profile
sentence from the catalog (what is and is not inspected), the Python status and the Go status. Python
entries are `supported` because every family has labelled fixtures proven by the inventory check; Go
entries start at `pending` and move to `experimental` or `parity-verified` only through the differential
harness (migration/parity). Usage: python3 -B tools/capabilities.py [--write migration/CAPABILITIES.json]
[--check migration/CAPABILITIES.json]
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from protocol_engine import content  # noqa: E402
from protocol_engine.catalog import supported_protocols  # noqa: E402
from protocol_engine.descriptors import MIDSTREAM_FAMILIES, build  # noqa: E402
from protocol_engine.applications import APPLICATIONS  # noqa: E402
from protocol_engine.host_apps import APP_DOMAINS  # noqa: E402

GO_STATUSES = ("pending", "experimental", "parity-verified")


def inventory(previous=None):
    descriptors = build()
    profiles = {entry.family: entry for entry in supported_protocols()}
    previous_go = {name: item.get("go", {}) for name, item in (previous or {}).get("families", {}).items()}
    families = {}
    for family in sorted(descriptors):
        descriptor = descriptors[family]
        profile = profiles.get(family)
        go = previous_go.get(family) or {"status": "pending", "parity": None, "notes": None}
        families[family] = {
            "transports": sorted(descriptor.transports),
            "selection": {transport: selection for transport, selection in zip(descriptor.transports, descriptor.selection)},
            "observation_modes": list(descriptor.observation),
            "midstream": family in MIDSTREAM_FAMILIES,
            "requires_hint": bool(descriptor.requires_hint),
            "scope": profile.scope if profile else None,
            "profile": profile.profile if profile else None,
            "directions": list(descriptor.directions) if getattr(descriptor, "directions", None) else None,
            "python": {"status": "supported", "fixtures": "labelled, inventory-checked (tools/check_inventory.py)"},
            "go": go,
        }
    applications = {"total": len(APPLICATIONS), "host_named": len(APP_DOMAINS),
                    "outcomes": sorted(name for name, app in APPLICATIONS.items() if app.category == "unknown")}
    return {"schema": 1, "content_release": content.CURRENT, "content_digest": content.digest(),
            "families": families, "counts": {"families": len(families), "tcp": sum("tcp" in f["transports"] for f in families.values()),
                                              "udp": sum("udp" in f["transports"] for f in families.values()),
                                              "hint_only": sum(f["requires_hint"] for f in families.values()),
                                              "midstream_capable": len(MIDSTREAM_FAMILIES)},
            "applications": applications,
            "go_status_vocabulary": list(GO_STATUSES)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", help="write the inventory here (keeps existing Go statuses)")
    parser.add_argument("--check", help="fail when this file's Python-side inventory differs from the registry")
    args = parser.parse_args(argv)
    target = Path(args.write or args.check or "migration/CAPABILITIES.json")
    previous = None
    if target.exists():
        previous = json.loads(target.read_text(encoding="utf-8"))
    current = inventory(previous)
    if args.check:
        if previous is None:
            print("capabilities: " + str(target) + " missing")
            return 1
        drift = [name for name in set(current["families"]) ^ set(previous.get("families", {}))]
        changed = [name for name in current["families"] if name in previous.get("families", {})
                   and {k: v for k, v in current["families"][name].items() if k != "go"} != {k: v for k, v in previous["families"][name].items() if k != "go"}]
        bad_go = [name for name, item in previous.get("families", {}).items() if item.get("go", {}).get("status") not in GO_STATUSES]
        if drift or changed or bad_go:
            print("capabilities: inventory drifted; added/removed {} changed {} invalid go status {}; regenerate with --write".format(drift, changed, bad_go))
            return 1
        print("capabilities ok: {} families, content {}".format(current["counts"]["families"], current["content_release"]))
        return 0
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("capabilities written: {} families ({} tcp, {} udp, {} hint-only), {} applications".format(
        current["counts"]["families"], current["counts"]["tcp"], current["counts"]["udp"], current["counts"]["hint_only"], current["applications"]["total"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
