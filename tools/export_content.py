"""Migration M6: export the detection content as one versioned pack both runtimes load.

    python3 -B tools/export_content.py [--write migration/fixtures/content.json] [--check PATH]

The pack carries the application catalog (every entry of protocol_engine/applications.py, host-named
services included), the engine label -> catalog name map, the server-name catalog tables as of the
current content release (D08: entries, service domains, exact web fronts), the flow-risk table and the
closed vocabularies the catalog is validated against, plus the content release and its digest from
protocol_engine/content.py. The Go backend validates the pack like applications._validate and
host_apps.build_tables do (duplicates, unknown categories, unresolved references) and refuses it
otherwise; nothing in it is detection logic, and nothing here is a payload.
"""
import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from protocol_engine import content  # noqa: E402
from protocol_engine.applications import APPLICATIONS, CATEGORIES, CHARACTERISTICS, OUTCOMES, TECHNOLOGIES, _PROTOCOL_NAMES  # noqa: E402
from protocol_engine.host_apps import APP_DOMAINS, HOST_SUFFIXES, WEB_FRONTS  # noqa: E402
from protocol_engine.risks import RISKS  # noqa: E402

SCHEMA = 1


def pack():
    release = content.description()
    return {
        "schema": SCHEMA,
        "release": {"version": release["version"], "digest": release["digest"], "released": release["released"],
                    "reviewed": release["reviewed"], "components": release["components"]},
        "vocabulary": {"categories": {k: list(v) for k, v in CATEGORIES.items()}, "technologies": list(TECHNOLOGIES),
                       "characteristics": list(CHARACTERISTICS), "outcomes": list(OUTCOMES)},
        "protocol_names": dict(_PROTOCOL_NAMES),
        "applications": [asdict(APPLICATIONS[name]) for name in sorted(APPLICATIONS)],
        "host_catalog": {"entries": [dict(entry) for entry in content.host_entries()],
                         "app_domains": {k: list(v) for k, v in sorted(APP_DOMAINS.items())},
                         "web_fronts": dict(sorted(WEB_FRONTS.items())),
                         "suffixes": dict(sorted(HOST_SUFFIXES.items()))},
        "risks": {name: {"severity": severity, "description": text} for name, (severity, text) in sorted(RISKS.items())},
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--write", default=str(ROOT / "migration/fixtures/content.json"))
    parser.add_argument("--check", default=None, help="fail when this pack differs from the current content")
    args = parser.parse_args(argv)
    current = pack()
    text = json.dumps(current, indent=1, sort_keys=True) + "\n"
    if args.check:
        on_disk = Path(args.check).read_text(encoding="utf-8")
        if on_disk != text:
            print("content pack drifted from the Python content: regenerate with tools/export_content.py")
            return 1
        print("content pack ok: release {} digest {} ({} applications, {} host entries, {} risks)".format(
            current["release"]["version"], current["release"]["digest"], len(current["applications"]),
            len(current["host_catalog"]["entries"]), len(current["risks"])))
        return 0
    Path(args.write).write_text(text, encoding="utf-8")
    print("content pack written: release {} digest {} ({} applications, {} host entries, {} risks)".format(
        current["release"]["version"], current["release"]["digest"], len(current["applications"]),
        len(current["host_catalog"]["entries"]), len(current["risks"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
