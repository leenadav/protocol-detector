#!/usr/bin/env python3
"""Migration M6/D08: the earlier content releases the Go backend embeds for `--content-version` rollback.

    python3 -B migration/content_history.py [--write go/internal/content/history.json] [--check PATH]

Rollback (protocol_engine/content.select) runs the server-name catalog of an earlier release; the application
catalog, vocabularies, protocol names and risk table roll back with the package, not with the content release.
So each earlier release is carried as its `release` block (version, dates, digest and component digests, as
content.description(version) states them) and its `host_catalog` (content.host_entries(version) and the
lookup tables host_apps.build_tables makes of them). The Go backend lays one of them over the current pack
(tools/export_content.py) and validates the result like any pack: it recomputes the components and the release
digest and refuses a pack that states anything else. Nothing here is detection logic or a payload.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from protocol_engine import content  # noqa: E402
from protocol_engine.host_apps import build_tables  # noqa: E402


def history():
    out = {}
    for item in content.releases():
        if item.version == content.CURRENT:
            continue
        release = content.description(item.version)
        entries = content.host_entries(item.version)
        domains, fronts, suffixes = build_tables(entries)
        out[item.version] = {
            "release": {"version": release["version"], "digest": release["digest"], "released": release["released"],
                        "reviewed": release["reviewed"], "components": release["components"]},
            "host_catalog": {"entries": [dict(entry) for entry in entries],
                             "app_domains": {k: list(v) for k, v in sorted(domains.items())},
                             "web_fronts": dict(sorted(fronts.items())),
                             "suffixes": dict(sorted(suffixes.items()))},
        }
    return {"schema": 1, "current": content.CURRENT, "releases": out}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--write", default=str(ROOT / "go/internal/content/history.json"))
    parser.add_argument("--check", default=None, help="fail when this file differs from the Python content")
    args = parser.parse_args(argv)
    text = json.dumps(history(), indent=1, sort_keys=True, default=list) + "\n"
    summary = ", ".join(sorted(json.loads(text)["releases"]))
    if args.check:
        if Path(args.check).read_text(encoding="utf-8") != text:
            print("content history drifted from the Python content: regenerate with migration/content_history.py")
            return 1
        print("content history ok: earlier releases " + summary)
        return 0
    Path(args.write).write_text(text, encoding="utf-8")
    print("content history written: earlier releases " + summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
