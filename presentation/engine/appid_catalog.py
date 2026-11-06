"""Print the application catalog used for App-ID style verdicts. Offline only."""
import argparse
import json
from dataclasses import asdict
from protocol_engine.applications import APPLICATIONS, ALIASES, CATEGORIES, CHARACTERISTICS, OUTCOMES


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="One JSON object per application")
    parser.add_argument("--category", choices=sorted(CATEGORIES), help="Only this category")
    parser.add_argument("--min-risk", type=int, default=1, choices=range(1, 6))
    args = parser.parse_args()
    rows = [app for app in APPLICATIONS.values()
            if (args.category is None or app.category == args.category) and app.risk >= args.min_risk]
    if args.json:
        for app in rows:
            print(json.dumps(asdict(app)))
        return
    print("{:<18} {:<17} {:<19} {:<16} {:>4}  {}".format("application", "category", "subcategory", "technology", "risk", "standard ports"))
    for app in rows:
        kind = " (outcome)" if app.name in OUTCOMES else ""
        print("{:<18} {:<17} {:<19} {:<16} {:>4}  {}{}".format(app.name, app.category, app.subcategory, app.technology,
                                                               app.risk, ", ".join(app.standard_ports) or "-", kind))
        if app.characteristics:
            print("{:<18} characteristics: {}".format("", ", ".join(app.characteristics)))
        if app.aliases:
            print("{:<18} aliases: {}".format("", ", ".join(app.aliases)))
    print("\n{} applications, {} aliases, {} characteristics defined".format(len(rows), len(ALIASES), len(CHARACTERISTICS)))


if __name__ == "__main__":
    main()
