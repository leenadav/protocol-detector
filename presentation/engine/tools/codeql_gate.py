"""Fail when a CodeQL SARIF result has error severity. Warnings are reported, not fatal.

Keeps CodeQL a real gate even when the repository has not enabled the code
scanning upload target. Usage: codeql_gate.py <directory-or-sarif-file>
"""
import json
import sys
from pathlib import Path


def main(target):
    path = Path(target)
    files = [path] if path.is_file() else sorted(path.glob("*.sarif"))
    if not files:
        print("no SARIF files found in", target)
        return 1
    errors = warnings = 0
    for file in files:
        document = json.loads(file.read_text(encoding="utf-8"))
        for run in document.get("runs", []):
            rules = {rule.get("id"): rule for rule in run.get("tool", {}).get("driver", {}).get("rules", [])}
            for result in run.get("results", []):
                level = result.get("level") or rules.get(result.get("ruleId"), {}).get("defaultConfiguration", {}).get("level", "warning")
                location = result.get("locations", [{}])[0].get("physicalLocation", {})
                where = "{}:{}".format(location.get("artifactLocation", {}).get("uri", "?"), location.get("region", {}).get("startLine", "?"))
                print("{}: {} {} ({})".format(level.upper(), result.get("ruleId"), where, result.get("message", {}).get("text", "")[:120]))
                if level == "error":
                    errors += 1
                else:
                    warnings += 1
    print("codeql gate: {} errors, {} warnings".format(errors, warnings))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "codeql-results"))
