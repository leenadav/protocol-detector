"""Fail when a CodeQL SARIF result has error severity. Warnings are reported, not fatal.

Keeps CodeQL a real gate even when the repository has not enabled the code
scanning upload target. When GITHUB_STEP_SUMMARY is set (or --summary FILE is
given) a Markdown table of the query packs run and the findings per rule and
level is appended to it. Usage: codeql_gate.py <directory-or-sarif-file> [--summary FILE]
"""
import json
import os
import sys
from collections import Counter
from pathlib import Path


def summarize(files, documents, counts, errors, warnings):
    """Markdown summary: which SARIF files, how many rules were evaluated, findings per rule."""
    rules_evaluated = 0
    for document in documents:
        for run in document.get("runs", []):
            rules_evaluated += len(run.get("tool", {}).get("driver", {}).get("rules", []))
            for extension in run.get("tool", {}).get("extensions", []):
                rules_evaluated += len(extension.get("rules", []))
    lines = ["### CodeQL", "", "{} SARIF file(s), {} rules evaluated, {} error(s), {} warning/note(s).".format(len(files), rules_evaluated, errors, warnings), ""]
    if counts:
        lines += ["| rule | level | findings |", "|---|---|---|"]
        for (rule, level), number in sorted(counts.items(), key=lambda item: (item[0][1] != "error", -item[1], item[0][0])):
            lines.append("| `{}` | {} | {} |".format(rule, level, number))
    else:
        lines.append("No findings.")
    lines.append("")
    return "\n".join(lines)


def main(target, summary_path=None):
    path = Path(target)
    files = [path] if path.is_file() else sorted(path.glob("*.sarif"))
    if not files:
        print("no SARIF files found in", target)
        return 1
    errors = warnings = 0
    counts = Counter()
    documents = []
    for file in files:
        document = json.loads(file.read_text(encoding="utf-8"))
        documents.append(document)
        for run in document.get("runs", []):
            rules = {rule.get("id"): rule for rule in run.get("tool", {}).get("driver", {}).get("rules", [])}
            for result in run.get("results", []):
                level = result.get("level") or rules.get(result.get("ruleId"), {}).get("defaultConfiguration", {}).get("level", "warning")
                location = result.get("locations", [{}])[0].get("physicalLocation", {})
                where = "{}:{}".format(location.get("artifactLocation", {}).get("uri", "?"), location.get("region", {}).get("startLine", "?"))
                print("{}: {} {} ({})".format(level.upper(), result.get("ruleId"), where, result.get("message", {}).get("text", "")[:120]))
                counts[(result.get("ruleId"), level)] += 1
                if level == "error":
                    errors += 1
                else:
                    warnings += 1
    print("codeql gate: {} errors, {} warnings".format(errors, warnings))
    summary_path = summary_path or os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write(summarize(files, documents, counts, errors, warnings))
    return 1 if errors else 0


if __name__ == "__main__":
    arguments = sys.argv[1:]
    summary = arguments[arguments.index("--summary") + 1] if "--summary" in arguments else None
    positional = [argument for index, argument in enumerate(arguments) if argument != "--summary" and (index == 0 or arguments[index - 1] != "--summary")]
    sys.exit(main(positional[0] if positional else "codeql-results", summary))
