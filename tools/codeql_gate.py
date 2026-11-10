"""Fail when a CodeQL SARIF result has error severity. Warnings are reported, not fatal.

Keeps CodeQL a real gate even when the repository has not enabled the code
scanning upload target. When GITHUB_STEP_SUMMARY is set (or --summary FILE is
given) a Markdown table of the query packs run and the findings per rule and
level is appended to it.

A result's level is its own `level`, else its rule's `defaultConfiguration.level`.
CodeQL lists its rules under `tool.extensions` (the query packs), not
`tool.driver`, and points each result at one through `rule.toolComponent.index`
and `rule.index`; the rule is resolved that way first, then by `ruleId` across the
driver and every extension. Until item 25 only the driver was read, so every
default-level CodeQL error counted as a warning and the gate could not fail. A
result whose level cannot be resolved counts as an error (fail closed).
Usage: codeql_gate.py <directory-or-sarif-file> [--summary FILE]
       codeql_gate.py --self-test
"""
import contextlib
import json
import os
import sys
import tempfile
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


def components(run):
    tool = run.get("tool", {})
    return [tool.get("driver", {})] + list(tool.get("extensions", []))


def result_level(run, result):
    """The result's level: its own, else its rule's default; "error" when neither resolves."""
    if result.get("level"):
        return result["level"]
    rule = None
    reference = result.get("rule") or {}
    component_index = (reference.get("toolComponent") or {}).get("index")
    rule_index = reference.get("index", result.get("ruleIndex"))
    packs = components(run)
    if isinstance(rule_index, int):
        # SARIF: toolComponent.index points into tool.extensions; no toolComponent means the driver
        extensions = packs[1:]
        if isinstance(component_index, int):
            pack = extensions[component_index] if 0 <= component_index < len(extensions) else {}
        else:
            pack = packs[0]
        rules = pack.get("rules", [])
        if 0 <= rule_index < len(rules):
            rule = rules[rule_index]
    if rule is None or rule.get("id") != (reference.get("id") or result.get("ruleId")):
        wanted = reference.get("id") or result.get("ruleId")
        rule = next((candidate for pack in packs for candidate in pack.get("rules", []) if candidate.get("id") == wanted), None)
    level = (rule or {}).get("defaultConfiguration", {}).get("level")
    return level or "error"


def self_test():
    def sarif(results, driver_rules=(), extension_rules=()):
        return {"runs": [{"tool": {"driver": {"name": "CodeQL", "rules": list(driver_rules)},
                                   "extensions": [{"name": "codeql-action/pr-diff-range", "rules": []},
                                                  {"name": "codeql/python-queries", "rules": list(extension_rules)}]},
                          "results": results}]}

    def rule(identifier, level):
        return {"id": identifier, "defaultConfiguration": {"level": level}}

    def result(identifier, index=None, component=None, level=None):
        entry = {"ruleId": identifier, "message": {"text": "m"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 1}}}]}
        if index is not None:
            entry["rule"] = {"id": identifier, "index": index, "toolComponent": {"index": component}}
        if level:
            entry["level"] = level
        return entry

    pack = [rule("py/note-rule", "note"), rule("py/uninitialized-local-variable", "error"), rule("py/warn", "warning")]
    run = sarif([], extension_rules=pack)["runs"][0]
    # the CodeQL shape seen on run 42363645288: rules only in an extension, referenced by component and index
    assert result_level(run, result("py/uninitialized-local-variable", 1, 1)) == "error"
    assert result_level(run, result("py/note-rule", 0, 1)) == "note"
    assert result_level(run, result("py/warn")) == "warning"                      # by id across the extensions
    assert result_level(run, result("py/warn", level="error")) == "error"           # the result's own level wins
    assert result_level(run, result("py/unknown")) == "error"                       # unresolvable fails closed
    assert result_level(run, result("py/warn", 0, 1)) == "warning"                  # a stale index falls back to the id
    driver_run = sarif([], driver_rules=[rule("x/err", "error")])["runs"][0]
    assert result_level(driver_run, result("x/err", 0, None)) == "error"            # driver-held rules still resolve
    directory = Path(tempfile.mkdtemp(prefix="codeql-gate-self-test-"))
    clean = directory / "clean"
    failing = directory / "failing"
    for folder, results in ((clean, [result("py/note-rule", 0, 1), result("py/warn", 2, 1)]),
                            (failing, [result("py/note-rule", 0, 1), result("py/uninitialized-local-variable", 1, 1)])):
        folder.mkdir()
        (folder / "python.sarif").write_text(json.dumps(sarif(results, extension_rules=pack)), encoding="utf-8")
    with open(os.devnull, "w", encoding="utf-8") as sink, contextlib.redirect_stdout(sink):
        assert main(str(clean), str(directory / "summary.md")) == 0
        assert main(str(failing), str(directory / "summary.md")) == 1
        assert main(str(directory / "missing")) == 1
    print("codeql_gate self-test: ok")
    return 0


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
            for result in run.get("results", []):
                level = result_level(run, result)
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
    if "--self-test" in sys.argv[1:]:
        sys.exit(self_test())
    arguments = sys.argv[1:]
    summary = arguments[arguments.index("--summary") + 1] if "--summary" in arguments else None
    positional = [argument for index, argument in enumerate(arguments) if argument != "--summary" and (index == 0 or arguments[index - 1] != "--summary")]
    sys.exit(main(positional[0] if positional else "codeql-results", summary))
