"""Second opinion for the workflow policy: compare its line parser with a real YAML parser.

`tools/check_workflow_policy.py` reads workflows line by line (standard library only), and
every review finding against it so far was a spelling a real YAML parser decodes differently
from those lines (escapes, flow collections, explicit keys, comments inside run blocks). This
check parses each workflow with PyYAML (hash-pinned in requirements-dev.txt) and fails when the
two disagree on any fact the policy rules depend on: top-level and job keys, job ids and
`needs`, tag triggers, workflow and job permissions, every step's keys, `name`, `if`, `uses`,
`env`, `with` and `run` lines, and the list of `uses` references rule 7 reads. It also runs the
stored-credential ban over every decoded key and string value. A disagreement is a policy
blind spot, so it fails closed.

PyYAML implements YAML 1.1 and GitHub's parser YAML 1.2; the known difference that matters here
(`on` decoding to the boolean True) is normalized. Usage (dev tools installed):
  check_workflow_yaml.py [--root DIR] [--self-test]
"""
import sys
from pathlib import Path

import check_workflow_policy as policy

try:
    import yaml
except ImportError:   # pragma: no cover - reported, never silently skipped
    yaml = None


def scalar(value):
    """The string a line parser would hold for a decoded scalar."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    return str(value)


def block(value):
    """A mapping value as the line parser holds it: block scalars as stripped, non-empty lines."""
    if isinstance(value, str) and "\n" in value.strip("\n"):
        return "\n".join(line.strip() for line in value.splitlines() if line.strip())
    return scalar(value).strip("\n").strip() if isinstance(value, str) else scalar(value)


def run_lines(value):
    return [line.strip() for line in str(value).splitlines() if line.strip()]


def decoded_facts(text):
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("the workflow is not a mapping")
    top = {("on" if key is True else str(key)) for key in data}
    triggers = data.get("on", data.get(True))
    push = triggers.get("push") if isinstance(triggers, dict) else None
    facts = {
        "top keys": top,
        "tag trigger": isinstance(push, dict) and bool({"tags", "tags-ignore"} & set(push)),
        "permissions": data.get("permissions") if not isinstance(data.get("permissions"), dict)
        else {str(k): scalar(v) for k, v in data["permissions"].items()},
        "jobs": {},
        "uses": [],
    }
    for job, body in (data.get("jobs") or {}).items():
        body = body or {}
        needs = body.get("needs", [])
        steps = []
        for step in body.get("steps") or []:
            entry = {"keys": set(step)}
            for key in ("name", "if", "uses"):
                if key in step:
                    entry[key] = scalar(step[key])
            for key in ("env", "with"):
                if isinstance(step.get(key), dict):
                    entry[key] = {str(k): block(v) for k, v in step[key].items()}
            if "run" in step:
                entry["run"] = run_lines(step["run"])
            if "uses" in step:
                facts["uses"].append(scalar(step["uses"]))
            steps.append(entry)
        permissions = body.get("permissions")
        facts["jobs"][str(job)] = {
            "keys": {str(k) for k in body},
            "needs": [needs] if isinstance(needs, str) else [str(n) for n in needs],
            "permissions": permissions if not isinstance(permissions, dict) else {str(k): scalar(v) for k, v in permissions.items()},
            "steps": steps,
        }
    return data, facts


def line_facts(text):
    lines = text.splitlines()
    ids, needs = policy.job_ids_and_needs(text)
    top = {policy.key_of(line, indent=0)[1] for line in lines if policy.key_of(line, indent=0)}
    facts = {
        "top keys": top,
        "tag trigger": policy.tag_trigger(text),
        "permissions": policy.mapping_at(lines, 0, "permissions"),
        "jobs": {},
        "uses": [],
    }
    for line in lines:
        found = policy.USES.match(line)
        if found:
            facts["uses"].append(policy.strip_quotes(found.group(1)))
    for job in ids:
        block = policy.job_lines(text, job)
        steps = []
        for step in policy.steps_of(block):
            fields = policy.step_fields(step)
            entry = {"keys": set(fields)}
            for key in ("name", "if", "uses"):
                if key in fields:
                    entry[key] = policy.strip_quotes(fields[key] or "")
            for key in ("env", "with"):
                if isinstance(fields.get(key), dict):
                    entry[key] = fields[key]
            if "run" in fields:
                entry["run"] = fields["run"] if isinstance(fields["run"], list) else [policy.strip_quotes(fields["run"])]
            steps.append(entry)
        facts["jobs"][job] = {
            "keys": {policy.key_of(line, indent=4)[1] for line in block if policy.key_of(line, indent=4)},
            "needs": needs[job],
            "permissions": policy.mapping_at(block, 4, "permissions"),
            "steps": steps,
        }
    return facts


def decoded_strings(node):
    """Every key and string value, recursively."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield str(key)
            yield from decoded_strings(value)
    elif isinstance(node, list):
        for item in node:
            yield from decoded_strings(item)
    elif isinstance(node, str):
        yield node


def compare(path, text):
    try:
        data, decoded = decoded_facts(text)
    except (yaml.YAMLError, ValueError, AttributeError, TypeError) as error:
        return ["{}: PyYAML cannot read it as a workflow: {}".format(path, str(error).splitlines()[0])]
    try:
        lined = line_facts(text)
    except ValueError as error:
        return ["{}: the policy line parser cannot read it: {}".format(path, error)]
    problems = []
    for fact in ("top keys", "tag trigger", "permissions", "uses"):
        if decoded[fact] != lined[fact]:
            problems.append("{}: parsers disagree on {}: yaml {!r} vs lines {!r}".format(path, fact, decoded[fact], lined[fact]))
    if set(decoded["jobs"]) != set(lined["jobs"]):
        problems.append("{}: parsers disagree on job ids: yaml {} vs lines {}".format(
            path, sorted(decoded["jobs"]), sorted(lined["jobs"])))
    for job in sorted(set(decoded["jobs"]) & set(lined["jobs"])):
        for fact in ("keys", "needs", "permissions"):
            if decoded["jobs"][job][fact] != lined["jobs"][job][fact]:
                problems.append("{}: job {}: parsers disagree on {}: yaml {!r} vs lines {!r}".format(
                    path, job, fact, decoded["jobs"][job][fact], lined["jobs"][job][fact]))
        ysteps, lsteps = decoded["jobs"][job]["steps"], lined["jobs"][job]["steps"]
        if len(ysteps) != len(lsteps):
            problems.append("{}: job {}: parsers disagree on the step count: yaml {} vs lines {}".format(
                path, job, len(ysteps), len(lsteps)))
        for number, (ystep, lstep) in enumerate(zip(ysteps, lsteps), 1):
            if ystep != lstep:
                keys = sorted(k for k in set(ystep) | set(lstep) if ystep.get(k) != lstep.get(k))
                problems.append("{}: job {} step {}: parsers disagree on {}".format(path, job, number, ", ".join(keys)))
    for value in decoded_strings(data):
        visible = value
        for allowed in policy.CREDENTIAL_ALLOWED:
            visible = visible.replace(allowed, "")
        found = policy.STORED_CREDENTIAL.search(visible)
        if found:
            problems.append("{}: decoded YAML references `{}` (stored credentials are not allowed)".format(path, found.group(1)))
            break
    return problems


def main(root):
    if yaml is None:
        print("check_workflow_yaml: PyYAML is not installed (pip install --require-hashes -r requirements-dev.txt)")
        return 2
    workflows = Path(root) / ".github" / "workflows"
    files = sorted(list(workflows.glob("*.yml")) + list(workflows.glob("*.yaml")))
    problems = []
    for path in files:
        problems += compare(path.relative_to(root).as_posix(), path.read_text(encoding="utf-8"))
    for problem in problems:
        print("workflow yaml cross-check:", problem)
    print("workflow yaml cross-check: {} ({} workflow files, PyYAML {})".format(
        "ok" if not problems else "{} problem(s)".format(len(problems)), len(files), yaml.__version__))
    return 1 if problems else 0


SELF_TEST = """name: t
on:
  push:
    branches: ["**"]
permissions:
  contents: read
defaults:
  run:
    shell: bash
jobs:
  build:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - name: Harden
        uses: step-security/harden-runner@0634a2670c59f64b4a01f0f96f84700a4088b9f0 # v2.12.0
        with:
          egress-policy: audit
      - name: Run
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          echo "a" | tee b
          # a shell comment
  gate:
    needs: [build]
    runs-on: ubuntu-24.04
    steps:
      - run: echo ok
"""


def self_test():
    if yaml is None:
        print("check_workflow_yaml self-test: PyYAML is not installed")
        return 2
    assert compare("t.yml", SELF_TEST) == [], compare("t.yml", SELF_TEST)
    # Each spelling decodes to something the line parser reads differently, or hides a credential.
    disagreements = {
        "flow mapping trigger": SELF_TEST.replace('  push:\n    branches: ["**"]\n', '  push: {? tags: ["v*"]}\n'),
        "escaped credential": SELF_TEST.replace("GH_TOKEN: ${{ github.token }}", 'GH_TOKEN: "${{ \\u0073ecrets.X }}"'),
        "flow step": SELF_TEST.replace("      - run: echo ok\n", "      - {run: echo ok, uses: x/y@" + "a" * 40 + "}\n"),
        "anchor alias job": SELF_TEST.replace("  gate:\n    needs: [build]\n", "  gate: &g\n    needs: [build]\n") + "  copy: *g\n",
        "escaped needs": SELF_TEST.replace("needs: [build]", 'needs: ["bu\\u0069ld", gate]'),
        "folded permission": SELF_TEST.replace("permissions:\n  contents: read\n", 'permissions: {contents: write}\n', 1),
        "multi-line uses": SELF_TEST.replace("        uses: step-security/harden-runner@0634a2670c59f64b4a01f0f96f84700a4088b9f0 # v2.12.0\n",
                                             "        uses:\n          step-security/harden-runner@0634a2670c59f64b4a01f0f96f84700a4088b9f0\n"),
        "heredoc secret": SELF_TEST.replace("          # a shell comment\n", "          #${{ secrets.X }}\n"),
    }
    for label, text in disagreements.items():
        assert text != SELF_TEST, label
        assert compare("t.yml", text), label
    print("check_workflow_yaml self-test: ok")
    return 0


if __name__ == "__main__":
    arguments = sys.argv[1:]
    if "--self-test" in arguments:
        sys.exit(self_test())
    sys.exit(main(arguments[arguments.index("--root") + 1] if "--root" in arguments else "."))
