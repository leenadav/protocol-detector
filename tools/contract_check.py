"""Compatibility of the product's external contract: the JSON schemas in schemas/ and the protodetect CLI.

The Go module has no importable package (tools/go_api.py), so the contract consumers actually depend on is the
records the engine emits, described by schemas/*.schema.json, and the protodetect command line. This compares
both at the base with this commit, with the same base, label and events as tools/go_api.py: a pull request's
base merge-based with HEAD, a push's first parent, and the `api-break` label (ci runs on labeled/unlabeled).

JSON schemas: each file at the base and here, with every $ref resolved first (local `#/...` and relative files).
  Breaking (fails without the label):
    a property removed; a property newly required (an existing one, or a new required one); a type narrowed or
    changed; an enum value removed or a const changed; additionalProperties restricted (to false, or from
    absent/true to a schema); a oneOf/anyOf branch added or removed (branches are matched by their `type`
    const, the event's discriminator, else by their $ref name); a bound tightened or added (minimum,
    exclusiveMinimum, minItems, minLength, minProperties raised; maximum, exclusiveMaximum, maxItems,
    maxLength, maxProperties lowered); a schema file deleted or renamed.
  Reported only: an optional property added, an enum value added, a type widened, a bound loosened or removed,
    a title or description changed, a schema file added.

protodetect CLI: the binary is built at the base and here (vendored, offline). Its contract is read from its own
help output, never from the source:
  - the subcommands, from the usage line `protodetect` prints without arguments;
  - each subcommand's flags, from `protodetect <subcommand> -h` (stdin empty, a scratch directory, a timeout).
    Two formats occur: Go's flag package (`  -name type` with `(default X)`), and a usage line
    (`[--name METAVAR]`, `--name`, `(--a NAME | --b)`).
  Breaking: a subcommand removed (a rename is a removal plus an addition); a flag removed; a flag's type or
    default changed (Go flag format); a flag that took a value no longer taking one, or the reverse; values
    dropped from a `a|b|c` choice.
  Reported only: an added subcommand or flag, another metavar text change.

    contract_check.py [--summary FILE]      (env: BASE_SHA, LABELS; the pinned Go on PATH)
    contract_check.py --self-test
Standard library only; Python 3.9 syntax.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import go_api  # noqa: E402  (base resolution helpers, the label)
import go_ci  # noqa: E402  (the pinned Go, the vendor tree, the environment)

SCHEMAS = "schemas"
MAIN = "./cmd/protodetect"
TIGHTER_IF_HIGHER = ("minimum", "exclusiveMinimum", "minItems", "minLength", "minProperties")
TIGHTER_IF_LOWER = ("maximum", "exclusiveMaximum", "maxItems", "maxLength", "maxProperties")
NOTE_KEYS = ("title", "description")


# ---------------------------------------------------------------------------------------------- JSON schemas
def pointer(document, fragment):
    node = document
    for part in [p for p in fragment.lstrip("/").split("/") if p]:
        part = part.replace("~1", "/").replace("~0", "~")
        node = node[int(part)] if isinstance(node, list) else node[part]
    return node


def resolve(node, documents, name, stack=()):
    """`node` with every $ref replaced by its target (siblings of $ref kept); a cycle keeps its $ref."""
    if isinstance(node, list):
        return [resolve(item, documents, name, stack) for item in node]
    if not isinstance(node, dict):
        return node
    if "$ref" in node and isinstance(node["$ref"], str):
        ref = node["$ref"]
        target_file, _, fragment = ref.partition("#")
        target_name = target_file or name
        key = (target_name, fragment)
        if key in stack or target_name not in documents:
            return dict(node)
        target = resolve(pointer(documents[target_name], fragment), documents, target_name, stack + (key,))
        merged = dict(target) if isinstance(target, dict) else {"allOf": [target]}
        merged["x-ref"] = ref
        for sibling, value in node.items():
            if sibling != "$ref":
                merged[sibling] = resolve(value, documents, name, stack)
        return merged
    return {key: resolve(value, documents, name, stack) for key, value in node.items() if key != "$defs"}


def types_of(node):
    value = node.get("type")
    if value is None:
        return None
    return set(value) if isinstance(value, list) else {value}


def branch_key(branch, index):
    properties = branch.get("properties") or {}
    discriminator = (properties.get("type") or {}).get("const") if isinstance(properties.get("type"), dict) else None
    if discriminator is not None:
        return "type={}".format(discriminator)
    if branch.get("x-ref"):
        return branch["x-ref"].rsplit("/", 1)[-1]
    return "#{}".format(index)


def compare_schema(old, new, path, breaking, notes):
    if not isinstance(old, dict) or not isinstance(new, dict):
        if old != new:
            breaking.append("{}: changed from {} to {}".format(path, json.dumps(old)[:80], json.dumps(new)[:80]))
        return
    for key in NOTE_KEYS:
        if old.get(key) != new.get(key):
            notes.append("{}: {} changed".format(path, key))
    old_types, new_types = types_of(old), types_of(new)
    if old_types is not None and new_types is not None:
        if old_types - new_types:
            breaking.append("{}: type {} changed to {}".format(path, sorted(old_types), sorted(new_types)))
        elif new_types - old_types:
            notes.append("{}: type widened to {}".format(path, sorted(new_types)))
    elif old_types is None and new_types is not None:
        breaking.append("{}: type restricted to {}".format(path, sorted(new_types)))
    if "const" in old or "const" in new:
        if old.get("const", object()) != new.get("const", object()) and "const" in old:
            breaking.append("{}: const {} changed to {}".format(path, json.dumps(old.get("const")), json.dumps(new.get("const"))))
        elif "const" in new and "const" not in old:
            breaking.append("{}: const {} added".format(path, json.dumps(new["const"])))
    if "enum" in old or "enum" in new:
        old_enum, new_enum = old.get("enum"), new.get("enum")
        if new_enum is not None and old_enum is None:
            breaking.append("{}: enum {} added".format(path, json.dumps(new_enum)[:80]))
        elif old_enum is not None and new_enum is not None:
            removed = [value for value in old_enum if value not in new_enum]
            added = [value for value in new_enum if value not in old_enum]
            if removed:
                breaking.append("{}: enum value(s) {} removed".format(path, json.dumps(removed)))
            if added:
                notes.append("{}: enum value(s) {} added".format(path, json.dumps(added)))
    for key in TIGHTER_IF_HIGHER + TIGHTER_IF_LOWER:
        if key not in old and key not in new:
            continue
        if key not in new:
            notes.append("{}: {} {} removed".format(path, key, old[key]))
        elif key not in old:
            breaking.append("{}: {} {} added".format(path, key, new[key]))
        elif (key in TIGHTER_IF_HIGHER and new[key] > old[key]) or (key in TIGHTER_IF_LOWER and new[key] < old[key]):
            breaking.append("{}: {} tightened from {} to {}".format(path, key, old[key], new[key]))
        elif new[key] != old[key]:
            notes.append("{}: {} loosened from {} to {}".format(path, key, old[key], new[key]))
    old_extra, new_extra = old.get("additionalProperties", True), new.get("additionalProperties", True)
    if old_extra is not False and new_extra is False:
        breaking.append("{}: additionalProperties restricted to false".format(path))
    elif old_extra is True and isinstance(new_extra, dict):
        breaking.append("{}: additionalProperties restricted to a schema".format(path))
    elif isinstance(old_extra, dict) and isinstance(new_extra, dict):
        compare_schema(old_extra, new_extra, path + ".additionalProperties", breaking, notes)
    old_props, new_props = old.get("properties") or {}, new.get("properties") or {}
    old_required, new_required = set(old.get("required") or []), set(new.get("required") or [])
    for name in sorted(old_props):
        if name not in new_props:
            breaking.append("{}.{}: property removed".format(path, name))
        else:
            compare_schema(old_props[name], new_props[name], "{}.{}".format(path, name), breaking, notes)
    for name in sorted(set(new_props) - set(old_props)):
        if name in new_required:
            breaking.append("{}.{}: new required property".format(path, name))
        else:
            notes.append("{}.{}: optional property added".format(path, name))
    for name in sorted((new_required - old_required) & set(old_props)):
        breaking.append("{}.{}: property became required".format(path, name))
    for name in sorted(old_required - new_required):
        notes.append("{}.{}: no longer required".format(path, name))
    if "items" in old and "items" in new:
        compare_schema(old["items"], new["items"], path + "[]", breaking, notes)
    for keyword in ("oneOf", "anyOf"):
        if keyword not in old and keyword not in new:
            continue
        old_branches = {branch_key(b, i): b for i, b in enumerate(old.get(keyword) or [])}
        new_branches = {branch_key(b, i): b for i, b in enumerate(new.get(keyword) or [])}
        for key in sorted(set(old_branches) - set(new_branches)):
            breaking.append("{}.{}: branch {} removed".format(path, keyword, key))
        for key in sorted(set(new_branches) - set(old_branches)):
            breaking.append("{}.{}: branch {} added (a consumer matching every branch no longer covers the output)".format(
                path, keyword, key))
        for key in sorted(set(old_branches) & set(new_branches)):
            compare_schema(old_branches[key], new_branches[key], "{}.{}[{}]".format(path, keyword, key), breaking, notes)


def compare_schema_sets(old_files, new_files):
    """(breaking, notes) over {file name: parsed document} at the base and here."""
    breaking, notes = [], []
    for name in sorted(set(old_files) - set(new_files)):
        breaking.append("{}: schema file deleted or renamed".format(name))
    for name in sorted(set(new_files) - set(old_files)):
        notes.append("{}: schema file added".format(name))
    for name in sorted(set(old_files) & set(new_files)):
        compare_schema(resolve(old_files[name], old_files, name), resolve(new_files[name], new_files, name), name, breaking, notes)
    return breaking, notes


# ---------------------------------------------------------------------------------------------- protodetect CLI
GO_FLAG = re.compile(r"^  -(?P<name>[A-Za-z0-9][\w-]*)(?: (?P<type>\S+))?\s*$")
DEFAULT = re.compile(r"\(default (?P<value>.*)\)\s*$")
USAGE_FLAG = re.compile(r"(?<![\w-])--(?P<name>[A-Za-z0-9][\w-]*)(?:[ =](?P<metavar>(?![\[(|-])[^\s\]|)]+(?:\|[^\s\]|)]+)*))?")


def subcommands_of(usage):
    """The subcommands of the top-level usage line `usage: protodetect a ... | b ... | c`."""
    line = next((l for l in (usage or "").splitlines() if l.startswith("usage: protodetect")), "")
    body = line[len("usage: protodetect"):]
    return sorted({part.split()[0] for part in body.split(" | ") if part.split()})


def flags_of(help_text):
    """{flag: {"type": ..., "default": ..., "metavar": ...}} from a subcommand's -h output, in either format."""
    flags, current = {}, None
    lines = (help_text or "").splitlines()
    if any(line.startswith("Usage of ") for line in lines):
        for line in lines:
            match = GO_FLAG.match(line)
            if match:
                current = match.group("name")
                flags[current] = {"type": match.group("type") or "bool", "default": None}
            elif current and line.startswith("    \t"):
                default = DEFAULT.search(line)
                if default:
                    flags[current]["default"] = default.group("value")
        return flags
    for line in lines:
        if "usage: protodetect" not in line and not line.lstrip().startswith("protodetect "):
            continue
        for match in USAGE_FLAG.finditer(line):
            name, metavar = match.group("name"), match.group("metavar")
            flags.setdefault(name, {"metavar": metavar})
    return flags


def compare_cli(old, new):
    """(breaking, notes) between {"subcommands": [...], "flags": {sub: {flag: info}}} at the base and here."""
    breaking, notes = [], []
    for sub in sorted(set(old["subcommands"]) - set(new["subcommands"])):
        breaking.append("protodetect {}: subcommand removed or renamed".format(sub))
    for sub in sorted(set(new["subcommands"]) - set(old["subcommands"])):
        notes.append("protodetect {}: subcommand added".format(sub))
    for sub in sorted(set(old["subcommands"]) & set(new["subcommands"])):
        before, after = old["flags"].get(sub, {}), new["flags"].get(sub, {})
        for flag in sorted(set(before) - set(after)):
            breaking.append("protodetect {} --{}: flag removed or renamed".format(sub, flag))
        for flag in sorted(set(after) - set(before)):
            notes.append("protodetect {} --{}: flag added".format(sub, flag))
        for flag in sorted(set(before) & set(after)):
            a, b = before[flag], after[flag]
            label = "protodetect {} --{}".format(sub, flag)
            if "type" in a and "type" in b:
                if a["type"] != b["type"]:
                    breaking.append("{}: type {} changed to {}".format(label, a["type"], b["type"]))
                if a.get("default") != b.get("default"):
                    breaking.append("{}: default {} changed to {}".format(label, a.get("default"), b.get("default")))
                continue
            old_meta, new_meta = a.get("metavar"), b.get("metavar")
            if (old_meta is None) != (new_meta is None):
                breaking.append("{}: {} a value now".format(label, "takes" if new_meta else "no longer takes"))
            elif old_meta and new_meta and old_meta != new_meta:
                old_choices, new_choices = old_meta.split("|"), new_meta.split("|")
                dropped = [c for c in old_choices if c not in new_choices] if len(old_choices) > 1 else []
                if dropped:
                    breaking.append("{}: value(s) {} no longer accepted".format(label, ", ".join(dropped)))
                else:
                    notes.append("{}: metavar {} changed to {}".format(label, old_meta, new_meta))
    return breaking, notes


def cli_contract(binary):
    """{"subcommands": [...], "flags": {...}} read from a built protodetect's own help output."""
    def ask(arguments):
        with tempfile.TemporaryDirectory(prefix="protodetect-help-") as scratch:
            try:
                result = subprocess.run([binary] + arguments, cwd=scratch, stdin=subprocess.DEVNULL,  # noqa: S603
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20, check=False)
            except subprocess.TimeoutExpired:
                return ""
        return result.stdout.decode("utf-8", "replace")
    subcommands = subcommands_of(ask([]))
    return {"subcommands": subcommands, "flags": {sub: flags_of(ask([sub, "-h"])) for sub in subcommands}}


# ---------------------------------------------------------------------------------------------- run
def schema_files(tree_root):
    folder = Path(tree_root, SCHEMAS)
    return {path.name: json.loads(path.read_text(encoding="utf-8")) for path in sorted(folder.glob("*.json"))} if folder.is_dir() else {}


def build(go_dir, out, env):
    result = subprocess.run(["go", "build", "-o", str(out), MAIN], cwd=str(go_dir), env=env,  # noqa: S603,S607
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    if result.returncode:
        raise RuntimeError("go build {} failed in {}: {}".format(MAIN, go_dir, result.stdout.decode("utf-8", "replace")[-300:]))


def run(summary):
    title = "### External contract compatibility (JSON schemas, protodetect CLI)"
    base_ref = os.environ.get("BASE_SHA") or "HEAD^1"
    try:
        base = go_api.git("merge-base", base_ref, "HEAD")
    except RuntimeError as error:
        go_ci.summarise(summary, [title, "", "- FAILED: no base to compare with ({})".format(error)])
        return 1
    scratch = tempfile.mkdtemp(prefix="contract-")
    worktree = Path(scratch, "base")
    breaking, notes, lines = [], [], [title, "", "Base `{}`.".format(base[:12])]
    try:
        go_api.git("worktree", "add", "--detach", str(worktree), base)
        found_breaking, found_notes = compare_schema_sets(schema_files(worktree), schema_files("."))
        breaking += found_breaking
        notes += found_notes
        lines.append("Schemas: {} at the base, {} here.".format(len(schema_files(worktree)), len(schema_files("."))))
        has_cli = Path("go", MAIN).is_dir() and (worktree / "go" / MAIN).is_dir()
        if has_cli:
            tree, problems = go_ci.toolchain_problems()
            if problems:
                raise RuntimeError("; ".join(problems))
            old_bin, new_bin = Path(scratch, "protodetect-base"), Path(scratch, "protodetect-head")
            build(worktree / "go", old_bin, go_ci.go_env((worktree / go_ci.VENDOR).is_file()))
            build(Path("go"), new_bin, go_ci.go_env(tree.get("vendored")))
            old_cli, new_cli = cli_contract(str(old_bin)), cli_contract(str(new_bin))
            found_breaking, found_notes = compare_cli(old_cli, new_cli)
            breaking += found_breaking
            notes += found_notes
            lines.append("CLI: {} subcommand(s), {} flag(s) here.".format(
                len(new_cli["subcommands"]), sum(len(f) for f in new_cli["flags"].values())))
        else:
            lines.append("CLI: no go/cmd/protodetect at the base or here, nothing to compare.")
    except (RuntimeError, ValueError, KeyError, OSError) as error:
        go_ci.summarise(summary, lines + ["", "- FAILED: {}".format(error)])
        return 1
    finally:
        go_api.git("worktree", "remove", "--force", str(worktree), check=False)
        shutil.rmtree(scratch, ignore_errors=True)
    failed, verdict = go_api.decide(breaking, go_api.labels_of(os.environ.get("LABELS")))
    verdict = verdict.replace("public API", "external contract")
    lines += ["", ("- FAILED: " if failed else "") + verdict] + ["  - {}".format(item) for item in breaking[:60]]
    lines += ["", "Reported only: {} change(s).".format(len(notes))] + ["- {}".format(item) for item in notes[:60]]
    go_ci.summarise(summary, lines)
    return 1 if failed else 0


def self_test():
    base = {"$defs": {"endpoint": {"type": "object", "additionalProperties": False, "required": ["ip"],
                                   "properties": {"ip": {"type": "string"}, "port": {"type": "integer", "minimum": 0, "maximum": 65535}}},
                      "started": {"type": "object", "properties": {"type": {"const": "started"}, "at": {"$ref": "#/$defs/endpoint"}}},
                      "summary": {"type": "object", "properties": {"type": {"const": "summary"},
                                                                     "status": {"enum": ["ok", "failed"]},
                                                                     "count": {"type": "integer"}, "note": {"type": "string"}}}},
            "oneOf": [{"$ref": "#/$defs/started"}, {"$ref": "#/$defs/summary"}]}

    def changed(edit):
        document = json.loads(json.dumps(base))
        edit(document)
        return compare_schema_sets({"live.schema.json": base}, {"live.schema.json": document})

    assert changed(lambda d: None) == ([], [])
    resolved = resolve(base, {"live.schema.json": base}, "live.schema.json")
    assert resolved["oneOf"][0]["properties"]["at"]["properties"]["ip"] == {"type": "string"}   # $ref resolved
    assert branch_key(resolved["oneOf"][1], 1) == "type=summary"
    cases = [
        ("property removed", lambda d: d["$defs"]["summary"]["properties"].pop("note"), "summary].note: property removed"),
        ("property removed through $ref", lambda d: d["$defs"]["endpoint"]["properties"].pop("port"), ".at.port: property removed"),
        ("new required property", lambda d: (d["$defs"]["summary"]["properties"].update({"id": {"type": "string"}}),
                                             d["$defs"]["summary"].setdefault("required", []).append("id")), ".id: new required property"),
        ("existing became required", lambda d: d["$defs"]["summary"].setdefault("required", []).append("count"), ".count: property became required"),
        ("type changed", lambda d: d["$defs"]["summary"]["properties"]["count"].update({"type": "string"}), "type ['integer'] changed to ['string']"),
        ("enum value removed", lambda d: d["$defs"]["summary"]["properties"]["status"].update({"enum": ["ok"]}), "enum value(s) [\"failed\"] removed"),
        ("const changed", lambda d: d["$defs"]["started"]["properties"]["type"].update({"const": "begin"}), "branch type=started removed"),
        ("additionalProperties restricted", lambda d: d["$defs"]["summary"].update({"additionalProperties": False}),
         "additionalProperties restricted to false"),
        ("oneOf branch added", lambda d: (d["$defs"].update({"gap": {"type": "object", "properties": {"type": {"const": "gap"}}}}),
                                          d["oneOf"].append({"$ref": "#/$defs/gap"})), "branch type=gap added"),
        ("oneOf branch removed", lambda d: d["oneOf"].pop(), "branch type=summary removed"),
        ("minimum raised", lambda d: d["$defs"]["endpoint"]["properties"]["port"].update({"minimum": 1}), "minimum tightened from 0 to 1"),
        ("maximum lowered", lambda d: d["$defs"]["endpoint"]["properties"]["port"].update({"maximum": 1024}), "maximum tightened from 65535 to 1024"),
        ("maxItems added", lambda d: d["$defs"]["summary"]["properties"]["note"].update({"maxLength": 10}), "maxLength 10 added")]
    for label, edit, expected in cases:
        breaking, _ = changed(edit)
        assert any(expected in item for item in breaking), (label, breaking)
    for label, edit, expected in [
            ("optional added", lambda d: d["$defs"]["summary"]["properties"].update({"extra": {"type": "string"}}), ".extra: optional property added"),
            ("enum value added", lambda d: d["$defs"]["summary"]["properties"]["status"].update({"enum": ["ok", "failed", "partial"]}),
             "enum value(s) [\"partial\"] added"),
            ("description", lambda d: d["$defs"]["summary"].update({"description": "x"}), "description changed"),
            ("type widened", lambda d: d["$defs"]["summary"]["properties"]["count"].update({"type": ["integer", "null"]}), "type widened")]:
        breaking, notes = changed(edit)
        assert breaking == [] and any(expected in item for item in notes), (label, breaking, notes)
    breaking, notes = compare_schema_sets({"a.json": {}, "b.json": {}}, {"a.json": {}, "c.json": {}})
    assert breaking == ["b.json: schema file deleted or renamed"] and notes == ["c.json: schema file added"]
    cyclic = {"$defs": {"node": {"type": "object", "properties": {"child": {"$ref": "#/$defs/node"}}}}, "$ref": "#/$defs/node"}
    assert compare_schema_sets({"t.json": cyclic}, {"t.json": cyclic}) == ([], [])                     # a cycle terminates
    usage = "usage: protodetect version | analyze CAPTURE [options] | present < CAPTURE | live ... | cases --file PATH\n"
    assert subcommands_of(usage) == ["analyze", "cases", "live", "present", "version"]
    go_flags = ("Usage of replay:\n  -cases string\n    \tthe cases file (default \"migration/fixtures/cases.json\")\n"
                "  -out string\n    \twhere to write (required)\n  -verbose\n    \tlog more\n")
    assert flags_of(go_flags) == {"cases": {"type": "string", "default": "\"migration/fixtures/cases.json\""},
                                  "out": {"type": "string", "default": None}, "verbose": {"type": "bool", "default": None}}, flags_of(go_flags)
    usage_flags = ("usage: protodetect live (--interface NAME | --stdin | --interfaces) [--filter BPF] [--json] "
                   "[--observation handshake|asymmetric|midstream] [--checksums POLICY]\nprotodetect live: error: unrecognized arguments: -h\n")
    parsed = flags_of(usage_flags)
    assert parsed == {"interface": {"metavar": "NAME"}, "stdin": {"metavar": None}, "interfaces": {"metavar": None},
                      "filter": {"metavar": "BPF"}, "json": {"metavar": None},
                      "observation": {"metavar": "handshake|asymmetric|midstream"}, "checksums": {"metavar": "POLICY"}}, parsed
    old = {"subcommands": ["live", "replay", "version"], "flags": {"live": parsed, "replay": flags_of(go_flags), "version": {}}}
    assert compare_cli(old, old) == ([], [])

    def cli_changed(edit):
        new = json.loads(json.dumps(old))
        edit(new)
        return compare_cli(old, new)
    for label, edit, expected in [
            ("subcommand removed", lambda n: n["subcommands"].remove("version"), "protodetect version: subcommand removed"),
            ("flag removed", lambda n: n["flags"]["live"].pop("filter"), "live --filter: flag removed"),
            ("default changed", lambda n: n["flags"]["replay"]["cases"].update({"default": "\"x.json\""}), "default"),
            ("type changed", lambda n: n["flags"]["replay"]["out"].update({"type": "int"}), "type string changed to int"),
            ("value dropped", lambda n: n["flags"]["live"]["json"].update({"metavar": "FORMAT"}), "takes a value now"),
            ("choice dropped", lambda n: n["flags"]["live"]["observation"].update({"metavar": "handshake|midstream"}),
             "value(s) asymmetric no longer accepted")]:
        breaking, _ = cli_changed(edit)
        assert any(expected in item for item in breaking), (label, breaking)
    breaking, notes = cli_changed(lambda n: (n["subcommands"].append("serve"), n["flags"].update({"serve": {}}),
                                             n["flags"]["live"].update({"pcap": {"metavar": "FILE"}})))
    assert breaking == [] and len(notes) == 2, (breaking, notes)
    print("contract_check self-test: ok ($ref resolution, every breaking and reported schema rule, file deletion, cycles, "
          "both CLI help formats, subcommand and flag rules)")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--summary", help="append a markdown summary here (GITHUB_STEP_SUMMARY)")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    return run(args.summary)


if __name__ == "__main__":
    sys.exit(main())
