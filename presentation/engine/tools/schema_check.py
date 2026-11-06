"""Minimal JSON Schema (draft-07 subset) validator with no dependencies.

Supports the keywords the published schemas use: type (string or list, with
"integer" distinct from "number" and booleans never counting as numbers),
enum, const, properties, required, additionalProperties (boolean or schema),
items (schema or positional list), minItems, maxItems, minimum, maximum,
oneOf, anyOf and local "$ref" into "$defs". Validation returns a list of
"path: message" strings; an empty list means the instance conforms.
"""
import json
import sys
from pathlib import Path

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"
_TYPES = {"string": str, "integer": int, "number": (int, float), "boolean": bool, "array": list, "object": dict, "null": type(None)}


def load(name):
    with open(SCHEMA_DIR / (name if name.endswith(".json") else name + ".schema.json"), "rb") as handle:
        return json.loads(handle.read().decode("utf-8"))


def names():
    return sorted(path.name[:-len(".schema.json")] for path in SCHEMA_DIR.glob("*.schema.json"))


def _type_ok(value, kind):
    if kind in ("integer", "number") and isinstance(value, bool):
        return False
    return isinstance(value, _TYPES[kind])


def _resolve(schema, root):
    while "$ref" in schema:
        reference = schema["$ref"]
        if not reference.startswith("#/"):
            raise ValueError("Only local references are supported: " + reference)
        target = root
        for part in reference[2:].split("/"):
            target = target[part]
        schema = target
    return schema


def validate(instance, schema, root=None, path="$"):
    root = schema if root is None else root
    schema = _resolve(schema, root)
    errors = []
    kinds = schema.get("type")
    if kinds is not None:
        kinds = [kinds] if isinstance(kinds, str) else kinds
        if not any(_type_ok(instance, kind) for kind in kinds):
            return ["{}: expected {}, got {}".format(path, "/".join(kinds), type(instance).__name__)]
    if "const" in schema and instance != schema["const"]:
        errors.append("{}: expected constant {!r}".format(path, schema["const"]))
    if "enum" in schema and instance not in schema["enum"]:
        errors.append("{}: {!r} not in enum".format(path, instance))
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append("{}: {} below minimum {}".format(path, instance, schema["minimum"]))
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append("{}: {} above maximum {}".format(path, instance, schema["maximum"]))
    if isinstance(instance, dict):
        properties = schema.get("properties", {})
        for key in schema.get("required", ()):
            if key not in instance:
                errors.append("{}: missing required property {!r}".format(path, key))
        for key, value in instance.items():
            if key in properties:
                errors.extend(validate(value, properties[key], root, "{}.{}".format(path, key)))
            else:
                extra = schema.get("additionalProperties", True)
                if extra is False:
                    errors.append("{}: unexpected property {!r}".format(path, key))
                elif isinstance(extra, dict):
                    errors.extend(validate(value, extra, root, "{}.{}".format(path, key)))
    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append("{}: fewer than {} items".format(path, schema["minItems"]))
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errors.append("{}: more than {} items".format(path, schema["maxItems"]))
        items = schema.get("items")
        if isinstance(items, list):
            for index, (value, item_schema) in enumerate(zip(instance, items)):
                errors.extend(validate(value, item_schema, root, "{}[{}]".format(path, index)))
        elif isinstance(items, dict):
            for index, value in enumerate(instance):
                errors.extend(validate(value, items, root, "{}[{}]".format(path, index)))
    for keyword in ("oneOf", "anyOf"):
        if keyword in schema:
            outcomes = [validate(instance, option, root, path) for option in schema[keyword]]
            matches = sum(1 for outcome in outcomes if not outcome)
            if matches == 0:
                best = min(outcomes, key=len)
                errors.append("{}: no {} branch matched; closest: {}".format(path, keyword, best[0] if best else "?"))
            elif keyword == "oneOf" and matches > 1:
                errors.append("{}: {} oneOf branches matched".format(path, matches))
    return errors


def validate_lines(lines, schema_name):
    """Validate JSON Lines text against a schema; returns (count, errors)."""
    schema = load(schema_name)
    count, errors = 0, []
    for number, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        count += 1
        try:
            instance = json.loads(line)
        except ValueError as error:
            errors.append("line {}: invalid JSON ({})".format(number, error))
            continue
        for problem in validate(instance, schema):
            errors.append("line {}: {}".format(number, problem))
    return count, errors


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description="Validate JSON Lines output against a published schema")
    parser.add_argument("schema", choices=names())
    parser.add_argument("file", help="JSON Lines file, or - for stdin")
    args = parser.parse_args(argv)
    stream = sys.stdin if args.file == "-" else open(args.file, "r", encoding="utf-8")
    with stream:
        count, errors = validate_lines(stream, args.schema)
    for error in errors[:50]:
        print(error)
    print("{} lines checked against {}: {}".format(count, args.schema, "ok" if not errors else "{} errors".format(len(errors))))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
