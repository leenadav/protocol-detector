"""Fail when the complete-product SBOM does not describe exactly the installed product.

The release ships the engine wheel and its optional `decryption` extra, installed from the hash-pinned
presentation/requirements-decryption.lock.txt. The SBOM is generated from an environment holding only
that product (the wheel, the lock's packages, pip removed), so it must name:
  - as its root component the project of pyproject.toml, at the version the wheel file carries;
  - as its components exactly the packages the lock pins, each at its pinned version with a
    `pkg:pypi/<name>@<version>` purl: a package missing (the extra was not installed) or extra (a
    build tool, pip, or an unpinned transitive dependency) fails.
Names compare in PEP 503 normalised form. Standard library only, Python 3.9 syntax. Usage:
  check_product_sbom.py SBOM --lock FILE --pyproject FILE --wheel FILE [--summary FILE]
  check_product_sbom.py --self-test
"""
import argparse
import json
import re
import sys
from pathlib import Path

PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)")
WHEEL = re.compile(r"^([A-Za-z0-9_.]+)-([^-]+)-[^-]+-[^-]+-[^-]+\.whl$")


def normalise(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def lock_pins(text):
    return {normalise(match.group(1)): match.group(2) for match in map(PIN.match, text.splitlines()) if match}


def project_of(pyproject_text):
    section = re.search(r"^\[project\]\s*$(.*?)(?=^\[|\Z)", pyproject_text, re.M | re.S)
    body = section.group(1) if section else ""
    name = re.search(r'^name\s*=\s*"([^"]+)"', body, re.M)
    version = re.search(r'^version\s*=\s*"([^"]+)"', body, re.M)
    return (normalise(name.group(1)) if name else None, version.group(1) if version else None)


def decide(document, pins, project, wheel_name):
    problems = []
    if document.get("bomFormat") != "CycloneDX":
        return ["not a CycloneDX document"]
    name, version = project
    wheel = WHEEL.match(wheel_name)
    if not wheel:
        problems.append("not a wheel file name: " + wheel_name)
    elif (normalise(wheel.group(1)), wheel.group(2)) != (name, version):
        problems.append("the wheel {} is not {} {} of pyproject.toml".format(wheel_name, name, version))
    root = document.get("metadata", {}).get("component") or {}
    if (normalise(root.get("name", "")), root.get("version")) != (name, version):
        problems.append("root component {} {} is not {} {}".format(root.get("name"), root.get("version"), name, version))
    found = {}
    for component in document.get("components", []):
        key = normalise(component.get("name", ""))
        found[key] = component.get("version")
        purl = "pkg:pypi/{}@{}".format(key, component.get("version"))
        if normalise(component.get("purl", "")) != normalise(purl):
            problems.append("{} {} has purl {} (expected {})".format(key, component.get("version"), component.get("purl"), purl))
    for key in sorted(set(pins) - set(found)):
        problems.append("{}=={} is pinned by the lock but missing from the SBOM".format(key, pins[key]))
    for key in sorted(set(found) - set(pins)):
        problems.append("{} {} is in the SBOM but not pinned by the lock".format(key, found[key]))
    for key in sorted(set(pins) & set(found)):
        if pins[key] != found[key]:
            problems.append("{} is {} in the SBOM but {} in the lock".format(key, found[key], pins[key]))
    return problems


def self_test():
    pins = lock_pins("# comment\ncffi==2.1.1 \\\n    --hash=sha256:aa\ncryptography==50.0.2 \\\npycparser==3.12 ; python_version >= '3.10'\n")
    assert pins == {"cffi": "2.1.1", "cryptography": "50.0.2", "pycparser": "3.12"}, pins
    project = project_of('[build-system]\nrequires = ["x"]\n\n[project]\nname = "protocol-stream-engine"\nversion = "0.66.0"\n\n[tool.ruff]\nversion = "9"\n')
    assert project == ("protocol-stream-engine", "0.66.0"), project
    wheel = "protocol_stream_engine-0.66.0-py3-none-any.whl"

    def bom(components, root=("protocol-stream-engine", "0.66.0")):
        return {"bomFormat": "CycloneDX", "metadata": {"component": {"name": root[0], "version": root[1]}},
                "components": [{"name": n, "version": v, "purl": "pkg:pypi/{}@{}".format(n.lower(), v)} for n, v in components]}
    good = [("cffi", "2.1.1"), ("cryptography", "50.0.2"), ("pycparser", "3.12")]
    assert decide(bom(good), pins, project, wheel) == []
    cases = {
        "extra missing": (bom(good[:1]), wheel, "missing from the SBOM"),
        "pip left in": (bom(good + [("pip", "26.2.1")]), wheel, "not pinned by the lock"),
        "version drift": (bom([("cffi", "2.0.0")] + good[1:]), wheel, "in the SBOM but 2.1.1 in the lock"),
        "wrong root": (bom(good, ("something", "1")), wheel, "root component"),
        "stale wheel": (bom(good), "protocol_stream_engine-0.65.0-py3-none-any.whl", "is not protocol-stream-engine 0.66.0"),
        "not a wheel": (bom(good), "protocol-stream-engine-0.66.0.tar.gz", "not a wheel"),
    }
    for label, (document, wheel_name, expected) in cases.items():
        found = decide(document, pins, project, wheel_name)
        assert any(expected in problem for problem in found), (label, found)
    bad_purl = bom(good)
    bad_purl["components"][0]["purl"] = "pkg:pypi/evil@2.1.1"
    assert any("has purl" in problem for problem in decide(bad_purl, pins, project, wheel))
    assert decide({"bomFormat": "SPDX"}, pins, project, wheel) == ["not a CycloneDX document"]
    print("check_product_sbom self-test: ok")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("sbom", nargs="?")
    parser.add_argument("--lock")
    parser.add_argument("--pyproject", default="pyproject.toml")
    parser.add_argument("--wheel")
    parser.add_argument("--summary")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if not (args.sbom and args.lock and args.wheel):
        parser.error("SBOM, --lock and --wheel are required")
    document = json.loads(Path(args.sbom).read_text(encoding="utf-8"))
    pins = lock_pins(Path(args.lock).read_text(encoding="utf-8"))
    project = project_of(Path(args.pyproject).read_text(encoding="utf-8"))
    problems = decide(document, pins, project, Path(args.wheel).name)
    lines = ["complete-product SBOM: {} {} with {} components ({})".format(
        project[0], project[1], len(document.get("components", [])),
        ", ".join("{} {}".format(c.get("name"), c.get("version")) for c in document.get("components", [])))]
    lines.extend("  " + problem for problem in problems)
    lines.append("check_product_sbom: " + ("ok, exactly the wheel and the lock's pins" if not problems else "FAILED, {} problem(s)".format(len(problems))))
    print("\n".join(lines))
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
