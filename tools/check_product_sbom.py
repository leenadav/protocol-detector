"""Fail when the complete-product SBOM does not describe exactly the installed product.

The release ships the engine wheel and its optional `decryption` extra, installed from the hash-pinned
presentation/requirements-decryption.lock.txt. The SBOM is generated from an environment holding only
that product (the wheel, the lock's packages, pip removed), so it must name:
  - as its root component the project of pyproject.toml, at the version the wheel file carries;
  - as its components exactly the packages the lock pins, each at its pinned version with a
    `pkg:pypi/<name>@<version>` purl: a package missing (the extra was not installed) or extra (a
    build tool, pip, or an unpinned transitive dependency) fails.
Names compare in PEP 503 normalised form. A package listed more than once in the SBOM fails
whatever the order and spelling of its entries.

The lock is universal (uv's layout): a package may carry several pins under disjoint
environment markers (`cffi==2.0.0 ; python_full_version < '3.10' and ...`). The pins that apply
are those whose marker holds for the interpreter of the product environment (--python, read
from that interpreter with the standard library only), evaluated with `packaging.markers` from
the hash-pinned toolchain. Exactly one pin must apply to each package the SBOM lists, and a
package with no applicable pin (typing-extensions on 3.11+) must be absent. Markers without
--python, an invalid marker or a missing `packaging` fail closed. Python 3.9 syntax. Usage:
  check_product_sbom.py SBOM --lock FILE --pyproject FILE --wheel FILE --python PRODUCT_PYTHON [--summary FILE]
  check_product_sbom.py --self-test
"""
import argparse
import json
import platform
import re
import subprocess
import sys
from pathlib import Path

PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)\s*(?:;\s*([^\\]*?))?\s*\\?\s*$")
# PEP 508 environment of an interpreter, computed by that interpreter with the standard library
# (the product environment has neither pip nor packaging).
ENVIRONMENT_PROBE = (
    "import json, os, platform, sys\n"
    "def version(info):\n"
    "    text = '{0.major}.{0.minor}.{0.micro}'.format(info)\n"
    "    return text if info.releaselevel == 'final' else text + info.releaselevel[0] + str(info.serial)\n"
    "print(json.dumps({'implementation_name': sys.implementation.name,\n"
    "                  'implementation_version': version(sys.implementation.version), 'os_name': os.name,\n"
    "                  'platform_machine': platform.machine(), 'platform_release': platform.release(),\n"
    "                  'platform_system': platform.system(), 'platform_version': platform.version(),\n"
    "                  'python_full_version': platform.python_version(),\n"
    "                  'platform_python_implementation': platform.python_implementation(),\n"
    "                  'python_version': '.'.join(platform.python_version_tuple()[:2]), 'sys_platform': sys.platform}))\n"
)
WHEEL = re.compile(r"^([A-Za-z0-9_.]+)-([^-]+)-[^-]+-[^-]+-[^-]+\.whl$")


def normalise(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def lock_pins(text):
    """{normalised name: [(version, marker or None) in lock order]}."""
    pins = {}
    for match in map(PIN.match, text.splitlines()):
        if match:
            pins.setdefault(normalise(match.group(1)), []).append((match.group(2), (match.group(3) or "").strip() or None))
    return pins


def environment_of(python):
    """The PEP 508 marker environment of the interpreter at `python`."""
    output = subprocess.run([python, "-I", "-c", ENVIRONMENT_PROBE], stdout=subprocess.PIPE, check=True, timeout=60).stdout  # noqa: S603
    return json.loads(output)


def applicable(pins, environment, problems):
    """{name: [versions whose marker holds]}; marker problems are appended to `problems`."""
    if environment is None:
        marked = sorted(name for name, entries in pins.items() if any(marker for _, marker in entries))
        if marked:
            problems.append("the lock pins {} under environment markers: --python (the product interpreter) is required".format(", ".join(marked)))
        return {name: [version for version, _ in entries] for name, entries in pins.items()}
    try:
        from packaging.markers import InvalidMarker, Marker
    except ImportError:
        problems.append("packaging is not installed: the lock's environment markers cannot be evaluated")
        return {}
    selected = {}
    for name, entries in pins.items():
        for version, marker in entries:
            try:
                holds = marker is None or Marker(marker).evaluate(environment)
            except InvalidMarker as error:
                problems.append("{}=={} has an invalid marker ({})".format(name, version, error))
                continue
            if holds:
                selected.setdefault(name, []).append(version)
    return selected


def project_of(pyproject_text):
    section = re.search(r"^\[project\]\s*$(.*?)(?=^\[|\Z)", pyproject_text, re.M | re.S)
    body = section.group(1) if section else ""
    name = re.search(r'^name\s*=\s*"([^"]+)"', body, re.M)
    version = re.search(r'^version\s*=\s*"([^"]+)"', body, re.M)
    return (normalise(name.group(1)) if name else None, version.group(1) if version else None)


def decide(document, pins, project, wheel_name, environment=None):
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
    pinned = {}
    for key, versions in applicable(pins, environment, problems).items():
        if len(versions) > 1:
            problems.append("{} is pinned more than once by the lock for this interpreter ({}): one pin must apply".format(key, ", ".join(versions)))
        pinned[key] = versions[0]
    found = {}
    for component in document.get("components", []):
        key = normalise(component.get("name", ""))
        found.setdefault(key, []).append(component.get("version"))
        purl = "pkg:pypi/{}@{}".format(key, component.get("version"))
        if normalise(component.get("purl", "")) != normalise(purl):
            problems.append("{} {} has purl {} (expected {})".format(key, component.get("version"), component.get("purl"), purl))
    for key in sorted(found):
        if len(found[key]) > 1:
            problems.append("{} is listed {} times in the SBOM ({}): each package must appear once".format(
                key, len(found[key]), ", ".join(str(version) for version in found[key])))
    for key in sorted(set(pinned) - set(found)):
        problems.append("{}=={} is pinned by the lock but missing from the SBOM".format(key, pinned[key]))
    for key in sorted(set(found) - set(pinned)):
        problems.append("{} {} is in the SBOM but not pinned by the lock".format(key, ", ".join(str(v) for v in found[key])))
    for key in sorted(set(pinned) & set(found)):
        for version in found[key]:
            if version != pinned[key]:
                problems.append("{} is {} in the SBOM but {} in the lock".format(key, version, pinned[key]))
    return problems


def self_test():
    pins = lock_pins("# comment\ncffi==2.1.1 \\\n    --hash=sha256:aa\ncryptography==50.0.2 \\\npycparser==3.12 ; python_version >= '3.10'\n")
    assert pins == {"cffi": [("2.1.1", None)], "cryptography": [("50.0.2", None)],
                    "pycparser": [("3.12", "python_version >= '3.10'")]}, pins
    pins = lock_pins("cffi==2.1.1 \\\ncryptography==50.0.2 \\\npycparser==3.12 \\\n")
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
    # item 25 round 1: a conflicting duplicate must fail in either order and under an aliased spelling
    for components in ([("cffi", "UNPINNED"), ("cffi", "2.1.1")], [("cffi", "2.1.1"), ("cffi", "UNPINNED")],
                       [("cffi", "2.1.1"), ("CFFI", "2.1.1")], [("Cffi", "2.1.1"), ("cffi", "2.1.1")]):
        found = decide(bom(components + good[1:]), pins, project, wheel)
        assert any("listed 2 times" in problem for problem in found), (components, found)
    alias_pins = lock_pins("typing_extensions==4.16.0 \\\n")
    assert decide(bom([("typing-extensions", "4.16.0")]), alias_pins, project, wheel) == []
    assert any("listed 2 times" in problem for problem in decide(
        bom([("typing-extensions", "4.16.0"), ("typing_extensions", "4.16.0")]), alias_pins, project, wheel))
    # the universal lock (engine 726007d): marker-split pins, evaluated for the product interpreter
    universal = lock_pins("\n".join([
        "cffi==2.0.0 ; python_full_version < '3.10' and platform_python_implementation != 'PyPy' \\",
        "cffi==2.1.1 ; python_full_version >= '3.10' and platform_python_implementation != 'PyPy' \\",
        "cryptography==50.0.2 \\",
        "pycparser==2.23 ; python_full_version < '3.10' and implementation_name != 'PyPy' and platform_python_implementation != 'PyPy' \\",
        "pycparser==3.11 ; python_full_version == '3.10.*' and implementation_name != 'PyPy' and platform_python_implementation != 'PyPy' \\",
        "pycparser==3.12 ; python_full_version >= '3.11' and implementation_name != 'PyPy' and platform_python_implementation != 'PyPy' \\",
        "typing-extensions==4.16.0 ; python_full_version < '3.11' \\", ""]))

    def interpreter(full, implementation="CPython"):
        return {"python_full_version": full, "python_version": ".".join(full.split(".")[:2]),
                "platform_python_implementation": implementation, "implementation_name": implementation.lower(),
                "implementation_version": full, "os_name": "posix", "sys_platform": "linux", "platform_machine": "x86_64",
                "platform_release": "", "platform_system": "Linux", "platform_version": ""}
    expected = {
        "3.9.25": [("cffi", "2.0.0"), ("cryptography", "50.0.2"), ("pycparser", "2.23"), ("typing-extensions", "4.16.0")],
        "3.10.4": [("cffi", "2.1.1"), ("cryptography", "50.0.2"), ("pycparser", "3.11"), ("typing-extensions", "4.16.0")],
        "3.13.16": [("cffi", "2.1.1"), ("cryptography", "50.0.2"), ("pycparser", "3.12")],
    }
    for full, components in expected.items():
        assert decide(bom(components), universal, project, wheel, interpreter(full)) == [], full
    assert decide(bom([("cryptography", "50.0.2"), ("typing-extensions", "4.16.0")]), universal, project, wheel,
                  interpreter("3.10.4", "PyPy")) == []                                   # PyPy: no cffi, no pycparser
    on_313 = interpreter("3.13.16")
    for components, problem in (
            (expected["3.9.25"], "in the SBOM but 2.1.1 in the lock"),                 # 3.9 set on 3.13
            (expected["3.13.16"] + [("typing-extensions", "4.16.0")], "not pinned by the lock"),   # no pin applies on 3.13
            (expected["3.13.16"][:2], "missing from the SBOM"),
            (expected["3.13.16"] + [("cffi", "2.0.0")], "listed 2 times")):
        assert any(problem in found for found in decide(bom(components), universal, project, wheel, on_313)), (components, problem)
    assert any("--python" in found for found in decide(bom(expected["3.13.16"]), universal, project, wheel))   # markers need the interpreter
    overlap = lock_pins("cffi==2.0.0 ; python_version >= '3.9' \\\ncffi==2.1.1 ; python_version >= '3.10' \\\n")
    assert any("pinned more than once" in found for found in decide(bom([("cffi", "2.1.1")]), overlap, project, wheel, on_313))
    broken = lock_pins("cffi==2.1.1 ; python_version >>> '3.10' \\\n")
    assert any("invalid marker" in found for found in decide(bom([("cffi", "2.1.1")]), broken, project, wheel, on_313))
    probe = environment_of(sys.executable)
    assert probe["python_full_version"] == platform.python_version() and "implementation_name" in probe, probe
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
    parser.add_argument("--python", help="the interpreter of the product environment (evaluates the lock's markers)")
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
    environment = environment_of(args.python) if args.python else None
    problems = decide(document, pins, project, Path(args.wheel).name, environment)
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
