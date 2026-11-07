"""Fail when a built wheel carries anything but the shipped packages, or misses a module of them.

Release gate: the wheel must contain exactly the modules under protocol_engine/,
protocol_adapters/ and, since A01, the presentation application as
protocol_observatory/ (presentation/*.py, poc_decryption/*.py, the web assets,
SOURCE.json and the decryption requirement files; no tests, captures, tools or
benchmarks) plus its dist-info, declare the `protocol-observatory` console
script, and declare no unconditional runtime dependency. The only dependency is
the optional `decryption` extra (cryptography) used by the TLS POC; the core
stays dependency-free. Usage: tools/check_wheel.py dist/*.whl
"""
import glob
import os
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def archive_read(wheel, member):
    with zipfile.ZipFile(wheel) as archive:
        return archive.read(member).decode("utf-8")


def main(paths):
    wheels = [path for pattern in paths for path in glob.glob(pattern)]
    if len(wheels) != 1:
        print("check_wheel: expected exactly one wheel, found", len(wheels))
        return 1
    with zipfile.ZipFile(wheels[0]) as archive:
        names = archive.namelist()
        metadata = next((name for name in names if name.endswith(".dist-info/METADATA")), None)
        requires = [line for line in archive.read(metadata).decode("utf-8").splitlines() if line.startswith("Requires-Dist:")] if metadata else ["missing"]
    failures = []
    # wheel package -> tree directory
    packages = {"protocol_engine": "protocol_engine", "protocol_adapters": "protocol_adapters",
                "protocol_observatory": "presentation", "protocol_observatory/poc_decryption": "presentation/poc_decryption"}
    prefixes = tuple(p + "/" for p in packages)
    packaged = {name for name in names if name.startswith(prefixes) and name.endswith(".py")}
    expected = {package + "/" + os.path.basename(path) for package, folder in packages.items()
                for path in glob.glob(os.path.join(ROOT, folder, "*.py"))}
    data_allowed = {"protocol_observatory/" + os.path.relpath(path, os.path.join(ROOT, "presentation")) for pattern in
                    ("web/*", "SOURCE.json", "requirements-decryption.txt", "requirements-decryption.lock.txt", "DECRYPTION.md")
                    for path in glob.glob(os.path.join(ROOT, "presentation", pattern))}
    data = {name for name in names if name.startswith(prefixes) and not name.endswith(".py")}
    foreign = [name for name in names if not name.startswith(prefixes) and ".dist-info/" not in name]
    if foreign:
        failures.append("files outside the shipped packages: " + ", ".join(sorted(foreign)[:10]))
    if packaged != expected:
        failures.append("module set differs from the tree: missing {} extra {}".format(sorted(expected - packaged), sorted(packaged - expected)))
    if data != data_allowed:
        failures.append("data files differ from the allowed set: missing {} extra {}".format(sorted(data_allowed - data), sorted(data - data_allowed)))
    entry_points = next((name for name in names if name.endswith(".dist-info/entry_points.txt")), None)
    scripts = archive_read(wheels[0], entry_points) if entry_points else ""
    if "protocol-observatory = protocol_observatory.launch:main" not in scripts:
        failures.append("console script protocol-observatory missing from entry_points.txt")
    unconditional = [line for line in requires if "; extra ==" not in line]
    if unconditional:
        failures.append("runtime dependencies declared: " + "; ".join(unconditional))
    extras = [line for line in requires if "; extra ==" in line]
    if extras != ['Requires-Dist: cryptography==50.0.2; extra == "decryption"']:
        failures.append("optional extras differ from the documented decryption extra: " + "; ".join(extras))
    for failure in failures:
        print("check_wheel:", failure)
    print("check_wheel:", ("ok" if not failures else "{} problem(s)".format(len(failures))), "({} entries, {} modules)".format(len(names), len(packaged)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or ["dist/*.whl"]))
