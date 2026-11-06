"""Fail when a built wheel carries anything but the engine package, or misses a module of it.

Release gate: the wheel must contain exactly the modules under protocol_engine/
in the tree (no tests, fixtures, captures, tools or benchmarks) plus its
dist-info, and declare no runtime dependencies. Usage:
tools/check_wheel.py dist/*.whl
"""
import glob
import os
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


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
    packaged = {name for name in names if name.startswith("protocol_engine/") and name.endswith(".py")}
    expected = {"protocol_engine/" + os.path.basename(path) for path in glob.glob(os.path.join(ROOT, "protocol_engine", "*.py"))}
    foreign = [name for name in names if not name.startswith("protocol_engine/") and ".dist-info/" not in name]
    if foreign:
        failures.append("files outside the engine package: " + ", ".join(sorted(foreign)[:10]))
    if packaged != expected:
        failures.append("module set differs from the tree: missing {} extra {}".format(sorted(expected - packaged), sorted(packaged - expected)))
    if requires:
        failures.append("runtime dependencies declared: " + "; ".join(requires))
    for failure in failures:
        print("check_wheel:", failure)
    print("check_wheel:", ("ok" if not failures else "{} problem(s)".format(len(failures))), "({} entries, {} modules)".format(len(names), len(packaged)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or ["dist/*.whl"]))
