"""Summarize a CycloneDX SBOM and enforce the zero-runtime-dependency contract.

The package declares `dependencies = []`; the SBOM of the analysis environment
may list development tools, but the published package itself must not depend
on anything beyond the Python standard library.
"""
import json
import sys
import re
from pathlib import Path


def main(path):
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    components = document.get("components", [])
    print("SBOM format {} {} with {} components".format(document.get("bomFormat"), document.get("specVersion"), len(components)))
    for component in sorted(components, key=lambda item: item.get("name", "")):
        print("  {} {}".format(component.get("name"), component.get("version")))
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    if not re.search(r"^dependencies = \[\]$", pyproject, re.M):
        print("pyproject.toml declares runtime dependencies; the engine contract forbids them")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "sbom.cdx.json"))
