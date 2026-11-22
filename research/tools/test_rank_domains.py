"""Tests for rank_domains.py: the --export-domains guard and the domains column (PRO-98 review).

Run from the repository root: python3 -B -m unittest discover -s research/tools -q
Each case runs the tool in a subprocess, so a fake catalog never collides with the real protocol_engine.
"""
import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parent / "rank_domains.py"
REGISTRY = Path(__file__).resolve().parents[1] / "apps.json"


def run(*args):
    return subprocess.run([sys.executable, "-B", "-I", str(TOOL), *args], capture_output=True, text=True, timeout=60)


def fake_checkout(root, ids):
    pkg = Path(root) / "protocol_engine"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    rows = ",\n".join("    (%r, 'c', 's', 't', 1, 'd', (), (%r,))" % (i, i + ".example") for i in ids)
    (pkg / "host_apps.py").write_text("_HOST_APPS = (\n%s,\n)\n" % rows)
    return pkg.parent


def registry_ids():
    reg = json.loads(REGISTRY.read_text())
    return sorted({i for k, v in reg.items() if not k.startswith("_") for i in v["ids"]})


class ExportGuard(unittest.TestCase):
    def test_refuses_checkout_missing_catalog_ids(self):
        ids = registry_ids()
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "co").mkdir()
            checkout = fake_checkout(Path(tmp) / "co", ids[:1])
            out = Path(tmp) / "app-domains.json"
            r = run("--export-domains", str(checkout), str(out))
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn("refusing", r.stderr)
            self.assertFalse(out.exists(), "no partial export may be written")

    def test_exports_when_every_id_is_present(self):
        ids = registry_ids()
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "co").mkdir()
            checkout = fake_checkout(Path(tmp) / "co", ids)
            out = Path(tmp) / "app-domains.json"
            r = run("--export-domains", str(checkout), str(out))
            self.assertEqual(r.returncode, 0, r.stderr)
            data = json.loads(out.read_text())
            reg = {k: v for k, v in json.loads(REGISTRY.read_text()).items() if not k.startswith("_")}
            self.assertEqual(set(data), set(reg))
            # a spec with ids gets their domains; a spec with no ids (a recommendation-only spec) exports none
            self.assertEqual({k for k in data if data[k]}, {k for k, v in reg.items() if v["ids"]})


class DomainsColumn(unittest.TestCase):
    def test_zero_domains_is_distinct_from_not_in_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            apps = Path(tmp) / "apps.json"
            apps.write_text(json.dumps({"none.md": [], "ranked.md": ["zoom.us"], "absent.md": ["not-listed.example"]}))
            mm = Path(tmp) / "mm.csv"
            mm.write_text("GlobalRank,TldRank,Domain,TLD\n1,1,google.com,com\n5,4,zoom.us,us\n")
            out = Path(tmp) / "out.tsv"
            r = run(str(apps), str(out), "--majestic", str(mm))
            self.assertEqual(r.returncode, 0, r.stderr)
            with out.open(newline="") as fh:
                rows = {row["spec"]: row for row in csv.DictReader(fh, delimiter="\t")}
            self.assertEqual((rows["none.md"]["majestic_rank"], rows["none.md"]["domains"]), ("", "0"))
            self.assertEqual((rows["absent.md"]["majestic_rank"], rows["absent.md"]["domains"]), ("", "1"))
            self.assertEqual((rows["ranked.md"]["majestic_rank"], rows["ranked.md"]["majestic_rank_host"],
                              rows["ranked.md"]["domains"]), ("5", "zoom.us", "1"))


if __name__ == "__main__":
    unittest.main()
