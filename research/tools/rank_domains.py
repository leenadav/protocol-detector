"""Popularity input for prioritisation (research method v2, item 6). Runs on the Hermes server; outputs ranks only.

Joins each spec's catalog domains (research/apps.json ids -> catalog domains, given as a JSON map) with public
popularity lists whose licence has been verified on the provider's own page (see research/datasets.md, "Ranking
sources"). For each app it reports the best (lowest) rank of any of its domains in each list.

Inputs:
  APP_DOMAINS.json   {"<spec>.md": ["domain", ...], ...}  (written by --export-domains from a checkout)
  --majestic FILE    Majestic Million CSV (header includes GlobalRank and Domain)
  --crux FILE        CrUX top list as CSV with columns origin,rank (rank is CrUX's magnitude bucket: 1000, 5000, ...)
usage:
  rank_domains.py --export-domains CHECKOUT APP_DOMAINS.json
  rank_domains.py APP_DOMAINS.json OUT.tsv [--majestic FILE] [--crux FILE]
Nothing but app, domain and rank is written. Attribution for the output: "Majestic Million (CC BY 3.0), majestic.com"
and "Chrome UX Report, Google (licence as recorded in research/datasets.md)".
"""
import csv
import json
import sys
from pathlib import Path
from urllib.parse import urlparse


def registrable_suffix_match(host, domains):
    host = host.lower().rstrip(".")
    return [d for d in domains if host == d or host.endswith("." + d)]


def load_majestic(path):
    ranks = {}
    with open(path, newline="") as fh:
        for row in csv.DictReader(fh):
            ranks[row["Domain"].lower()] = int(row["GlobalRank"])
    return ranks


def load_crux(path):
    ranks = {}
    with open(path, newline="") as fh:
        for row in csv.DictReader(fh):
            host = urlparse(row["origin"]).hostname or row["origin"]
            r = int(row["rank"])
            ranks[host.lower()] = min(r, ranks.get(host.lower(), r))
    return ranks


def best(ranks, domains):
    hits = [(r, h) for h, r in ranks.items() if registrable_suffix_match(h, domains)]
    return min(hits) if hits else (None, None)


def export_domains(checkout, out):
    sys.path.insert(0, str(checkout))
    from protocol_engine import host_apps
    cat = {e[0]: e[7] for e in host_apps._HOST_APPS}
    reg = json.loads((Path(__file__).resolve().parents[1] / "apps.json").read_text())
    data = {k: sorted({d for i in v["ids"] if i in cat for d in cat[i]}) for k, v in reg.items() if not k.startswith("_")}
    Path(out).write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
    print(len(data), "specs")


def main(argv):
    if argv[1] == "--export-domains":
        return export_domains(Path(argv[2]), argv[3])
    apps = json.loads(Path(argv[1]).read_text())
    lists = {}
    if "--majestic" in argv:
        lists["majestic_rank"] = load_majestic(argv[argv.index("--majestic") + 1])
    if "--crux" in argv:
        lists["crux_bucket"] = load_crux(argv[argv.index("--crux") + 1])
    with open(argv[2], "w") as fh:
        fh.write("spec\t" + "\t".join("%s\t%s_host" % (k, k) for k in lists) + "\n")
        for spec, domains in sorted(apps.items()):
            cells = []
            for ranks in lists.values():
                r, h = best(ranks, domains)
                cells += ["" if r is None else str(r), h or ""]
            fh.write(spec + "\t" + "\t".join(cells) + "\n")
    print(len(apps), "specs ranked against", ", ".join(lists) or "no list")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
