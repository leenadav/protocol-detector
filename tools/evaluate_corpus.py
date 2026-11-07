"""D09: evaluate the engine against an independently labelled capture corpus.

The corpus is a directory with `manifest.json` and the capture files it names. Labels come from
outside this engine (the generating client, the test-bed configuration, a human analyst); the
manifest must say who labelled the flows and on what basis, and the report repeats it. Nothing
about the corpus is read beyond what the Analyzer reads: the report holds endpoints, labels,
counts and digests, never payload. Scoring is per labelled flow:

* correct: the session record names the labelled family (and the labelled application, when given);
* wrong: the record names another family (a false identification, the serious case);
* unidentified: the record exists but ends without an identification (incomplete, unknown, ...);
* missing: no session record was produced for the labelled flow;
* unlabelled: flows the engine reported that the manifest does not label (not scored).

Manifest:
{
  "corpus": "name", "version": "2026.01", "independent": true,
  "source": "who produced the captures and under what authorization / licence",
  "labelled_by": "who or what assigned the labels, independently of this engine",
  "label_basis": "generating client configuration | test-bed | analyst review | ...",
  "captures": [
    {"file": "http.pcap", "sha256": "<hex>", "options": {"observation": "handshake"},
     "flows": [{"transport": "tcp", "client": ["192.0.2.10", 52000], "server": ["198.51.100.20", 80],
                "family": "http", "application": "web-browsing"}]}
  ]
}
"""
import argparse
import hashlib
import json
import sys
from collections import Counter, OrderedDict, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from protocol_adapters.analyze_pcap import Analyzer  # noqa: E402
from protocol_adapters.link_packets import decode_frame  # noqa: E402
from protocol_adapters.packets import PacketError, read_pcap_records  # noqa: E402
from protocol_engine.descriptors import build  # noqa: E402

REQUIRED = ("corpus", "source", "labelled_by", "label_basis", "captures")
ANALYZER_OPTIONS = ("observation", "checksums", "continuation", "tcp_hint", "udp_hint", "fingerprints", "certificates")


class CorpusError(ValueError):
    pass


def family_of(label):
    return (label or "").split("/", 1)[0]


def sha256_of(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def load_manifest(folder):
    folder = Path(folder)
    try:
        manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    except OSError as error:
        raise CorpusError("manifest.json unreadable: {}".format(error)) from None
    except ValueError as error:
        raise CorpusError("manifest.json is not JSON: {}".format(error)) from None
    missing = [key for key in REQUIRED if not manifest.get(key)]
    if missing:
        raise CorpusError("manifest lacks " + ", ".join(missing) + " (provenance and labelling must be stated)")
    families = build()
    for capture in manifest["captures"]:
        for key in ("file", "sha256", "flows"):
            if key not in capture:
                raise CorpusError("capture entry lacks " + key)
        path = folder / capture["file"]
        if not path.is_file() or path.resolve().parent != folder.resolve():
            raise CorpusError("capture file outside the corpus directory or missing: " + capture["file"])
        digest = sha256_of(path)
        if digest != capture["sha256"]:
            raise CorpusError("sha256 mismatch for {}: manifest {} file {}".format(capture["file"], capture["sha256"][:12], digest[:12]))
        for flow in capture["flows"]:
            if flow.get("transport") not in ("tcp", "udp") or len(flow.get("client", ())) != 2 or len(flow.get("server", ())) != 2:
                raise CorpusError("flow label needs transport, client [ip, port] and server [ip, port]")
            if family_of(flow.get("family")) not in families:
                raise CorpusError("flow labelled with a family the engine does not declare: {!r}".format(flow.get("family")))
        unknown = set(capture.get("options", {})) - set(ANALYZER_OPTIONS)
        if unknown:
            raise CorpusError("unsupported capture options: " + ", ".join(sorted(unknown)))
    return manifest


def _key(transport, client, server):
    return (transport, tuple(client), tuple(server))


def run_capture(path, options):
    """Session records of one capture through the recorded-adapter path (no payload kept)."""
    records = []
    analyzer = Analyzer(on_session=records.append, **options)
    checksums = options.get("checksums", "ignore")
    quality = Counter()
    for record in read_pcap_records(str(path)):
        if record.truncated:
            quality["truncated"] += 1
            continue
        try:
            packet = decode_frame(record.data, record.linktype, checksums)
        except PacketError as error:
            quality[error.kind] += 1
            if error.endpoints is not None:
                analyzer.note_input(error.kind, error.endpoints)
            continue
        analyzer.process(record.timestamp, packet)
    analyzer.finish("Capture input EOF before initial message completed")
    return records, dict(quality), analyzer.content


def observed_family(record):
    return family_of(record.get("encryption") or record.get("client_protocol") or record.get("server_protocol"))


def evaluate(folder, manifest=None):
    folder = Path(folder)
    manifest = manifest or load_manifest(folder)
    per_family = defaultdict(Counter)
    confusion = Counter()
    captures = []
    totals = Counter()
    pins = set()
    for capture in manifest["captures"]:
        options = dict(capture.get("options", {}))
        records, quality, pin = run_capture(folder / capture["file"], options)
        pins.add((pin["version"], pin["digest"]))
        by_key = {}
        for record in records:
            by_key.setdefault(_key(record["transport"], record["client"], record["server"]), []).append(record)
        labelled = set()
        rows = Counter()
        for flow in capture["flows"]:
            key = _key(flow["transport"], flow["client"], flow["server"])
            labelled.add(key)
            expected = family_of(flow["family"])
            matches = by_key.get(key)
            if not matches:
                outcome = "missing"
            else:
                record = matches[-1]
                found = observed_family(record)
                if not found:
                    outcome = "unidentified"
                elif found == expected:
                    outcome = "correct"
                    if flow.get("application") and record.get("app") != flow["application"]:
                        outcome = "wrong-application"
                        confusion[(expected + ":" + flow["application"], record.get("app"))] += 1
                else:
                    outcome = "wrong"
                    confusion[(expected, found)] += 1
                    per_family[found]["false-positive"] += 1
            per_family[expected][outcome] += 1
            rows[outcome] += 1
            totals[outcome] += 1
        unlabelled = sum(1 for key in by_key if key not in labelled)
        rows["unlabelled"] = unlabelled
        totals["unlabelled"] += unlabelled
        captures.append(OrderedDict([("file", capture["file"]), ("sha256", capture["sha256"]), ("options", options),
                                     ("records", len(records)), ("input_quality", quality), ("outcomes", dict(rows))]))
    families = OrderedDict()
    for family in sorted(per_family):
        counts = per_family[family]
        labelled = counts["correct"] + counts["wrong"] + counts["wrong-application"] + counts["unidentified"] + counts["missing"]
        tp = counts["correct"] + counts["wrong-application"]
        fp = counts["false-positive"]
        recall = tp / labelled if labelled else None
        precision = tp / (tp + fp) if tp + fp else None
        families[family] = OrderedDict([("labelled", labelled), ("correct", counts["correct"]), ("wrong_application", counts["wrong-application"]),
                                        ("wrong", counts["wrong"]), ("unidentified", counts["unidentified"]), ("missing", counts["missing"]),
                                        ("false_positive", fp), ("recall", recall), ("precision", precision)])
    labelled_total = sum(row["labelled"] for row in families.values())
    report = OrderedDict([
        ("corpus", {key: manifest.get(key) for key in ("corpus", "version", "independent", "source", "labelled_by", "label_basis")}),
        ("engine", {"content": sorted(["{}@{}".format(version, digest) for version, digest in pins]),
                    "label_set_digest": hashlib.sha256(json.dumps(manifest["captures"], sort_keys=True).encode("utf-8")).hexdigest()[:16]}),
        ("totals", OrderedDict([("labelled_flows", labelled_total), ("correct", totals["correct"]), ("wrong_application", totals["wrong-application"]),
                                ("wrong", totals["wrong"]), ("unidentified", totals["unidentified"]), ("missing", totals["missing"]),
                                ("unlabelled_flows", totals["unlabelled"]),
                                ("family_accuracy", (totals["correct"] + totals["wrong-application"]) / labelled_total if labelled_total else None)])),
        ("families", families),
        ("confusion", [{"expected": expected, "found": found, "count": count} for (expected, found), count in sorted(confusion.items())]),
        ("captures", captures),
    ])
    return report


def _pct(value):
    return "—" if value is None else "%.1f%%" % (100 * value)


def render(report):
    corpus = report["corpus"]
    independent = corpus.get("independent")
    lines = ["# Corpus evaluation: %s %s" % (corpus["corpus"], corpus.get("version") or ""), "",
             "Source: %s  " % corpus["source"], "Labelled by: %s (%s)  " % (corpus["labelled_by"], corpus["label_basis"]),
             "Independent of the engine: %s  " % ("yes" if independent else "NOT STATED — this is a self-check, not an independent evaluation"),
             "Engine content: %s; label set %s" % (", ".join(report["engine"]["content"]), report["engine"]["label_set_digest"]), ""]
    totals = report["totals"]
    lines += ["| labelled flows | correct | wrong application | wrong family | unidentified | missing | unlabelled | family accuracy |",
              "|---|---|---|---|---|---|---|---|",
              "| %d | %d | %d | %d | %d | %d | %d | %s |" % (totals["labelled_flows"], totals["correct"], totals["wrong_application"], totals["wrong"],
                                                            totals["unidentified"], totals["missing"], totals["unlabelled_flows"], _pct(totals["family_accuracy"])), "",
              "| family | labelled | correct | wrong app | wrong | unidentified | missing | false positive | recall | precision |",
              "|---|---|---|---|---|---|---|---|---|---|"]
    for family, row in report["families"].items():
        lines.append("| %s | %d | %d | %d | %d | %d | %d | %d | %s | %s |" % (
            family, row["labelled"], row["correct"], row["wrong_application"], row["wrong"], row["unidentified"], row["missing"],
            row["false_positive"], _pct(row["recall"]), _pct(row["precision"])))
    if report["confusion"]:
        lines += ["", "Confusions (expected → found): " + "; ".join("%s → %s ×%d" % (item["expected"], item["found"], item["count"]) for item in report["confusion"])]
    lines += ["", "| capture | records | outcomes | input quality |", "|---|---|---|---|"]
    for capture in report["captures"]:
        lines.append("| %s (%s) | %d | %s | %s |" % (capture["file"], capture["sha256"][:12], capture["records"],
                                                    ", ".join("%s %d" % item for item in sorted(capture["outcomes"].items())) or "—",
                                                    ", ".join("%s %d" % item for item in sorted(capture["input_quality"].items())) or "clean"))
    lines += ["", "Scores are per labelled flow of this corpus and say nothing about traffic it does not contain. No payload was stored."]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("corpus", help="directory holding manifest.json and the capture files")
    parser.add_argument("--write", help="write the Markdown report here")
    parser.add_argument("--json", help="write the JSON report here")
    parser.add_argument("--min-accuracy", type=float, default=None, help="exit 1 when family accuracy is below this fraction")
    parser.add_argument("--max-wrong", type=int, default=None, help="exit 1 when wrong-family identifications exceed this count")
    args = parser.parse_args(argv)
    try:
        report = evaluate(args.corpus)
    except CorpusError as error:
        print("corpus error: {}".format(error))
        return 2
    text = render(report)
    if args.write:
        Path(args.write).write_text(text, encoding="utf-8")
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(text if not (args.write or args.json) else text.splitlines()[6])
    totals = report["totals"]
    failed = (args.max_wrong is not None and totals["wrong"] > args.max_wrong) or \
             (args.min_accuracy is not None and (totals["family_accuracy"] or 0.0) < args.min_accuracy)
    if failed:
        print("corpus evaluation FAILED thresholds: wrong {} accuracy {}".format(totals["wrong"], _pct(totals["family_accuracy"])))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
