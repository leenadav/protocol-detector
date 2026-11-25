"""Build the software batch (PRO-406 batch 7): software_project rows kept by the network-service filter.

    python3 tools/make_software_batch.py VERDICTS CHECKS OUT_BATCH OUT_FILTER

VERDICTS maps app_id to {verdict, reason} (SERVICE / NOT_SERVICE / UNSURE, from a Message Batch run of
claude-haiku-5-5 over name and domain); only SERVICE rows are kept. CHECKS is the DNS check file
(`unresolved` app_ids). Writes the batch (pack.json record format, as make_pack_batch.py) and the filter
record: one line per software_project row with its outcome and reason. Standard library only.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import make_pack_batch as mp  # noqa: E402


def main():
    verdicts = json.loads(Path(sys.argv[1]).read_text())
    unresolved = set(json.loads(Path(sys.argv[2]).read_text())["unresolved"])
    rows = sorted((r for r in mp.load("wikidata-1-3000.json") if r["entry_kind"] == "software_project"),
                  key=lambda r: r["candidate_rank"])
    record, keep = [], []
    for r in rows:
        v = verdicts.get(r["app_id"])
        if r["app_id"] in unresolved:
            outcome, reason = "dropped:domain_does_not_resolve", "no DNS answer on 2026-11-25"
        elif not v or v["verdict"] == "UNSURE":
            outcome, reason = "dropped:classification_unsure", (v or {}).get("reason", "no verdict")
        elif v["verdict"] == "NOT_SERVICE":
            outcome, reason = "dropped:not_a_network_service", v["reason"]
        else:
            outcome, reason = "kept", v["reason"]
            keep.append(r)
        record.append({"name": r["app_id"], "domain": r["domains"][0], "outcome": outcome, "reason": reason})
    Path(sys.argv[3]).parent.mkdir(parents=True, exist_ok=True)
    apps, hosts, evidence = mp.build(keep)
    for a, h in zip(apps, hosts):
        a["description"] = h["description"] = a["description"].replace(" (game publisher site)", "")
    doc = {"kind": "software_project", "count": len(keep), "applications": apps, "host_entries": hosts,
           "evidence": evidence}
    Path(sys.argv[3]).write_text(json.dumps(doc, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    Path(sys.argv[4]).write_text("".join(json.dumps(x, ensure_ascii=False) + "\n" for x in record), encoding="utf-8")
    print(len(keep), len(record))


if __name__ == "__main__":
    main()
