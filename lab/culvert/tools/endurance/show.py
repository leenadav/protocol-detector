"""Print the endurance samples as a table (PRO-540): python3 show.py <out dir>."""
import json
import sys
from pathlib import Path


def main(d):
    d = Path(d)
    if (d / "samples.jsonl").exists():
        rows = [json.loads(ln) for ln in (d / "samples.jsonl").read_text().splitlines() if ln.strip()]
    else:  # as committed: the same rows as one JSON array (the repository ignores *.jsonl)
        rows = json.loads((d / "samples.json").read_text())
    t0 = rows[0]["t_unix"] if rows else 0
    print("%7s %-15s %-6s %6s %10s %10s %5s %8s %6s %8s %7s  %s" % (
        "t_s", "phase", "proc", "gor", "heap_live", "heap_inuse", "fds", "rss_kib", "pd_act", "pd_adm", "pd_ref", "releases"))
    for s in rows:
        if "error" in s:
            print("%7.0f %-15s %-6s error %s" % (s["t_unix"] - t0, s.get("phase"), s.get("proc"), s["error"][:80]))
            continue
        st = s.get("pd_engine_stats") or {}
        print("%7.0f %-15s %-6s %6d %10d %10d %5d %8d %6s %8s %7s  %s" % (
            s["t_unix"] - t0, s["phase"], s["proc"], s["goroutines"], s["heap_live"], s["heap_inuse"], s["open_fds"],
            s["rss_kib"], st.get("active"), st.get("admitted"), st.get("refused"), s.get("pd_releases", "")))


if __name__ == "__main__":
    main(sys.argv[1])
