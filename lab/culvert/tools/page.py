"""Render results.json as one self-contained HTML page (auto-refreshing while the run is in progress)."""
import html, json, sys
src, dst = sys.argv[1], sys.argv[2]
r = json.load(open(src))
builds = list(r["builds"].items())
running = r.get("state") != "finished"
def cell(x):
    if x is None:
        return '<td class="na">not run</td>'
    t, d = x["traffic_ok"], x["detector_ok"]
    cls = "fail" if (not t or d is False) else ("gap" if d == "gap" else "pass")
    mark = {"pass": "PASS", "fail": "FAIL", "gap": "KNOWN GAP"}[cls]
    extra = ""
    det = x.get("detail", {})
    bits = []
    for k in ("bytes", "received", "seconds", "key_exchange", "tls", "status", "error", "flows", "failed"):
        if k in det:
            v = det[k]
            if k == "status":
                v = ", ".join(f"{a} → {b}" for a, b in v.items())
            bits.append(f"{k.replace('_',' ')}: {html.escape(str(v))}")
    if bits:
        extra = '<div class="meta">' + " · ".join(bits) + "</div>"
    return f'<td class="{cls}"><b>{mark}</b><div class="obs">{html.escape(x["detector"])}</div>{extra}</td>'
rows, group, total, failed, gaps = [], None, 0, 0, 0
for s in r["scenarios"]:
    if s["group"] != group:
        group = s["group"]
        rows.append(f'<tr class="group"><td colspan="{len(builds)+2}">{html.escape(group)}</td></tr>')
    cells = []
    for b, _ in builds:
        x = s["results"].get(b)
        cells.append(cell(x))
        if x is not None:
            total += 1
            if not x["traffic_ok"] or x["detector_ok"] is False: failed += 1
            elif x["detector_ok"] == "gap": gaps += 1
    same = s.get("same_bytes_all_builds")
    same = "" if same is None else ('<span class="ok">identical</span>' if same else '<span class="bad">DIFFERENT</span>')
    rows.append(f'<tr><th>{html.escape(s["name"])}</th>{"".join(cells)}<td class="same">{same}</td></tr>')
head = "".join(f'<th><span class="b">{b}</span><div>{html.escape(v["label"])}</div><div class="meta">port {v["port"]} · engine {v["engine"]}</div></th>' for b, v in builds)
state = "RUNNING — this page refreshes every 2 seconds" if running else f'Finished {r.get("finished","")}'
summary = f"{total - failed - gaps} passed · {gaps} known gap · {failed} failed · {total} checks"
page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
{'<meta http-equiv="refresh" content="2">' if running else ''}
<title>Culvert Detector Lab</title><style>
:root{{--bg:#f6f7f9;--fg:#15181d;--mut:#5b6472;--card:#fff;--line:#dfe3ea;--pass:#e6f4ea;--passf:#136c2e;--fail:#fde8e8;--failf:#a11818;--gap:#fff4d6;--gapf:#7a5200;--grp:#eceff4}}
@media (prefers-color-scheme:dark){{:root:not([data-theme="light"]){{--bg:#12151a;--fg:#e8eaee;--mut:#9aa3b2;--card:#1a1f27;--line:#2c3440;--pass:#12301c;--passf:#7fd99a;--fail:#3a1616;--failf:#ff9a9a;--gap:#3a2e0d;--gapf:#ffd36b;--grp:#202630}}}}
:root[data-theme="dark"]{{--bg:#12151a;--fg:#e8eaee;--mut:#9aa3b2;--card:#1a1f27;--line:#2c3440;--pass:#12301c;--passf:#7fd99a;--fail:#3a1616;--failf:#ff9a9a;--gap:#3a2e0d;--gapf:#ffd36b;--grp:#202630}}
body{{background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,sans-serif;margin:0;padding:16px}}
h1{{font-size:20px;margin:0 0 4px}} .sub{{color:var(--mut);margin:0 0 12px}}
.bar{{display:flex;gap:12px;flex-wrap:wrap;margin:0 0 14px}} .pill{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 12px}}
.wrap{{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}}
table{{border-collapse:collapse;width:100%;min-width:1100px}} th,td{{border-bottom:1px solid var(--line);padding:8px 10px;text-align:left;vertical-align:top}}
thead th{{font-weight:600;font-size:12px}} .b{{font-size:18px}} tbody th{{font-weight:600;width:190px}}
.group td{{background:var(--grp);font-weight:700;font-size:12px;letter-spacing:.04em;text-transform:uppercase}}
td.pass{{background:var(--pass)}} td.pass b{{color:var(--passf)}} td.fail{{background:var(--fail)}} td.fail b{{color:var(--failf)}}
td.gap{{background:var(--gap)}} td.gap b{{color:var(--gapf)}} td.na{{color:var(--mut)}}
.obs{{font-size:12px;margin-top:2px}} .meta{{font-size:11px;color:var(--mut);margin-top:2px;word-break:break-word}}
.ok{{color:var(--passf);font-weight:600}} .bad{{color:var(--failf);font-weight:700}} .same{{font-size:12px;white-space:nowrap}}
ul{{margin:6px 0 0 18px;padding:0}} .note{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin-top:14px}}
</style></head><body>
<h1>Protocol detector in Culvert — live lab</h1>
<p class="sub">Same synthetic scenarios against five proxies running side by side. Started {html.escape(r["started"])}. <b>{state}</b></p>
<div class="bar"><div class="pill"><b>{summary}</b></div><div class="pill">Observe mode only: the detector never blocks or delays traffic</div><div class="pill">Loopback only · origins on 203.0.113.10 · all Culvert protections on</div></div>
<div class="wrap"><table><thead><tr><th>Scenario</th>{head}<th>Bytes delivered across builds</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div>
<div class="note"><b>How to read this</b><ul>
<li>Each cell first checks the traffic itself (the right bytes arrived, the right status code), then the detector's record against an expectation written from what the scenario sends.</li>
<li>A and B must have no detector records at all. C uses a scripted fake engine, D the real detector, E a fake engine that panics on every call: its tunnels must still deliver every byte.</li>
<li>"Known gap" is a real detection gap this lab reproduces: a TLS server reply using the post-quantum key exchange is not recognised yet (work item #4).</li>
<li>This is one container, not two VMs, and it measures correctness, not performance. Timings are shown for context only.</li></ul></div>
</body></html>"""
open(dst, "w").write(page)
