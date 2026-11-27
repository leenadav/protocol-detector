import json,glob,collections


def _rd(path, **kw):
    with open(path, **kw) as fh:
        return fh.read()


def _wj(obj, path, **kw):
    with open(path, "w") as fh:
        json.dump(obj, fh, **kw)


def _wt(path, text):
    with open(path, "w") as fh:
        fh.write(text)


def _wb(path, data):
    with open(path, "wb") as fh:
        fh.write(data)

rows=[]
for f in sorted(glob.glob('enterprise-300/wave1/*.json')): rows+=json.loads(_rd(f))
order=['remote-access','vpn','proxy-anonymizer','file-sharing','genai','webmail','messaging','social','code-paste','crypto','p2p']
rows.sort(key=lambda r:(order.index(r['class']),r['name']))
sep=collections.Counter(s['separable'] for r in rows for s in r['subfunctions'])
o=["# Enterprise priority list: wave 1 (PRO-491 part B)\n",
"Research only; nothing changes in the pack (release 2026.11.9, 544 apps). Wave 1 = %d services **not in the pack** (PRO-495 covers the 30 already in it). Waves 2+ (to ~300) follow; the other classes (SaaS collaboration, social media at scale) are not in wave 1.\n"%len(rows),
"Method: 7 research passes over public vendor pages only (WebSearch/WebFetch, no sign-in, no traffic). A domain is listed under `domains` only if an official vendor page names it (URL + short quote in `enterprise-300/wave1/*.json`); everything else is `unsourced`. Pack overlap = the domain already appears in the pack host catalog (805 domains), checked by grep. Order: class by enterprise block priority (remote access, VPN, anonymizers, file sharing, GenAI, webmail, messaging, social, code/paste, crypto, P2P), then name; a numeric rank comes with wave 2.\n",
"Separability legend (Culvert = proxy seeing SNI and, with TLS inspection, HTTP): **sni** distinct hostname in the handshake; **http** needs host/path/method after inspection; **pattern** only traffic-pattern detection; **no** not separable.\n",
"## Headline\n",
"| | n |\n|---|---|\n| services | %d |\n| confidence high / medium / low | %s |\n| sub-functions: sni / http / pattern / no | %d / %d / %d / %d |\n"%(len(rows),' / '.join(str(sum(r['confidence']==c for r in rows)) for c in('high','medium','low')),sep['sni'],sep['http'],sep['pattern'],sep['no']),
"Many low-confidence rows come from vendors that publish no network-requirements page or block fetches (403): their domains sit in `domains_unsourced` and must not enter the pack without a capture.\n",
"## Services\n","| # | service | class | status | pack overlap | sourced domains | conf |\n|---|---|---|---|---|---|---|"]
for i,r in enumerate(rows,1):
    d=', '.join(sorted({x['domain'] for x in r['domains']})[:6]) or '(none sourced)'
    o.append(f"| {i} | {r['name']} (`{r['id']}`) | {r['class']} | {r['status']} | {r['pack_overlap']} | {d} | {r['confidence']} |")
o.append("\n## Sub-functions and separability\n")
for r in rows:
    o.append(f"### {r['name']}\n")
    for s in r['subfunctions']:
        o.append(f"- **{s['name']}** [{s['separable']}] `{s['path_or_host']}`: {s['note']} ([doc]({s['evidence_url']}))")
    if r.get('notes'): o.append(f"\n_Note: {r['notes']}_")
    o.append("")
_wt('enterprise-300.md', '\n'.join(o))
