"""Merge batch results -> classification.json + summary.md. Run from quality/."""
import json,collections,random,sys


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

meta={m['custom_id']:m for m in json.loads(_rd('out/entries.json'))}
res={}
for f in ['out/results.jsonl','out/results_retry.jsonl']:
    for l in _rd(f).splitlines():
        r=json.loads(l)
        if r['result']['type']!='succeeded': continue
        t=''.join(b.get('text','') for b in r['result']['message']['content'])
        try: res[r['custom_id']]=json.loads(t[t.index('{'):t.rindex('}')+1])
        except ValueError as e: print(f"unparsed {r['custom_id']}: {e}", file=sys.stderr)  # row stays verdict=unparsed
rows=[{**{('current' if a=='category' else a):b for a,b in meta[k].items()},**res.get(k,{'verdict':'unparsed','reason_code':'','reason':'','confidence':'low'})} for k in meta]
_wj(rows, 'classification.json', indent=0,ensure_ascii=False)
V=collections.Counter(r['verdict'] for r in rows)
o=["# Quality filter: 1,696 catalog proposals (PRO-491 part A)\n",
"Method: each entry (name, official domain, current category, source note) classified by claude-sonnet-5-5 through one Message Batch (+ one retry batch for 252 requests cut off by the token limit), with the PRO-498 40-row calibration set in the prompt. **Model judgement from names and domains; no per-entry web check or liveness test** (DNS resolution was already checked when the batches were built). Treat `low` confidence rows as a review queue. Machine-readable result: `classification.json`; scripts in `scripts/`.\n",
"Pack vocabulary = the 25 category/subcategory pairs in pack.json 2026.11.9. Nothing in the pack changes.\n",
"## Headline\n","| verdict | n | % |\n|---|---|---|"]
for k in ['keep','fix','drop','unparsed']:
    if V[k]: o.append(f"| {k} | {V[k]} | {100*V[k]/len(rows):.1f}% |")
o.append(f"| total | {len(rows)} | |\n")
o.append("## Drops by reason\n\n| reason | n |\n|---|---|")
for k,v in collections.Counter(r.get('reason_code') for r in rows if r['verdict']=='drop').most_common(): o.append(f"| {k} | {v} |")
o.append("\n## By batch\n\n| batch | keep | fix | drop | unparsed |\n|---|---|---|---|---|")
for b in sorted({r['batch'] for r in rows}):
    c=collections.Counter(r['verdict'] for r in rows if r['batch']==b); o.append(f"| {b} | {c['keep']} | {c['fix']} | {c['drop']} | {c['unparsed']} |")
o.append("\n## Confidence\n\n"+', '.join(f"{k}: {v}" for k,v in collections.Counter(r['confidence'] for r in rows).items()))
o.append("\n\n## Fix targets (new category)\n\n| target | n |\n|---|---|")
for k,v in collections.Counter(r.get('category') for r in rows if r['verdict']=='fix').most_common(): o.append(f"| {k} | {v} |")
random.seed(491)
for cls in ['keep','fix','drop']:
    pool=[r for r in rows if r['verdict']==cls]; s=random.sample(pool,min(30,len(pool)))
    o.append(f"\n## 30 sample rows: {cls} (random.seed(491))\n\n| name | domain | current | new | reason | conf |\n|---|---|---|---|---|---|")
    for r in s: o.append(f"| {r['name']} | {','.join(r['domains'])} | {r['current']} | {(r.get('category') or '') if cls=='fix' else ''} | {r.get('reason','').replace('|','/')} | {r['confidence']} |")
_wt('summary.md', '\n'.join(o))
print(V)
