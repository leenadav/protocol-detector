#!/usr/bin/env python3
"""Submit the PRO-491 quality classification as one Message Batch. Usage: submit_batch.py <repo> <outdir>"""
import json,glob,os,sys,urllib.request
repo,out=sys.argv[1:3]
key=os.environ['ANTHROPIC_API_KEY']
pack=json.load(open(f'{repo}/go/internal/content/pack.json'))
vocab=sorted({f"{a['category']}/{a['subcategory']}" for a in pack['applications']})
SYS=f"""You classify catalog proposals for a network application detector (secure web gateway / proxy that sees DNS, TLS SNI and HTTP).
A proposal = app name + official domain. Decide:
- keep: a real network service or client that calls its OWN servers on that domain (SaaS, web service, online database, live game with own servers, desktop client that calls vendor update/cloud servers).
- fix: keep, but category/subcategory is wrong; give the right one from the pack vocabulary.
- drop: non-application (bot, internal tool, project, library, file format, person, work of fiction); desktop/offline/self-hosted software with no vendor servers in the traffic path (a match would only be a website visit); game publisher/studio marketing pages (game traffic goes to platform or game servers); news/content-only sites (use reason news_content_site); dead or defunct service/domain.
Drop reason codes: non_application, offline_or_selfhosted_software, marketing_page, gaming_publisher_page, news_content_site, dead_or_defunct, other.
Pack vocabulary (category/subcategory): {', '.join(vocab)}.
Calibration (verdicts by a human reviewer): sci-hub FIX general-internet/internet-utility; jdownloader DROP offline; photobucket FIX media/photo-video; digikam DROP offline; mybb DROP selfhosted; yahoo.co.jp KEEP; mycobank KEEP; swarmapp FIX collaboration/social-networking; pubpeer FIX collaboration/social-networking; pressreader KEEP; doctrine-project DROP library; samplitude DROP desktop; bandainamcoent/bioware/lostgame/endless-space DROP gaming_publisher_page; teamfortress/dota2 DROP (traffic goes to Steam); cryptokitties KEEP; identity-v DROP marketing; h5p DROP selfhosted; lutris FIX media/gaming; comodo FIX business-systems/general-business (desktop AV calling own cloud); briar DROP p2p no servers; getpocket KEEP.
Reply with ONE JSON object only: {{"verdict":"keep|fix|drop","reason_code":"...","reason":"<=20 words","category":"<only for fix: category/subcategory>","confidence":"high|medium|low"}}. If you do not know the entity, verdict by what the name/domain suggest and confidence low."""
ONLY=set(json.load(open(os.environ["ONLY"]))) if os.environ.get("ONLY") else None
MAXT=int(os.environ.get("MAXT","200"))
reqs=[];meta=[]
for f in sorted(glob.glob(f'{repo}/research/catalog-pipeline/batches/batch-*.json')):
    d=json.load(open(f))
    if 'applications' not in d: continue
    b=os.path.basename(f).split('-')[1]
    ev={e['name']:e for e in d['evidence']}
    for a in d['applications']:
        e=ev.get(a['name'],{})
        cid=f"b{b}-{a['name']}"[:64].replace('.','_')
        txt=f"name: {a['name']}\ndescription: {a['description']}\ndomain: {','.join(e.get('domains',[]))}\ncurrent category: {a['category']}/{a['subcategory']}\nsource: {e.get('source_note','')}"
        if ONLY is not None and cid not in ONLY: continue
        reqs.append({"custom_id":cid,"params":{"model":"claude-sonnet-5-5","max_tokens":MAXT,"system":SYS,"messages":[{"role":"user","content":txt}]}})
        meta.append({"custom_id":cid,"batch":b,"name":a['name'],"domains":e.get('domains',[]),"category":f"{a['category']}/{a['subcategory']}","description":a['description'],"wikidata":e.get('wikidata')})
assert len({m['custom_id'] for m in meta})==len(meta)
if ONLY is None: json.dump(meta,open(f'{out}/entries.json','w'),indent=0)
body=json.dumps({"requests":reqs}).encode()
r=urllib.request.Request('https://api.anthropic.com/v1/messages/batches',body,{'x-api-key':key,'anthropic-version':'2023-06-01','content-type':'application/json'})
resp=json.load(urllib.request.urlopen(r))
open(f'{out}/batch_id'+('_retry' if ONLY else '')+'.txt','w').write(resp['id'])
print(len(reqs),resp['id'],resp['processing_status'])
