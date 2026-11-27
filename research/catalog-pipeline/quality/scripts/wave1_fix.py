"""PRO-491 review fixes: move non-matchable hosts out of `domains`, add priority rank."""
import json,glob,re


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

EXCL={ # domain -> reason
 'software.cisco.com':'download host','ocsp.digicert.com':'CA/OCSP shared','download.pulsesecure.net':'download host',
 'binaries.twingate.com':'download host','storage.googleapis.com':'shared cloud storage','browsec.cx':'download mirror',
 'bs-dl.s3.eu-central-1.amazonaws.com':'shared cloud storage','infomaniakusercontent.com':'shared user-content host',
 'dst.yandex.net':'download host','download.agent.dev.azure.com':'download host','pubnub.com':'shared third-party service',
 'drp-<airport>.amazonworkspaces.com':'placeholder / per-airport shared host','lovable.app':'shared user-content host',
 'codeberg.page':'shared user-content host','brdtest.com':'test host','geo.brdtest.com':'test host',
 'feedback.resilio.com':'feedback endpoint','dl.hoptodesk.com':'download/update host','fctupdate.fortinet.net':'update host',
 '*.cdn.office.net':'shared CDN','*.windows.static.microsoft':'shared CDN','vsassets.io':'shared CDN','wwcdn.weixin.qq.com':'shared CDN',
 'sf-cdn.net':'CDN','design.codeberg.org':'design/docs host','cdn4.hola.org':'CDN',
}
DOCS=re.compile(r'^(docs|help|support)\.')
RANK=('citrix-workspace-daas windows-365-avd amazon-workspaces omnissa-horizon cisco-secure-client paloalto-globalprotect fortinet-forticlient-vpn ivanti-connect-secure twingate '
 'bright-data urban-vpn hola-vpn browsec astrill-vpn purevpn x-vpn torguard vyprvpn opera-vpn croxyproxy '
 'citrix-sharefile tresorit terabox baidu-netdisk yandex-disk smash swisstransfer filemail pixeldrain '
 'kimi-moonshot manus lovable bolt-new gamma otter-ai deepl mail-ru hey-com temp-mail '
 'wecom dingtalk feishu-lark mattermost wire mastodon truth-social '
 'bitbucket azure-devops codeberg rentry hoptodesk todesk sunlogin-awesun radmin '
 'okx bybit kucoin bitget uniswap trust-wallet ledger-live qbittorrent utorrent resilio-sync soulseek').split()
rank={s:i+1 for i,s in enumerate(RANK)}
allr={}
n=0
for f in sorted(glob.glob('enterprise-300/wave1/*.json')):
    d=json.loads(_rd(f))
    for s in d:
        keep=[];out=[]
        for x in s['domains']:
            dom=x['domain']
            r=EXCL.get(dom) or ('documentation/support page' if DOCS.match(dom) else None)
            (out if r else keep).append({**x,'excluded_reason':r} if r else x)
        s['domains']=keep; s['domains_not_a_match']=out; n+=len(out)
        s['priority_rank']=rank[s['id']]
        allr[s['id']]=s
    _wj(d, f, indent=1,ensure_ascii=False)
assert set(rank)==set(allr),set(rank)^set(allr)
print('moved',n,'ranked',len(rank))
# md
md=_rd('enterprise-300.md').split('\n')
out=[];rows={}
for l in md:
    m=re.match(r'^\| \d+ \| .*\(`([^`]+)`\) \|',l)
    if m and m.group(1) in allr:
        c=l.split(' | ');s=allr[m.group(1)]
        c[0]='| %d'%s['priority_rank']
        c[-2]=', '.join(x['domain'] for x in s['domains']) or '(none sourced)'
        rows[s['priority_rank']]=' | '.join(c)
        out.append(None)
    else: out.append(l)
it=iter(sorted(rows))
res=[(rows[next(it)] if l is None else l) for l in out]
t='\n'.join(res)
t=t.replace('a numeric rank comes with wave 2.','`#` is the numeric enterprise-priority rank (1 = block/monitor first). Download hosts, OCSP/CA, docs/help pages, CDNs and shared hosts are excluded from `domains` and listed under `domains_not_a_match` in the JSON.')
_wt('enterprise-300.md', t)
