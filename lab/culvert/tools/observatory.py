"""Render the lab run as a Protocol Observatory style page: the detector's own front-end design (its
stylesheet is inlined unchanged) showing the tunnels the detector observed INSIDE Culvert.

Usage: observatory.py <results.json> <presentation/web/styles.css> <out.html>
The page is self-contained (no network, no external fonts or scripts). Data: synthetic lab traffic only.
"""
import json, sys

results, css_path, out = sys.argv[1], sys.argv[2], sys.argv[3]
r = json.load(open(results))
css = open(css_path).read()

sessions = []
for sc in r["scenarios"]:
    for build in ("D", "F"):
        res = sc["results"].get(build)
        if not res or not res.get("records"):
            continue
        if build == "F" and "policy" not in sc["group"].lower():
            continue
        extra = res.get("record_count", len(res["records"])) - len(res["records"])
        for i, rec in enumerate(res["records"]):
            sessions.append({"id": f"{len(sessions) + 1:03d}", "scenario": sc["name"], "group": sc["group"], "build": build,
                             "rec": rec, "more": extra if i == len(res["records"]) - 1 else 0,
                             "check": "gap" if res["detector_ok"] == "gap" else ("pass" if res["traffic_ok"] and res["detector_ok"] else "fail")})

data = json.dumps({"sessions": sessions, "started": r.get("started", ""), "finished": r.get("finished", ""),
                   "builds": r["builds"]}).replace("</", "<\\/")

page = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#101e25"><title>Observatory Culvert Lab</title>
<style>__CSS__
/* lab additions, in the Observatory's own vocabulary */
.lab-note{font-size:11px;color:var(--muted);line-height:1.7;margin:0}
.badge.red{background:#fdecea;color:#a3271b;border-color:#f3c9c3}
.scenario{display:block;font-size:10px;color:var(--muted);margin-top:4px}
.dir-cell small{display:block;color:var(--muted);font-size:10px;margin-top:3px}
.lab-strip{display:flex;gap:10px;flex-wrap:wrap;margin:0 0 18px}
.lab-strip span{background:#fff;border:1px solid var(--border);border-radius:30px;padding:7px 12px;font-size:11px;color:#55726b}
.mix-wrap{display:flex;gap:28px;align-items:center;padding:22px 24px;flex-wrap:wrap}
.policy-box{border:1px solid var(--border);border-radius:8px;padding:12px 14px;font-size:12px;line-height:1.8;background:#fbfcfc}
table{min-width:980px}
.timeline-event small{display:block}
</style>
</head>
<body>
  <aside class="sidebar">
    <a class="brand" href="#" aria-label="Protocol Observatory"><span class="brand-icon">◈</span><span>PROTOCOL<span class="brand-sub">OBSERVATORY</span></span></a>
    <div class="workspace"><span class="workspace-icon">C</span><div>Culvert lab<small>Detector inside the proxy</small></div><span class="workspace-dot"></span></div>
    <div class="nav-label">WORKSPACE</div>
    <nav aria-label="Main navigation">
      <button class="nav-item active" data-view="overview"><span class="nav-icon">▦</span> Overview <span class="nav-arrow">↗</span></button>
      <button class="nav-item" data-view="sessions"><span class="nav-icon">⇄</span> Tunnels <span id="nav-count" class="nav-count">—</span></button>
      <button class="nav-item" data-view="about"><span class="nav-icon">◇</span> Lab & scope</button>
    </nav>
    <div class="sidebar-bottom"><div class="local-label"><i></i> SYNTHETIC LAB TRAFFIC</div><p>Loopback only.<br>No real traffic.</p><div class="sidebar-rule"></div><div class="engine-version">Go engine <span>go/detector</span></div><small>Culvert 52eb9d1 · lab branch</small></div>
  </aside>
  <div class="shell">
    <header class="topbar"><div><span class="breadcrumb">Culvert lab</span><span class="slash">/</span><span id="breadcrumb">Overview</span></div><div class="top-right"><span class="demo-pill"><i></i> Recorded lab run</span><span class="avatar">PD</span></div></header>
    <main>
      <section class="page-heading"><div><div class="eyebrow">DETECTOR INSIDE THE PROXY</div><h1>See inside the tunnel.</h1><p>What the protocol detector reported for each CONNECT tunnel that Culvert relayed.</p></div><div class="heading-actions"><button class="button primary" id="replay-button"><span>▶</span> Replay the run</button></div></section>
      <div class="lab-strip"><span id="strip-run"></span><span>Observe mode never holds or blocks bytes</span><span>Restriction rules: enforce holds the client's first bytes until the protocol is decided</span></div>

      <section id="overview-view" class="view">
        <div class="metrics">
          <article class="metric"><div class="metric-label">OBSERVED TUNNELS <span>⇄</span></div><div class="metric-value" id="m-sessions">—</div><div class="metric-note">Records shown from this run</div></article>
          <article class="metric"><div class="metric-label">IDENTIFIED <span>◎</span></div><div class="metric-value" id="m-identified">—</div><div class="metric-note" id="m-percent">Structural profile matches</div></article>
          <article class="metric"><div class="metric-label">PROTOCOLS SEEN <span>▦</span></div><div class="metric-value" id="m-apps">—</div><div class="metric-note">Unique identified protocols</div></article>
          <article class="metric accent-metric"><div class="metric-label">NEEDS A CLOSER LOOK <span>↗</span></div><div class="metric-value" id="m-review">—</div><div class="metric-note">Unresolved, signals or policy blocks</div></article>
        </div>
        <article class="panel"><div class="panel-heading"><div><h2>Protocol mix</h2><p>What the detector actually identified inside the tunnels</p></div><span>◔</span></div><div id="mix" class="mix-wrap"></div></article>
      </section>

      <section id="sessions-panel" class="panel sessions-panel">
        <div class="panel-heading session-heading"><div><h2>Tunnel explorer <span id="table-count" class="count-badge">0</span></h2><p>Select a tunnel to inspect its classification, policy verdict and evidence</p></div><div class="table-tools"><label class="search-box"><span>⌕</span><input id="session-search" placeholder="Search protocol, host or scenario…" aria-label="Search tunnels"></label></div></div>
        <div class="filter-tabs" role="group" aria-label="Tunnel filters"><button class="filter-tab active" data-filter="all">All tunnels</button><button class="filter-tab" data-filter="identified">Identified</button><button class="filter-tab" data-filter="attention">Needs attention</button><button class="filter-tab" data-filter="policy">Policy restriction</button></div>
        <div class="table-scroll"><table><thead><tr><th>PROTOCOL</th><th>DESTINATION</th><th>CLIENT → SERVER</th><th>SERVER → CLIENT</th><th>POLICY</th><th>SIGNALS</th><th>FORWARDED</th><th></th></tr></thead><tbody id="session-rows"></tbody></table></div>
        <div class="table-footer"><span id="table-footer-text"></span><span>CONNECT bypass tunnels · initial-message inspection</span></div>
      </section>

      <section id="about-view" class="view" hidden>
        <div class="about-hero panel"><div class="eyebrow">FROM TUNNEL BYTES TO EVIDENCE</div><h2>How the detector sits inside Culvert.</h2><p>Culvert reads the tunnel as it always does. The detector is shown the first bytes of each direction and reports what it can prove. Culvert keeps every transport and policy decision.</p><div class="pipeline"><span>CONNECT tunnel<small>Culvert relay</small></span><b>→</b><span>First bytes<small>Bounded window</small></span><b>→</b><span>Validation<small>go/detector</small></span><b>→</b><span>Log entry<small>pd block</small></span></div></div>
        <div class="about-grid"><article class="panel scope-card"><h2>What this run shows</h2><ul><li>Protocols identified from payload structure, in both directions</li><li>Server-first protocols (SSH, SMTP) without waiting for the client</li><li>Honest unknown, incomplete, budget and outside-profile outcomes</li><li>A per-rule protocol restriction, in monitor and enforce mode</li><li>No client byte of a blocked protocol reaching the origin</li></ul></article><article class="panel scope-card"><h2>How to read the results</h2><ul><li>This is a recorded lab run with synthetic traffic on loopback.</li><li>Signals are not a threat verdict.</li><li>Host names and ALPN are peer assertions, not authenticated identity.</li><li>One container, not two machines; no performance claim.</li><li>The Culvert change is a local lab branch, not proposed upstream.</li></ul></article></div>
      </section>
      <footer class="page-footer"><span><span class="footer-mark">◈</span> Protocol Observatory · Culvert lab</span><span>Inspect the evidence. Understand the traffic.</span></footer>
    </main>
  </div>
  <div id="drawer-backdrop" class="drawer-backdrop" hidden></div>
  <aside id="detail-drawer" class="detail-drawer" role="dialog" aria-modal="true" aria-labelledby="detail-title" hidden><div id="detail-content"></div></aside>
<script>
const LAB = __DATA__;
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const colors = ['#2f9a84','#3d6f8f','#d19a3a','#8a6fb3','#c2675a','#9aa8ab'];
const OUT = {identified:['green','Identified'],unknown:['','Unresolved'],incomplete:['','Incomplete'],outside_profile:['amber','Outside profile'],budget_exhausted:['amber','Budget exhausted'],unsupported:['','Unsupported'],malformed:['amber','Malformed'],failed:['red','Engine failed'],detecting:['','Detecting']};
const SIG = {nonstandard_port:'Protocol on a port it is not usually seen on',host_mismatch:'Client-asserted host differs from the CONNECT destination',server_unresolved:'Server reply not recognised by the detector (post-quantum key exchange)'};
const VER = {allowed:['green','Allowed'],would_block:['amber','Would block'],blocked:['red','Blocked']};
const WHY = {protocol_allowed:"the detected protocol is in the rule's allowed list",protocol_not_allowed:"the detected protocol is not in the rule's allowed list",unknown_allowed:'the protocol could not be named; the rule allows unknown',unknown_blocked:'the protocol could not be named; the rule blocks unknown',detector_unavailable:"the detector was unavailable; the rule's unknown action was applied"};
const name = d => d.encryption ? d.encryption.toUpperCase() : d.protocol ? d.protocol.toUpperCase() : (d.family || '').toUpperCase();
const lead = r => r.client.outcome === 'identified' ? r.client : r.server.outcome === 'identified' ? r.server : r.client;
const label = s => { const d = lead(s.rec); return d.outcome === 'identified' ? name(d) : d.outcome === 'outside_profile' ? name(d) + ' · outside profile' : (OUT[d.outcome] || ['', d.outcome])[1]; };
const attention = s => lead(s.rec).outcome !== 'identified' || (s.rec.signals || []).length > 0 || (s.rec.policy && s.rec.policy.verdict !== 'allowed');
const bytes = n => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB';
const state = { filter: 'all', shown: LAB.sessions.length, timer: null };
const visible = () => LAB.sessions.slice(0, state.shown);
function filtered() {
  const q = $('session-search').value.trim().toLowerCase();
  return visible().filter(s => {
    if (state.filter === 'identified' && lead(s.rec).outcome !== 'identified') return false;
    if (state.filter === 'attention' && !attention(s)) return false;
    if (state.filter === 'policy' && !s.rec.policy) return false;
    return !q || (label(s) + ' ' + s.rec.dest + ' ' + s.scenario + ' ' + (s.rec.client.hostname || '')).toLowerCase().includes(q);
  });
}
function dirCell(d) { const o = OUT[d.outcome] || ['', d.outcome]; return '<span class="badge ' + o[0] + '">' + esc(o[1]) + '</span>' + (name(d) && d.outcome === 'identified' ? ' <strong>' + esc(name(d)) + '</strong>' : '') + '<small>' + esc(d.reason) + ' · ' + d.observed_bytes + ' B observed</small>'; }
function render() {
  const all = visible(), data = filtered();
  $('nav-count').textContent = all.length; $('table-count').textContent = data.length;
  const ident = all.filter(s => lead(s.rec).outcome === 'identified');
  $('m-sessions').textContent = all.length; $('m-identified').textContent = ident.length;
  $('m-percent').textContent = all.length ? Math.round(ident.length / all.length * 100) + '% of observed tunnels' : 'Structural profile matches';
  $('m-apps').textContent = new Set(ident.map(label)).size; $('m-review').textContent = all.filter(attention).length;
  const counts = {}; all.forEach(s => counts[label(s)] = (counts[label(s)] || 0) + 1);
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]); let groups = sorted.slice(0, 5);
  if (sorted.length > 5) groups.push(['Other', sorted.slice(5).reduce((a, b) => a + b[1], 0)]);
  let off = 0; const grad = groups.map(([n, c], i) => { const from = off; off += c / Math.max(1, all.length) * 100; return colors[i] + ' ' + from + '% ' + off + '%'; }).join(',');
  $('mix').innerHTML = all.length ? '<div class="donut" style="background:conic-gradient(' + grad + ')"><div class="donut-inner">' + all.length + '<small>tunnels</small></div></div><div class="mix-legend">' + groups.map(([n, c], i) => '<div class="mix-row"><i style="background:' + colors[i] + '"></i><span>' + esc(n) + '</span><strong>' + c + '</strong></div>').join('') + '</div>' : '<div class="empty-ring"><span>0<small>tunnels</small></span></div>';
  $('session-rows').innerHTML = data.map(s => { const r = s.rec, pol = r.policy, v = pol ? (VER[pol.verdict] || ['', pol.verdict]) : null, sig = (r.signals || []).length;
    return '<tr tabindex="0" role="button" data-session="' + s.id + '"><td><div class="app-cell"><span class="app-glyph">' + esc((label(s)[0] || '?')) + '</span><div><strong>' + esc(label(s)) + '</strong><small>' + esc(r.client.hostname || s.group) + '</small><span class="scenario">' + esc(s.scenario) + (s.more ? ' · +' + s.more + ' more like it' : '') + '</span></div></div></td><td class="endpoint">' + esc(r.dest) + '</td><td class="dir-cell">' + dirCell(r.client) + '</td><td class="dir-cell">' + dirCell(r.server) + '</td><td>' + (v ? '<span class="badge ' + v[0] + '">' + esc(v[1]) + '</span><small class="scenario">' + esc(pol.mode) + ' · allow ' + esc(pol.allow.join('+').toUpperCase()) + '</small>' : '<span class="muted">—</span>') + '</td><td>' + (sig ? '<span class="badge amber">' + sig + ' signal' + (sig > 1 ? 's' : '') + '</span>' : '<span class="muted">—</span>') + '</td><td>' + bytes(r.forwarded_bytes[0]) + ' ↑ · ' + bytes(r.forwarded_bytes[1]) + ' ↓</td><td class="muted">↗</td></tr>'; }).join('');
  $('table-footer-text').textContent = 'Showing ' + data.length + ' of ' + all.length + ' tunnels' + (state.shown < LAB.sessions.length ? ' · replaying…' : '');
}
function openDetail(id) {
  const s = LAB.sessions.find(x => x.id === id); if (!s) return; const r = s.rec, d = lead(r), pol = r.policy;
  const layers = ['TCP']; if (d.outcome === 'identified' && name(d)) layers.push(name(d));
  const ev = [...(r.client.evidence || []).map(e => ({...e, dir: 'client'})), ...(r.server.evidence || []).map(e => ({...e, dir: 'server'}))];
  const field = (k, v) => '<div><label>' + esc(k) + '</label><span>' + esc(v ?? 'Not observed') + '</span></div>';
  const tl = (title, x) => '<div class="timeline-event"><small>' + title + '</small><strong>' + esc((OUT[x.outcome] || ['', x.outcome])[1]) + (name(x) ? ' · ' + esc(name(x)) : '') + '</strong><p>' + esc(x.detail || 'No reason sentence for this outcome.') + '</p><small>' + esc(x.reason) + ' · ' + x.observed_bytes + ' bytes observed</small></div>';
  $('detail-content').innerHTML = '<div class="drawer-head"><div class="drawer-top"><span>TUNNEL ' + esc(s.id) + ' · BUILD ' + esc(s.build) + '</span><button class="close-button" id="close-detail" aria-label="Close tunnel details">×</button></div><h2 id="detail-title">' + esc(label(s)) + '</h2><span class="badge ' + (attention(s) ? 'amber' : 'green') + '">' + (d.outcome === 'identified' ? 'Identified profile' : 'Unresolved') + '</span>' + (pol ? ' <span class="badge ' + (VER[pol.verdict] || [''])[0] + '">' + esc((VER[pol.verdict] || ['', pol.verdict])[1]) + ' by rule restriction</span>' : '') + '<p>client → ' + esc(r.dest) + '</p></div>' +
    '<section class="drawer-section"><h3>What the detector observed</h3><div class="layer-row">' + layers.map(x => '<span class="layer">' + esc(x) + '</span>').join('<span class="muted">→</span>') + '</div><div class="reason-box">' + esc(d.detail || 'No identification was established for this tunnel.') + '</div><p class="detail-note">Scenario: ' + esc(s.scenario) + '</p></section>' +
    (pol ? '<section class="drawer-section"><h3>Rule protocol restriction</h3><div class="policy-box"><strong>' + esc((VER[pol.verdict] || ['', pol.verdict])[1]) + '</strong> — ' + esc(WHY[pol.reason] || pol.reason) + '.<br>Mode: ' + esc(pol.mode) + ' · allowed protocols: ' + esc(pol.allow.join(', ').toUpperCase()) + '<br>Client bytes held for the decision: ' + pol.held_bytes + ' · forwarded to the server: ' + r.forwarded_bytes[0] + '</div><p class="detail-note">A restriction can only narrow a rule that already allows the tunnel. In enforce mode the client\\'s first bytes are held until the protocol is decided.</p></section>' : '') +
    '<section class="drawer-section"><div class="detail-grid">' + field('DESTINATION', r.dest) + field('CLIENT-ASSERTED HOST', r.client.hostname || null) + field('FORWARDED TO SERVER / CLIENT', bytes(r.forwarded_bytes[0]) + ' / ' + bytes(r.forwarded_bytes[1])) + field('ENGINE', r.engine + (r.quarantined ? ' · flow quarantined' : '')) + field('ALPN OFFERED', (r.client.offered_alpn || []).join(', ') || null) + field('LAB CHECK', s.check === 'pass' ? 'expected result' : s.check === 'gap' ? 'known gap (work item #4)' : 'unexpected') + '</div></section>' +
    '<section class="drawer-section"><h3>Signals <span class="count-badge">' + (r.signals || []).length + '</span></h3>' + ((r.signals || []).length ? r.signals.map(x => '<div class="signal">' + esc(SIG[x] || x) + '</div>').join('') : '<p class="detail-note">No advisory signals were raised.</p>') + '<p class="detail-note">Signals describe observed properties. They do not mean the tunnel is malicious or blocked.</p></section>' +
    '<section class="drawer-section"><h3>Detection timeline</h3>' + tl('Client → server', r.client) + tl('Server → client', r.server) + '</section>' +
    '<section class="drawer-section"><h3>Evidence ledger <span class="count-badge">' + ev.length + '</span></h3>' + (ev.length ? ev.map(e => '<div class="evidence-row"><label>' + esc(e.field) + '</label><div><span>' + (e.class === 'withheld' ? '<i>withheld</i>' : esc(e.value)) + '</span><small>' + esc(e.dir) + ' · ' + esc(e.source) + ' · ' + esc(e.strength) + '</small></div></div>').join('') : '<p class="detail-note">No structural evidence was established.</p>') + '<p class="detail-note">Host names and ALPN are peer assertions; they do not authenticate application identity.</p></section>';
  $('detail-drawer').hidden = false; $('drawer-backdrop').hidden = false; document.body.style.overflow = 'hidden';
  $('close-detail').onclick = closeDetail; $('detail-drawer').scrollTop = 0; $('close-detail').focus();
}
function closeDetail() { $('detail-drawer').hidden = true; $('drawer-backdrop').hidden = true; document.body.style.overflow = ''; }
function setView(v) {
  document.querySelectorAll('[data-view]').forEach(b => b.classList.toggle('active', b.dataset.view === v));
  $('overview-view').hidden = v !== 'overview'; $('about-view').hidden = v !== 'about'; $('sessions-panel').hidden = v === 'about';
  $('breadcrumb').textContent = v === 'overview' ? 'Overview' : v === 'sessions' ? 'Tunnels' : 'Lab & scope';
  if (v === 'sessions') $('sessions-panel').scrollIntoView({ block: 'start' });
}
function replay() {
  if (state.timer) clearInterval(state.timer);
  state.shown = 0; render(); $('replay-button').disabled = true;
  state.timer = setInterval(() => { state.shown++; render(); if (state.shown >= LAB.sessions.length) { clearInterval(state.timer); state.timer = null; $('replay-button').disabled = false; } }, 260);
}
document.querySelectorAll('[data-view]').forEach(b => b.onclick = () => setView(b.dataset.view));
document.querySelectorAll('[data-filter]').forEach(b => b.onclick = () => { state.filter = b.dataset.filter; document.querySelectorAll('[data-filter]').forEach(x => x.classList.toggle('active', x === b)); render(); });
$('session-search').oninput = render; $('replay-button').onclick = replay; $('drawer-backdrop').onclick = closeDetail;
$('session-rows').onclick = e => { const row = e.target.closest('[data-session]'); if (row) openDetail(row.dataset.session); };
$('session-rows').onkeydown = e => { if (e.key === 'Enter' || e.key === ' ') { const row = e.target.closest('[data-session]'); if (row) { e.preventDefault(); openDetail(row.dataset.session); } } };
document.addEventListener('keydown', e => { if (!$('detail-drawer').hidden && e.key === 'Escape') closeDetail(); });
$('strip-run').textContent = 'Lab run ' + LAB.started + (LAB.finished ? ' → ' + LAB.finished.slice(11) : '');
render();
</script>
</body>
</html>
"""
open(out, "w").write(page.replace("__CSS__", css).replace("__DATA__", data))
print("sessions:", len(sessions))
