'use strict';
const live = {token:null, timer:null, shown:false, busy:false};
async function liveInterfaces() {
  try {
    const info = await api('/api/live/interfaces');
    live.token = info.token;
    $('live-interface').innerHTML = info.interfaces.map(name => '<option>'+esc(name)+'</option>').join('');
    if (info.interfaces.includes('lo0')) $('live-interface').value = 'lo0';
    else if (info.interfaces.includes('lo')) $('live-interface').value = 'lo';
    $('live-start').disabled = !info.available || !info.interfaces.length;
    if (!info.available) $('live-note').textContent = 'tcpdump was not found. Install it before using live capture.';
    await initialization;
    const current = await api('/api/live/status');
    if (current.interface) {
      clearTimeout(live.timer);
      await pollLive();
    }
  } catch (e) { $('live-note').textContent = e.message; }
}
function renderLive(data) {
  live.latest = data;
  const running = ['running','stopping'].includes(data.state);
  $('live-status').textContent = data.state;
  $('live-start').disabled = running;
  $('live-stop').disabled = !running || data.state === 'stopping';
  ['live-interface','live-duration','live-scope','live-keylog','live-refresh','run-button','upload-button','empty-run','decrypt-run','decrypt-demo','live-app-demo'].forEach(id => $(id).disabled = running);
  const summary = data.summary || {}, counts = summary.counts || {};
  const drops = summary.capture_stats;
  $('live-metrics').textContent = (counts.packets || 0)+' packets · '+(summary.active_connections || 0)+' active TCP · '+(summary.active_udp_flows || 0)+' active UDP · '+data.sessions_total+' finalized sessions · '+(counts.unsupported_or_malformed_packets || 0)+' skipped · '+(counts.truncated || 0)+' truncated · kernel drops: '+(drops && drops.dropped_by_kernel !== undefined ? drops.dropped_by_kernel : 'not yet reported');
  $('live-note').textContent = data.error ? data.error+' Capture may require OS permission for tcpdump. No privilege changes were made.' : 'Interface '+data.interface+' · '+(summary.capture_quality || 'capture quality pending')+' · stops after the selected duration or 30 seconds without dashboard polling.';
  $('live-events-panel').hidden = false;
  renderLiveLogs(data);
  if (!state.catalog) return;
  state.result = {sessions:mergeDecryption(data.sessions, data.decryption), meta:{live:true, synthetic:false, frames:counts.packets || 0, skipped:counts.unsupported_or_malformed_packets || 0, timeline:[], processing_ms:0, capture_quality:summary.capture_quality || 'pending', capture_stats:drops || null}};
  state.visible = data.sessions.length;
  state.sourceName = 'Live capture · '+data.interface;
  render();
  $('source-title').textContent = 'Live capture';
  $('source-detail').textContent = 'Latest finalized sessions · '+data.interface;
  $('replay-label').textContent = data.state;
  $('play-button').hidden = true;
  $('export-button').disabled = running;
  $('activity-chart').innerHTML = '<div class="chart-empty">Live counters above · session verdicts below</div>';
  $('chart-badge').textContent = 'Live IPv4';
  $('processing-label').textContent = 'UI refresh: 1 second · not forwarding latency';
  $('metric-percent').textContent = 'Of retained finalized sessions';
  if (data.error) showError(data.error);
}
async function pollLive() {
  try {
    const data = await api('/api/live/status');
    renderLive(data);
    if (['running','stopping'].includes(data.state)) live.timer = setTimeout(pollLive,1000);
  } catch (e) {
    showError('Live status unavailable. Capture stops automatically after 30 seconds without polling. '+e.message);
    live.timer = setTimeout(pollLive,2000);
  }
}
$('live-refresh').onclick = liveInterfaces;
$('live-start').onclick = async () => {
  if (live.busy || state.busy) return;
  live.busy = true;
  $('live-start').disabled = true;
  stopReplay(); closeDetail(); clearTimeout(live.timer);
  try {
    const keylog = $('live-keylog').value.trim();
    const duration = Number($('live-duration').value);
    if(keylog && duration > 120) throw new Error('Capture with decryption supports up to 2 minutes. Select a shorter duration.');
    await api('/api/live/start',{method:'POST',headers:{'Content-Type':'application/json','X-Live-Token':live.token},body:JSON.stringify({interface:$('live-interface').value,duration,scope:$('live-scope').value,...(keylog?{keylog_path:keylog}:{})})});
    $('error').hidden = true;
    $('live-events-panel').open = true;
    live.shown = true;
    await pollLive();
  } catch (e) { showError(e.message); $('live-start').disabled = false; }
  finally { live.busy = false; }
};
$('live-stop').onclick = async () => {
  $('live-stop').disabled = true;
  clearTimeout(live.timer);
  try { await api('/api/live/stop',{method:'POST',headers:{'X-Live-Token':live.token}}); await pollLive(); }
  catch (e) { showError(e.message); live.timer = setTimeout(pollLive,1000); }
};
function openLiveDetail(sequence) {
  const event = (live.events || []).find(item => String(item.sequence) === String(sequence));
  if (!event) return;
  state.lastFocus = document.activeElement;
  const field = (name, value) => '<div class="evidence-row"><label>'+esc(name)+'</label><span>'+esc(value == null ? 'Not reported' : typeof value === 'object' ? JSON.stringify(value, null, 2) : value)+'</span></div>';
  $('detail-content').innerHTML = '<div class="drawer-head"><div class="drawer-top"><span>LIVE EVENT '+event.sequence+'</span><button class="close-button" id="close-detail" aria-label="Close session details">×</button></div><h2 id="detail-title">'+esc(event.app || event.protocol || event.type)+'</h2><p>Snapshot of a directional observation, not a final session verdict.</p></div><section class="drawer-section"><h3>What the engine observed</h3><div class="reason-box">'+esc(event.reason || 'No reason reported')+'</div>'+Object.entries(event).filter(([key]) => key !== 'reason').map(([key,value]) => field(label(key),value)).join('')+'</section>';
  $('detail-drawer').hidden = false;
  $('drawer-backdrop').hidden = false;
  document.body.style.overflow = 'hidden';
  $('detail-drawer').scrollTop = 0;
  $('close-detail').onclick = closeDetail;
  $('close-detail').focus();
}
function chainOf(record) {
  // Stage 5 (A05): the layered view is the one source for the protocol chain and the identity basis.
  const layers = record && record.layers;
  if (layers && layers.chain && layers.chain.length) return layers.chain.join(' → ');
  return [record.encryption, record.client_protocol || record.server_protocol || record.inner_protocol].filter(Boolean).join(' → ');
}
function basisOf(record) {
  const basis = record && record.layers && record.layers.application && record.layers.application.basis;
  return basis ? basis.replace(/_/g, ' ') : '';
}
function mergeDecryption(sessions, decryption) {
  // One session view: a decoder row joins its session by session_id (stage 4 ids); the session's app
  // becomes the layered effective application, never a second independent label.
  const rows = decryption && decryption.report ? decryption.report.connections : [];
  const bySession = new Map(rows.filter(r => r.session_id).map(r => [r.session_id, r]));
  return sessions.map(s => {
    const row = s.session_id && bySession.get(s.session_id);
    if (!row || !row.layers) return s;
    const merged = {...s, layers: row.layers, decrypted_log: 'TLS-'+JSON.stringify([row.client,row.server])};
    if (row.layers.application && row.layers.application.name) merged.app = row.layers.application.name;
    if (row.layers.inner && row.layers.inner.protocol) merged.client_protocol = row.layers.inner.protocol;
    if (row.layers.application && row.layers.application.category) merged.category = row.layers.application.category;
    return merged;
  });
}
function renderLiveLogs(data) {
  const decrypted = data.decryption ? data.decryption.report.connections : [];
  const rows = decrypted.map(row => ({...row,sequence:'TLS-'+JSON.stringify([row.client,row.server]),type:'decryption',event:(row.version || 'TLS')+' decryption',source:row.client,destination:row.server,app:(row.layers && row.layers.application && row.layers.application.name) || row.application || 'Not determined',protocol:chainOf(row) || 'tls',basis:basisOf(row),reason:row.reason || (row.reasons || []).join(' · ')}));
  live.events = rows.concat(data.events.slice().reverse());
  syncApplicationFilter($('live-app-filter'),live.events.map(e=>e.app || e.protocol || 'Not determined'));
  const app=$('live-app-filter').value;
  const visible=live.events.filter(e=>app==='all'||(e.app || e.protocol || 'Not determined')===app);
  $('live-log-count').textContent='Showing '+visible.length+' of '+live.events.length+' logs'+(data.decryption?' · '+data.decryption.report.decrypted+' decrypted connections · '+(data.decryption.provisional?'provisional':data.decryption.capture_quality || 'quality unverified'):'');
  updateRows($('live-events'),visible.map(e=>'<tr tabindex="0" role="button" title="Open event details" data-live-event="'+esc(e.sequence)+'" aria-label="Inspect live log"><td>'+esc(e.event || e.type)+'<br>'+esc(e.status || '')+'</td><td>'+esc(e.source?e.source.join(':')+' → '+e.destination.join(':'):'Capture-wide')+'</td><td><strong>'+esc(e.app || 'Not determined')+'</strong><br>'+esc(e.protocol || '—')+(e.basis?'<br><small>'+esc(e.basis)+'</small>':'')+'</td><td>'+esc(e.reason || '')+'</td></tr>').join(''),'data-live-event');
}
$('live-app-filter').onchange=()=>{if(live.latest)renderLiveLogs(live.latest);};
$('live-keylog').oninput=()=>{$('live-start').textContent=$('live-keylog').value.trim()?'Start capture + decryption':'Start capture';};
function activateLiveEvent(event) {
  const row = event.target.closest('[data-live-event]');
  if (row) openLiveDetail(row.dataset.liveEvent);
}
$('live-events').onclick = activateLiveEvent;
$('live-events').ondblclick = activateLiveEvent;
$('live-events').onkeydown = event => {
  if (event.key === 'Enter' || event.key === ' ') {
    event.preventDefault();
    activateLiveEvent(event);
  }
};
liveInterfaces();
