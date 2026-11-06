'use strict';
let decryptedReport = null;
async function decryptCapture(demo) {
  const capture = $('decrypt-capture').files[0], keys = $('decrypt-keys').files[0];
  if (!demo && (!capture || !keys)) { toast('Choose a capture and its TLS key log.'); return; }
  if (!demo && (capture.size > 8*1024*1024 || keys.size > 262144)) { toast('Limits: capture 8 MiB, key log 256 KiB.'); return; }
  $('live-app-demo').disabled = $('decrypt-run').disabled = $('decrypt-demo').disabled = true;
  decryptedReport = null;
  $('decrypt-results').innerHTML = '';
  $('decrypt-status').textContent = 'Authenticating TLS records and classifying decrypted bytes…';
  try {
    let body;
    if (!demo) {
      const bytes = new Uint8Array(await capture.arrayBuffer());
      let binary = '';
      for (let i=0;i<bytes.length;i+=32768) binary += String.fromCharCode(...bytes.subarray(i,i+32768));
      body = JSON.stringify({capture:btoa(binary),keylog:await keys.text()});
    }
    const runId = demo ? beginRun('decrypt-demo', 'Encrypted application demo') : store.getState().runId;
    const data = await runJob(demo?'decrypt-demo':'decrypt', body, {'Content-Type':'application/json'});
    if (!isCurrentRun(runId)) { store.dispatch({type:'run/result', runId, result:{sessions:[]}}); return; }
    showDecryption(data);
    if (demo) {
      stopReplay();
      state.result={sessions:data.connections.map((row,index)=>({id:'D-'+index,app:row.application || 'unknown-tcp',client:row.client,server:row.server,transport:'tcp',category:row.category || 'unknown',encryption:'tls',client_protocol:row.inner_protocol,port_usage:'not evaluated',risks:[],client_bytes:row.client_plaintext_bytes || 0,server_bytes:row.server_plaintext_bytes || 0,reasons:row.reasons || [row.reason],events:[],engine_status:row.status,decrypted_log:'TLS-'+JSON.stringify([row.client,row.server])})),meta:{synthetic:true,frames:data.frames,skipped:data.skipped,timeline:[],processing_ms:0}};
      store.dispatch({type:'run/result', runId, result:state.result, sourceName:'Encrypted application demo'});
      render();
      setView('overview');
      $('live-events-panel').hidden = false;
      $('live-events-panel').open = true;
      const demoLogs={events:[],decryption:{report:data,provisional:false,capture_quality:'Synthetic in-memory TLS; no network capture'}};
      live.latest=demoLogs;
      $('live-app-filter').value='all';
      renderLiveLogs(demoLogs);
      $('source-title').textContent='Encrypted application demo';
      $('source-detail').textContent='3 independent OpenSSL exchanges · TLS 1.2 + TLS 1.3';
      $('replay-label').textContent='Decrypted';
      $('export-button').disabled=true;
      $('processing-label').textContent='Synthetic encrypted exchanges · authenticated decryption';
      $('chart-badge').textContent='TLS 1.2 + TLS 1.3';
      $('live-note').textContent='ENCRYPTED DEMO · 3 synthetic OpenSSL connections · real decryption and classification · no network traffic.';
    }
    decryptedReport = data;
    $('decrypt-status').textContent = (data.synthetic?'Synthetic OpenSSL demonstration · ':'Uploaded capture · ')+data.decrypted+' decrypted / '+data.connections.length+' candidate connections · '+data.frames+' frames';
    $('decrypt-results').innerHTML = data.connections.map((row,index) => '<tr tabindex="0" role="button" data-decrypted="'+index+'" aria-label="Inspect decrypted connection '+(index+1)+'"><td>'+esc(row.client.join(':')+' → '+row.server.join(':'))+'</td><td>TLS</td><td>'+esc(row.status)+'</td><td><strong>'+esc(row.application || 'Not determined')+'</strong><br>'+esc(row.inner_protocol || '—')+'</td><td>'+esc(row.reason || row.reasons.join(' · '))+'</td></tr>').join('');
    if (!data.connections.length) $('decrypt-status').textContent += ' · No supported TLS connection found.';
  } catch (error) { $('decrypt-status').textContent = error.message; }
  finally {
    $('live-app-demo').disabled = $('decrypt-run').disabled = $('decrypt-demo').disabled = false;
    $('decrypt-keys').value = ''; // Do not retain the key file selection after analysis.
  }
}
function showDecryption(data) {
  decryptedReport = data;
  updateRows($('decrypt-results'), data.connections.map((row,index) => '<tr tabindex="0" role="button" data-decrypted="'+index+'" aria-label="Inspect decrypted connection '+(index+1)+'"><td>'+esc(row.client.join(':')+' → '+row.server.join(':'))+'</td><td>TLS</td><td>'+esc(row.status)+'</td><td><strong>'+esc(row.application || 'Not determined')+'</strong><br>'+esc(row.inner_protocol || '—')+'</td><td>'+esc(row.reason || (row.reasons || []).join(' · '))+'</td></tr>').join(''), 'data-decrypted');
}
function openDecrypted(event) {
  const target = event.target.closest('[data-decrypted]');
  if (!target || !decryptedReport) return;
  const row = decryptedReport.connections[Number(target.dataset.decrypted)];
  state.lastFocus = document.activeElement;
  $('detail-content').innerHTML = '<div class="drawer-head"><div class="drawer-top"><span>DECRYPTED CONNECTION</span><button id="close-detail" class="close-button" aria-label="Close session details">×</button></div><h2 id="detail-title">'+esc(row.application || 'Not determined')+'</h2><p>TLS → '+esc(row.inner_protocol || 'unknown')+' → '+esc(row.application || 'unknown application')+'</p></div><section class="drawer-section"><h3>Decryption & application evidence</h3>'+Object.entries(row).map(([key,value]) => '<div class="evidence-row"><label>'+esc(label(key))+'</label><span>'+esc(typeof value === 'object'?JSON.stringify(value,null,2):value)+'</span></div>').join('')+'<p class="detail-note">Application labels come from existing structural profiles. They do not establish a vendor/product identity unless that profile supports it. Plaintext and keys are not included.</p></section>';
  $('detail-drawer').hidden = $('drawer-backdrop').hidden = false;
  document.body.style.overflow = 'hidden';
  $('close-detail').onclick = closeDetail;
  $('detail-drawer').scrollTop = 0;
  $('close-detail').focus();
}
$('decrypt-run').onclick = () => decryptCapture(false);
$('decrypt-demo').onclick = () => decryptCapture(true);
$('decrypt-results').onclick = openDecrypted;
$('decrypt-results').onkeydown = e => { if (e.key==='Enter' || e.key===' ') {e.preventDefault();openDecrypted(e);} };

$('live-app-demo').onclick=()=>decryptCapture(true);
