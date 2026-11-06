'use strict';
// Stage 6 (A14): browser tests against a running LocalServer (port in argv[2]); Playwright + bundled Chromium.
const assert = require('assert');
const { chromium } = require('playwright');

const base = 'http://127.0.0.1:' + process.argv[2];
const HOSTILE = '<img src=x onerror="window.__xss=1">"\'&';

function hostileResult() {
  const make = (id, app) => ({id, app, client: ['192.0.2.9', 51000], server: ['198.51.100.9', 443], transport: 'tcp',
    category: HOSTILE, encryption: 'tls', client_protocol: HOSTILE, server_protocol: null, port_usage: 'standard',
    risks: [HOSTILE], client_bytes: 1, server_bytes: 2, packets: 3, start: 0, end: 1, end_reason: HOSTILE, engine_status: 'identified',
    reasons: [HOSTILE], events: [{kind: HOSTILE, frame: 1, revision: 1, source: ['192.0.2.9', 51000], destination: ['198.51.100.9', 443],
      observation: {status: 'identified', application_protocol: HOSTILE, encryption: 'tls', reason: HOSTILE, scope: HOSTILE,
                    evidence: [{field: HOSTILE, value: HOSTILE, source: HOSTILE, strength: 'structural'}]}}],
    fingerprints: {[HOSTILE]: HOSTILE}, layers: {chain: ['tls', HOSTILE], application: {name: app, basis: 'structural'}}});
  return {sessions: [make('S-0001', HOSTILE), make('S-0002', 'ssl')], meta: {frames: 2, skipped: 0, timeline: [[0, 1], [1, 1]], processing_ms: 1}};
}

async function waitFor(page, fn, timeout) {
  const deadline = Date.now() + (timeout || 30000);
  for (;;) {
    if (await page.evaluate(fn)) return;
    if (Date.now() > deadline) {
      const diagnostics = await page.evaluate(() => ({error: (document.getElementById('error') || {}).textContent, title: document.title,
                                                       mode: typeof store !== 'undefined' ? store.getState().mode : null, busy: typeof state !== 'undefined' ? state.busy : null,
                                                       job: sessionStorage.getItem('observatory.job')}));
      throw new Error('timeout waiting for ' + fn.toString().slice(0, 80) + ' :: ' + JSON.stringify(diagnostics));
    }
    await page.waitForTimeout(100);
  }
}

(async () => {
  const browser = await chromium.launch();
  try {
    // A. The demo renders; counts and table rows come from the same store.
    const context = await browser.newContext();
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', e => errors.push(String(e)));
    await page.goto(base + '/');
    await waitFor(page, () => document.querySelectorAll('#session-rows tr').length > 0);
    await waitFor(page, () => document.getElementById('replay-label').textContent.includes('complete') || !document.getElementById('play-button').hidden);
    await page.evaluate(() => { stopReplay(); store.dispatch({type: 'set', key: 'visible', value: state.result.sessions.length}); render(); updateBanner(); });
    const counts = await page.evaluate(() => ({metric: Number(document.getElementById('metric-sessions').textContent), rows: document.querySelectorAll('#session-rows tr').length,
                                                table: Number(document.getElementById('table-count').textContent), store: Store.selectors.metrics(store.getState()).sessions}));
    assert.strictEqual(counts.metric, 18, 'demo sessions');
    assert.strictEqual(counts.rows, 18);
    assert.strictEqual(counts.table, 18);
    assert.strictEqual(counts.store, 18);
    // Filters and navigation touch the store, not the run.
    await page.fill('#session-search', 'ssh');
    await waitFor(page, () => document.querySelectorAll('#session-rows tr').length < 18);
    const afterFilter = await page.evaluate(() => ({rows: document.querySelectorAll('#session-rows tr').length, run: store.getState().runId, visible: state.visible}));
    assert.ok(afterFilter.rows >= 1 && afterFilter.rows < 18);
    assert.strictEqual(afterFilter.visible, 18);
    await page.fill('#session-search', '');
    // Export reads the same store.
    const exported = await page.evaluate(() => Store.selectors.exportData(store.getState()));
    assert.strictEqual(exported.sessions.length, 18);
    assert.strictEqual(exported.mode, 'demo');
    // Browser storage: nothing in localStorage, no key material anywhere.
    const storage = await page.evaluate(() => ({local: localStorage.length, session: Object.keys(sessionStorage)}));
    assert.strictEqual(storage.local, 0);
    assert.ok(storage.session.every(k => k === 'observatory.job'), JSON.stringify(storage.session));

    // B. Hostile strings in every rendered field never execute and never break rendering.
    await page.route('**/api/jobs?kind=demo', route => route.fulfill({status: 202, contentType: 'application/json', body: JSON.stringify({id: 'hostile', kind: 'demo', state: 'queued'})}));
    await page.route('**/api/jobs/hostile', route => route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify({id: 'hostile', kind: 'demo', state: 'done', result: hostileResult()})}));
    await page.evaluate(() => loadCapture(null, false));
    await waitFor(page, () => document.querySelectorAll('#session-rows tr').length === 2);
    const xss = await page.evaluate(() => window.__xss);
    assert.strictEqual(xss, undefined, 'hostile app name executed');
    const cell = await page.evaluate(() => document.querySelector('#session-rows tr strong').textContent);
    assert.strictEqual(cell, HOSTILE);
    await page.click('#session-rows tr');
    await waitFor(page, () => !document.getElementById('detail-drawer').hidden);
    assert.strictEqual(await page.evaluate(() => window.__xss), undefined, 'hostile detail executed');
    assert.ok((await page.evaluate(() => document.getElementById('detail-content').textContent)).includes(HOSTILE));
    await page.evaluate(() => closeDetail());
    await page.unroute('**/api/jobs?kind=demo');
    await page.unroute('**/api/jobs/hostile');

    // C. A late demo response cannot overwrite a newer run (the encrypted demo started afterwards).
    await page.route('**/api/jobs?kind=demo', async route => { await new Promise(r => setTimeout(r, 1500)); await route.fulfill({status: 202, contentType: 'application/json', body: JSON.stringify({id: 'slow', kind: 'demo', state: 'queued'})}); });
    await page.route('**/api/jobs/slow', route => route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify({id: 'slow', kind: 'demo', state: 'done', result: hostileResult()})}));
    const staleBefore = await page.evaluate(() => store.getState().stale);
    await page.evaluate(() => { loadCapture(null, false); });
    await page.waitForTimeout(100);
    await page.evaluate(() => { store.dispatch({type: 'set', key: 'busy', value: false}); return decryptCapture(true); });
    await waitFor(page, () => document.getElementById('source-title').textContent === 'Encrypted application demo', 40000);
    await page.waitForTimeout(2500);
    const after = await page.evaluate(() => ({title: document.getElementById('source-title').textContent, mode: store.getState().mode, stale: store.getState().stale,
                                              apps: [...document.querySelectorAll('#session-rows tr strong')].map(e => e.textContent)}));
    assert.strictEqual(after.title, 'Encrypted application demo');
    assert.strictEqual(after.mode, 'decrypt-demo');
    assert.ok(after.stale > staleBefore, 'late response was not counted stale');
    assert.ok(!after.apps.includes(HOSTILE), 'late demo result overwrote the newer run');
    assert.ok(after.apps.includes('webdav'), JSON.stringify(after.apps));
    await page.unroute('**/api/jobs?kind=demo');
    await page.unroute('**/api/jobs/slow');

    // D. A refresh resumes the run in flight from the job id kept in sessionStorage (no result, no keys).
    await page.route('**/api/jobs?kind=demo', route => route.fulfill({status: 202, contentType: 'application/json', body: JSON.stringify({id: 'resume', kind: 'demo', state: 'running'})}));
    let polls = 0;
    await page.route('**/api/jobs/resume', route => { polls += 1; const done = polls > 3; route.fulfill({status: 200, contentType: 'application/json',
      body: JSON.stringify(done ? {id: 'resume', kind: 'demo', state: 'done', result: hostileResult()} : {id: 'resume', kind: 'demo', state: 'running'})}); });
    await page.evaluate(() => { store.dispatch({type: 'set', key: 'busy', value: false}); loadCapture(null, false); });
    await waitFor(page, () => sessionStorage.getItem('observatory.job') !== null);
    await page.reload();
    await waitFor(page, () => document.querySelectorAll('#session-rows tr').length === 2, 20000);
    assert.strictEqual(await page.evaluate(() => sessionStorage.getItem('observatory.job')), null);
    assert.strictEqual(await page.evaluate(() => localStorage.length), 0);

    // E. Row identity is stable across re-renders (the same DOM node survives an update).
    const same = await page.evaluate(() => { const before = document.querySelector('#session-rows tr'); render(); return before === document.querySelector('#session-rows tr'); });
    assert.strictEqual(same, true);
    assert.deepStrictEqual(errors, []);
    console.log('browser tests ok');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exit(1); });
