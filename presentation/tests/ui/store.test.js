'use strict';
// Stage 6 (A14): store and selector unit tests, run by Node (no browser).
const assert = require('assert');
const Store = require('../../web/store.js');

const session = (over) => Object.assign({id: 'S-1', app: 'ssl', client: ['192.0.2.1', 50000], server: ['198.51.100.2', 443],
  transport: 'tcp', category: 'networking', encryption: 'tls', client_protocol: null, server_protocol: null,
  port_usage: 'standard', risks: [], client_bytes: 10, server_bytes: 20, session_id: 'abc', reasons: []}, over || {});
const catalog = {outcomes: ['unknown-tcp', 'insufficient-data'], source: {version: 'x'}};

function freshStore() {
  const store = Store.createStore();
  store.dispatch({type: 'catalog', catalog});
  return store;
}

// 1. A late result for an older run never overwrites a newer run.
{
  const store = freshStore();
  const demo = store.dispatch({type: 'run/start', mode: 'demo'}).runId;
  const live = store.dispatch({type: 'run/start', mode: 'live'}).runId;
  store.dispatch({type: 'live/snapshot', runId: live, snapshot: {state: 'running', sessions: [session()], events: [], summary: {}}});
  store.dispatch({type: 'run/result', runId: demo, result: {sessions: [session({app: 'late-demo'})], meta: {}}});
  const state = store.getState();
  assert.strictEqual(state.mode, 'live');
  assert.strictEqual(state.result.sessions[0].app, 'ssl');
  assert.strictEqual(state.stale, 1);
}

// 2. A retraction in a live snapshot degrades quality and the sessions it withdrew are gone from every selector.
{
  const store = freshStore();
  const live = store.dispatch({type: 'run/start', mode: 'live'}).runId;
  store.dispatch({type: 'live/snapshot', runId: live, snapshot: {state: 'running', sessions: [session(), session({id: 'S-2', session_id: 'def'})], events: [], summary: {}}});
  assert.strictEqual(Store.selectors.metrics(store.getState()).sessions, 2);
  store.dispatch({type: 'live/snapshot', runId: live, snapshot: {state: 'running', sessions: [], events: [{type: 'capture_gap', reason: 'loss', scope: 'all_observations_this_capture'}], summary: {}}});
  const state = store.getState();
  assert.strictEqual(state.quality, 'degraded');
  assert.strictEqual(state.retracted, 1);
  assert.strictEqual(Store.selectors.metrics(state).sessions, 0);
  assert.strictEqual(Store.selectors.filtered(state, {}).length, 0);
  assert.strictEqual(Store.selectors.exportData(state).retractions, 1);
}

// 3. Counts, filters and exports read the same sessions; a decoder row joins its session (one view).
{
  const store = freshStore();
  const run = store.dispatch({type: 'run/start', mode: 'live'}).runId;
  const row = {client: ['192.0.2.1', 50000], server: ['198.51.100.2', 443], status: 'decrypted', session_id: 'abc', generation: 0,
               layers: {chain: ['tls', 'http/1.1', 'webdav'], application: {name: 'webdav', basis: 'authenticated_plaintext', category: 'collaboration'}, inner: {protocol: 'http/1.1'}}};
  store.dispatch({type: 'live/snapshot', runId: run, snapshot: {state: 'running', sessions: [session(), session({id: 'S-2', app: 'unknown-tcp', session_id: 'zzz'})],
                  decryption: {report: {connections: [row], decrypted: 1, frames: 3}}, events: [], summary: {}}});
  const state = store.getState();
  const merged = Store.selectors.sessions(state)[0];
  assert.strictEqual(merged.app, 'webdav');
  assert.deepStrictEqual(Store.selectors.chain(merged), ['tls', 'http/1.1', 'webdav']);
  assert.strictEqual(Store.selectors.basis(merged), 'authenticated plaintext');
  const metrics = Store.selectors.metrics(state);
  assert.deepStrictEqual([metrics.sessions, metrics.identified, metrics.apps, metrics.review], [2, 1, 1, 1]);
  assert.strictEqual(Store.selectors.filtered(state, {application: 'webdav'}).length, 1);
  assert.strictEqual(Store.selectors.filtered(state, {query: '198.51.100.2:443'}).length, 2);
  assert.strictEqual(Store.selectors.exportData(state).sessions.length, 2);
  store.dispatch({type: 'set', key: 'filter', value: 'unknown'});
  assert.strictEqual(Store.selectors.filtered(store.getState(), {}).length, 1);
}

// 4. Unknown modes and actions are errors, never silent state.
{
  const store = freshStore();
  assert.throws(() => store.dispatch({type: 'run/start', mode: 'bogus'}));
  assert.throws(() => store.dispatch({type: 'nope'}));
}
// 5. A14: the live view is built from cursor pages of the event log and the server's reduced view.
{
  const envelope = (sequence, kind, payload, extra) => Object.assign({sequence, kind, payload, quality: 'intact', reason_code: null}, extra || {});
  const view = (over) => Object.assign({quality: 'intact', retracted_total: 0, errors: [], last_sequence: 2, summary: {counts: {packets: 7}},
    sessions: [{id: 'abc', status: 'final', generation: 0, revision: 1, session: session(), classifications: 1, decryption: null, retracted_by: null}]}, over || {});
  const store = freshStore();
  const run = store.dispatch({type: 'run/start', mode: 'live'}).runId;
  store.dispatch({type: 'live/events', runId: run, control: {state: 'running', run_id: 'cap1', summary: {counts: {packets: 7}}},
                  page: {capture_id: 'cap1', cursor: 2, reset_required: false, view: view(),
                         events: [envelope(1, 'classification', {status: 'identified', app: 'ssl'}), envelope(2, 'session', session())]}});
  let state = store.getState();
  assert.strictEqual(state.liveLog.length, 2);
  assert.strictEqual(state.liveCursor, 2);
  assert.strictEqual(Store.selectors.metrics(state).sessions, 1);
  assert.strictEqual(state.result.meta.frames, 7);
  // the next page appends; a re-polled page is applied by sequence (the server never repeats a cursor window)
  store.dispatch({type: 'live/events', runId: run, control: {state: 'running', run_id: 'cap1'},
                  page: {capture_id: 'cap1', cursor: 3, reset_required: false, view: view({last_sequence: 3}), events: [envelope(3, 'classification', {status: 'malformed'})]}});
  assert.strictEqual(store.getState().liveLog.length, 3);
  // a decoder row in the reduced view joins its session (one view); the latest decryption event is kept
  const row = {client: ['192.0.2.1', 50000], server: ['198.51.100.2', 443], status: 'decrypted', session_id: 'abc', generation: 0,
               layers: {chain: ['tls', 'http/1.1', 'webdav'], application: {name: 'webdav', basis: 'authenticated_plaintext', category: 'collaboration'}, inner: {protocol: 'http/1.1'}}};
  store.dispatch({type: 'live/events', runId: run, control: {state: 'running', run_id: 'cap1'},
                  page: {capture_id: 'cap1', cursor: 4, reset_required: false, view: view({sessions: [Object.assign(view().sessions[0], {decryption: row})]}),
                         events: [envelope(4, 'decryption', {report: {connections: [row], decrypted: 1}})]}});
  state = store.getState();
  assert.strictEqual(Store.selectors.sessions(state)[0].app, 'webdav');
  assert.strictEqual(state.decryption.report.decrypted, 1);
  // reset_required empties the local log before applying; a retracted view session is gone and quality degrades
  store.dispatch({type: 'live/events', runId: run, control: {state: 'running', run_id: 'cap1'},
                  page: {capture_id: 'cap1', cursor: 6, reset_required: true,
                         view: view({quality: 'degraded', retracted_total: 1, sessions: [Object.assign(view().sessions[0], {status: 'retracted'})]}),
                         events: [envelope(5, 'capture_gap', {reason: 'loss'}, {quality: 'degraded'}), envelope(6, 'classification', {status: 'unknown'})]}});
  state = store.getState();
  assert.strictEqual(state.liveLog.length, 2);
  assert.strictEqual(state.quality, 'degraded');
  assert.strictEqual(state.retracted, 1);
  assert.strictEqual(Store.selectors.metrics(state).sessions, 0);
  assert.strictEqual(state.decryption, null);
  // a new capture id starts a fresh log; a page for an older run is counted stale and changes nothing
  store.dispatch({type: 'live/events', runId: run, control: {state: 'running', run_id: 'cap2'},
                  page: {capture_id: 'cap2', cursor: 1, reset_required: false, view: view({sessions: []}), events: [envelope(1, 'classification', {status: 'identified'})]}});
  assert.strictEqual(store.getState().liveLog.length, 1);
  assert.strictEqual(store.getState().liveCaptureId, 'cap2');
  const demo = store.dispatch({type: 'run/start', mode: 'demo'}).runId;
  store.dispatch({type: 'live/events', runId: run, control: {}, page: {capture_id: 'cap2', cursor: 2, events: [envelope(2, 'classification', {})], view: view()}});
  assert.strictEqual(store.getState().stale, 1);
  assert.strictEqual(store.getState().liveLog.length, 1);
  void demo;
}
console.log('store tests ok');
