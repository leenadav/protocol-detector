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
console.log('store tests ok');
