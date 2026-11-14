'use strict';
/* Stage 6 (A14): one store for the dashboard.
 *
 * Modules in one file (no bundler): `createStore` (state + reducer + subscribers), `reducer` (the only place
 * state changes), `selectors` (sessions, filters, metrics, export: every view reads the same functions) and
 * run identity (a late response for an older run is rejected, never rendered). Loads in the browser as a
 * plain script and in Node for the unit tests (module.exports). No key material is ever placed here, and
 * nothing is written to localStorage; sessionStorage holds only a job id to resume after a refresh.
 */
(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) module.exports = factory();
  else root.Store = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  const MODES = ['idle', 'demo', 'offline', 'live', 'decrypt-demo'];

  function initialState() {
    return {catalog: null, mode: 'idle', runId: 0, result: null, visible: 0, view: 'overview', filter: 'all',
            timer: null, busy: false, selected: null, lastFocus: null, sourceName: 'Synthetic demonstration',
            live: null, decryption: null, stale: 0, retracted: 0, quality: 'intact',
            liveLog: [], liveCaptureId: null, liveCursor: 0};
  }
  const LIVE_LOG_LIMIT = 4000;

  function reducer(state, action) {
    switch (action.type) {
      case 'catalog':
        return Object.assign({}, state, {catalog: action.catalog});
      case 'run/start': {
        if (MODES.indexOf(action.mode) < 0) throw new Error('unknown mode ' + action.mode);
        return Object.assign({}, state, {mode: action.mode, runId: state.runId + 1, busy: true, selected: null,
                                          sourceName: action.sourceName || state.sourceName});
      }
      case 'run/result': {
        if (action.runId !== state.runId) return Object.assign({}, state, {stale: state.stale + 1});   // late answer for an older run
        const result = action.result;
        return Object.assign({}, state, {result: result, busy: false, filter: 'all',
                                          visible: action.animate ? 0 : result.sessions.length,
                                          sourceName: action.sourceName || state.sourceName, quality: 'intact', retracted: 0});
      }
      case 'run/error':
        if (action.runId !== state.runId) return Object.assign({}, state, {stale: state.stale + 1});
        return Object.assign({}, state, {busy: false});
      case 'live/snapshot': {
        // A live snapshot belongs to the run it was requested for; a newer run (another mode started) ignores it.
        if (action.runId !== state.runId) return Object.assign({}, state, {stale: state.stale + 1});
        const snapshot = action.snapshot;
        const sessions = mergeDecryption(snapshot.sessions || [], snapshot.decryption);
        const retraction = (snapshot.events || []).some(function (e) { return e.type === 'capture_gap'; });
        return Object.assign({}, state, {live: snapshot, decryption: snapshot.decryption || null,
                                          busy: liveBusy(snapshot.state, state.busy),
                                          quality: retraction ? 'degraded' : state.quality,
                                          retracted: retraction ? state.retracted + 1 : state.retracted,
                                          result: {sessions: sessions, meta: liveMeta(snapshot)}, visible: sessions.length});
      }
      case 'live/events': {
        // A14: the live view is built from the versioned event log read by cursor and the server's reduced
        // session view (identical whether built live or replayed), never from the legacy snapshot. A page for
        // another run is stale; a new capture id or reset_required empties the local log before applying.
        if (action.runId !== state.runId) return Object.assign({}, state, {stale: state.stale + 1});
        const page = action.page || {}, control = action.control || {}, view = page.view || null;
        const fresh = page.capture_id !== state.liveCaptureId || page.reset_required;
        let log = fresh ? [] : state.liveLog;
        const incoming = (page.events || []).map(function (e) {
          return Object.assign({sequence: e.sequence, type: e.kind, quality: e.quality, reason_code: e.reason_code}, e.payload || {});
        });
        if (incoming.length) {
          log = log.concat(incoming);
          if (log.length > LIVE_LOG_LIMIT) log = log.slice(log.length - LIVE_LOG_LIMIT);
        }
        const latestDecryption = incoming.filter(function (e) { return e.type === 'decryption'; }).pop();
        const decryption = latestDecryption || (fresh ? null : state.decryption);
        const views = view ? view.sessions : [];
        const rows = views.map(function (v) { return v.decryption; }).filter(Boolean);
        const sessions = mergeDecryption(views.filter(function (v) { return v.session && v.status !== 'retracted'; })
                                              .map(function (v) { return Object.assign({id: v.id}, v.session); }),
                                         rows.length ? {report: {connections: rows}} : null);
        const summary = (view && view.summary) || control.summary || {};
        return Object.assign({}, state, {live: Object.assign({}, control, {cursor: page.cursor, capture_id: page.capture_id}),
                                          busy: liveBusy(control.state, state.busy),
                                          liveLog: log, liveCaptureId: page.capture_id === undefined ? state.liveCaptureId : page.capture_id,
                                          liveCursor: page.cursor === undefined ? state.liveCursor : page.cursor,
                                          decryption: decryption,
                                          quality: view ? view.quality : state.quality,
                                          retracted: view ? view.retracted_total : state.retracted,
                                          result: {sessions: sessions, meta: liveMeta({summary: summary})}, visible: sessions.length});
      }
      case 'live/reset': {
        // M0: "Clear sessions & reset capture" for the run it names; a reset answered for an older run (a
        // stale tab) is counted stale and never clears a replacement run's results.
        if (action.runId !== state.runId) return Object.assign({}, state, {stale: state.stale + 1});
        return Object.assign({}, state, {live: action.control || null, liveLog: [], liveCaptureId: null, liveCursor: 0,
                                          decryption: null, busy: false, quality: 'intact', retracted: 0, selected: null,
                                          result: {sessions: [], meta: liveMeta({summary: {}})}, visible: 0});
      }
      case 'set': {
        const next = Object.assign({}, state);
        next[action.key] = action.value;
        return next;
      }
      default:
        throw new Error('unknown action ' + action.type);
    }
  }

  function liveBusy(liveState, current) {
    // A live run holds `busy` only while it is running or stopping; a stopped or failed run releases it so
    // the next start (or another mode) is not blocked. An unknown state leaves the flag as it is.
    if (liveState === 'running' || liveState === 'stopping') return true;
    if (liveState === 'stopped' || liveState === 'failed' || liveState === 'idle') return false;
    return current;
  }

  function liveMeta(snapshot) {
    const summary = snapshot.summary || {}, counts = summary.counts || {};
    return {live: true, synthetic: false, frames: counts.packets || 0, skipped: counts.unsupported_or_malformed_packets || 0,
            timeline: [], processing_ms: 0, capture_quality: summary.capture_quality || 'pending',
            capture_stats: summary.capture_stats || null};
  }

  function mergeDecryption(sessions, decryption) {
    // One session view (stage 5): a decoder row joins its session by session_id; the layered effective
    // application replaces the flat label, never a second independent one.
    const rows = decryption && decryption.report ? decryption.report.connections || [] : [];
    const bySession = new Map(rows.filter(function (r) { return r.session_id; }).map(function (r) { return [r.session_id, r]; }));
    return sessions.map(function (s) {
      const row = s.session_id && bySession.get(s.session_id);
      if (!row || !row.layers) return s;
      const merged = Object.assign({}, s, {layers: row.layers, decrypted_log: 'TLS-' + JSON.stringify([row.client, row.server])});
      if (row.layers.application && row.layers.application.name) merged.app = row.layers.application.name;
      if (row.layers.inner && row.layers.inner.protocol) merged.client_protocol = row.layers.inner.protocol;
      if (row.layers.application && row.layers.application.category) merged.category = row.layers.application.category;
      return merged;
    });
  }

  const selectors = {
    sessions: function (state) { return state.result ? state.result.sessions.slice(0, state.visible) : []; },
    unresolved: function (state, s) { return !!state.catalog && state.catalog.outcomes.indexOf(s.app) >= 0; },
    displayLabel: function (state, s) {
      // M0: a frontend-only fallback label for traffic the engine did not identify: destination port and
      // transport (for example "8789 udp"). The verdict (`app`), filters and exports keep the raw outcome;
      // a port is a place the traffic went, never an application identity.
      if (!selectors.unresolved(state, s) || !s.server || s.server.length < 2 || !s.transport) return s.app;
      return s.server[1] + ' ' + String(s.transport).toLowerCase();
    },
    attention: function (state, s) { return selectors.unresolved(state, s) || s.port_usage === 'nonstandard' || (s.risks || []).length > 0; },
    chain: function (s) {
      const layers = s && s.layers;
      if (layers && layers.chain && layers.chain.length) return layers.chain.slice();
      return [s.encryption, s.client_protocol || s.server_protocol || s.inner_protocol].filter(Boolean);
    },
    basis: function (s) {
      const basis = s && s.layers && s.layers.application && s.layers.application.basis;
      return basis ? basis.replace(/_/g, ' ') : '';
    },
    filtered: function (state, controls) {
      const query = (controls.query || '').trim().toLowerCase(), transport = controls.transport || 'all', app = controls.application || 'all';
      return selectors.sessions(state).filter(function (s) {
        if (app !== 'all' && s.app !== app) return false;
        if (transport !== 'all' && s.transport !== transport) return false;
        if (query && [s.app, s.client.join(':'), s.server.join(':'), s.client_protocol, s.server_protocol, s.category, s.encryption].join(' ').toLowerCase().indexOf(query) < 0) return false;
        if (state.filter === 'identified') return !selectors.unresolved(state, s);
        if (state.filter === 'attention') return selectors.attention(state, s);
        if (state.filter === 'unknown') return selectors.unresolved(state, s);
        return true;
      });
    },
    metrics: function (state) {
      const data = selectors.sessions(state);
      const identified = data.filter(function (s) { return !selectors.unresolved(state, s); });
      return {sessions: data.length, identified: identified.length,
              apps: new Set(identified.map(function (s) { return s.app; })).size,
              review: data.filter(function (s) { return selectors.attention(state, s); }).length,
              percent: data.length ? Math.round(identified.length / data.length * 100) : 0};
    },
    exportData: function (state) {
      if (!state.result) return null;
      return Object.assign({source: state.catalog ? state.catalog.source : null, capture: state.sourceName, mode: state.mode,
                            run: state.runId, quality: state.quality, retractions: state.retracted}, state.result);
    }
  };

  function createStore(initial) {
    let state = initial || initialState();
    const listeners = [];
    return {
      getState: function () { return state; },
      dispatch: function (action) {
        state = reducer(state, action);
        listeners.forEach(function (fn) { fn(state, action); });
        return state;
      },
      subscribe: function (fn) { listeners.push(fn); return function () { listeners.splice(listeners.indexOf(fn), 1); }; }
    };
  }

  const resume = {
    // The only browser storage use: a job id (never a key, a path or a result) so a refresh resumes polling.
    save: function (job) { try { sessionStorage.setItem('observatory.job', JSON.stringify(job)); } catch (e) { /* storage may be unavailable */ } },
    load: function () { try { return JSON.parse(sessionStorage.getItem('observatory.job') || 'null'); } catch (e) { return null; } },
    clear: function () { try { sessionStorage.removeItem('observatory.job'); } catch (e) { /* ignore */ } }
  };

  return {MODES: MODES, initialState: initialState, reducer: reducer, createStore: createStore, selectors: selectors,
          mergeDecryption: mergeDecryption, resume: resume};
});
