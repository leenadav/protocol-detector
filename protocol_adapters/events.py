"""Versioned event contracts: envelope, bounded log with cursors, retractions and a replayable reducer (stage 2, A06).

Before this module the live path had five loose event shapes, locally numbered by whoever buffered them,
with no shared identity: a `capture_gap` cleared every session without saying which, an older snapshot
could overwrite a newer one, and a consumer that fell behind silently saw a window with holes.

An `Envelope` gives every event one identity and ordering:

    schema_version   contract version of the payload ("1")
    sequence         position in the capture's log (assigned by the EventLog, never by the producer)
    capture_id       one capture run; ids from different runs never compare
    session_id       deterministic from transport and both endpoints (see session_identity)
    generation       bumped when the same 5-tuple starts a new connection (SYN after a close)
    layer            "transport" | "outer" | "encryption" | "inner" | "application" | "capture"
    revision         monotonic per (session_id, generation): a reducer ignores an older revision
    kind             the payload type (session, classification, capture_gap, error, summary, decryption)
    source           who produced it ("wire", "decrypted", "capture", "control")
    quality          capture quality at that moment ("intact" | "provisional" | "degraded")
    reason_code      short machine code; free text stays in the payload's `reason`
    budget           {"exhausted": bool, "scope": str} when a budget decided the outcome
    retracts         session_ids whose dependent observations this event invalidates
    payload          the original event dict, unchanged (the compatibility surface)

`EventLog` is the bounded sequence (A06 "bounded event sequence with cursors"). `read(cursor)` returns the
events after `cursor`; when the cursor predates what is retained, it returns `reset_required=True` with a
fresh snapshot cursor instead of a silent gap. `reduce()` folds a sequence of envelopes into a session view
deterministically, so replaying the log rebuilds exactly the state a live consumer reached.

No payload bytes, hostnames or secrets are added here; the envelope only carries what the producers already
emitted plus identity and ordering. Python 3.9, standard library only.
"""
import hashlib
from collections import OrderedDict, deque

SCHEMA_VERSION = "1"
LAYERS = ("transport", "outer", "encryption", "inner", "application", "capture")
QUALITIES = ("intact", "provisional", "degraded")
SOURCES = ("wire", "decrypted", "capture", "control")
KINDS = ("session", "classification", "capture_gap", "error", "summary", "started", "decryption", "progress")
DEFAULT_RETENTION = 4096
MAX_RETRACTS = 1024


def session_identity(transport, client, server):
    """Deterministic session id from transport and both endpoints, independent of direction.

    The id is a hash, so no address or port leaves through it; the same two endpoints yield the same id
    whichever side spoke first.
    """
    a, b = sorted((tuple(client), tuple(server)))
    text = "{}|{}:{}|{}:{}".format(transport, a[0], a[1], b[0], b[1])
    return hashlib.blake2s(text.encode("ascii", "replace"), digest_size=8).hexdigest()


class Envelope(dict):
    """A dict (JSON-friendly) with the fixed contract keys; attribute access for the common ones."""
    __slots__ = ()
    _KEYS = ("schema_version", "sequence", "capture_id", "session_id", "generation", "layer", "revision", "kind",
             "source", "quality", "reason_code", "budget", "retracts", "payload")

    def __init__(self, **fields):
        unknown = set(fields) - set(self._KEYS)
        if unknown:
            raise ValueError("unknown envelope fields: " + ", ".join(sorted(unknown)))
        if fields.get("layer") not in LAYERS:
            raise ValueError("invalid layer")
        if fields.get("quality") not in QUALITIES:
            raise ValueError("invalid quality")
        if fields.get("source") not in SOURCES:
            raise ValueError("invalid source")
        if fields.get("kind") not in KINDS:
            raise ValueError("invalid kind")
        retracts = tuple(fields.get("retracts") or ())
        if len(retracts) > MAX_RETRACTS:
            raise ValueError("too many retractions in one event")
        super().__init__(schema_version=SCHEMA_VERSION, sequence=None, generation=0, revision=0,
                         reason_code=None, budget=None)
        self.update(fields)
        self["retracts"] = list(retracts)

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name) from None


class SessionGenerations:
    """Tracks the generation of each session id within one capture: a new SYN on a known tuple bumps it."""

    def __init__(self):
        self._generation = {}

    def current(self, session_id):
        return self._generation.get(session_id, 0)

    def renew(self, session_id):
        self._generation[session_id] = self._generation.get(session_id, 0) + 1
        return self._generation[session_id]


def wrap(event, capture_id, generations=None, revision=0, quality="intact"):
    """Compatibility adapter: turn one legacy live event into an Envelope without changing the payload.

    `event` is a dict as live_capture.py / poc_decryption emit today. Retractions are derived from a
    `capture_gap`: its `active_connections` (session ids when the producer knows them) or, with scope
    `all_observations_this_capture`, the marker "*" meaning every session of this capture.
    """
    kind = event.get("type", "session")
    if kind not in KINDS:
        raise ValueError("unknown event type " + repr(kind))
    client = event.get("client") or event.get("source")
    server = event.get("server") or event.get("destination")
    session_id = session_identity(event.get("transport", "tcp"), client, server) if client and server else None
    generation = generations.current(session_id) if generations is not None and session_id else 0
    layer = {"session": "application", "classification": "outer", "decryption": "inner",
             "capture_gap": "capture", "error": "capture", "summary": "capture", "started": "capture",
             "progress": "capture"}[kind]
    source = "decrypted" if kind == "decryption" else "capture" if layer == "capture" else "wire"
    budget = None
    status = event.get("status") or event.get("engine_status")
    if status == "budget_exhausted":
        budget = {"exhausted": True, "scope": event.get("scope") or "inspection"}
    retracts = []
    if kind == "capture_gap":
        quality = "degraded"
        if event.get("scope") == "all_observations_this_capture":
            retracts = ["*"]
        else:
            retracts = list(event.get("session_ids") or [])
    reason_code = _reason_code(kind, event, status)
    return Envelope(capture_id=capture_id, session_id=session_id, generation=generation, layer=layer,
                    revision=revision, kind=kind, source=source, quality=quality, reason_code=reason_code,
                    budget=budget, retracts=retracts, payload=event)


def _reason_code(kind, event, status):
    if kind == "capture_gap":
        return "capture.loss" if "loss" in str(event.get("reason", "")).lower() else "capture.gap"
    if kind == "error":
        return "capture.error"
    if status:
        return "engine." + str(status)
    return None


class EventLog:
    """Bounded, sequenced log of envelopes for one capture, read by cursor.

    `append` assigns the sequence. `read(cursor)` yields what came after that sequence; a consumer whose
    cursor is older than the oldest retained event gets `reset_required` and must rebuild from `snapshot`.
    Appending never blocks and never grows past `retention`: the oldest events drop and the start moves.
    """

    def __init__(self, capture_id, retention=DEFAULT_RETENTION):
        if not 1 <= retention <= 1_000_000:
            raise ValueError("retention outside 1..1000000")
        self.capture_id = capture_id
        self.retention = retention
        self._events = deque()
        self._next = 1
        self._start = 1          # sequence of the oldest retained event
        self._generations = SessionGenerations()
        self._revision = {}      # (session_id, generation) -> last revision assigned

    @property
    def generations(self):
        return self._generations

    def append(self, envelope):
        if envelope["capture_id"] != self.capture_id:
            raise ValueError("event from another capture")
        if envelope.get("sequence") is not None:
            raise ValueError("producers never assign sequences")
        key = (envelope["session_id"], envelope["generation"])
        if envelope["session_id"] is not None:
            # Revision is per session generation and strictly increasing: a stale producer cannot win.
            envelope["revision"] = self._revision.get(key, 0) + 1
            self._revision[key] = envelope["revision"]
        envelope["sequence"] = self._next
        self._next += 1
        self._events.append(envelope)
        if len(self._events) > self.retention:
            self._events.popleft()
            self._start += 1
        return envelope["sequence"]

    def wrap_and_append(self, event, quality="intact"):
        return self.append(wrap(event, self.capture_id, self._generations, quality=quality))

    def read(self, cursor=0, limit=1000):
        """Events after `cursor`. Returns {"events": [...], "cursor": int, "reset_required": bool, "start": int}."""
        if not isinstance(cursor, int) or cursor < 0:
            raise ValueError("cursor must be a non-negative integer")
        if not 1 <= limit <= 10_000:
            raise ValueError("limit outside 1..10000")
        if cursor and cursor < self._start - 1:
            # The consumer missed events that are no longer retained; a window with a hole is never handed out.
            return {"events": [], "cursor": self._next - 1, "reset_required": True, "start": self._start}
        events = [e for e in self._events if e["sequence"] > cursor][:limit]
        new_cursor = events[-1]["sequence"] if events else max(cursor, self._next - 1)
        return {"events": events, "cursor": new_cursor, "reset_required": False, "start": self._start}

    def snapshot(self):
        """Every retained event, oldest first, with the cursor to continue from."""
        return {"events": list(self._events), "cursor": self._next - 1, "start": self._start,
                "retention": self.retention, "dropped": self._start - 1}

    def __len__(self):
        return len(self._events)


def reduce(envelopes, state=None):
    """Fold envelopes into a session view. Deterministic: replaying the same envelopes gives the same state.

    state = {
      "sessions": OrderedDict(session_id -> {"generation", "revision", "status", "session"|None,
                                            "classifications": [...], "decryption": ..., "retracted_by"}),
      "quality": str, "errors": [...], "summary": dict|None, "last_sequence": int, "retracted_total": int,
      "_seen": set of sequences already folded; reducer bookkeeping, not part of the view contract
                (public_state() drops it so the state serializes and compares across live/replay)
    }
    Rules:
      - an envelope whose sequence was already folded is a duplicate delivery and is ignored; the check is a
        set of seen sequences, not a high-water mark, so a late event with a lower sequence than one already
        folded is still applied (revision and generation, below, decide whether it changes anything);
      - an envelope with revision lower than the retained one for its (session, generation) is ignored;
      - a new generation replaces the previous generation's view for that session id (history stays in the log);
      - a retraction marks dependent sessions `retracted` (status, reason_code) but never deletes them, so a
        consumer can show "this verdict was withdrawn because of loss" instead of an unexplained disappearance;
      - inner-layer (decrypted) evidence depends on the capture being intact: a degrading retraction clears it.
    """
    if state is None:
        state = {"sessions": OrderedDict(), "quality": "intact", "errors": [], "summary": None,
                 "last_sequence": 0, "retracted_total": 0, "_seen": set()}
    sessions, seen = state["sessions"], state.setdefault("_seen", set())
    for e in envelopes:
        if e["sequence"] is not None:
            if e["sequence"] in seen:
                continue                            # duplicate delivery (re-polled window) is a no-op
            seen.add(e["sequence"])
            state["last_sequence"] = max(state["last_sequence"], e["sequence"])
        kind, sid = e["kind"], e["session_id"]
        if kind == "decryption" and sid is None and isinstance(e["payload"].get("report"), dict):
            # Stage 5 (A05): a decoder report is one event with many rows; each row carries its session id and
            # generation (stage 4), so the inner layer lands on the session view it belongs to.
            for row in e["payload"]["report"].get("connections") or ():
                row_sid = row.get("session_id")
                if not row_sid:
                    continue
                view = sessions.get(row_sid)
                generation = row.get("generation", 0)
                if view is None or generation > view["generation"]:
                    view = sessions[row_sid] = _new_view(generation)
                elif generation < view["generation"] or view["status"] == "retracted":
                    continue
                view["decryption"] = row
                _effective(view)
            continue
        if kind in ("summary", "progress"):
            state["summary"] = e["payload"]
        elif kind == "error":
            state["errors"].append({"sequence": e["sequence"], "reason_code": e["reason_code"],
                                    "reason": e["payload"].get("reason")})
        elif kind == "capture_gap":
            state["quality"] = "degraded"
            targets = sessions.keys() if "*" in e["retracts"] else [s for s in e["retracts"] if s in sessions]
            for target in list(targets):
                view = sessions[target]
                if view["status"] != "retracted":
                    state["retracted_total"] += 1
                view["status"] = "retracted"
                view["retracted_by"] = {"sequence": e["sequence"], "reason_code": e["reason_code"]}
                view["decryption"] = None       # inner evidence cannot outlive the capture it depended on
                _effective(view)
        elif sid is not None:
            view = sessions.get(sid)
            if view is None or e["generation"] > view["generation"]:
                # A new generation (tuple reuse) starts a fresh view; its revisions count from 1 again.
                view = sessions[sid] = _new_view(e["generation"])
            elif e["generation"] < view["generation"]:
                continue                        # an older generation never overwrites the current one
            elif e["revision"] <= view["revision"]:
                continue                        # a stale revision of the current generation never overwrites
            view["revision"] = e["revision"]
            if view["status"] == "retracted":
                continue                        # nothing after a retraction revives a verdict for that generation
            if kind == "session":
                view["session"] = e["payload"]
                view["status"] = "final"
            elif kind == "classification":
                view["classifications"].append(e["payload"])
            elif kind == "decryption":
                view["decryption"] = e["payload"]
            _effective(view)
    return state


def _new_view(generation):
    return {"generation": generation, "revision": 0, "status": "open", "session": None, "classifications": [],
            "decryption": None, "retracted_by": None, "effective": None}


def _effective(view):
    """Stage 5 (A05): the one answer for a session, from the layered view of its deepest intact layer.

    The decoder's row wins while it holds a layered view (it includes the wire layers); otherwise the
    session record's own layered view; otherwise the flat session verdict. Logs, tables and exports that
    read `effective` therefore agree on e.g. tls -> http/1.1 -> webdav.
    """
    source = None
    for candidate in (view.get("decryption"), view.get("session")):
        if isinstance(candidate, dict) and isinstance(candidate.get("layers"), dict):
            source = candidate["layers"]
            break
    if source is not None:
        view["effective"] = {"app": source["application"]["name"], "basis": source["application"]["basis"],
                             "chain": list(source["chain"]), "status": source["application"]["status"], "from": "layers"}
    elif isinstance(view.get("session"), dict):
        session = view["session"]
        chain = [x for x in (session.get("encryption"), session.get("client_protocol") or session.get("server_protocol"), session.get("app")) if x]
        view["effective"] = {"app": session.get("app"), "basis": None, "chain": list(dict.fromkeys(chain)),
                             "status": session.get("engine_status"), "from": "session"}
    else:
        view["effective"] = None
    return view["effective"]


def public_state(state):
    """The reduced state without reducer bookkeeping: JSON-serializable and comparable across live and replay."""
    return {key: value for key, value in state.items() if not key.startswith("_")}
