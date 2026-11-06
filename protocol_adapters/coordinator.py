"""SessionCoordinator: one owner of connection lifecycle for every capture path (stage 3, A03/A04).

The normal live path drove the Analyzer's lifecycle itself (expire on each loop, finish at stop); the
decryption live path and the offline decryption adapter never called either, so a connection without FIN
got no final session when they stopped (A04, reproduced in tools/stage0_baseline.py and in
presentation/tests/test_live_decryption.py::LiveShutdownWiringTests). Each path also kept its own flow
table over the same Stream class (A03).

This coordinator is the single place that owns the lifecycle. Time is injected: nothing here reads a clock,
so tests and replays are deterministic and offline captures drive it with packet timestamps. The
operations are the ones the review names:

    tick(now)        advance time; idle connections and flows expire exactly once
    end(reason)      finalize everything still tracked exactly once (capture stop, EOF, operator stop)
    gap(reason)      capture loss or truncation: retract every active session (named ids) and drop state

Identity: every session carries the coordinator's capture_id and a generation from SessionGenerations,
bumped when a tracked tuple starts over (SYN on a known key). The Analyzer stays the connection table and
the App-ID source; the coordinator adds ownership, identity and exactly-once semantics around it, and
exposes stream deltas so a second consumer (the TLS decoder, stage 4) reads bytes from the same owner.
"""
import secrets
import weakref
from collections import deque

from .analyze_pcap import Analyzer
from .events import SessionGenerations, session_identity
from .sessions import MODULUS, Stream, StreamError

END_REASON = "Capture stopped before initial message completed"
SYN, FIN, RST, ACK = 2, 1, 4, 16


class _NoInspector:
    """A Stream needs an inspector; the retained tier only reassembles, so this one does nothing."""
    observation = candidate = boundary = None

    def feed(self, data):
        return ()

    def invalidate(self, reason):
        return ()

    def end(self, reason):
        return ()


class RetentionBudget:
    """Aggregate limits for the retained reassembly tier (stage 4, A07): explicit, counted rejections.

    per_direction  bytes one direction may retain (its Stream limit)
    aggregate      bytes all retained streams together may have allocated
    connections    retained connections at once
    pending        queued consumer events before the run is declared exhausted
    """
    def __init__(self, per_direction=262144, aggregate=4 * 1024 * 1024, connections=64, pending=8192):
        if not (1 <= per_direction <= 1 << 24 and aggregate >= per_direction and connections >= 1 and pending >= 16):
            raise ValueError("Invalid retention budget")
        self.per_direction, self.aggregate, self.connections, self.pending = per_direction, aggregate, connections, pending


class SessionCoordinator:
    def __init__(self, analyzer=None, capture_id=None, emit=None, retain=None, idle_timeout=60, **analyzer_options):
        self.capture_id = capture_id or secrets.token_hex(8)
        self.generations = SessionGenerations()
        self.emit = emit
        self._ended = False
        # Stage 4 (A03/A07): the retained tier. The Analyzer keeps only the bounded initial window and retires a
        # connection once its verdict is terminal; a consumer that needs the whole bounded stream (the TLS
        # decoder) reads it here, from the same owner and the same Stream class, never from its own flow table.
        self.retain = retain            # RetentionBudget or None (no retained tier)
        self.retained = {}              # key -> {"client","server","streams":{endpoint: Stream},"fin":{}, "error","time","sid","generation"}
        self.retained_allocated = 0
        self.idle_timeout = idle_timeout
        self._pending = deque()         # consumer events: ("open"|"data"|"error"|"close", key, ...)
        self._retired_sessions = set()       # (session_id, generation) already finalized: never twice
        self._session_hook = analyzer_options.pop("on_session", None)
        # The analyzer must not retain its owner through a bound-method cycle (test_lifecycle guards this
        # with gc disabled): the sink reaches the coordinator through a weak reference, like CaptureMonitor.
        reference = weakref.ref(self)

        def sink(record):
            owner = reference()
            if owner is not None:
                owner._on_session(record)
        self._sink = sink
        if analyzer is None:
            analyzer = Analyzer(on_session=sink, **analyzer_options)
        else:
            if analyzer.on_session is not None and analyzer.on_session is not sink:
                self._session_hook = analyzer.on_session
            analyzer.on_session = sink
        self.analyzer = analyzer
        self.now = 0.0
        self.counts = {"ticks": 0, "finalized": 0, "duplicates_suppressed": 0, "gaps": 0, "generations": 0,
                       "retained_opened": 0, "retained_closed": 0, "retained_rejected_connections": 0,
                       "retained_rejected_bytes": 0, "retained_errors": 0, "pending_overflow": 0}

    # ----- identity ---------------------------------------------------------
    def identity(self, transport, client, server):
        sid = session_identity(transport, client, server)
        return sid, self.generations.current(sid)

    def renew(self, transport, client, server):
        """A tracked tuple starts a new connection: the next session on it is a new generation."""
        sid = session_identity(transport, client, server)
        self.counts["generations"] += 1
        return self.generations.renew(sid)

    # ----- the one session sink --------------------------------------------
    def _on_session(self, record):
        sid, generation = self.identity(record["transport"], record["client"], record["server"])
        key = (sid, generation)
        if key in self._retired_sessions:
            # The Analyzer can only emit a session once per drop, but a path that both expires and
            # finishes, or that replays, must still never publish the same (session, generation) twice.
            self.counts["duplicates_suppressed"] += 1
            return
        self._retired_sessions.add(key)
        self.counts["finalized"] += 1
        record = dict(record, capture_id=self.capture_id, session_id=sid, generation=generation)
        if self._session_hook is not None:
            self._session_hook(record)
        if self.emit is not None:
            self.emit(record)

    # ----- packets ------------------------------------------------------------
    def accept(self, packet, now):
        """Hand one decoded TCP/UDP packet to the owner; tuple reuse on a SYN renews the generation."""
        self.now = max(self.now, now)
        transport = "tcp" if hasattr(packet, "flags") else "udp"
        if transport == "tcp" and packet.flags & SYN and not packet.flags & ACK:
            key = self.analyzer.manager.key(packet.source, packet.destination)
            if key in self.analyzer.tracked or key in self.retained:
                # A fresh SYN on a tracked key: finalize the old generation first, then start the next.
                if key in self.analyzer.tracked:
                    self.analyzer.drop(key, "Connection restarted (new SYN on a tracked tuple)")
                if key in self.retained:
                    self._retained_close(key, "Connection restarted (new SYN on a tracked tuple)")
                self.renew(transport, packet.source, packet.destination)
        message = self.analyzer.process(now, packet)
        if transport == "tcp" and self.retain is not None:
            self._retain(packet)
        return message

    # ----- retained tier (stage 4) ------------------------------------------------
    def _queue(self, item):
        if len(self._pending) >= self.retain.pending:
            self.counts["pending_overflow"] += 1
            raise StreamError("Retained consumer queue exhausted; the consumer must drain between packets")
        self._pending.append(item)

    def _retained_error(self, key, state, reason):
        if state["error"] is None:
            state["error"] = reason
            self.counts["retained_errors"] += 1
            self._queue(("error", key, reason))

    def _retained_close(self, key, reason):
        state = self.retained.pop(key, None)
        if state is None:
            return
        for stream in state["streams"].values():
            self.retained_allocated -= stream.allocated
        self.counts["retained_closed"] += 1
        self._queue(("close", key, reason, self._progress(state)))

    @staticmethod
    def _progress(state):
        """Per direction: contiguous and stored byte counts plus the FIN offset (None without FIN)."""
        out = {}
        for endpoint, stream in state["streams"].items():
            fin = state["fin"].get(endpoint)
            out[endpoint] = {"contiguous": stream.contiguous, "stored": stream.stored,
                             "fin": None if fin is None else (fin - stream.first_sequence) % MODULUS}
        return out

    def _retain(self, packet):
        """Reassemble the bounded full stream for a consumer, under the retention budget (A03, A07)."""
        key = self.analyzer.manager.key(packet.source, packet.destination)
        state = self.retained.get(key)
        flags = packet.flags
        if flags & RST:
            if state is not None:
                self._retained_close(key, "Observed RST; retained stream ended")
            return
        if flags & SYN:
            first = (packet.sequence + 1) % MODULUS
            if state is None:
                if flags & ACK:
                    return                                   # SYN-ACK without its SYN: origin unknown
                if len(self.retained) >= self.retain.connections:
                    self.counts["retained_rejected_connections"] += 1
                    return
                sid = session_identity("tcp", packet.source, packet.destination)
                state = self.retained[key] = {"client": packet.source, "server": packet.destination, "streams": {},
                                              "fin": {}, "error": None, "time": self.now, "sid": sid,
                                              "generation": self.generations.current(sid)}
                self.counts["retained_opened"] += 1
                self._queue(("open", key, packet.source, packet.destination, sid, state["generation"]))
            state["time"] = self.now
            previous = state["streams"].get(packet.source)
            if previous is not None:
                if previous.first_sequence != first:
                    self._retained_error(key, state, "Connection tuple reuse is outside the POC profile.")
                return
            if flags & ACK and packet.source != state["server"]:
                self._retained_error(key, state, "Inconsistent SYN-ACK direction.")
                return
            state["streams"][packet.source] = Stream(first, self.retain.per_direction, _NoInspector, compatibility=False)
            if packet.payload:
                self._retained_error(key, state, "SYN with data (Fast Open) is outside the POC profile.")
            return
        if state is None:
            return
        state["time"] = self.now
        stream = state["streams"].get(packet.source)
        if packet.payload:
            if stream is None:
                self._retained_error(key, state, "TCP SYN is missing; stream origin cannot be established.")
            elif state["error"] is None:
                before = stream.allocated
                grow = max(0, (packet.sequence - stream.first_sequence) % MODULUS + len(packet.payload) - len(stream.buffer))
                if self.retained_allocated + 2 * grow > self.retain.aggregate:
                    self.counts["retained_rejected_bytes"] += len(packet.payload)
                    self._retained_error(key, state, "Aggregate reassembly budget exhausted; this connection is not decoded.")
                else:
                    try:
                        stream.feed((packet.sequence + bool(flags & SYN)) % MODULUS, packet.payload)
                    except StreamError as error:
                        self._retained_error(key, state, str(error))
                    finally:
                        self.retained_allocated += stream.allocated - before
                    delta = stream.deltas() if state["error"] is None else None
                    if delta is not None:
                        self._queue(("data", key, packet.source, delta))
        if flags & FIN and packet.source not in state["fin"]:
            state["fin"][packet.source] = (packet.sequence + len(packet.payload)) % MODULUS
            if len(state["fin"]) == 2 and len(state["streams"]) == 2:
                # Both directions ended. The streams stay retained until idle timeout, end() or a gap, so a late
                # conflicting retransmission still invalidates (AGENTS.md: conflicting retained overlaps
                # invalidate before new bytes are admitted); the consumer may finalize its view now.
                self._queue(("fin", key, self._progress(state)))

    def drain(self):
        """Consumer events queued since the last call, in order; each delta is handed out exactly once."""
        items = list(self._pending)
        self._pending.clear()
        return items

    def retained_bytes(self):
        return self.retained_allocated

    # ----- lifecycle operations ------------------------------------------------
    def tick(self, now):
        """Advance injected time; idle expiration happens here, never on packet arrival alone."""
        if self._ended:
            return
        self.now = max(self.now, now)
        self.counts["ticks"] += 1
        self.analyzer.expire(self.now)
        for key, state in list(self.retained.items()):
            if self.now - state["time"] >= self.idle_timeout:
                self._retained_close(key, "Idle timeout; retained stream ended")

    def gap(self, reason, scope="active_connections"):
        """Capture loss or truncation: name and retract every active session, then drop their state."""
        self.counts["gaps"] += 1
        retracted = sorted({session_identity("tcp", s["client"], s["server"]) for s in self.analyzer.tracked.values()}
                           | {s["sid"] for s in self.retained.values()})
        if self.emit is not None and (retracted or scope == "all_observations_this_capture"):
            self.emit({"type": "capture_gap", "active_connections": len(retracted), "scope": scope,
                       "reason": reason, "session_ids": retracted, "capture_id": self.capture_id})
        for key in list(self.analyzer.tracked):
            state = self.analyzer.tracked[key]
            sid = session_identity("tcp", state["client"], state["server"])
            self._retired_sessions.add((sid, self.generations.current(sid)))   # retracted, never finalized
        self.analyzer.tracked.clear()
        self.analyzer.udp_flows.clear()
        self.analyzer.quic_assembler.clear()
        self.analyzer.manager.connections.clear()
        for key in list(self.retained):
            state = self.retained[key]
            self._retained_error(key, state, reason)
            self._retained_close(key, reason)

    def end(self, reason=END_REASON):
        """Finalize everything still tracked, exactly once. Safe to call more than once."""
        if self._ended:
            return False
        self._ended = True
        self.analyzer.finish(reason)
        for key in list(self.retained):
            self._retained_close(key, reason)
        return True

    # ----- deltas for a second consumer -----------------------------------------
    def deltas(self, client, server):
        """StreamDeltas for both directions of one connection since the last call: {endpoint: delta|None}."""
        key = self.analyzer.manager.key(client, server)
        connection = self.analyzer.manager.connections.get(key)
        if connection is None:
            return {}
        out = {}
        for endpoint, stream in connection["directions"].items():
            try:
                out[endpoint] = stream.deltas()
            except StreamError:
                out[endpoint] = None
        return out
