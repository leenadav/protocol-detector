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

from .analyze_pcap import Analyzer
from .events import SessionGenerations, session_identity
from .sessions import StreamError

END_REASON = "Capture stopped before initial message completed"


class SessionCoordinator:
    def __init__(self, analyzer=None, capture_id=None, emit=None, **analyzer_options):
        self.capture_id = capture_id or secrets.token_hex(8)
        self.generations = SessionGenerations()
        self.emit = emit
        self._ended = False
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
        self.counts = {"ticks": 0, "finalized": 0, "duplicates_suppressed": 0, "gaps": 0, "generations": 0}

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
        if transport == "tcp" and packet.flags & 2 and not packet.flags & 16:
            key = self.analyzer.manager.key(packet.source, packet.destination)
            if key in self.analyzer.tracked:
                # A fresh SYN on a tracked key: finalize the old generation first, then start the next.
                self.analyzer.drop(key, "Connection restarted (new SYN on a tracked tuple)")
                self.renew(transport, packet.source, packet.destination)
        return self.analyzer.process(now, packet)

    # ----- lifecycle operations ------------------------------------------------
    def tick(self, now):
        """Advance injected time; idle expiration happens here, never on packet arrival alone."""
        if self._ended:
            return
        self.now = max(self.now, now)
        self.counts["ticks"] += 1
        self.analyzer.expire(self.now)

    def gap(self, reason, scope="active_connections"):
        """Capture loss or truncation: name and retract every active session, then drop their state."""
        self.counts["gaps"] += 1
        retracted = sorted({session_identity("tcp", s["client"], s["server"]) for s in self.analyzer.tracked.values()})
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

    def end(self, reason=END_REASON):
        """Finalize everything still tracked, exactly once. Safe to call more than once."""
        if self._ended:
            return False
        self._ended = True
        self.analyzer.finish(reason)
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
