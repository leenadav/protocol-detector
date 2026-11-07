"""Offline PCAP analysis. No capture privileges or network access required."""
import argparse
import json
import weakref
from dataclasses import asdict, replace
from collections import Counter
from functools import partial
from .link_packets import CHECKSUM_POLICIES, decode_frame
from .packets import CaptureError, PacketError, UDPPacket, read_pcap_records
from protocol_engine import Config, DatagramInspector, Event, Inspector, SignatureSet
from .layers import layered_view
from protocol_engine.continuation import continuation_summary
from protocol_engine import content as detection_content
from protocol_engine.unknown import session_unknown
from .observability import Telemetry
from .quality import InputQuality
from protocol_engine.appid import classify, midstream_outcome, session_verdict, unobserved_start_outcome, verdict_fields
from protocol_engine.descriptors import MIDSTREAM_FAMILIES, OBSERVATION_MODES
from protocol_engine.policy import Policy, PolicyError
from protocol_engine.registry import PARSERS
from protocol_engine.datagram import VALIDATORS
from protocol_engine.quic import QuicAssembler
from protocol_engine.x509 import validity
from .sessions import MODULUS, SessionManager, StreamError

SYN, ACK, FIN, RST, URG = 2, 16, 1, 4, 32


def certificate_fields(observations, at):
    """Certificate structure labels from the observations, plus validity at capture time `at` (v0.57).

    `at` is the capture timestamp (POSIX seconds) of the session's first packet or
    of the live event; validity is never judged against the analysis run's clock.
    """
    certificate = {evidence.field[16:]: evidence.value for obs in observations if obs is not None
                   for evidence in obs.evidence if evidence.field.startswith("tls_certificate_")}
    label = validity(certificate.get("not_before"), certificate.get("not_after"), at)
    if label is not None:
        certificate["validity"] = label
    return certificate


class Analyzer:
    """Bounded connection tracking plus per-session application verdicts.

    on_retire receives directional terminal events. on_session receives one
    JSON-friendly record per TCP connection or UDP flow when tracking ends,
    carrying the App-ID style verdict for the whole session. Both callbacks are
    synchronous and bounded by the connection/flow tables; no queue is kept.
    """
    def __init__(self, max_connections=32, byte_limit=65536, idle_timeout=60, compact=False, udp_hint=None, tcp_hint=None,
                 crc32c_byte_limit=4096, on_retire=None, on_session=None, max_udp_flows=None, include_hostnames=False,
                 signatures=None, fingerprints=False, heuristics=False, policy=None, certificates=False, observation="handshake",
                 continuation=0):
        if observation not in OBSERVATION_MODES:
            raise ValueError("observation must be one of " + ", ".join(OBSERVATION_MODES))
        self.observation = observation      # D05: handshake (default), asymmetric or midstream
        for callback in (on_retire, on_session):
            if callback is not None and not callable(callback):
                raise TypeError("Analyzer callbacks must be callable")
        self.on_retire = on_retire
        self.on_session = on_session
        self.include_hostnames = bool(include_hostnames)
        self.compact = compact
        if udp_hint is not None and udp_hint not in VALIDATORS:
            raise ValueError("Unsupported UDP candidate hint")
        self.udp_hint = udp_hint
        self.next_expiry = float("-inf")
        if signatures is not None and not isinstance(signatures, SignatureSet):
            raise TypeError("signatures must be a SignatureSet")
        self.signatures = signatures if signatures is not None and len(signatures) else None
        if policy is not None and not isinstance(policy, Policy):
            raise TypeError("policy must be a Policy")
        self.policy = policy
        self.inspection_config = Config(max_bytes=byte_limit, max_crc32c_bytes=crc32c_byte_limit,
                                        retain_contexts=self.signatures is not None, fingerprints=bool(fingerprints),
                                        heuristics=bool(heuristics), certificates=bool(certificates),
                                        continuation=int(continuation))
        self.content = detection_content.pinned()       # D08: the content release every record of this run names
        self.quic_assembler = QuicAssembler(idle_seconds=idle_timeout)   # D01: scoped per flow, expires with the flow table
        self.udp = DatagramInspector(self.inspection_config, self.signatures, self.quic_assembler)
        self.udp_revision = 0
        self.now = 0
        if tcp_hint is not None:
            Inspector(protocol_hint=tcp_hint)  # Validate before processing packets.
        factory = partial(Inspector, config=self.inspection_config, protocol_hint=tcp_hint, signatures=self.signatures)
        clock_owner = weakref.proxy(self)
        self.manager = SessionManager(clock=lambda: clock_owner.now, max_connections=max_connections,
                                      byte_limit=byte_limit, idle_timeout=idle_timeout,
                                      inspector_factory=factory,
                                      compatibility=not compact, expiry_interval=1 if compact else 0, prefix_only=compact)
        self.tracked = {}
        self.last_events = ()
        self.last_classification = None
        self.last_server = None
        # Events a correlation produced on the other direction of the packet's connection, as
        # (source, destination, event): replayed bytes publish there, not on the packet's direction.
        self.peer_events = ()
        self._replayed = []
        self.retiring = None
        self.max_udp_flows = max_connections if max_udp_flows is None else max_udp_flows
        if not 0 <= self.max_udp_flows <= 65536:
            raise ValueError("Invalid UDP flow table limit")
        self.quic_assembler.max_connections = max(1, min(self.max_udp_flows, 1024))
        self.udp_flows = {}
        self.counts = Counter()
        self.telemetry = Telemetry()      # stage 7 (A15): one registry per capture path, shared with its owners

    # ----- session records -------------------------------------------------
    def _record(self, transport, client, server, state, verdict, reason, observations, inspectors=(None, None)):
        record = {"type": "session", "transport": transport, "client": client, "server": server,
                  "start": state["start"], "end": self.now, "packets": state["packets"],
                  "client_bytes": state["bytes"].get(client, 0), "server_bytes": state["bytes"].get(server, 0),
                  "end_reason": reason}
        record.update(verdict_fields(verdict))
        record["content"] = self.content
        unknown = session_unknown(verdict, observations[0], observations[1], inspectors[0], inspectors[1],
                                  mode=state.get("mode", "handshake"), handshake=transport != "tcp" or bool(state.get("ready")))
        if unknown:
            record["unknown"] = unknown                                 # D12: why this was not an identification, per direction
        # D05: how the connection was observed. Roles are assumed from the first segment in midstream mode.
        record["observation"] = {"mode": state.get("mode", "handshake" if transport == "tcp" else "datagram"),
                                 "handshake_observed": transport == "tcp" and state.get("mode", "handshake") == "handshake" and bool(state.get("ready")),
                                 "directions_seen": sorted(["client" if endpoint == client else "server" for endpoint in state["bytes"] if state["bytes"].get(endpoint)]),
                                 "roles": "assumed-from-first-segment" if state.get("mode") == "midstream" else "observed"}
        continuation = continuation_summary(observations[0], observations[1])
        if continuation:
            record["continuation"] = continuation                   # D07: what followed the identification, per direction
        quality = "intact"
        if state.get("input"):
            record["input_quality"] = dict(state["input"])          # D06: this flow was not fully inspected
            quality = "degraded"
        # Stage 5 (A05/A13): the layered view, from the same observations and verdict; labels only.
        record["layers"] = layered_view(transport, observations[0], observations[1], verdict, server[1],
                                        state["bytes"].get(client, 0), state["bytes"].get(server, 0), capture_quality=quality)[0]
        if self.signatures is not None:
            record["signature_set"] = self.signatures.digest      # stage 7 (A11): the rule set this verdict used
        # Latency telemetry (P2 of the stage-6 review): the session's lifetime is not its decision time.
        self.telemetry.observe("session_lifetime_seconds", max(0.0, self.now - state["start"]))
        if state.get("first_decision") is not None:
            self.telemetry.observe("time_to_first_decision_seconds", max(0.0, state["first_decision"] - state["start"]))
            self.telemetry.observe("time_to_stable_verdict_seconds", max(0.0, state["stable_at"] - state["start"]))
            record["decision"] = {"first_seconds": round(state["first_decision"] - state["start"], 6),
                                  "stable_seconds": round(state["stable_at"] - state["start"], 6)}
        self.telemetry.add("sessions." + verdict.status)
        if self.policy is not None:
            # D04: the decision sees the typed evidence contract (identity basis, activity, affiliation,
            # decryption state, capture quality), never a confidence number.
            record["policy"] = self.policy.evaluate(verdict, transport, server[1], layers=record["layers"],
                                                    observation=record["observation"]["mode"]).fields()
        fingerprints = {evidence.field: evidence.value for obs in observations if obs is not None
                        for evidence in obs.evidence if evidence.strength == "derived"}
        if fingerprints:
            record["fingerprints"] = fingerprints
        certificate = certificate_fields(observations, state["start"])
        if certificate:
            record["certificate"] = certificate  # structure labels only (v0.39): no names, serials or keys
        if self.include_hostnames:
            record["hostname"] = next((obs.hostname for obs in observations if obs is not None and obs.hostname), None)
        self.counts["sessions"] += 1
        self.on_session(record)

    def note_input(self, kind, endpoints):
        """D06: a packet of this flow was rejected or suspect (fragment, length, checksum, truncated). The flow is
        marked so its record never reads as fully inspected; a truncated TCP record ends the connection, since
        bytes are missing from the stream. Returns True when a tracked flow was marked."""
        if endpoints is None:
            return False
        key = self.manager.key(*endpoints)
        state = self.tracked.get(key) or self.udp_flows.get(key)
        if state is None:
            return False
        state.setdefault("input", {})
        state["input"][kind] = state["input"].get(kind, 0) + 1
        if kind == "truncated" and key in self.tracked:
            self.drop(key, "Capture record truncated; stream bytes missing")
        return True

    def _decided(self, state, label):
        """Record when a flow or connection was first identified and when its label last changed."""
        if state.get("first_decision") is None:
            state["first_decision"] = self.now
        if state.get("label") != label:
            state["label"], state["stable_at"] = label, self.now

    def _open_shift(self, state, endpoint, boundary, expected=None):
        """Open a peer-decided phase on one direction's stream and keep the events its replay published."""
        connection = self.manager.connections[self.manager.key(state["client"], state["server"])]
        stream = connection["directions"][endpoint]
        if not stream.open_shift(boundary, expected):
            return False
        other = state["server"] if endpoint == state["client"] else state["client"]
        self._replayed.append((endpoint, other, stream.events))
        return True

    def _correlate_connect(self, key, state):
        """Open the tunnel phase on the server direction of a CONNECT once its 2xx answer is seen.

        The client request announces the http-connect shift by itself; the server's
        2xx cannot (a 200 without body framing looks like any other reply), so the
        host correlates both directions and asks the server Inspector to inspect its
        later bytes as the tunnel (usually the TLS ServerHello). Nothing is retracted:
        the server stays identified as HTTP until the shifted phase publishes.
        """
        connection = self.manager.connections.get(key)
        if connection is None:
            return
        client = connection["directions"][state["client"]].inspector
        request, response = client.observation, connection["directions"][state["server"]].inspector.observation
        if response.status != "identified" or not (response.application_protocol or "").startswith("http/"):
            return
        if request.status != "identified" or not any(
                (e.field == "http_method" and e.value == "CONNECT") or (e.field == "shift" and e.value == "http-connect") for e in request.evidence):
            return
        status = next((e.value for e in response.evidence if e.field == "http_status"), "")
        if status[:1] == "2" and self._open_shift(state, state["server"], "http-connect"):
            # The stream replays a ServerHello that shared the 2xx's segment (v0.54, review round 2).
            self.counts["connect_tunnels_correlated"] += 1

    def _correlate_ldap(self, key, state):
        """Open the TLS phase of an LDAP StartTLS exchange once the server's success answers the client's request.

        The client's StartTLS ExtendedRequest decides nothing on its own: the client
        must wait for the answer and continues in plaintext after a refusal, so its
        direction is opened here only when the server's ExtendedResponse carries
        resultCode success for the same message id. A response that names the
        StartTLS OID shifts the server direction by itself; RFC 4511 lets the server
        omit the responseName, and that unnamed success is opened here as well, again
        only with a matching message id (v0.54, review round 1). Bytes a direction
        already carried past its LDAP message are replayed into the opened phase by
        the stream (review round 2).
        """
        connection = self.manager.connections.get(key)
        if connection is None:
            return
        client, server = connection["directions"][state["client"]].inspector, connection["directions"][state["server"]].inspector
        request, response = client.observation, server.observation
        if request.status != "identified" or response.status != "identified" or response.application_protocol != "ldap":
            return
        asked = {e.field: e.value for e in request.evidence if e.field in ("ldap_message", "ldap_extended")}
        if asked != {"ldap_message": "extended_request", "ldap_extended": "starttls"}:
            return
        answered = {e.field: e.value for e in response.evidence if e.field in ("ldap_message", "ldap_extended", "ldap_result")}
        if answered.get("ldap_message") != "extended_response" or answered.get("ldap_result") != "success" \
                or answered.get("ldap_extended") not in ("starttls", "unnamed"):
            return
        ids = [(inspector.correlation or {}).get("ldap_message_id") for inspector in (client, server)]
        if ids[0] is None or ids[0] != ids[1]:
            return
        # Opening through the streams replays bytes the inspectors skipped while terminal: a ClientHello
        # recorded before the server's answer, or a ServerHello coalesced with the response (review round 2).
        opened = self._open_shift(state, state["client"], "ldap-starttls", "tls")
        if answered["ldap_extended"] == "unnamed":
            opened = self._open_shift(state, state["server"], "ldap-starttls", "tls") or opened
        if opened:
            self.counts["ldap_starttls_correlated"] += 1

    def _correlate_http2(self, key, state):
        """Expect HTTP/2 on the server direction once the client's preface identified the connection.

        With prior knowledge (RFC 9113 3.3, including after ALPN) the server's first
        frame is a bare SETTINGS frame that no prefix routes anywhere. The client
        preface decides the family; the server bytes still have to validate as
        SETTINGS and HEADERS. Only a direction that has not sent anything yet adopts
        the expectation.
        """
        connection = self.manager.connections.get(key)
        if connection is None:
            return
        client = connection["directions"][state["client"]].inspector
        server = connection["directions"][state["server"]].inspector
        request = client.observation
        if request.status != "identified" or request.application_protocol != "http/2" or any(e.field == "shift" for e in request.evidence):
            return
        if server.expect("http2-server", "http2-preface"):
            self.counts["http2_servers_expected"] += 1

    def _tcp_session(self, key, state, connection, reason):
        if self.on_session is None:
            return
        client, server = state["client"], state["server"]
        client_obs = server_obs = None
        inspectors = (None, None)
        if connection is not None:
            inspectors = (connection["directions"][client].inspector, connection["directions"][server].inspector)
            client_obs = connection["directions"][client].inspector.observation
            server_obs = connection["directions"][server].inspector.observation
            seen = sum(state["bytes"].values())
            unique = sum(stream.stored for stream in connection["directions"].values())
            self.telemetry.add("bytes.new", min(seen, unique))
            self.telemetry.add("bytes.replayed", max(0, seen - unique))
            self.telemetry.add("signatures.candidates", sum(stream.inspector.metrics.signature_candidates
                                                            for stream in connection["directions"].values()))
        verdict = session_verdict(client_obs, server_obs, "tcp", server[1], state["bytes"].get(client, 0),
                                  state["bytes"].get(server, 0), handshake_complete=state["ready"], signatures=self.signatures,
                                  at=state["start"])
        if state.get("mode") == "midstream":
            # D05: midstream recognition is conservative. Only families whose profile recurs at every message
            # boundary may be identified; anything else is an incomplete observation, never unknown-tcp.
            if verdict.identified:
                family = (verdict.client_protocol or verdict.server_protocol or "").split("/", 1)[0]
                if family not in MIDSTREAM_FAMILIES:
                    verdict = midstream_outcome("tcp", family or verdict.app)
            elif verdict.app in ("unknown-tcp", "incomplete", "insufficient-data"):
                verdict = unobserved_start_outcome("tcp", verdict.reasons[0] if verdict.reasons else "no reason")
        self._record("tcp", client, server, state, verdict, reason, (client_obs, server_obs), inspectors)

    def _udp_session(self, key, flow, reason):
        self.quic_assembler.reset((flow["client"], flow["server"]))     # D01: the flow's CRYPTO state ends with it
        if self.on_session is None:
            return
        # v0.43: both directions contribute. The client datagram decides as before; a server
        # datagram (DNS response, SNMP response or trap) adds its evidence and risks.
        client_obs = flow["observation"]
        server_obs = flow["observations"].get(flow["server"])
        if server_obs is None:
            verdict = classify(client_obs, "udp", flow["server"][1], flow["bytes"].get(flow["client"], 0), self.signatures)
        else:
            verdict = session_verdict(client_obs, server_obs, "udp", flow["server"][1], flow["bytes"].get(flow["client"], 0),
                                      flow["bytes"].get(flow["server"], 0), True, self.signatures)
        self._record("udp", flow["client"], flow["server"], flow, verdict, reason, (client_obs, server_obs))

    def server_endpoint(self, packet):
        """Server endpoint for an event about this packet, when tracking knows it."""
        if isinstance(packet, UDPPacket):
            flow = self.udp_flows.get(self.manager.key(packet.source, packet.destination))
            return flow["server"] if flow is not None else packet.destination
        state = self.tracked.get(self.manager.key(packet.source, packet.destination))
        return state["server"] if state is not None else None

    # ----- lifecycle --------------------------------------------------------
    def drop(self, key, reason="Tracking ended before initial message completed"):
        connection = self.manager.connections.pop(key, None)
        state = self.tracked.pop(key, None)
        self.retiring = state  # Lets on_retire consumers read per-direction byte counts.
        try:
            if connection is not None:
                for source, stream in connection['directions'].items():
                    events = stream.inspector.end(reason)
                    if self.on_retire is not None:
                        destination = key[1] if source == key[0] else key[0]
                        for event in events:
                            self.on_retire(source, destination, event)
            if state is not None:
                self._tcp_session(key, state, connection, reason)
        finally:
            self.retiring = None

    def reject(self, key, source, reason):
        """Publish a directional retraction before releasing rejected TCP state."""
        connection = self.manager.connections.get(key)
        if connection is not None:
            stream = connection['directions'][source]
            self.last_events = stream.inspector.invalidate(reason)
            self.last_classification = stream.inspector.observation
        self.drop(key, reason)
        return "INVALIDATED: " + reason

    def finish(self, reason="Capture ended before initial message completed"):
        """Release all tracking; ending observation is not proof of TCP EOF."""
        if not isinstance(reason, str) or not reason or len(reason) > 256:
            raise ValueError("End reason must contain 1..256 characters")
        for key in tuple(self.tracked):
            self.drop(key, reason)
        for key in tuple(self.udp_flows):
            self._udp_session(key, self.udp_flows.pop(key), reason)

    def expire(self, timestamp):
        self.now = max(self.now, timestamp)
        if self.now < self.next_expiry:
            return
        self.next_expiry = self.now + (1 if self.compact else 0)
        for key, state in list(self.tracked.items()):
            if self.now - state["time"] >= self.manager.idle_timeout:
                self.drop(key, "Idle timeout before initial message completed")
        for key, flow in list(self.udp_flows.items()):
            if self.now - flow["time"] >= self.manager.idle_timeout:
                self._udp_session(key, self.udp_flows.pop(key), "Idle timeout")
        self.manager.expire()

    def _udp(self, packet):
        self.last_classification = self.udp.inspect(packet.payload, self.udp_hint, scope=(packet.source, packet.destination), now=self.now)
        self.udp_revision += 1
        self.last_events = (Event(self.udp_revision, "datagram", self.last_classification),)
        key = self.manager.key(packet.source, packet.destination)
        flow = self.udp_flows.get(key)
        if flow is None:
            if len(self.udp_flows) >= self.max_udp_flows:
                self.counts["udp_flow_limit"] += 1
            else:
                flow = self.udp_flows[key] = {"client": packet.source, "server": packet.destination, "start": self.now,
                                              "time": self.now, "packets": 0, "bytes": {}, "ready": True,
                                              "observation": self.last_classification, "observations": {},
                                              "first_decision": None, "stable_at": None, "label": None}
        if flow is not None:
            flow["time"] = self.now
            flow["packets"] += 1
            flow["bytes"][packet.source] = flow["bytes"].get(packet.source, 0) + len(packet.payload)
            latest = self.last_classification
            if latest.status == "invalidated":
                # D02: a contradiction in this direction withdraws the identification it had established.
                flow["observation"] = latest
                flow["observations"][packet.source] = latest
            else:
                # Keep the first identification; otherwise the latest outcome describes the flow.
                if flow["observation"].status != "identified":
                    flow["observation"] = latest
                # Per direction, the same rule: the first identified datagram of each side is kept.
                previous = flow["observations"].get(packet.source)
                if previous is None or previous.status != "identified":
                    flow["observations"][packet.source] = latest
            if latest.status == "identified":
                self._decided(flow, (latest.application_protocol or latest.encryption, latest.application))
        self.last_server = flow["server"] if flow is not None else packet.destination
        result = self.last_classification
        return "UDP {}:{} -> {}:{} | {} | {} | {}".format(
            *packet.source, *packet.destination, result.status.upper(),
            result.application_protocol or result.encryption or "unidentified", result.reason)

    def process(self, timestamp, packet):
        self.last_events = ()
        self.last_classification = None
        self.last_server = None
        self.peer_events = ()
        self._replayed = []
        self.now = max(self.now, timestamp)
        self.expire(self.now)
        if isinstance(packet, UDPPacket):
            return self._udp(packet)
        source, destination = packet.source, packet.destination
        key = self.manager.key(source, destination)
        state = self.tracked.get(key)
        if state is not None:
            self.last_server = state["server"]
            state["packets"] += 1
            if packet.payload:
                state["bytes"][source] = state["bytes"].get(source, 0) + len(packet.payload)
        flags = packet.flags
        if flags & RST:
            self.drop(key, "Observed RST before initial message completed; reset not endpoint-validated")
            return "RESET: tracking stopped (RST not endpoint-validated)"
        if flags & SYN and not flags & ACK:
            if flags & FIN or packet.payload:
                self.drop(key)
                return "UNSUPPORTED: SYN with FIN or data (Fast Open)"
            if state and state["client"] == source and state["isn"] == packet.sequence:
                state["time"] = self.now
                if key in self.manager.connections:
                    self.manager.connections[key]["last_seen"] = self.now
                return "SYN retransmission"
            self.drop(key)
            if len(self.tracked) >= self.manager.max_connections:
                return "LIMIT: too many tracked connections"
            self.tracked[key] = {"client": source, "server": destination, "isn": packet.sequence,
                                 "time": self.now, "start": self.now, "packets": 1, "bytes": {},
                                 "ready": False, "fin": {}, "reported": {},
                                 "first_decision": None, "stable_at": None, "label": None}
            self.last_server = destination
            return "SYN: waiting for SYN-ACK"
        if state is None:
            if self.observation != "midstream" or not packet.payload or flags & SYN or not flags & ACK or flags & URG:
                return "SKIP: connection beginning not observed"
            # D05 midstream: no start observed. The first data segment's sender is taken as the client (a role
            # assumption, recorded as such); its sequence is this direction's origin and its acknowledgement
            # number is, by TCP semantics, the next byte expected from the peer, hence the peer's origin.
            if len(self.tracked) >= self.manager.max_connections:
                return "LIMIT: too many tracked connections"
            try:
                self.manager.open_connection(source, destination, packet.sequence, packet.acknowledgement)
            except (StreamError, ValueError) as error:
                return "INVALIDATED: " + str(error)
            state = self.tracked[key] = {"client": source, "server": destination, "isn": None, "time": self.now, "start": self.now,
                                         "packets": 0, "bytes": {}, "ready": True, "fin": {}, "reported": {},
                                         "first_decision": None, "stable_at": None, "label": None, "mode": "midstream"}
            state["packets"] += 1
            state["bytes"][source] = len(packet.payload)
            self.last_server = destination
            self.counts["midstream_connections"] += 1
        state["time"] = self.now
        if key in self.manager.connections:
            self.manager.connections[key]["last_seen"] = self.now
        if flags & SYN and state.get("mode") == "midstream":
            # A SYN on a midstream-tracked tuple is a new connection: the coordinator renews the generation and
            # the ordinary handshake path takes over; the midstream view ends here, explicitly.
            self.drop(key, "Connection restarted with an observed SYN after a midstream observation")
            return self.process(self.now, packet)
        if flags & SYN:
            if (source == state["client"] or not flags & ACK or flags & FIN
                    or packet.acknowledgement != (state["isn"] + 1) % MODULUS or packet.payload):
                return self.reject(key, source, "inconsistent or unsupported SYN-ACK")
            if state["ready"]:
                if packet.sequence != state["server_isn"]:
                    return self.reject(key, source, "changed server sequence")
                return "SYN-ACK retransmission"
            try:
                self.manager.open_connection(destination, source,
                    (state["isn"] + 1) % MODULUS, (packet.sequence + 1) % MODULUS)
            except (StreamError, ValueError) as error:
                self.drop(key)
                return "INVALIDATED: " + str(error)
            state["ready"] = True
            state["server_isn"] = packet.sequence
            return "Tracking both directions (SYN/SYN-ACK observed)"
        if not state["ready"]:
            if self.observation != "asymmetric" or source != state["client"] or not packet.payload or not flags & ACK:
                return "SKIP: SYN-ACK not observed"
            # D05 asymmetric: the client's SYN and data were observed, the server's SYN-ACK never (one-direction
            # capture). The client direction is inspected exactly as after a handshake; the server origin is the
            # client's acknowledgement number. Handshake validation is not relaxed: a later SYN-ACK is still
            # checked against the client's ISN, and a server segment before any client data is still skipped.
            try:
                self.manager.open_connection(source, destination, (state["isn"] + 1) % MODULUS, packet.acknowledgement)
            except (StreamError, ValueError) as error:
                self.drop(key)
                return "INVALIDATED: " + str(error)
            state["ready"], state["mode"], state["server_isn"] = True, "asymmetric", (packet.acknowledgement - 1) % MODULUS
            self.counts["asymmetric_connections"] += 1
        if flags & URG or not flags & ACK:
            return self.reject(key, source, "urgent data or missing ACK unsupported")
        # FIN marks the end of one direction; retain state while any gap remains.
        stream = self.manager.connections[key]["directions"][source]
        offset = (packet.sequence - stream.first_sequence) % MODULUS
        end = offset + len(packet.payload)
        if self.compact and offset >= MODULUS // 2:
            # Compare all leading segments in the same signed coordinate
            # system, including payload wholly before the retained origin.
            end -= MODULUS
            if end < 0 and flags & FIN:
                # A wholly pre-origin FIN cannot be a huge future boundary.
                # Multiple sequence epochs are outside this prefix observer.
                return self.reject(key, source, "FIN outside unambiguous retained-origin range")
        previous_fin = state["fin"].get(source)
        if packet.payload and previous_fin is not None and end > previous_fin:
            return self.reject(key, source, "data beyond observed FIN")
        if flags & FIN:
            if (end > stream.limit and not self.compact) or (previous_fin is not None and previous_fin != end):
                return self.reject(key, source, "inconsistent FIN or stream limit")
            if stream.highest_end > end:
                return self.reject(key, source, "stored data beyond FIN")
            state["fin"][source] = end
        try:
            snapshot = self.manager.feed(source, destination, packet.sequence, packet.payload)
        except StreamError as error:
            self.last_events = stream.events
            self.last_classification = stream.inspector.observation
            self.drop(key)
            return "INVALIDATED: " + str(error)
        self.last_events = snapshot.events
        for event in snapshot.events:
            if event.observation.status == "identified":
                self._decided(state, (event.observation.application_protocol or event.observation.encryption, event.observation.application))
        if any(event.observation.status == "identified" for event in snapshot.events):
            self._correlate_connect(key, state)
            self._correlate_ldap(key, state)
            self._correlate_http2(key, state)
            # Replayed bytes publish on their own direction: the packet's direction extends this
            # packet's events, the other direction is reported as peer events (review round 3).
            for endpoint, other, events in self._replayed:
                if endpoint == source:
                    self.last_events += events
                else:
                    self.peer_events += tuple((endpoint, other, event) for event in events)
            self._replayed = []
        final = state['fin'].get(source)
        if final is not None and final <= stream.limit and stream.contiguous == final:
            finished = self.manager.finish_direction(source, destination,
                "Observed contiguous TCP FIN before initial message completed")
            # Keep the correlation-replay events already appended to last_events (review round 1 of v0.55).
            snapshot = replace(finished, events=self.last_events + finished.events)
            self.last_events = snapshot.events
        self.last_classification = snapshot.classification
        changed = state["reported"].get(source) != snapshot
        state["reported"][source] = snapshot
        message = "No new contiguous data"
        if not self.compact and changed and (snapshot.contiguous_bytes or snapshot.pending_bytes):
            evidence = "; ".join("{}={} ({})".format(r.protocol, r.status, r.evidence)
                                 for r in snapshot.results)
            message = "{}:{} -> {}:{} | contiguous={} pending={} | {}".format(
                *source, *destination, snapshot.contiguous_bytes, snapshot.pending_bytes, evidence)
        if len(state["fin"]) == 2 and all(
                self.manager.connections[key]["directions"][endpoint].contiguous == (min(final, stream.limit) if self.compact else final)
                for endpoint, final in state["fin"].items()):
            self.drop(key, "Both TCP directions closed with FIN")
            message += " | CLOSED: both FIN boundaries reached"
        return message


def readable_session(record):
    endpoint = lambda value: "{}:{}".format(*value)
    return ("SESSION {:<16} {} -> {} | {}/{} risk={} port={} | client={} server={} | {} pkts {}+{} B | {}".format(
        record["app"], endpoint(record["client"]), endpoint(record["server"]), record["category"],
        record["subcategory"], record["risk"], record["port_usage"], record["client_protocol"] or "-",
        record["server_protocol"] or "-", record["packets"], record["client_bytes"], record["server_bytes"],
        record["end_reason"])) + (" | risks=" + ",".join(record["risks"]) if record.get("risks") else "") + (
            " | policy={}{}".format(record["policy"]["action"], "({})".format(record["policy"]["rule"]) if record["policy"]["rule"] else "")
            if record.get("policy") else "") + (
            " | certificate=" + ",".join("{}={}".format(k, v) for k, v in sorted(record["certificate"].items())) if record.get("certificate") else "")


def analyze(path, json_output=False, events_only=False, tcp_hint=None, crc32c_byte_limit=4096, udp_hint=None,
            sessions=False, include_hostnames=False, signatures=None, fingerprints=False, heuristics=False, policy=None,
            certificates=False, observation="handshake", checksums="ignore", continuation=0):
    def retired(source, destination, event):
        if json_output:
            print(json.dumps({'type': 'stream_end', 'source': source, 'destination': destination,
                              'classification': asdict(event.observation), 'events': [asdict(event)]}))
        else:
            print('END {}:{} -> {}:{} | {} | {}'.format(*source, *destination,
                  event.observation.status.upper(), event.observation.reason))

    def session(record):
        print(json.dumps(record) if json_output else readable_session(record))

    analyzer = Analyzer(tcp_hint=tcp_hint, crc32c_byte_limit=crc32c_byte_limit, on_retire=retired, udp_hint=udp_hint,
                        on_session=session if sessions else None, include_hostnames=include_hostnames, signatures=signatures,
                        fingerprints=fingerprints, heuristics=heuristics, policy=policy, certificates=certificates, observation=observation,
                        continuation=continuation)
    quality = InputQuality("recorded", checksums)          # D06 input-quality contract of the recorded adapter
    counts = Counter()
    def capture_gap(reason, scope="active_connections", number=None):
        active = len(analyzer.tracked)
        counts["connections_discarded_after_gap"] += active
        # A partial link/IP header cannot safely identify the affected flow.
        # Retract active labels explicitly, discard both directions, and require
        # a new observed handshake. Do not turn capture loss into clean EOF.
        event = {"type": "capture_gap", "scope": scope,
                 "active_connections": active, "reason": reason}
        if number is not None:
            event["frame"] = number
        print(json.dumps(event) if json_output else "CAPTURE_GAP: " + reason)
        analyzer.tracked.clear()
        analyzer.udp_flows.clear()
        analyzer.quic_assembler.clear()
        analyzer.manager.connections.clear()
        analyzer.last_events = ()
        analyzer.last_classification = None

    try:
        for number, record in enumerate(read_pcap_records(path), 1):
            timestamp, frame = record.timestamp, record.data
            counts["frames"] += 1
            if record.truncated:
                counts["truncated"] += 1
                counts["skipped"] += 1
                quality.truncated()
                capture_gap("Capture truncation; active stream observations invalidated", number=number)
                continue
            try:
                packet = decode_frame(frame, record.linktype, checksums)
            except PacketError as error:
                counts["skipped"] += 1
                if quality.rejected(error) is not None and analyzer.note_input(error.kind, error.endpoints):
                    quality.flows_marked += 1
                if not events_only:
                    print(json.dumps({"frame": number, "status": "skipped", "reason": str(error), "kind": error.kind})
                          if json_output else "#{} SKIP ({}): {}".format(number, error.kind, error))
                continue
            if packet.checksum_failures:
                quality.audited(packet.checksum_failures)
                if analyzer.note_input("checksum", (packet.source, packet.destination)):
                    quality.flows_marked += 1
            counts["udp" if isinstance(packet, UDPPacket) else "tcp"] += 1
            message = analyzer.process(timestamp, packet)
            if not events_only or analyzer.last_events:
                if json_output:
                    row = {"frame": number, "source": packet.source,
                           "destination": packet.destination, "message": message,
                           "classification": asdict(analyzer.last_classification)
                           if analyzer.last_classification is not None else None,
                           "events": [asdict(event) for event in analyzer.last_events]}
                    if analyzer.last_classification is not None:
                        server = analyzer.last_server
                        row["app"] = classify(analyzer.last_classification, "udp" if isinstance(packet, UDPPacket) else "tcp",
                                              server[1] if server else None, None, analyzer.signatures).app
                    print(json.dumps(row))
                else:
                    print("#{} {}".format(number, message))
    except (CaptureError, OSError):
        capture_gap("Capture failed; observations may be incomplete", "all_observations_this_capture")
        raise
    analyzer.finish("Capture input EOF before initial message completed")
    counts["sessions"] = analyzer.counts["sessions"]
    print(json.dumps({"summary": dict(counts), "input_quality": quality.render(), "content": analyzer.content}) if json_output else
          "\nFrames: {frames}; TCP: {tcp}; UDP: {udp}; skipped: {skipped}; sessions: {sessions}".format(
              frames=counts["frames"], tcp=counts["tcp"], udp=counts["udp"], skipped=counts["skipped"], sessions=counts["sessions"]))
    return counts


def main():
    parser = argparse.ArgumentParser(description="Inspect IPv4 TCP/UDP captures (classic PCAP or pcapng) offline")
    parser.add_argument("capture", help="Path to a classic .pcap or .pcapng file")
    parser.add_argument("--json", action="store_true", help="Write structured JSON Lines")
    parser.add_argument("--events-only", action="store_true", help="Only classification changes and final summary")
    parser.add_argument("--sessions", action="store_true", help="Emit one App-ID verdict record per TCP connection / UDP flow")
    parser.add_argument("--hostnames", action="store_true", help="Include asserted SNI/Host names in session records")
    parser.add_argument("--signatures", help="JSON file of custom application signatures (see SIGNATURES.md)")
    parser.add_argument("--fingerprints", action="store_true", help="Derive JA3/JA4/JA3S/JA4S/HASSH/HTTP2 fingerprints (FINGERPRINTS.md)")
    parser.add_argument("--heuristics", action="store_true", help="Profile unknown payload prefixes and DNS name shape; advisory evidence only (RISKS.md)")
    parser.add_argument("--policy", help="JSON policy evaluated on every session record (POLICY.md); implies --sessions")
    parser.add_argument("--certificates", action="store_true", help="Read the leaf certificate structure after a TLS 1.2 ServerHello: key, signature, lifetime, self-issued, CA flag, key usage, alternative-name presence, validity at capture time (no names)")
    parser.add_argument("--observation", choices=OBSERVATION_MODES, default="handshake",
                        help="D05: handshake (default: SYN and SYN-ACK required), asymmetric (client side only captured), midstream (no start captured; conservative)")
    parser.add_argument("--checksums", choices=CHECKSUM_POLICIES, default="ignore",
                        help="D06: ignore (default; host captures precede offload), audit (compute and count, still inspect) or verify (skip failing packets, mark their flows)")
    parser.add_argument("--continuation", type=int, default=0, metavar="BYTES",
                        help="D07: after an HTTP/1 or TLS identification keep framing up to BYTES new bytes per direction (later HTTP messages, TLS record kinds); 0 (default) stops at the first message")
    parser.add_argument("--content-version", choices=[item.version for item in detection_content.releases()], default=None,
                        help="D08: run the built-in server-name catalog as of an earlier content release (rollback); records pin the version used")
    parser.add_argument("--udp-hint", choices=sorted(VALIDATORS), help="Restrict UDP validation to one candidate")
    parser.add_argument("--tcp-hint", choices=sorted(PARSERS), help="Restrict both TCP directions to one validated candidate")
    parser.add_argument('--crc32c-byte-limit', type=int, default=4096, help='Maximum bytes checked by Python CRC-32C; 0 disables checksummed profiles')
    args = parser.parse_args()
    try:
        if args.content_version:
            detection_content.select(args.content_version)
        signatures = SignatureSet.from_path(args.signatures) if args.signatures else None
        policy = Policy.from_path(args.policy) if args.policy else None
        analyze(args.capture, json_output=args.json, events_only=args.events_only, tcp_hint=args.tcp_hint,
                crc32c_byte_limit=args.crc32c_byte_limit, udp_hint=args.udp_hint, sessions=args.sessions or policy is not None,
                include_hostnames=args.hostnames, signatures=signatures, fingerprints=args.fingerprints,
                heuristics=args.heuristics, policy=policy, certificates=args.certificates, observation=args.observation, checksums=args.checksums,
                continuation=args.continuation)
    except (OSError, CaptureError, ValueError, PolicyError) as error:
        parser.exit(1, "Capture error: {}\n".format(error))


if __name__ == "__main__":
    main()
