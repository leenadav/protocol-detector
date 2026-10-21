"""Offline PCAP analysis. No capture privileges or network access required."""
import argparse
import json
import weakref
from dataclasses import asdict, replace
from collections import Counter
from functools import partial
from link_packets import decode_frame
from packets import CaptureError, PacketError, UDPPacket, read_pcap_records
from protocol_engine import Config, DatagramInspector, Event, Inspector, SignatureSet
from protocol_engine.appid import classify, session_verdict, verdict_fields
from protocol_engine.policy import Policy, PolicyError
from protocol_engine.registry import PARSERS
from protocol_engine.datagram import VALIDATORS
from protocol_engine.quic import QuicAssembler
from sessions import MODULUS, SessionManager, StreamError

SYN, ACK, FIN, RST, URG = 2, 16, 1, 4, 32


class Analyzer:
    """Bounded connection tracking plus per-session application verdicts.

    on_retire receives directional terminal events. on_session receives one
    JSON-friendly record per TCP connection or UDP flow when tracking ends,
    carrying the App-ID style verdict for the whole session. Both callbacks are
    synchronous and bounded by the connection/flow tables; no queue is kept.
    """
    def __init__(self, max_connections=32, byte_limit=65536, idle_timeout=60, compact=False, udp_hint=None, tcp_hint=None,
                 crc32c_byte_limit=4096, on_retire=None, on_session=None, max_udp_flows=None, include_hostnames=False,
                 signatures=None, fingerprints=False, heuristics=False, policy=None, certificates=False):
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
                                        heuristics=bool(heuristics), certificates=bool(certificates))
        self.quic_assembler = QuicAssembler()
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
        self.retiring = None
        self.max_udp_flows = max_connections if max_udp_flows is None else max_udp_flows
        if not 0 <= self.max_udp_flows <= 65536:
            raise ValueError("Invalid UDP flow table limit")
        self.quic_assembler.max_connections = max(1, min(self.max_udp_flows, 1024))
        self.udp_flows = {}
        self.counts = Counter()

    # ----- session records -------------------------------------------------
    def _record(self, transport, client, server, state, verdict, reason, observations):
        record = {"type": "session", "transport": transport, "client": client, "server": server,
                  "start": state["start"], "end": self.now, "packets": state["packets"],
                  "client_bytes": state["bytes"].get(client, 0), "server_bytes": state["bytes"].get(server, 0),
                  "end_reason": reason}
        record.update(verdict_fields(verdict))
        if self.policy is not None:
            record["policy"] = self.policy.evaluate(verdict, transport, server[1]).fields()
        fingerprints = {evidence.field: evidence.value for obs in observations if obs is not None
                        for evidence in obs.evidence if evidence.strength == "derived"}
        if fingerprints:
            record["fingerprints"] = fingerprints
        certificate = {evidence.field[16:]: evidence.value for obs in observations if obs is not None
                       for evidence in obs.evidence if evidence.field.startswith("tls_certificate_")}
        if certificate:
            record["certificate"] = certificate  # structure labels only (v0.39): no names, serials or keys
        if self.include_hostnames:
            record["hostname"] = next((obs.hostname for obs in observations if obs is not None and obs.hostname), None)
        self.counts["sessions"] += 1
        self.on_session(record)

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
        server = connection["directions"][state["server"]].inspector
        request, response = client.observation, server.observation
        if response.status != "identified" or not (response.application_protocol or "").startswith("http/"):
            return
        if request.status != "identified" or not any(
                (e.field == "http_method" and e.value == "CONNECT") or (e.field == "shift" and e.value == "http-connect") for e in request.evidence):
            return
        status = next((e.value for e in response.evidence if e.field == "http_status"), "")
        if status[:1] == "2" and server.open_shift("http-connect"):
            self.counts["connect_tunnels_correlated"] += 1

    def _tcp_session(self, key, state, connection, reason):
        if self.on_session is None:
            return
        client, server = state["client"], state["server"]
        client_obs = server_obs = None
        if connection is not None:
            client_obs = connection["directions"][client].inspector.observation
            server_obs = connection["directions"][server].inspector.observation
        verdict = session_verdict(client_obs, server_obs, "tcp", server[1], state["bytes"].get(client, 0),
                                  state["bytes"].get(server, 0), handshake_complete=state["ready"], signatures=self.signatures)
        self._record("tcp", client, server, state, verdict, reason, (client_obs, server_obs))

    def _udp_session(self, key, flow, reason):
        if self.on_session is None:
            return
        verdict = classify(flow["observation"], "udp", flow["server"][1], flow["bytes"].get(flow["client"], 0), self.signatures)
        self._record("udp", flow["client"], flow["server"], flow, verdict, reason, (flow["observation"],))

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
        self.last_classification = self.udp.inspect(packet.payload, self.udp_hint)
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
                                              "observation": self.last_classification}
        if flow is not None:
            flow["time"] = self.now
            flow["packets"] += 1
            flow["bytes"][packet.source] = flow["bytes"].get(packet.source, 0) + len(packet.payload)
            # Keep the first identification; otherwise the latest outcome describes the flow.
            if flow["observation"].status != "identified":
                flow["observation"] = self.last_classification
        self.last_server = flow["server"] if flow is not None else packet.destination
        result = self.last_classification
        return "UDP {}:{} -> {}:{} | {} | {} | {}".format(
            *packet.source, *packet.destination, result.status.upper(),
            result.application_protocol or result.encryption or "unidentified", result.reason)

    def process(self, timestamp, packet):
        self.last_events = ()
        self.last_classification = None
        self.last_server = None
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
                                 "ready": False, "fin": {}, "reported": {}}
            self.last_server = destination
            return "SYN: waiting for SYN-ACK"
        if state is None:
            return "SKIP: connection beginning not observed"
        state["time"] = self.now
        if key in self.manager.connections:
            self.manager.connections[key]["last_seen"] = self.now
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
            return "SKIP: SYN-ACK not observed"
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
        if any(event.observation.status == "identified" for event in snapshot.events):
            self._correlate_connect(key, state)
        final = state['fin'].get(source)
        if final is not None and final <= stream.limit and stream.contiguous == final:
            finished = self.manager.finish_direction(source, destination,
                "Observed contiguous TCP FIN before initial message completed")
            snapshot = replace(finished, events=snapshot.events + finished.events)
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
            certificates=False):
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
                        fingerprints=fingerprints, heuristics=heuristics, policy=policy, certificates=certificates)
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
                capture_gap("Capture truncation; active stream observations invalidated", number=number)
                continue
            try:
                packet = decode_frame(frame, record.linktype)
            except PacketError as error:
                counts["skipped"] += 1
                if not events_only:
                    print(json.dumps({"frame": number, "status": "skipped", "reason": str(error)})
                          if json_output else "#{} SKIP: {}".format(number, error))
                continue
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
    print(json.dumps({"summary": dict(counts)}) if json_output else
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
    parser.add_argument("--certificates", action="store_true", help="Read the leaf certificate structure after a TLS 1.2 ServerHello: key, signature, lifetime, self-issued (no names)")
    parser.add_argument("--udp-hint", choices=sorted(VALIDATORS), help="Restrict UDP validation to one candidate")
    parser.add_argument("--tcp-hint", choices=sorted(PARSERS), help="Restrict both TCP directions to one validated candidate")
    parser.add_argument('--crc32c-byte-limit', type=int, default=4096, help='Maximum bytes checked by Python CRC-32C; 0 disables checksummed profiles')
    args = parser.parse_args()
    try:
        signatures = SignatureSet.from_path(args.signatures) if args.signatures else None
        policy = Policy.from_path(args.policy) if args.policy else None
        analyze(args.capture, json_output=args.json, events_only=args.events_only, tcp_hint=args.tcp_hint,
                crc32c_byte_limit=args.crc32c_byte_limit, udp_hint=args.udp_hint, sessions=args.sessions or policy is not None,
                include_hostnames=args.hostnames, signatures=signatures, fingerprints=args.fingerprints,
                heuristics=args.heuristics, policy=policy, certificates=args.certificates)
    except (OSError, CaptureError, ValueError, PolicyError) as error:
        parser.exit(1, "Capture error: {}\n".format(error))


if __name__ == "__main__":
    main()
