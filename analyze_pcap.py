"""Offline PCAP analysis. No capture privileges or network access required."""
import argparse
import json
import weakref
from dataclasses import asdict, replace
from collections import Counter
from functools import partial
from packets import CaptureError, PacketError, UDPPacket, decode_packet, read_pcap_records
from protocol_engine import Config, DatagramInspector, Event, Inspector
from protocol_engine.registry import PARSERS
from protocol_engine.datagram import VALIDATORS
from sessions import MODULUS, SessionManager, StreamError

SYN, ACK, FIN, RST, URG = 2, 16, 1, 4, 32


class Analyzer:
    def __init__(self, max_connections=32, byte_limit=65536, idle_timeout=60, compact=False, udp_hint=None, tcp_hint=None, crc32c_byte_limit=4096, on_retire=None):
        if on_retire is not None and not callable(on_retire):
            raise TypeError("on_retire must be callable")
        self.on_retire = on_retire
        self.compact = compact
        if udp_hint is not None and udp_hint not in VALIDATORS:
            raise ValueError("Unsupported UDP candidate hint")
        self.udp_hint = udp_hint
        self.next_expiry = float("-inf")
        self.udp = DatagramInspector()
        self.udp_revision = 0
        self.now = 0
        if tcp_hint is not None:
            Inspector(protocol_hint=tcp_hint)  # Validate before processing packets.
        self.inspection_config = Config(max_bytes=byte_limit, max_crc32c_bytes=crc32c_byte_limit)
        factory = partial(Inspector, config=self.inspection_config, protocol_hint=tcp_hint)
        clock_owner = weakref.proxy(self)
        self.manager = SessionManager(clock=lambda: clock_owner.now, max_connections=max_connections,
                                      byte_limit=byte_limit, idle_timeout=idle_timeout,
                                      inspector_factory=factory,
                                      compatibility=not compact, expiry_interval=1 if compact else 0, prefix_only=compact)
        self.tracked = {}
        self.last_events = ()
        self.last_classification = None

    def drop(self, key, reason="Tracking ended before initial message completed"):
        connection = self.manager.connections.pop(key, None)
        self.tracked.pop(key, None)
        if connection is not None:
            for source, stream in connection['directions'].items():
                events = stream.inspector.end(reason)
                if self.on_retire is not None:
                    destination = key[1] if source == key[0] else key[0]
                    for event in events:
                        self.on_retire(source, destination, event)

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

    def expire(self, timestamp):
        self.now = max(self.now, timestamp)
        if self.now < self.next_expiry:
            return
        self.next_expiry = self.now + (1 if self.compact else 0)
        for key, state in list(self.tracked.items()):
            if self.now - state["time"] >= self.manager.idle_timeout:
                self.drop(key, "Idle timeout before initial message completed")
        self.manager.expire()

    def process(self, timestamp, packet):
        self.last_events = ()
        self.last_classification = None
        self.now = max(self.now, timestamp)
        self.expire(self.now)
        if isinstance(packet, UDPPacket):
            self.last_classification = self.udp.inspect(packet.payload, self.udp_hint)
            self.udp_revision += 1
            self.last_events = (Event(self.udp_revision, "datagram", self.last_classification),)
            result = self.last_classification
            return "UDP {}:{} -> {}:{} | {} | {} | {}".format(
                *packet.source, *packet.destination, result.status.upper(),
                result.application_protocol or result.encryption or "unidentified", result.reason)
        source, destination = packet.source, packet.destination
        key = self.manager.key(source, destination)
        state = self.tracked.get(key)
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
            self.tracked[key] = {"client": source, "isn": packet.sequence,
                                 "time": self.now, "ready": False, "fin": {}, "reported": {}}
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
            self.drop(key)
            message += " | CLOSED: both FIN boundaries reached"
        return message


def analyze(path, json_output=False, events_only=False, tcp_hint=None, crc32c_byte_limit=4096, udp_hint=None):
    def retired(source, destination, event):
        if json_output:
            print(json.dumps({'type': 'stream_end', 'source': source, 'destination': destination,
                              'classification': asdict(event.observation), 'events': [asdict(event)]}))
        else:
            print('END {}:{} -> {}:{} | {} | {}'.format(*source, *destination,
                  event.observation.status.upper(), event.observation.reason))
    analyzer = Analyzer(tcp_hint=tcp_hint, crc32c_byte_limit=crc32c_byte_limit, on_retire=retired, udp_hint=udp_hint)
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
                packet = decode_packet(frame)
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
                    print(json.dumps({"frame": number, "source": packet.source,
                                      "destination": packet.destination, "message": message,
                                      "classification": asdict(analyzer.last_classification)
                                      if analyzer.last_classification is not None else None,
                                      "events": [asdict(event) for event in analyzer.last_events]}))
                else:
                    print("#{} {}".format(number, message))
    except (CaptureError, OSError):
        capture_gap("Capture failed; observations may be incomplete", "all_observations_this_capture")
        raise
    analyzer.finish("Capture input EOF before initial message completed")
    print(json.dumps({"summary": dict(counts)}) if json_output else
          "\nFrames: {frames}; TCP: {tcp}; UDP: {udp}; skipped: {skipped}".format(
              frames=counts["frames"], tcp=counts["tcp"], udp=counts["udp"], skipped=counts["skipped"]))
    return counts


def main():
    parser = argparse.ArgumentParser(description="Inspect classic Ethernet/IPv4 TCP/UDP PCAP offline")
    parser.add_argument("capture", help="Path to a classic .pcap file")
    parser.add_argument("--json", action="store_true", help="Write structured JSON Lines")
    parser.add_argument("--events-only", action="store_true", help="Only classification changes and final summary")
    parser.add_argument("--udp-hint", choices=sorted(VALIDATORS), help="Restrict UDP validation to one candidate")
    parser.add_argument("--tcp-hint", choices=sorted(PARSERS), help="Restrict both TCP directions to one validated candidate")
    parser.add_argument('--crc32c-byte-limit', type=int, default=4096, help='Maximum bytes checked by Python CRC-32C; 0 disables checksummed profiles')
    args = parser.parse_args()
    try:
        analyze(args.capture, json_output=args.json, events_only=args.events_only, tcp_hint=args.tcp_hint, crc32c_byte_limit=args.crc32c_byte_limit, udp_hint=args.udp_hint)
    except (OSError, CaptureError, ValueError) as error:
        parser.exit(1, "Capture error: {}\n".format(error))


if __name__ == "__main__":
    main()
