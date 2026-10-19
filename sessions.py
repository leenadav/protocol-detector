"""Bounded educational TCP payload reassembly, not a complete TCP stack.

Call open_connection with the first DATA sequence number for each direction
(normally SYN sequence + 1). Feed decoded TCP payloads, not raw packets.
The caller owns SYN/FIN/RST processing and connection lifecycle.
"""
import time
from dataclasses import dataclass, field
from typing import Optional
from detectors import Result
from protocol_engine import Inspector, Observation, supported_protocols

MODULUS = 2 ** 32
# Legacy display only: compiled once from the public inventory. Live capture
# disables compatibility results and never iterates this collection.
_LEGACY_ORDER = ('http', 'ssh', 'tls', 'http2', 'socks5', 'smtp', 'mqtt', 'resp', 'amqp',
                 'dns', 'stun', 'postgresql', 'rfb', 'bittorrent', 'memcached', 'ldap',
                 'sip', 'rtsp', 'bgp', 'smb2', 'stomp', 'nats', 'imap', 'rdp', 'mysql', 'mongodb')
TCP_FAMILIES = _LEGACY_ORDER + tuple(entry.family for entry in supported_protocols()
                                   if 'tcp' in entry.transports and entry.family not in _LEGACY_ORDER)


class StreamError(ValueError):
    pass


class Stream:
    """Keep one direction's first bytes, including bytes beyond a gap."""
    def __init__(self, first_sequence, limit, inspector_factory=Inspector, compatibility=True, prefix_only=False):
        if not 0 <= first_sequence < MODULUS:
            raise ValueError("Sequence must be an unsigned 32-bit number")
        self.compatibility = compatibility
        self.prefix_only = prefix_only
        self.first_sequence = first_sequence
        self.limit = limit
        self.buffer = bytearray(limit)
        self.present = bytearray(limit)
        self.contiguous = 0
        self.stored = 0
        self.highest_end = 0  # Exclusive end of the highest retained payload byte.
        self.error = None
        self.inspector = inspector_factory()
        self.events = ()
        self.results = self._compat_results()

    def _compat_results(self):
        if not self.compatibility:
            return []
        observation = self.inspector.observation
        candidate = self.inspector.candidate
        if candidate == "git_text":
            candidate = "text"  # Shared routing scope before a structural discriminator.
        matched = "tls" if observation.encryption == "tls" else observation.application_protocol
        if matched == "http/2":
            matched = "http2"
        elif matched and matched.startswith("http/"):
            matched = "http"
        results = []
        if matched and matched.startswith("mqtt/"):
            matched = "mqtt"
        if matched and matched.startswith("amqp/"):
            matched = "amqp"
        if matched and "/" in matched:
            matched = matched.split("/", 1)[0]
        candidates = {candidate} if candidate != "text" else {"http", "ssh", "smtp", "sip", "rtsp", "nats", "imap", "git"}
        for name in TCP_FAMILIES:
            status = "NO_MATCH"
            if observation.status == "identified" and matched == name:
                status = "MATCH"
            elif observation.status == "detecting" and (candidate is None or name in candidates):
                status = "NEED_MORE"
            elif observation.status == "unknown" and (candidate is None or name in candidates):
                status = "UNKNOWN"
            elif observation.status in ("budget_exhausted", "incomplete", "invalidated") and (candidate is None or name in candidates):
                status = observation.status.upper()
            results.append(Result(name.upper(), status, observation.reason if candidate is None or name in candidates
                                  else "Excluded by prefix dispatch"))
        return results

    def feed(self, sequence, payload):
        self.events = ()
        if self.error:
            raise StreamError(self.error)
        if not isinstance(payload, bytes) or not 0 <= sequence < MODULUS:
            raise ValueError("Expected bytes and an unsigned 32-bit sequence")
        if not payload:
            return
        # Modulo subtraction handles a sequence counter wrapping past 2**32.
        offset = (sequence - self.first_sequence) % MODULUS
        # A segment can start before offset zero and still cover retained
        # bytes. In prefix mode clip that leading portion before the ordinary
        # upper-bound check; modulo subtraction alone would ignore its tail.
        if self.prefix_only and offset >= MODULUS // 2:
            leading = MODULUS - offset
            if leading >= len(payload):
                return
            payload = payload[leading:]
            offset = 0
        if offset + len(payload) > self.limit:
            if self.prefix_only:
                # Live observation covers the bounded initial prefix only.
                # Continue checking overlaps within it; ignore later bytes.
                if offset >= self.limit:
                    return
                payload = payload[:self.limit - offset]
            else:
                self.error = "Data lies outside the bounded initial stream window"
                self.events = self.inspector.invalidate(self.error)
                self.results = []
                raise StreamError(self.error)
        # Common in-order case: copy slices once, no byte-by-byte Python loops.
        if offset == self.contiguous and self.stored == self.contiguous:
            end = offset + len(payload)
            self.buffer[offset:end] = payload
            self.present[offset:end] = b"\x01" * len(payload)
            self.stored = self.contiguous = end
            self.highest_end = end
            self.events = self.inspector.feed(payload)
            self.results = self._compat_results()
            return
        end = offset + len(payload)
        # Count in C without allocating a bitmap slice. Fully absent and fully
        # present ranges cover ordinary reordering and retransmission cheaply.
        missing = self.present.count(0, offset, end)
        if missing == 0:
            conflict = self.buffer[offset:end] != payload
        elif missing == len(payload):
            conflict = False
        else:
            # Mixed overlaps are bounded by the initial window. Check every
            # occupied byte BEFORE writing anything: a late conflict must not
            # admit earlier new bytes or feed them into the inspector.
            conflict = False
            for index, value in enumerate(payload, offset):
                if self.present[index] and self.buffer[index] != value:
                    conflict = True
                    break
        if conflict:
            self.error = "Conflicting overlapping bytes; classification invalidated"
            self.events = self.inspector.invalidate(self.error)
            self.results = []
            raise StreamError(self.error)
        if missing == 0:
            return  # Identical duplicate: never feed the inspector twice.
        self.buffer[offset:end] = payload
        self.present[offset:end] = b"\x01" * len(payload)
        self.stored += missing
        self.highest_end = max(self.highest_end, end)
        old_length = self.contiguous
        # Only a segment touching the current gap can extend the ready prefix.
        if offset <= old_length < end:
            gap = self.present.find(b"\x00", old_length, self.highest_end)
            self.contiguous = self.highest_end if gap == -1 else gap
        if self.contiguous != old_length:
            self.events = self.inspector.feed(bytes(self.buffer[old_length:self.contiguous]))
            self.results = self._compat_results()


@dataclass(frozen=True)
class Snapshot:
    contiguous_bytes: int
    pending_bytes: int
    next_sequence: int
    results: tuple
    classification: Optional[Observation] = None
    events: tuple = field(default=(), compare=False)


class SessionManager:
    def __init__(self, byte_limit=65536, max_connections=32, idle_timeout=60, clock=time.monotonic,
                 inspector_factory=Inspector, compatibility=True, expiry_interval=0, prefix_only=False):
        if not 1 <= byte_limit <= 65536 or max_connections < 1 or idle_timeout <= 0:
            raise ValueError("Invalid reassembly limits")
        self.compatibility = compatibility
        self.prefix_only = prefix_only
        self.expiry_interval = expiry_interval
        self.next_expiry = float("-inf")
        self.byte_limit = byte_limit
        self.max_connections = max_connections
        self.idle_timeout = idle_timeout
        self.clock = clock
        self.inspector_factory = inspector_factory
        self.connections = {}

    @staticmethod
    def key(source, destination):
        # Endpoint = (IP address string, port). Reverse traffic gets the same key.
        return tuple(sorted((source, destination)))

    def expire(self):
        now = self.clock()
        if now < self.next_expiry:
            return 0
        self.next_expiry = now + self.expiry_interval
        expired = [key for key, connection in self.connections.items()
                   if now - connection["last_seen"] >= self.idle_timeout]
        for key in expired:
            del self.connections[key]
        return len(expired)

    def open_connection(self, source, destination, source_sequence, destination_sequence):
        self.expire()
        key = self.key(source, destination)
        if source == destination:
            raise ValueError("Endpoints must differ")
        if key in self.connections:
            raise ValueError("Connection already exists; close it before reusing endpoints")
        if len(self.connections) >= self.max_connections:
            raise StreamError("Connection limit reached")
        self.connections[key] = {
            "last_seen": self.clock(),
            "directions": {
                source: Stream(source_sequence, self.byte_limit, self.inspector_factory, self.compatibility, self.prefix_only),
                destination: Stream(destination_sequence, self.byte_limit, self.inspector_factory, self.compatibility, self.prefix_only),
            },
        }

    def feed(self, source, destination, sequence, payload):
        self.expire()
        key = self.key(source, destination)
        if key not in self.connections:
            raise StreamError("Unknown connection: first data sequences must be established")
        connection = self.connections[key]
        stream = connection["directions"][source]
        stream.feed(sequence, payload)
        connection["last_seen"] = self.clock()
        return Snapshot(
            stream.contiguous, stream.stored - stream.contiguous,
            (stream.first_sequence + stream.contiguous) % MODULUS,
            tuple(stream.results),
            stream.inspector.observation, stream.events,
        )

    def close(self, source, destination):
        self.connections.pop(self.key(source, destination), None)

    def finish_direction(self, source, destination, reason="EOF before identification completed"):
        """Caller asserts the observed direction has ended at a trusted boundary.

        Retain bytes for overlap checks until the caller closes the connection.
        This does not turn a FIN beyond a reassembly gap into a complete stream.
        """
        stream = self.connections[self.key(source, destination)]["directions"][source]
        events = stream.inspector.end(reason)
        if events:
            stream.results = stream._compat_results()
        return Snapshot(stream.contiguous, stream.stored - stream.contiguous,
                        (stream.first_sequence + stream.contiguous) % MODULUS,
                        tuple(stream.results), stream.inspector.observation, events)
