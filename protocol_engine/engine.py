from dataclasses import replace
from typing import Optional, Tuple
from .model import Config, Evidence, Event, Metrics, Observation, RuleIndex
from .parsers import BudgetError, ParseError
from .extended import AmbiguousPrefix, UnsupportedPrefix
from .dispatch import LOOKAHEAD, select
from .registry import PARSERS, FACTORIES
from .signatures import SignatureSet

_UNKNOWN_FAMILY = "unknown-tcp"


class Inspector:
    """One direction of one ordered stream; not thread safe.

    feed() returns only state-change events. Terminal initial-message inspection
    takes a constant-work bypass; it does NOT imply bypassing security policy.
    feed_decrypted() is a distinct trust boundary for plaintext supplied by a proxy.
    """
    def __init__(self, config: Optional[Config] = None, rules: Optional[RuleIndex] = None,
                 source: str = "wire", protocol_hint: Optional[str] = None,
                 signatures: Optional[SignatureSet] = None):
        if source not in ("wire", "decrypted"):
            raise ValueError("Invalid byte provenance")
        self.config = config if config is not None else Config()
        self.rules = rules if rules is not None else RuleIndex()
        if not isinstance(self.config, Config) or not isinstance(self.rules, RuleIndex):
            raise TypeError("Expected Config and RuleIndex")
        if signatures is not None and not isinstance(signatures, SignatureSet):
            raise TypeError("Expected a SignatureSet")
        if signatures is not None and len(signatures) and not self.config.retain_contexts:
            raise ValueError("Signatures require Config(retain_contexts=True)")
        self.signatures = signatures
        self._unknown = None  # bounded unknown-payload buffer while signatures may still match or heuristics profile it
        wants_signatures = signatures is not None and len(signatures) and signatures.wants(_UNKNOWN_FAMILY)
        self._unknown_limit = max(self.config.signature_bytes if wants_signatures else 0,
                                  self.config.heuristic_bytes if self.config.heuristics else 0)
        self._continuing = False  # identified; parser still deriving optional evidence (fingerprints)
        if protocol_hint is not None and protocol_hint not in PARSERS:
            raise ValueError("Unsupported TCP candidate hint")
        self._hint = protocol_hint
        self.source = source
        self.metrics = Metrics()
        self.observation = Observation()
        self.revision = 0
        self._prefix = bytearray()
        self._parser = None
        self._candidate = None
        self._terminal = False
        self.correlation = None   # the identifying parser's private correlation metadata (e.g. an LDAP message id); never emitted
        self._inner = None
        self._outer = None
        self._hint_source = "caller"
        self._next = None      # Inspector for the phase after a structural application shift
        self._carrier = None   # identification that announced the shift
        self._shift = None     # boundary name
        self._shift_source = source  # "wire" for a boundary this direction announced, "wire:peer" when the host opened it

    @property
    def candidate(self):
        return self._candidate

    def _signature(self, family, contexts):
        """First matching custom signature for a completed parser family, or None."""
        if self.signatures is None or contexts is None or not self.signatures.wants(family):
            return None
        return self.signatures.match(family, contexts)

    def _unknown_observation(self, reason, final=True, data=None):
        """Unknown prefix: consult unknown-payload signatures over the bounded buffer.

        A match is terminal. Without a match the stream stays detecting until the
        buffer is full (final) or the caller ends it; then it is unknown.
        """
        if data is None:
            data = bytes(self._unknown) if self._unknown is not None else b""
        match = self._signature(_UNKNOWN_FAMILY, {"unknown-req-tcp-payload": data,
                                                  "unknown-req-tcp-payload-length": len(data)})
        if match is None:
            if not final:
                return ()
            self._unknown = None
            evidence = ()
            if self.config.heuristics:
                from .heuristics import heuristic_evidence
                evidence = heuristic_evidence(data, self.source, self.config.heuristic_bytes)
            return self._finish(Observation(status="unknown", reason=reason, evidence=evidence))
        self._unknown = None
        evidence = (Evidence("application", match.name, "signature:" + _UNKNOWN_FAMILY, "configured_signature"),)
        if self._hint is not None:
            evidence += (Evidence("candidate_hint", self._hint, self._hint_source, "context"),)
        return self._finish(Observation(status="identified", application=match.name, evidence=evidence,
                                        reason="Custom signature matched an unknown payload prefix; no protocol profile validated",
                                        scope="signature_match"))

    def _publish(self, observation, kind="updated"):
        if observation == self.observation:
            return ()
        self.observation = observation
        self.revision += 1
        self.metrics.events_emitted += 1
        return (Event(self.revision, kind, observation),)

    def _finish(self, observation, kind="updated"):
        self._terminal = True
        self._continuing = False
        self._parser = None
        self._prefix.clear()
        return self._publish(observation, kind)

    # -- application shift at a structural boundary (CONNECT, Upgrade, STARTTLS, SSLRequest, RDP negotiation) --

    def _begin_shift(self, shift, rest):
        """The parser consumed exactly up to a boundary after which another protocol starts.

        The identification is published as it stands. Bytes after the boundary go
        to a fresh inner Inspector that shares the remaining byte budget; when it
        reaches a terminal observation the merged result is published as a
        "shifted" event. A failed inner inspection never removes the carrier's
        identification: it is recorded as shifted_payload context.
        """
        boundary, expected = shift
        events = self._publish(self._identified())
        self._parser = None
        self._continuing = False
        self._prefix.clear()
        self._carrier, self._shift = self.observation, boundary
        remaining = self.config.max_bytes - self.metrics.bytes_inspected
        if remaining < 64:
            self._next = None
            return events + self._finish(self._shift_result(Observation(status="budget_exhausted", reason="Byte budget exhausted at the shift boundary")), "shifted")
        config = replace(self.config, max_bytes=remaining) if remaining != self.config.max_bytes else self.config
        self._next = Inspector(config, self.rules, self.source, protocol_hint=expected, signatures=self.signatures)
        self._next._hint_source = "shift:" + boundary
        if rest:
            events += self._forward(rest)
        return events

    def open_shift(self, boundary, expected=None):
        """Host-driven shift: the peer direction established that a boundary applies here too.

        Used when the other direction's structure decides this one's (an HTTP 2xx
        answering a CONNECT: the response alone cannot be told from a body-less
        reply, but together with the request it marks the start of the tunnel).
        Allowed only on a terminal identified observation that has not shifted;
        returns True when the next bytes will be inspected as the new phase.
        """
        if not isinstance(boundary, str) or not 1 <= len(boundary) <= 64:
            raise ValueError("Shift boundary must be a short name")
        if expected is not None and expected not in PARSERS:
            raise ValueError("Unsupported shifted-phase candidate")
        if (not self._terminal or self._next is not None or self.observation.status != "identified"
                or any(e.field == "shift" for e in self.observation.evidence)):
            return False
        remaining = self.config.max_bytes - self.metrics.bytes_inspected
        if remaining < 64:
            return False
        self._carrier, self._shift, self._shift_source = self.observation, boundary, self.source + ":peer"
        config = replace(self.config, max_bytes=remaining) if remaining != self.config.max_bytes else self.config
        self._next = Inspector(config, self.rules, self.source, protocol_hint=expected, signatures=self.signatures)
        self._next._hint_source = "shift:" + boundary
        self._terminal = False
        return True

    def expect(self, candidate, source):
        """Host-driven candidate: the peer direction established which family this one must be.

        Used for the server side of an HTTP/2 connection with prior knowledge: the
        client preface identifies the connection, the server's first SETTINGS frame
        alone is routed nowhere. The candidate only selects the parser; its bytes
        still have to validate structurally. Allowed only before any byte arrived
        and when no hint exists; returns True when adopted.
        """
        if candidate not in PARSERS:
            raise ValueError("Unsupported expected candidate")
        if not isinstance(source, str) or not 1 <= len(source) <= 64:
            raise ValueError("Expectation source must be a short name")
        if self.metrics.bytes_received or self._hint is not None or self._terminal or self._next is not None:
            return False
        self._hint, self._hint_source = candidate, "peer:" + source
        return True

    def _forward(self, data):
        inner = self._next
        bytes_before, calls_before = inner.metrics.bytes_inspected, inner.metrics.parser_calls
        events = inner.feed(data)
        self.metrics.bytes_inspected += inner.metrics.bytes_inspected - bytes_before
        self.metrics.parser_calls += inner.metrics.parser_calls - calls_before
        # An inner phase that ends its continuation without new evidence publishes
        # nothing, yet the shift is complete: merge so this inspector turns terminal too.
        return self._merge_shift() if events or inner._terminal else ()

    def _shift_result(self, inner):
        carrier, boundary = self._carrier, self._shift
        marker = (Evidence("shift", boundary, self._shift_source, "structural"),)
        if inner.status == "identified":
            kept = tuple(e for e in carrier.evidence
                         if (e.field == "hostname" and inner.hostname is None) or (e.field == "application" and inner.application is None and inner.hostname is None))
            evidence = inner.evidence + kept + marker + (Evidence("shift_from", carrier.application_protocol or carrier.encryption or "unknown", self.source, "structural"),)
            return replace(inner, hostname=inner.hostname if inner.hostname is not None else carrier.hostname,
                           application=inner.application if (inner.application is not None or inner.hostname is not None) else carrier.application,
                           evidence=evidence, reason="After {} boundary: {}".format(boundary, inner.reason))
        return replace(carrier, evidence=carrier.evidence + marker + (Evidence("shifted_payload", inner.status, self.source, "context"),),
                       reason=carrier.reason + "; bytes after the {} boundary: {}".format(boundary, inner.reason))

    def _merge_shift(self):
        inner = self._next
        if inner.observation.status == "detecting":
            return ()
        merged = self._shift_result(inner.observation)
        if inner._terminal:
            self._next = None
            self._carrier = None
            self._terminal = True
        return self._publish(merged, "shifted")

    def _refined(self):
        """Observation after a continuation: rebuilt only when the parser derived something new.

        Parsers may expose `refined = False` while nothing beyond the published
        identification was learned; the published observation then stands as is.
        """
        return self._identified() if getattr(self._parser, "refined", True) else self.observation

    def _continue(self, chunk):
        """Bytes for a parser that already identified (fingerprints, STARTTLS watch)."""
        try:
            consumed = self._parser.feed(chunk)
            self.metrics.bytes_inspected += consumed
        except ParseError:
            self.metrics.bytes_inspected += len(chunk)
            return self._finish(self._refined(), "refined")
        if not self._parser.continues:
            shift = getattr(self._parser, "shift", None)
            if shift is not None:
                return self._begin_shift(shift, chunk[consumed:])
            return self._finish(self._refined(), "refined")
        if self.metrics.bytes_inspected >= self.config.max_bytes:
            return self._finish(self._refined(), "refined")
        return ()

    def invalidate(self, reason: str) -> Tuple[Event, ...]:
        """Call when upstream reassembly/provenance is no longer trustworthy."""
        if not isinstance(reason, str) or not reason or len(reason) > 256:
            raise ValueError("Invalidation reason must contain 1..256 characters")
        self._inner = None
        self._outer = None
        self._next = None
        self._carrier = None
        self._unknown = None
        self._terminal = True
        self._parser = None
        self._prefix.clear()
        return self._publish(Observation(status="invalidated", reason=reason), "invalidated")

    def end(self, reason="EOF before identification completed") -> Tuple[Event, ...]:
        """Finish observation; a capture boundary need not mean network EOF."""
        if not isinstance(reason, str) or not reason or len(reason) > 256:
            raise ValueError("End reason must contain 1..256 characters")
        if not self._terminal:
            if self._next is not None:
                events = self._next.end(reason)
                if events or self._next._terminal:
                    # A continuing inner phase that ends without new evidence publishes
                    # nothing; its identification is still the shifted result.
                    return self._merge_shift()
                self._next = None
                return self._finish(self._shift_result(Observation(status="incomplete", reason=reason)), "shifted")
            if self._continuing:
                shift = getattr(self._parser, "shift", None)
                if shift is not None:
                    return self._begin_shift(shift, b"") + self.end(reason)
                return self._finish(self._refined(), "refined")  # keep the identification; no further evidence
            if self._unknown is not None:
                return self._unknown_observation("Prefix outside supported protocol families")
            if self._candidate is None and self._prefix and self.signatures is not None and self.signatures.wants(_UNKNOWN_FAMILY):
                # Dispatch never resolved; the short prefix may still name a custom application.
                events = self._unknown_observation(reason, final=False, data=bytes(self._prefix))
                if events:
                    return events
            return self._finish(Observation(status="incomplete", reason=reason))
        if self._inner is not None:
            events = self._inner.end(reason)
            if events:
                return self._merge_inner()
        return ()

    def _identified(self):
        parser = self._parser
        self.correlation = getattr(parser, "correlation", None)
        encryption = "tls" if self._candidate == "tls" else None
        protocol = None if encryption else parser.protocol_name
        if self._candidate in ("text", "git_text", "tpkt"):
            self._candidate = parser.family
        hostname = parser.host if hasattr(parser, "host") else None
        alpn = parser.alpn if encryption else ()
        evidence = [Evidence("encryption" if encryption else "application_protocol",
                             encryption or protocol, self.source, "structural")]
        if self._hint is not None:
            evidence.append(Evidence('candidate_hint', self._hint, self._hint_source, 'context'))
        host_source = getattr(parser, "host_source", "tls_sni" if encryption else "http_host")
        application = None
        if hostname:
            evidence.append(Evidence("hostname", hostname, self.source + ":" + host_source, "asserted"))
        match = self._signature(self._candidate, getattr(parser, "contexts", None))
        if match is not None:
            application = match.name
            evidence.append(Evidence("application", application, "signature:" + self._candidate, "configured_signature"))
        elif hostname:
            application = self.rules.lookup(host_source, hostname)
            if application:
                evidence.append(Evidence("application", application, host_source + ":exact_rule", "configured_mapping"))
        for offered in alpn:
            evidence.append(Evidence("offered_alpn", offered, self.source + ":client_hello", "offered"))
        for field, value, provenance, strength in getattr(parser, "extra_evidence", ()):
            evidence.append(Evidence(field, value, self.source + ":" + provenance, strength))
        for field, value, provenance in getattr(parser, "fingerprints", ()):
            evidence.append(Evidence(field, value, self.source + ":" + provenance, "derived"))
        return Observation(status="identified", encryption=encryption, application_protocol=protocol,
                           application=application, hostname=hostname, offered_alpn=alpn,
                           evidence=tuple(evidence), reason=parser.reason,
                           scope=getattr(parser, "scope", "initial_message"))

    def feed(self, data: bytes) -> Tuple[Event, ...]:
        if not isinstance(data, bytes):
            raise TypeError("feed expects bytes")
        self.metrics.bytes_received += len(data)
        if self._terminal or not data:
            return ()
        if self.metrics.updates >= self.config.max_updates:
            return self._finish(Observation(status="budget_exhausted", reason="Update budget exhausted"))
        self.metrics.updates += 1
        allowance = self.config.max_bytes - self.metrics.bytes_inspected
        chunk = data[:allowance]
        if self._next is not None:
            return self._forward(chunk)
        if self._unknown is not None:
            # Dispatch already failed; only unknown-payload signatures remain. Collect a
            # bounded prefix and evaluate after each update: a positive match is final,
            # a miss waits for more bytes, the budget or EOF. No parser runs here.
            room = self._unknown_limit - len(self._unknown)
            self._unknown.extend(chunk[:room])
            self.metrics.bytes_inspected += min(room, len(chunk))
            self.metrics.parser_calls += 1
            return self._unknown_observation("Prefix outside supported protocol families",
                                             final=len(self._unknown) >= self._unknown_limit)
        try:
            previous = 0
            if self._candidate is None:
                previous = len(self._prefix)
                probe = (bytes(self._prefix) + chunk[:LOOKAHEAD - previous]
                         if previous else chunk[:LOOKAHEAD])
                candidate = self._hint or select(probe)
                if candidate == "unknown":
                    self.metrics.bytes_inspected += len(probe) - previous
                    if self._unknown_limit:
                        self._unknown = bytearray(bytes(self._prefix) + chunk[:self._unknown_limit - previous])
                        self._prefix.clear()
                        self.metrics.bytes_inspected += len(self._unknown) - len(probe)
                        self.metrics.parser_calls += 1
                        return self._unknown_observation("Prefix outside supported protocol families",
                                                         final=len(self._unknown) >= self._unknown_limit)
                    return self._finish(Observation(status="unknown", reason="Prefix outside supported protocol families"))
                if candidate is None:
                    # select() always resolves once LOOKAHEAD bytes are available.
                    self._prefix.extend(chunk)
                    self.metrics.bytes_inspected += len(chunk)
                    return ()
                self._candidate = candidate
                self.metrics.candidates_selected += 1
                self._parser = FACTORIES[candidate](self.config)
                if previous:
                    # Replay the bounded routing prefix once, not the accumulated stream.
                    chunk = bytes(self._prefix) + chunk
                    self._prefix.clear()
            self.metrics.parser_calls += 1
            if self._continuing:
                # Already identified: the parser only derives optional evidence now or
                # watches for a shift boundary. Any failure or budget end keeps the
                # identification and stops quietly.
                return self._continue(chunk)
            # Charge submitted new bytes conservatively on errors. Prefix bytes
            # were already charged while dispatch waited for a discriminator.
            new_bytes = len(chunk) - previous
            self.metrics.bytes_inspected += new_bytes
            consumed = self._parser.feed(chunk)
            self.metrics.bytes_inspected -= new_bytes - max(0, consumed - previous)
            if self._parser is not None and self._parser.done:
                if getattr(self._parser, "continues", False):
                    # Publish the identification now; keep the parser for derived evidence
                    # (for example SSH KEXINIT after the banner) or a later shift command
                    # (SMTP STARTTLS). Remaining bytes of this chunk belong to the continuation.
                    self._continuing = True
                    events = self._publish(self._identified())
                    rest = chunk[consumed:]
                    if rest:
                        events += self._continue(rest)
                    return events
                shift = getattr(self._parser, "shift", None)
                if shift is not None:
                    return self._begin_shift(shift, chunk[consumed:])
                return self._finish(self._identified())
        except BudgetError as error:
            return self._finish(Observation(status="budget_exhausted", reason=str(error)))
        except AmbiguousPrefix as error:
            # Structurally valid for several families: record the candidates so a
            # session-level verdict can intersect both directions. Never a guess here.
            return self._finish(Observation(status="unknown", reason=str(error), evidence=(
                Evidence("ambiguous_candidates", ",".join(error.candidates), self.source, "context"),)))
        except UnsupportedPrefix as error:
            return self._finish(Observation(status="unknown", reason=str(error)))
        except ParseError as error:
            # Errors are terminal; no unrelated protocol scan is restarted.
            return self._finish(Observation(status="malformed", reason=str(error)))
        if self.metrics.bytes_inspected >= self.config.max_bytes:
            return self._finish(Observation(status="budget_exhausted", reason="Byte budget exhausted"))
        return ()

    def feed_decrypted(self, data: bytes) -> Tuple[Event, ...]:
        """Accept authenticated/decrypted plaintext ONLY from the host TLS stack.

        Must begin at the plaintext stream start, not at an arbitrary record.
        This API does not decrypt and must never receive encrypted TLS records.
        """
        if not isinstance(data, bytes):
            raise TypeError("feed_decrypted expects bytes")
        if self.source != "wire" or self.observation.encryption != "tls" or self.observation.status == "invalidated":
            raise ValueError("Decrypted data requires a previously identified TLS envelope")
        if self._inner is None:
            self._outer = self.observation
            self._inner = Inspector(self.config, self.rules, source="decrypted", signatures=self.signatures)
        events = self._inner.feed(data)
        return self._merge_inner() if events else ()

    def _merge_inner(self):
        outer, inner = self._outer, self._inner.observation
        # Never promote the offered ALPN to an observed inner protocol.
        # Do not retain an outer hostname mapping when a different inner host appears.
        has_inner_host = inner.hostname is not None
        application = inner.application if has_inner_host else outer.application
        if inner.status != "identified":
            application = None
        outer_evidence = tuple(e for e in outer.evidence
                               if e.field != "application" or (not has_inner_host and application))
        merged = replace(inner, encryption="tls", offered_alpn=outer.offered_alpn,
                         hostname=inner.hostname if has_inner_host else outer.hostname,
                         application=application,
                         evidence=outer_evidence + inner.evidence,
                         reason="TLS envelope retained; plaintext: " + inner.reason)
        return self._publish(merged, "refined")

    @property
    def decrypted_metrics(self):
        return self._inner.metrics if self._inner is not None else None
