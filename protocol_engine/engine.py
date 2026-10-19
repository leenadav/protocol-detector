from dataclasses import replace
from typing import Optional, Tuple
from .model import Config, Evidence, Event, Metrics, Observation, RuleIndex
from .parsers import BudgetError, ParseError
from .extended import UnsupportedPrefix
from .dispatch import LOOKAHEAD, select
from .registry import PARSERS, FACTORIES


class Inspector:
    """One direction of one ordered stream; not thread safe.

    feed() returns only state-change events. Terminal initial-message inspection
    takes a constant-work bypass; it does NOT imply bypassing security policy.
    feed_decrypted() is a distinct trust boundary for plaintext supplied by a proxy.
    """
    def __init__(self, config: Optional[Config] = None, rules: Optional[RuleIndex] = None,
                 source: str = "wire", protocol_hint: Optional[str] = None):
        if source not in ("wire", "decrypted"):
            raise ValueError("Invalid byte provenance")
        self.config = config if config is not None else Config()
        self.rules = rules if rules is not None else RuleIndex()
        if not isinstance(self.config, Config) or not isinstance(self.rules, RuleIndex):
            raise TypeError("Expected Config and RuleIndex")
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
        self._inner = None
        self._outer = None

    @property
    def candidate(self):
        return self._candidate

    def _publish(self, observation, kind="updated"):
        if observation == self.observation:
            return ()
        self.observation = observation
        self.revision += 1
        self.metrics.events_emitted += 1
        return (Event(self.revision, kind, observation),)

    def _finish(self, observation):
        self._terminal = True
        self._parser = None
        self._prefix.clear()
        return self._publish(observation)

    def invalidate(self, reason: str) -> Tuple[Event, ...]:
        """Call when upstream reassembly/provenance is no longer trustworthy."""
        if not isinstance(reason, str) or not reason or len(reason) > 256:
            raise ValueError("Invalidation reason must contain 1..256 characters")
        self._inner = None
        self._outer = None
        self._terminal = True
        self._parser = None
        self._prefix.clear()
        return self._publish(Observation(status="invalidated", reason=reason), "invalidated")

    def end(self, reason="EOF before identification completed") -> Tuple[Event, ...]:
        """Finish observation; a capture boundary need not mean network EOF."""
        if not isinstance(reason, str) or not reason or len(reason) > 256:
            raise ValueError("End reason must contain 1..256 characters")
        if not self._terminal:
            return self._finish(Observation(status="incomplete", reason=reason))
        if self._inner is not None:
            events = self._inner.end(reason)
            if events:
                return self._merge_inner()
        return ()

    def _identified(self):
        parser = self._parser
        encryption = "tls" if self._candidate == "tls" else None
        protocol = None if encryption else parser.protocol_name
        if self._candidate in ("text", "git_text"):
            self._candidate = parser.family
        hostname = parser.host if hasattr(parser, "host") else None
        alpn = parser.alpn if encryption else ()
        evidence = [Evidence("encryption" if encryption else "application_protocol",
                             encryption or protocol, self.source, "structural")]
        if self._hint is not None:
            evidence.append(Evidence('candidate_hint', self._hint, 'caller', 'context'))
        host_source = "tls_sni" if encryption else "http_host"
        application = None
        if hostname:
            evidence.append(Evidence("hostname", hostname, self.source + ":" + host_source, "asserted"))
            application = self.rules.lookup(host_source, hostname)
            if application:
                evidence.append(Evidence("application", application, host_source + ":exact_rule", "configured_mapping"))
        for offered in alpn:
            evidence.append(Evidence("offered_alpn", offered, self.source + ":client_hello", "offered"))
        for field, value, provenance, strength in getattr(parser, "extra_evidence", ()):
            evidence.append(Evidence(field, value, self.source + ":" + provenance, strength))
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
        try:
            previous = 0
            if self._candidate is None:
                previous = len(self._prefix)
                probe = (bytes(self._prefix) + chunk[:LOOKAHEAD - previous]
                         if previous else chunk[:LOOKAHEAD])
                candidate = self._hint or select(probe)
                if candidate == "unknown":
                    self.metrics.bytes_inspected += len(probe) - previous
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
            # Charge submitted new bytes conservatively on errors. Prefix bytes
            # were already charged while dispatch waited for a discriminator.
            new_bytes = len(chunk) - previous
            self.metrics.bytes_inspected += new_bytes
            consumed = self._parser.feed(chunk)
            self.metrics.bytes_inspected -= new_bytes - max(0, consumed - previous)
            if self._parser is not None and self._parser.done:
                return self._finish(self._identified())
        except BudgetError as error:
            return self._finish(Observation(status="budget_exhausted", reason=str(error)))
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
            self._inner = Inspector(self.config, self.rules, source="decrypted")
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
