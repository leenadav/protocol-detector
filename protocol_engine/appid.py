"""Application identification verdicts in the vocabulary of application firewalls.

The engine's Observation records structural evidence per direction. This layer
turns one or two Observations into a single session verdict: a catalog
application or a session outcome (unknown-tcp, unknown-udp, incomplete,
insufficient-data, not-applicable), plus category/risk metadata and an
application-default port check. It adds no parsing and performs no lookup
proportional to the catalog size; a verdict is a handful of dictionary reads.

A verdict is as strong as the evidence beneath it: an identified structural
profile, never an authenticated product identity.
"""
from typing import NamedTuple, Optional, Tuple
from .applications import APPLICATIONS, OUTCOMES, application_name, custom_application
from .model import Observation

# Statuses that mean payload existed but no supported profile matched it.
_UNMATCHED = ("unknown", "malformed", "budget_exhausted")
_OUTCOMES = frozenset(OUTCOMES)


class Verdict(NamedTuple):
    """Immutable verdict; a tuple so that per-event construction stays cheap."""
    app: str
    category: str
    subcategory: str
    technology: str
    risk: int
    characteristics: Tuple[str, ...]
    base_app: Optional[str]          # catalog application carrying a configured mapping, else None
    implicitly_uses: Tuple[str, ...]
    port_usage: str                  # standard | nonstandard | unknown
    status: str                      # engine status that produced the verdict
    client_protocol: Optional[str]
    server_protocol: Optional[str]
    encryption: Optional[str]
    reasons: Tuple[str, ...]

    @property
    def identified(self):
        return self.app not in _OUTCOMES


def _label(observation):
    return observation.application_protocol or observation.encryption


def _application(observation):
    """Catalog entry for an identified observation; configured mappings become custom applications."""
    base = application_name(observation.application_protocol, observation.encryption)
    if base is None:
        return None
    if observation.application:
        return custom_application(observation.application, base)
    return APPLICATIONS[base]


def _port_usage(application, transport, server_port):
    if server_port is None or not application.has_ports:
        return "unknown"
    return "standard" if application.uses_port(transport, server_port) else "nonstandard"


def _build(application, transport, server_port, status, client, server, reasons):
    return Verdict(application.name, application.category, application.subcategory, application.technology,
                   application.risk, application.characteristics, application.container,
                   application.implicitly_uses, _port_usage(application, transport, server_port), status,
                   _label(client) if client is not None and client.status == "identified" else None,
                   _label(server) if server is not None and server.status == "identified" else None,
                   (client.encryption if client is not None else None) or (server.encryption if server is not None else None),
                   tuple(reasons))


def _outcome(name, transport, status, reasons, client=None, server=None):
    application = APPLICATIONS[name]
    return Verdict(name, application.category, application.subcategory, application.technology, application.risk,
                   application.characteristics, None, (), "unknown", status, None, None, None, tuple(reasons))


def classify(observation, transport=None, server_port=None, payload_bytes=None):
    """Verdict for one direction or one datagram.

    transport defaults to the observation's own transport. payload_bytes
    distinguishes incomplete (no payload) from insufficient-data (payload
    present, inspection unfinished) when the engine status is incomplete or
    detecting. None means unknown and is treated as payload seen.
    """
    if not isinstance(observation, Observation):
        raise TypeError("classify expects an Observation")
    return session_verdict(observation, None, transport or observation.transport, server_port, payload_bytes, None, True)


def session_verdict(client, server, transport="tcp", server_port=None, client_bytes=None, server_bytes=None,
                    handshake_complete=True):
    """Combine both directions of one session into a single verdict.

    Rules, in order: an identified direction wins (client preferred; a differing
    server identification is recorded, not silently dropped); otherwise payload
    outside every profile is unknown-tcp/udp; otherwise invalidated integrity is
    not-applicable; otherwise payload without a finished profile is
    insufficient-data; otherwise the session is incomplete.
    """
    if transport not in ("tcp", "udp"):
        raise ValueError("transport must be tcp or udp")
    unknown_name = "unknown-" + transport
    reasons = []
    if not handshake_complete:
        return _outcome("incomplete", transport, "no_handshake", ["Transport handshake not completed before tracking ended"])
    identified = [obs for obs in (client, server) if obs is not None and obs.status == "identified"]
    if identified:
        chosen = identified[0]
        application = _application(chosen)
        if application is None:
            reasons.append("Identified protocol has no catalog entry: " + str(_label(chosen)))
            return _outcome(unknown_name, transport, chosen.status, reasons, client, server)
        if len(identified) == 2:
            other = _application(identified[1])
            if other is not None and other.name != application.name:
                reasons.append("Server direction identified as " + other.name)
        reasons.append(chosen.reason)
        for obs in (client, server):
            if obs is not None and obs.status == "invalidated":
                reasons.append("One direction was invalidated: " + obs.reason)
        return _build(application, transport, server_port, "identified", client, server, reasons)
    observations = [obs for obs in (client, server) if obs is not None]
    unmatched = [obs for obs in observations if obs.status in _UNMATCHED]
    if unmatched:
        return _outcome(unknown_name, transport, unmatched[0].status, [obs.reason for obs in unmatched], client, server)
    invalidated = [obs for obs in observations if obs.status == "invalidated"]
    if invalidated:
        return _outcome("not-applicable", transport, "invalidated", [obs.reason for obs in invalidated], client, server)
    counts = [count for count in (client_bytes, server_bytes) if count is not None]
    payload = sum(counts) > 0 if counts else True
    if payload and observations:
        return _outcome("insufficient-data", transport, observations[0].status,
                        [obs.reason for obs in observations if obs.status in ("incomplete", "detecting")] or ["Payload without completed profile"],
                        client, server)
    return _outcome("incomplete", transport, observations[0].status if observations else "no_payload",
                    ["No application payload observed"], client, server)


def verdict_fields(verdict):
    """Flat JSON-friendly mapping, stable key order, no payload-derived values."""
    return {"app": verdict.app, "category": verdict.category, "subcategory": verdict.subcategory,
            "technology": verdict.technology, "risk": verdict.risk, "characteristics": list(verdict.characteristics),
            "base_app": verdict.base_app, "implicitly_uses": list(verdict.implicitly_uses),
            "port_usage": verdict.port_usage, "engine_status": verdict.status,
            "client_protocol": verdict.client_protocol, "server_protocol": verdict.server_protocol,
            "encryption": verdict.encryption, "reasons": list(verdict.reasons)}
