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
from .applications import APPLICATIONS, OUTCOMES, Application, application_name, custom_application
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
    shifted_from: Optional[str] = None  # application whose structural boundary announced this one (CONNECT, STARTTLS, ...)

    @property
    def identified(self):
        return self.app not in _OUTCOMES


def _label(observation):
    return observation.application_protocol or observation.encryption


def _evidence(observation, field):
    for evidence in observation.evidence:
        if evidence.field == field:
            return evidence.value
    return None


def _shifted_from(observation):
    """Catalog name of the application that carried a shift into this observation, or None."""
    carrier = _evidence(observation, "shift_from")
    if carrier is None:
        return None
    if _evidence(observation, "shift") == "http-connect":
        return "http-proxy"
    return application_name(carrier if not carrier.startswith("http") else carrier, None) or carrier


def _candidates(observation):
    """Candidate families recorded by an ambiguous unknown direction, or an empty set."""
    if observation.status != "unknown":
        return frozenset()
    for evidence in observation.evidence:
        if evidence.field == "ambiguous_candidates":
            return frozenset(evidence.value.split(","))
    return frozenset()


def _application(observation, transport, signatures=None):
    """Catalog entry for an identified observation.

    Configured mappings and custom signatures become applications of their own:
    a signature supplies its own category/risk metadata, a RuleIndex mapping
    inherits its carrier. A signature on an unknown payload is carried by
    unknown-tcp/unknown-udp.
    """
    base = application_name(observation.application_protocol, observation.encryption)
    if base == "web-browsing" and _evidence(observation, "http_method") == "CONNECT":
        base = "http-proxy"
    if observation.application:
        if base is None:
            base = "unknown-" + transport
        signature = signatures.get(observation.application) if signatures is not None else None
        if signature is not None:
            carrier = APPLICATIONS[base]
            return Application(signature.name, signature.category, signature.subcategory, signature.technology,
                               signature.risk, signature.description or ("Custom signature carried over " + base),
                               signature.characteristics, carrier.standard_ports, carrier.secure_ports,
                               (signature.parent or base,) if (signature.parent or base) in APPLICATIONS else (base,),
                               (), signature.parent if signature.parent in APPLICATIONS else base, ())
        return custom_application(observation.application, base)
    if base is None:
        return None
    return APPLICATIONS[base]


def _port_usage(application, transport, server_port):
    if server_port is None or not application.has_ports:
        return "unknown"
    return "standard" if application.uses_port(transport, server_port) else "nonstandard"


def _build(application, transport, server_port, status, client, server, reasons, shifted_from=None):
    implicitly_uses = application.implicitly_uses
    port_usage = _port_usage(application, transport, server_port)
    if shifted_from is not None and shifted_from != application.name:
        if shifted_from not in implicitly_uses:
            implicitly_uses = implicitly_uses + (shifted_from,)
        if port_usage != "standard" and shifted_from in APPLICATIONS:
            # ssl after STARTTLS on 587 or after RDP negotiation on 3389 is the carrier's standard port.
            carrier_usage = _port_usage(APPLICATIONS[shifted_from], transport, server_port)
            port_usage = carrier_usage if carrier_usage == "standard" else port_usage
    return Verdict(application.name, application.category, application.subcategory, application.technology,
                   application.risk, application.characteristics, application.container,
                   implicitly_uses, port_usage, status,
                   _label(client) if client is not None and client.status == "identified" else None,
                   _label(server) if server is not None and server.status == "identified" else None,
                   (client.encryption if client is not None else None) or (server.encryption if server is not None else None),
                   tuple(reasons), shifted_from)


def _outcome(name, transport, status, reasons, client=None, server=None):
    application = APPLICATIONS[name]
    return Verdict(name, application.category, application.subcategory, application.technology, application.risk,
                   application.characteristics, None, (), "unknown", status, None, None, None, tuple(reasons))


def classify(observation, transport=None, server_port=None, payload_bytes=None, signatures=None):
    """Verdict for one direction or one datagram.

    transport defaults to the observation's own transport. payload_bytes
    distinguishes incomplete (no payload) from insufficient-data (payload
    present, inspection unfinished) when the engine status is incomplete or
    detecting. None means unknown and is treated as payload seen.
    """
    if not isinstance(observation, Observation):
        raise TypeError("classify expects an Observation")
    return session_verdict(observation, None, transport or observation.transport, server_port, payload_bytes, None, True, signatures)


def session_verdict(client, server, transport="tcp", server_port=None, client_bytes=None, server_bytes=None,
                    handshake_complete=True, signatures=None):
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
        application = _application(chosen, transport, signatures)
        if application is None:
            reasons.append("Identified protocol has no catalog entry: " + str(_label(chosen)))
            return _outcome(unknown_name, transport, chosen.status, reasons, client, server)
        if len(identified) == 2:
            other = _application(identified[1], transport, signatures)
            if other is not None and other.name != application.name:
                reasons.append("Server direction identified as " + other.name)
        reasons.append(chosen.reason)
        for obs in (client, server):
            if obs is not None and obs.status == "invalidated":
                reasons.append("One direction was invalidated: " + obs.reason)
        shifted_from = _shifted_from(chosen) or (_shifted_from(identified[1]) if len(identified) == 2 else None)
        return _build(application, transport, server_port, "identified", client, server, reasons, shifted_from)
    observations = [obs for obs in (client, server) if obs is not None]
    candidate_sets = [_candidates(obs) for obs in observations]
    candidate_sets = [item for item in candidate_sets if item]
    if len(candidate_sets) == 2:
        # Both directions were structurally valid text for several families; the
        # intersection names the one family consistent with both sides.
        common = candidate_sets[0] & candidate_sets[1]
        if len(common) == 1:
            name = next(iter(common))
            if name in APPLICATIONS:
                reasons.append("Bidirectional correlation of ambiguous directions: " + ",".join(sorted(candidate_sets[0])) +
                               " with " + ",".join(sorted(candidate_sets[1])))
                return _build(APPLICATIONS[name], transport, server_port, "correlated", client, server, reasons)
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
            "encryption": verdict.encryption, "reasons": list(verdict.reasons), "shifted_from": verdict.shifted_from}
