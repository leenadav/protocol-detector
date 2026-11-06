"""Protocol capability descriptors and inventory validation (stage 7, A12).

The engine's knowledge of a protocol family is spread over several tables that each describe one aspect:
the public inventory (catalog.supported_protocols), the stream parser factories (registry.PARSERS and the
internal FACTORIES), the datagram validators (datagram.VALIDATORS), the first-byte dispatch routes
(dispatch.FIRST_BYTE) and the application catalog. This module assembles one descriptor per family from
those tables and validates that they agree, at import time of the check and in `make check`, so that a new
protocol has one explicit capability definition to complete and a standard test template to copy
(test_protocol_template.py). It derives, never duplicates: the tables stay the single source of each fact.

A descriptor states: family, transports, how a candidate is selected per transport (prefix route, shared
text route, explicit hint, peer-driven shift, datagram probe), the parser or validator that implements it,
the profile scope and text, whether both directions are supported, and the evidence fields the family is
allowed to emit (closed per family: a field outside the list fails the inventory check when a fixture
produces it). The protocol inventory stays distinct from the application catalog.
"""
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Tuple

from .catalog import supported_protocols
from .datagram import VALIDATORS
from .dispatch import FIRST_BYTE
from .registry import FACTORIES, PARSERS

# Families reached through the shared text route (line-oriented request/response protocols): no parser of
# their own in PARSERS, the TextParser discriminates them.
TEXT_ROUTED = frozenset(("http", "ssh", "smtp", "sip", "rtsp", "nats", "imap", "ftp", "pop3"))
# Internal factories that implement a public family's other direction or an ambiguity route.
DIRECTION_FACTORIES = MappingProxyType({"http2-server": "http2", "x11-server": "x11", "text": None, "git_text": "git", "tpkt": None})
# Datagram families validated by a sibling validator (same layout, discriminated inside it).
VALIDATOR_ALIASES = MappingProxyType({"ipfix": "netflow"})
SELECTIONS = ("prefix", "text", "hint", "peer", "datagram", "datagram-hint")


@dataclass(frozen=True)
class ProtocolDescriptor:
    family: str
    transports: Tuple[str, ...]
    selection: Tuple[str, ...]           # one entry per transport, from SELECTIONS
    implementation: Tuple[str, ...]      # parser/validator names, one per transport
    scope: str
    profile: str
    requires_hint: bool
    directions: Tuple[str, ...] = ("client",)
    evidence_fields: Tuple[str, ...] = field(default_factory=tuple)


def _prefix_families():
    return frozenset(route for route in FIRST_BYTE if route not in ("ambiguous", "unknown", "text", "tpkt"))


def build():
    """One descriptor per public family, derived from the tables; raises InventoryError on contradictions."""
    prefix = _prefix_families()
    descriptors = {}
    errors = []
    for entry in supported_protocols():
        if entry.family in descriptors:
            errors.append("duplicate inventory family: " + entry.family)
            continue
        selection, implementation = [], []
        for transport in entry.transports:
            if transport == "tcp":
                if entry.family in PARSERS:
                    implementation.append(entry.family)
                    selection.append("hint" if entry.requires_hint else "prefix" if entry.family in prefix else "prefix")
                elif entry.family in TEXT_ROUTED:
                    implementation.append("text")
                    selection.append("text")
                else:
                    errors.append("tcp family without parser or text route: " + entry.family)
                    continue
            elif transport == "udp":
                name = VALIDATOR_ALIASES.get(entry.family, entry.family)
                if name not in VALIDATORS:
                    errors.append("udp family without validator: " + entry.family)
                    continue
                implementation.append(name)
                selection.append("datagram-hint" if entry.requires_hint else "datagram")
            else:
                errors.append("unknown transport %r for %s" % (transport, entry.family))
        directions = ("client", "server") if any(DIRECTION_FACTORIES.get(name) == entry.family for name in FACTORIES) \
            or "response" in entry.profile.lower() or "both directions" in entry.profile.lower() or "server" in entry.profile.lower() else ("client",)
        descriptors[entry.family] = ProtocolDescriptor(entry.family, tuple(entry.transports), tuple(selection), tuple(implementation),
                                                       entry.scope, entry.profile, entry.requires_hint, directions)
    inventory = set(descriptors)
    for name in PARSERS:
        if name not in inventory and DIRECTION_FACTORIES.get(name, name) not in inventory and name != "text":
            errors.append("parser without inventory entry: " + name)
    for name in VALIDATORS:
        if name not in inventory and name not in VALIDATOR_ALIASES.values():
            errors.append("validator without inventory entry: " + name)
    for route in prefix:
        if route not in inventory and DIRECTION_FACTORIES.get(route, route) not in inventory:
            errors.append("dispatch route without inventory entry: " + route)
    for name in FACTORIES:
        if name not in PARSERS and name not in DIRECTION_FACTORIES:
            errors.append("internal factory without a declared role: " + name)
    if errors:
        raise InventoryError("; ".join(sorted(errors)))
    return MappingProxyType(descriptors)


class InventoryError(ValueError):
    pass


def validate_inventory():
    """Build the descriptors and return summary counts; raises InventoryError on any contradiction."""
    descriptors = build()
    return {"families": len(descriptors), "tcp": sum("tcp" in d.transports for d in descriptors.values()),
            "udp": sum("udp" in d.transports for d in descriptors.values()),
            "hint_only": sum(d.requires_hint for d in descriptors.values()),
            "text_routed": sum("text" in d.selection for d in descriptors.values())}
