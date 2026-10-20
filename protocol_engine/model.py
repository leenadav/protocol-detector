from dataclasses import dataclass
from types import MappingProxyType
from typing import Optional, Tuple
import re
import ipaddress


@dataclass(frozen=True)
class Config:
    max_bytes: int = 65536
    max_updates: int = 4096
    max_line: int = 8192
    max_headers: int = 128
    max_crc32c_bytes: int = 4096
    retain_contexts: bool = False   # keep bounded parser fields for signature evaluation
    signature_bytes: int = 2000     # unknown-payload prefix retained for custom signatures
    fingerprints: bool = False      # derive JA3/JA4/JA3S/JA4S/HASSH/HTTP2 handshake fingerprints

    def __post_init__(self):
        limits = ((self.max_bytes, 64, 1048576), (self.max_updates, 1, 1000000),
                  (self.max_line, 16, 65536), (self.max_headers, 1, 4096),
                  (self.max_crc32c_bytes, 0, 1048576), (self.signature_bytes, 16, 65536))
        if any(type(value) is not int or not low <= value <= high for value, low, high in limits):
            raise ValueError("Invalid inspection resource limits")
        if type(self.retain_contexts) is not bool or type(self.fingerprints) is not bool:
            raise ValueError("retain_contexts and fingerprints must be booleans")


@dataclass(frozen=True)
class Evidence:
    field: str
    value: str
    source: str
    strength: str


@dataclass(frozen=True)
class Observation:
    status: str = "detecting"
    transport: str = "tcp"
    encryption: Optional[str] = None
    application_protocol: Optional[str] = None
    application: Optional[str] = None
    hostname: Optional[str] = None
    offered_alpn: Tuple[str, ...] = ()
    evidence: Tuple[Evidence, ...] = ()
    reason: str = "Waiting for stream prefix"
    scope: str = "initial_message"


@dataclass(frozen=True)
class Event:
    revision: int
    kind: str
    observation: Observation


@dataclass
class Metrics:
    bytes_received: int = 0
    bytes_inspected: int = 0
    updates: int = 0
    parser_calls: int = 0
    candidates_selected: int = 0
    events_emitted: int = 0


def normalize_hostname(value):
    """Exact ASCII DNS host matching; IP literals are not application identities."""
    if not isinstance(value, str):
        raise ValueError("Hostname must be text")
    value = value.lower()
    if value.endswith("."):
        value = value[:-1]
    if not value or len(value) > 253:
        raise ValueError("Invalid DNS hostname length")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("IP literals are not DNS application identities")
    for label in value.split("."):
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):
            raise ValueError("Expected ASCII DNS labels (use IDNA A-labels)")
    return value


@dataclass(frozen=True)
class ApplicationRule:
    hostname: str
    application: str
    source: str  # tls_sni or http_host


class RuleIndex:
    """Immutable exact-host index, built once and shareable across inspectors.

    Rules produce an administrative attribution, never proof of application identity.
    No wildcard/suffix fallback: a.b.example must not accidentally match example.
    """
    def __init__(self, rules=(), max_rules=100000):
        if type(max_rules) is not int or not 0 <= max_rules <= 1000000:
            raise ValueError("Invalid maximum rule count")
        index = {}
        for rule in rules:
            if len(index) >= max_rules:
                raise ValueError("Application rule limit reached")
            if rule.source not in ("tls_sni", "http_host"):
                raise ValueError("Unsupported rule evidence source")
            if not isinstance(rule.application, str) or not 1 <= len(rule.application) <= 128:
                raise ValueError("Application name must contain 1..128 characters")
            if any(ord(c) < 32 or ord(c) == 127 for c in rule.application):
                raise ValueError("Control character in application name")
            key = (rule.source, normalize_hostname(rule.hostname))
            if key in index:
                raise ValueError("Duplicate application rule")
            index[key] = rule.application
        self._index = MappingProxyType(index)

    def lookup(self, source, hostname):
        return self._index.get((source, hostname))

    def __len__(self):
        return len(self._index)
