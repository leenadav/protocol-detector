"""Internal enriched success result for layered UDP protocol profiles."""
from dataclasses import dataclass
from typing import Optional, Tuple
from .model import Evidence


@dataclass(frozen=True)
class DatagramMatch:
    reason: str
    encryption: Optional[str] = None
    application_protocol: Optional[str] = None
    hostname: Optional[str] = None
    offered_alpn: Tuple[str, ...] = ()
    evidence: Tuple[Evidence, ...] = ()
    contexts: Optional[dict] = None          # bounded signature contexts, never emitted
    signature_family: Optional[str] = None   # family whose signatures may read the contexts
