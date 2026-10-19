"""Incremental stream classification for proxy integrations.

Single-owner objects: one Inspector per direction, fed ordered, deduplicated bytes.
No network I/O, logging, decryption, policy enforcement or external lookups.
"""
from .catalog import ProtocolSupport, supported_protocols
from .engine import Inspector
from .datagram import DatagramInspector
from .model import ApplicationRule, Config, Evidence, Event, Observation, RuleIndex

__all__ = ["ProtocolSupport", "supported_protocols", "Inspector", "DatagramInspector", "ApplicationRule", "Config", "Evidence", "Event", "Observation", "RuleIndex"]
