"""Capture, reassembly and live adapters around the engine (stage 1b, A01): one source, importable as a package.

    from protocol_adapters import sessions, analyze_pcap
    from protocol_adapters.live_capture import CaptureMonitor

The repository-root modules of the same names are shims over these for existing scripts and tests. Import
direction: adapters import protocol_engine; the engine never imports adapters.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULES = ("detectors", "packets", "link_packets", "capture_stream", "sessions", "analyze_pcap", "live_capture",
           "make_sample_pcap", "protocol_fixtures", "proxy_demo")
__all__ = list(MODULES) + ["ROOT"]
