"""Input normalization and quality contracts per adapter (D06).

Three adapters feed the engine and each states what it does with bytes it cannot or will not normalize:

    recorded     PCAP/pcapng files (analyze_pcap): truncated records end every active observation with a
                 capture gap; frames the decoder rejects are skipped rows with a typed reason; checksum policy
                 defaults to ignore because recorded host captures predate offload too
    host         live tcpdump (live_capture): a truncated record retracts every active observation (the
                 flow it belonged to cannot be known); rejected frames are counted by kind; checksum policy
                 defaults to ignore (transmit-side offload makes checksums meaningless on the capturing host)
    reassembled  the coordinator's retained tier and the TLS decoder: gaps, conflicting overlaps and budget
                 rejections are typed reason codes on the connection (stage 4), never partial inspection

What every adapter guarantees: a packet the decoder rejects never reaches an inspector; a flow whose first
fragment, length-inconsistent or checksum-failing packet named its endpoints is marked (`input_quality` on its
session record, capture quality `degraded` in its layered view) so it never appears fully inspected; IPv4
fragmentation, IPv6 and non-IPv4 link types are unsupported and said so. Checksum policies:

    ignore   never computed (default): correct for host captures with offload and for most recorded ones
    audit    computed and counted, packets still inspected: shows whether a capture point sees offload
    verify   a failing packet is skipped and its flow marked: for recorded captures from a tap or SPAN only
"""
from collections import Counter

from .packets import PacketError

ADAPTERS = ("recorded", "host", "reassembled")
KINDS = PacketError.KINDS


class InputQuality:
    """Counts of rejected or suspect input by kind, plus the checksum policy in force."""

    def __init__(self, adapter, checksums="ignore"):
        if adapter not in ADAPTERS:
            raise ValueError("unknown adapter")
        self.adapter = adapter
        self.checksums = checksums
        self.counts = Counter()
        self.flows_marked = 0

    def rejected(self, error):
        self.counts[error.kind] += 1
        return error.endpoints

    def audited(self, failures):
        if failures:
            self.counts["checksum"] += 1

    def truncated(self):
        self.counts["truncated"] += 1

    def render(self):
        return {"adapter": self.adapter, "checksums": self.checksums, "rejected": {kind: self.counts[kind] for kind in KINDS if self.counts[kind]},
                "flows_marked": self.flows_marked,
                "unsupported": ["ipv4-fragments", "ipv6", "non-ipv4-link-types"],
                "checksums_note": ("not verified: capture may precede checksum offload" if self.checksums == "ignore"
                                   else "computed; failures counted, packets inspected" if self.checksums == "audit"
                                   else "verified; failing packets skipped and their flows marked")}
