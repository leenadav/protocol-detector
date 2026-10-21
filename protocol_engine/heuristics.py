"""Bounded payload heuristics for traffic no profile matched.

Heuristics never identify an application. They describe the shape of an unknown
payload prefix (entropy, printable ratio, zero ratio) so that a verdict can say
"unknown-tcp, high-entropy" rather than only "unknown-tcp". Every number is
computed over at most `Config.heuristic_bytes` bytes with one pass and a
256-entry histogram; no payload byte is emitted. Evidence strength is
`heuristic`.
"""
import math
from typing import NamedTuple


class PayloadProfile(NamedTuple):
    size: int
    entropy: float          # Shannon entropy in bits per byte, 0..8
    printable: float        # fraction of bytes in 0x09,0x0a,0x0d,0x20..0x7e
    zeros: float            # fraction of 0x00 bytes
    longest_run: int        # longest run of printable bytes


_PRINTABLE = frozenset(range(0x20, 0x7f)) | {0x09, 0x0a, 0x0d}


def payload_profile(data, limit=512):
    """Profile of the first `limit` bytes; constant memory, one pass."""
    data = data[:limit]
    size = len(data)
    if size == 0:
        return PayloadProfile(0, 0.0, 0.0, 0.0, 0)
    counts = [0] * 256
    printable = zeros = run = longest = 0
    for byte in data:
        counts[byte] += 1
        if byte in _PRINTABLE:
            printable += 1
            run += 1
            if run > longest:
                longest = run
        else:
            run = 0
    zeros = counts[0]
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / size
            entropy -= probability * math.log2(probability)
    return PayloadProfile(size, round(abs(entropy), 2), round(printable / size, 3), round(zeros / size, 3), longest)


def payload_class(profile):
    """Coarse class of a payload prefix. Thresholds are documented in RISKS.md.

    insufficient: fewer than 8 bytes, nothing can be said.
    text: at least 95% printable bytes.
    high-entropy: at least 64 bytes whose entropy reaches 90% of the maximum a
    sample of that size can have (log2(min(size, 256)) bits); encrypted,
    compressed and random data look alike, so this is not a tunnel claim.
    sparse-binary: at least 30% zero bytes (length-prefixed or padded records).
    binary: everything else.
    """
    if profile.size < 8:
        return "insufficient"
    if profile.printable >= 0.95:
        return "text"
    if profile.size >= 64 and profile.entropy >= 0.90 * math.log2(min(profile.size, 256)):
        return "high-entropy"
    if profile.zeros >= 0.30:
        return "sparse-binary"
    return "binary"


def heuristic_evidence(data, source, limit=512):
    """Evidence tuple describing an unknown payload prefix; empty for empty data."""
    from .model import Evidence
    profile = payload_profile(data, limit)
    if not profile.size:
        return ()
    provenance = source + ":heuristic"
    return (Evidence("payload_class", payload_class(profile), provenance, "heuristic"),
            Evidence("payload_entropy", "{:.2f}".format(profile.entropy), provenance, "heuristic"),
            Evidence("payload_printable", "{:.3f}".format(profile.printable), provenance, "heuristic"),
            Evidence("payload_bytes_profiled", str(profile.size), provenance, "heuristic"))


def label_entropy(label):
    """Shannon entropy of one DNS label's bytes (bits per byte)."""
    if not label:
        return 0.0
    counts = {}
    for byte in label:
        counts[byte] = counts.get(byte, 0) + 1
    size = len(label)
    return round(abs(sum(c / size * math.log2(c / size) for c in counts.values())), 2)
