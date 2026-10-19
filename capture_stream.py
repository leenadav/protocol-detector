"""Incremental classic PCAP framing for pipes and files. No blocking reads here."""
import struct
from dataclasses import dataclass
from packets import CaptureError

LINK_TYPES = frozenset((0, 1, 101, 108, 113, 228, 276))
FORMATS = {b"\xd4\xc3\xb2\xa1": ("<", 1000000), b"\xa1\xb2\xc3\xd4": (">", 1000000),
           b"\x4d\x3c\xb2\xa1": ("<", 1000000000), b"\xa1\xb2\x3c\x4d": (">", 1000000000)}


@dataclass(frozen=True)
class CaptureRecord:
    timestamp: float
    data: bytes
    original_length: int
    linktype: int

    @property
    def truncated(self):
        return len(self.data) < self.original_length


class PcapStreamDecoder:
    def __init__(self):
        self.buffer = bytearray()
        self.linktype = None
        self.finished = False
        self.failed = False

    def feed(self, chunk):
        if self.finished or self.failed:
            raise CaptureError("PCAP decoder is closed")
        if not isinstance(chunk, bytes):
            raise TypeError("Expected bytes")
        # Reader feeds <=64KiB. Bound caller input as well as advertised frames.
        if len(chunk) > 65536:
            raise CaptureError("PCAP input chunk exceeds 64 KiB")
        self.buffer.extend(chunk)
        try:
            return self._parse()
        except CaptureError:
            self.failed = True
            self.buffer.clear()
            raise

    def _parse(self):
        if self.linktype is None:
            if len(self.buffer) < 24:
                return []
            magic = bytes(self.buffer[:4])
            if magic not in FORMATS:
                raise CaptureError("Expected classic PCAP; PCAPNG is unsupported")
            self.endian, self.resolution = FORMATS[magic]
            major, minor, _, _, self.snaplen, self.linktype = struct.unpack(self.endian + "HHIIII", self.buffer[4:24])
            if (major, minor) != (2, 4) or not 1 <= self.snaplen <= 1048576:
                raise CaptureError("Unsupported PCAP version or snapshot length")
            if self.linktype not in LINK_TYPES:
                raise CaptureError("Unsupported capture link type: " + str(self.linktype))
            del self.buffer[:24]
        records, pos = [], 0
        while len(self.buffer) - pos >= 16:
            seconds, fraction, included, original = struct.unpack_from(self.endian + "IIII", self.buffer, pos)
            if included > self.snaplen or included > original or fraction >= self.resolution:
                raise CaptureError("Invalid PCAP record lengths or timestamp")
            end = pos + 16 + included
            if end > len(self.buffer):
                break
            records.append(CaptureRecord(seconds + fraction / self.resolution,
                                         bytes(self.buffer[pos + 16:end]), original, self.linktype))
            pos = end
        if pos:
            del self.buffer[:pos]
        return records

    def end(self):
        self.finished = True
        if self.failed or self.linktype is None or self.buffer:
            raise CaptureError("Incomplete or failed PCAP stream")
