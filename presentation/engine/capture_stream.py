"""Incremental PCAP and pcapng framing for pipes and files. No blocking reads here.

Classic PCAP (RFC 9460 draft format, all four magics) and pcapng (Section Header,
Interface Description, Enhanced Packet and Simple Packet blocks; other block
types are skipped) are detected from the first bytes. Every length is checked
before any slice is taken, blocks and records are bounded, and a failure closes
the decoder: capture framing is untrusted input.
"""
import struct
from packets import CaptureError, CaptureRecord

LINK_TYPES = frozenset((0, 1, 101, 108, 113, 228, 276))
FORMATS = {b"\xd4\xc3\xb2\xa1": ("<", 1000000), b"\xa1\xb2\xc3\xd4": (">", 1000000),
           b"\x4d\x3c\xb2\xa1": ("<", 1000000000), b"\xa1\xb2\x3c\x4d": (">", 1000000000)}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
MAX_SNAPLEN = 1048576
MAX_BLOCK = MAX_SNAPLEN + 65536      # packet data plus bounded options
_SHB, _IDB, _SPB, _EPB = 0x0A0D0D0A, 1, 3, 6


class PcapStreamDecoder:
    def __init__(self):
        self.buffer = bytearray()
        self.format = None            # "pcap" or "pcapng" once the first bytes arrived
        self.linktype = None          # classic header link type, or the first pcapng interface's
        self.finished = False
        self.failed = False
        self.endian = None
        self.resolution = None
        self.snaplen = None
        self.interfaces = []          # pcapng: (linktype, snaplen, resolution) per interface of the current section
        self.sections = 0
        self.blocks_skipped = 0

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
            if self.format is None:
                if len(self.buffer) < 4:
                    return []
                self.format = "pcapng" if bytes(self.buffer[:4]) == PCAPNG_MAGIC else "pcap"
            return self._parse_pcapng() if self.format == "pcapng" else self._parse()
        except CaptureError:
            self.failed = True
            self.buffer.clear()
            raise

    # ---- classic PCAP ----

    def _parse(self):
        if self.linktype is None:
            if len(self.buffer) < 24:
                return []
            magic = bytes(self.buffer[:4])
            if magic not in FORMATS:
                raise CaptureError("Not a classic PCAP or pcapng capture")
            self.endian, self.resolution = FORMATS[magic]
            major, minor, _, _, self.snaplen, self.linktype = struct.unpack(self.endian + "HHIIII", self.buffer[4:24])
            if (major, minor) != (2, 4) or not 1 <= self.snaplen <= MAX_SNAPLEN:
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

    # ---- pcapng ----

    def _parse_pcapng(self):
        records, pos = [], 0
        while len(self.buffer) - pos >= 12:
            block_type = bytes(self.buffer[pos:pos + 4])
            if block_type == PCAPNG_MAGIC:
                bom = bytes(self.buffer[pos + 8:pos + 12])
                if bom == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                elif bom == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                else:
                    raise CaptureError("pcapng section header without a valid byte-order magic")
            elif self.endian is None:
                raise CaptureError("pcapng stream must start with a section header block")
            else:
                endian = self.endian
            total = struct.unpack_from(endian + "I", self.buffer, pos + 4)[0]
            if total < 12 or total % 4 or total > MAX_BLOCK:
                raise CaptureError("Invalid pcapng block length")
            if len(self.buffer) - pos < total:
                break
            if struct.unpack_from(endian + "I", self.buffer, pos + total - 4)[0] != total:
                raise CaptureError("pcapng block trailer disagrees with its header")
            body = bytes(self.buffer[pos + 8:pos + total - 4])
            kind = struct.unpack(endian + "I", block_type)[0]
            if block_type == PCAPNG_MAGIC:
                self._section(endian, body)
            elif kind == _IDB:
                self._interface(body)
            elif kind == _EPB:
                records.append(self._enhanced(body))
            elif kind == _SPB:
                records.append(self._simple(body))
            else:
                self.blocks_skipped += 1  # name resolution, statistics, decryption secrets, custom blocks
            pos += total
        if pos:
            del self.buffer[:pos]
        return records

    def _section(self, endian, body):
        if len(body) < 16:
            raise CaptureError("Truncated pcapng section header")
        major, minor = struct.unpack_from(endian + "HH", body, 4)
        if (major, minor) != (1, 0):
            raise CaptureError("Unsupported pcapng version")
        self.endian = endian
        self.interfaces = []
        self.sections += 1
        self._options(body[16:])

    def _interface(self, body):
        if len(body) < 8:
            raise CaptureError("Truncated pcapng interface description")
        linktype, _, snaplen = struct.unpack_from(self.endian + "HHI", body, 0)
        if linktype not in LINK_TYPES:
            raise CaptureError("Unsupported capture link type: " + str(linktype))
        if snaplen > MAX_SNAPLEN:
            raise CaptureError("pcapng snapshot length exceeds 1 MiB")
        resolution = 1000000
        for code, value in self._options(body[8:]):
            if code == 9:
                if len(value) != 1:
                    raise CaptureError("Invalid pcapng if_tsresol option")
                exponent = value[0] & 0x7f
                if value[0] & 0x80:
                    if exponent > 48:
                        raise CaptureError("pcapng binary timestamp resolution outside profile")
                    resolution = 1 << exponent
                else:
                    if exponent > 12:
                        raise CaptureError("pcapng decimal timestamp resolution outside profile")
                    resolution = 10 ** exponent
        if len(self.interfaces) >= 256:
            raise CaptureError("pcapng interface count exceeds profile")
        self.interfaces.append((linktype, snaplen or MAX_SNAPLEN, resolution))
        if self.linktype is None:
            self.linktype, self.snaplen, self.resolution = linktype, snaplen or MAX_SNAPLEN, resolution

    def _options(self, data):
        """Yield (code, value) pairs; every option must fit the block and end at opt_endofopt or the end."""
        pos, found = 0, []
        while pos < len(data):
            if pos + 4 > len(data):
                raise CaptureError("Truncated pcapng option header")
            code, length = struct.unpack_from(self.endian + "HH", data, pos)
            padded = (length + 3) & ~3
            if pos + 4 + padded > len(data):
                raise CaptureError("pcapng option exceeds its block")
            if code == 0:
                return found
            found.append((code, data[pos + 4:pos + 4 + length]))
            if len(found) > 256:
                raise CaptureError("pcapng option count exceeds profile")
            pos += 4 + padded
        return found

    def _enhanced(self, body):
        if len(body) < 20:
            raise CaptureError("Truncated pcapng enhanced packet block")
        interface, high, low, captured, original = struct.unpack_from(self.endian + "IIIII", body, 0)
        if interface >= len(self.interfaces):
            raise CaptureError("pcapng packet references an undefined interface")
        linktype, snaplen, resolution = self.interfaces[interface]
        if captured > snaplen or captured > original:
            raise CaptureError("Invalid pcapng packet lengths")
        padded = (captured + 3) & ~3
        if 20 + padded > len(body):
            raise CaptureError("pcapng packet data exceeds its block")
        self._options(body[20 + padded:])
        return CaptureRecord(((high << 32) | low) / resolution, body[20:20 + captured], original, linktype)

    def _simple(self, body):
        if not self.interfaces:
            raise CaptureError("pcapng simple packet without an interface description")
        if len(body) < 4:
            raise CaptureError("Truncated pcapng simple packet block")
        linktype, snaplen, _ = self.interfaces[0]
        original = struct.unpack_from(self.endian + "I", body, 0)[0]
        captured = min(original, snaplen)
        if 4 + ((captured + 3) & ~3) != len(body):
            raise CaptureError("pcapng simple packet length disagrees with its block")
        return CaptureRecord(0.0, body[4:4 + captured], original, linktype)

    def end(self):
        self.finished = True
        if self.failed or self.buffer or (self.format == "pcap" and self.linktype is None) or (self.format != "pcap" and not self.sections):
            raise CaptureError("Incomplete or failed PCAP stream")
