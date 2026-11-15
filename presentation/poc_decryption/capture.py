"""Offline capture adapter: the coordinator reassembles, the Decryptor decodes (stage 4).

Nothing here decodes TCP state or keeps a flow table: packets go to the SessionCoordinator (the same owner the
live paths use), its retained tier hands StreamDeltas to the Decryptor, and the report is the Decryptor's.
"""
from . import DecryptionError, KeyProvider, MAX_STREAM
from .decryptor import Decryptor

MAX_CAPTURE = 8 * 1024 * 1024
MAX_FRAMES = 20000
MAX_CONNECTIONS = 64


def build(keys=None, connections=MAX_CONNECTIONS, emit=None):
    """A coordinator with the retained tier plus its Decryptor; shared by the offline and live adapters."""
    from protocol_adapters.coordinator import RetentionBudget, SessionCoordinator
    coordinator = SessionCoordinator(emit=emit, retain=RetentionBudget(per_direction=MAX_STREAM, connections=connections),
                                     max_connections=connections, byte_limit=16384, compact=True)
    return coordinator, Decryptor(coordinator, keys)


def analyze_capture(data, keylog):
    from protocol_adapters.capture_stream import PcapStreamDecoder
    from protocol_adapters.link_packets import decode_frame
    from protocol_adapters.packets import TCPPacket, PacketError
    if len(data) > MAX_CAPTURE:
        raise DecryptionError('Capture exceeds 8 MiB.', 'budget_exhausted')
    keys = KeyProvider()
    keys.append(keylog)
    coordinator, decryptor = build(keys)
    decoder, frames, skipped = PcapStreamDecoder(), 0, 0
    for offset in range(0, len(data), 65536):
        for record in decoder.feed(data[offset:offset + 65536]):
            frames += 1
            if frames > MAX_FRAMES or record.truncated:
                raise DecryptionError('Capture is truncated or exceeds 20,000 frames.', 'budget_exhausted')
            try:
                packet = decode_frame(record.data, record.linktype)
            except PacketError:
                skipped += 1
                continue
            if not isinstance(packet, TCPPacket):
                continue
            coordinator.accept(packet, record.timestamp)
            if coordinator.counts['retained_rejected_connections']:
                raise DecryptionError('Capture exceeds 64 TCP connections.', 'budget_exhausted')
        decryptor.pump()
        decryptor.work(quantum=256, rounds=64)
    decoder.end()
    coordinator.end('Capture input EOF')
    decryptor.pump()
    decryptor.work(quantum=1 << 20, rounds=1)
    return decryptor.report(frames, skipped)
