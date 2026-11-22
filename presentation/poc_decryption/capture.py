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


GO_SECONDS = 25


def analyze_capture(data, keylog, backend=None):
    """The decryption report of one capture and its key log. The Go engine answers when its binary is installed
    (migration M8; the selection of `protodetect analyze`: `backend`, then PROTODETECT_BACKEND, then Go when
    go_binary() finds it), the Python reference on request, without a binary, and for a request the binary
    declines. Both produce the same report and raise the same refusals. The capture and the key log reach the
    binary on its standard input only: never in arguments, the environment or a file."""
    import json
    import os
    import struct
    import subprocess
    from protocol_adapters.analyze_pcap import BACKENDS, GO_NOT_PORTED, go_binary
    requested = backend or os.environ.get("PROTODETECT_BACKEND") or None
    if requested is not None and requested not in BACKENDS:
        raise ValueError("Unknown backend {!r}; use go or python".format(requested))
    binary = None if requested == "python" else go_binary()
    if binary is None and requested == "go":
        raise ValueError("The Go backend binary is not installed (make go-build, or set PROTODETECT_GO_BINARY).")
    if binary is None or not isinstance(data, (bytes, bytearray)) or not isinstance(keylog, str) or len(data) > MAX_CAPTURE:
        return analyze_capture_reference(data, keylog)       # also the reference's own answer to a malformed request
    try:
        text = keylog.encode("utf-8")
    except UnicodeEncodeError:
        return analyze_capture_reference(data, keylog)
    try:
        done = subprocess.run([binary, "decrypt-capture"], input=struct.pack(">Q", len(data)) + bytes(data) + text,  # noqa: S603 - fixed argv; capture and secrets go to stdin
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=GO_SECONDS)
    except subprocess.TimeoutExpired:
        raise DecryptionError("Decryption exceeded %d seconds." % GO_SECONDS, "budget_exhausted") from None
    if done.returncode == GO_NOT_PORTED and requested != "go":
        return analyze_capture_reference(data, keylog)
    try:
        result = json.loads(done.stdout) if done.returncode in (0, 3) else None
    except ValueError:
        result = None
    if not isinstance(result, dict) or (done.returncode == 3) != ("error" in result):
        raise ValueError("The Go backend failed (status {}).".format(done.returncode))     # its stderr is not relayed
    if done.returncode == 3:
        from protocol_adapters.packets import CaptureError
        from protocol_adapters.sessions import StreamError
        kind, message = result.get("error_type"), str(result["error"])
        if kind == "DecryptionError":
            raise DecryptionError(message, result.get("code") or "unsupported_profile")
        raise {"CaptureError": CaptureError, "StreamError": StreamError}.get(kind, ValueError)(message)
    return result


def analyze_capture_reference(data, keylog):
    """analyze_capture on the Python reference engine (needs the `cryptography` extra)."""
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
