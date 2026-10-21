"""Educational payload detectors. Input must start at a TCP stream boundary.

MATCH means the documented structure passed, not full protocol validation.
No packet capture, TCP reassembly, decryption, or port-based guessing here.
"""
import re
from dataclasses import dataclass

MATCH = "MATCH"
NEED_MORE = "NEED_MORE"
NO_MATCH = "NO_MATCH"
LIMIT = 65536
TOKEN = rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+"


@dataclass(frozen=True)
class Result:
    protocol: str
    status: str
    evidence: str


def detect_http(data):
    """Check HTTP/1.0 or 1.1 start-line and header syntax, not the body."""
    def result(status, reason):
        return Result("HTTP", status, reason)

    end = data.find(b"\r\n\r\n")
    head = data[:end] if end >= 0 else data
    if len(head) > LIMIT:
        return result(NO_MATCH, "HTTP header exceeds demo limit")
    if any(c < 32 and c not in (9, 10, 13) or c == 127 for c in head):
        return result(NO_MATCH, "Control byte in HTTP header")
    if re.search(rb"(?<!\r)\n|\r(?!\n|$)", head):
        return result(NO_MATCH, "Invalid line ending")
    if b"\r\n" not in data:
        return result(NEED_MORE, "Waiting for complete start-line")
    first = data.split(b"\r\n", 1)[0]
    request = re.fullmatch(TOKEN + rb" [\x21-\x7e]+ HTTP/1\.[01]", first)
    response = re.fullmatch(rb"HTTP/1\.[01] [1-5][0-9]{2} [\x09\x20-\x7e\x80-\xff]*", first)
    if not (request or response):
        return result(NO_MATCH, "Start-line is not supported HTTP/1.x syntax")
    if end < 0:
        return result(NEED_MORE, "Start-line fits; waiting for end of headers")
    headers = []
    for line in head.split(b"\r\n")[1:]:
        name, separator, value = line.partition(b":")
        if not separator or not re.fullmatch(TOKEN, name):
            return result(NO_MATCH, "Malformed header name or missing colon")
        headers.append((name.lower(), value.strip()))
    if request and first.endswith(b"HTTP/1.1"):
        hosts = [value for name, value in headers if name == b"host"]
        if len(hosts) != 1 or not hosts[0]:
            return result(NO_MATCH, "HTTP/1.1 request needs one nonempty Host header")
    kind = "request" if request else "response"
    return result(MATCH, "HTTP/1.x " + kind + " and header syntax; body not validated")


def detect_ssh(data):
    """Check a leading SSH identification line; pre-banner text unsupported."""
    def result(status, reason):
        return Result("SSH", status, reason)

    prefix = b"SSH-"
    if not data.startswith(prefix) and not prefix.startswith(data):
        return result(NO_MATCH, "No leading SSH identification prefix")
    end = data.find(b"\r\n")
    if end < 0:
        if len(data) >= 255 or b"\n" in data or b"\x00" in data:
            return result(NO_MATCH, "Invalid or overlong SSH identification")
        return result(NEED_MORE, "Waiting for complete SSH identification line")
    line = data[:end]
    if end + 2 > 255:
        return result(NO_MATCH, "SSH identification exceeds 255 bytes")
    if not re.fullmatch(rb"SSH-(?:2\.0|1\.99)-[\x21-\x2c\x2e-\x7e]+(?: [\x20-\x7e]*)?", line):
        return result(NO_MATCH, "Invalid or unsupported SSH identification syntax")
    return result(MATCH, "SSH identification syntax; key exchange not validated")


def _client_hello_valid(body):
    # Validate nested vector lengths before reading their contents.
    if len(body) < 35 or body[:2] not in (b"\x03\x01", b"\x03\x02", b"\x03\x03"):
        return False
    pos = 34  # version (2 bytes) + random (32 bytes)

    def vector(width):
        nonlocal pos
        if pos + width > len(body):
            raise ValueError
        size = int.from_bytes(body[pos:pos + width], "big")
        pos += width
        if pos + size > len(body):
            raise ValueError
        value = body[pos:pos + size]
        pos += size
        return value

    try:
        session = vector(1)
        ciphers = vector(2)
        compression = vector(1)
        if len(session) > 32 or len(ciphers) < 2 or len(ciphers) % 2:
            return False
        if not compression or 0 not in compression:
            return False
        if pos == len(body):
            return True  # Older ClientHello may omit extensions.
        extensions = vector(2)
        if pos != len(body):
            return False
        offset = 0
        seen = set()
        while offset < len(extensions):
            if offset + 4 > len(extensions):
                return False
            kind = bytes(extensions[offset:offset + 2])
            size = int.from_bytes(extensions[offset + 2:offset + 4], "big")
            if kind in seen:
                return False
            seen.add(kind)
            offset += 4 + size
            if offset > len(extensions):
                return False
        return True
    except ValueError:
        return False


def detect_tls(data):
    """Check plaintext TLS records carrying an initial ClientHello.

    Handles a hello spanning records, but expects already ordered TCP bytes.
    Extension contents, cipher semantics and subsequent handshake are not checked.
    """
    def result(status, reason):
        return Result("TLS", status, reason)

    pos = 0
    handshake = bytearray()
    while True:
        header = data[pos:pos + 5]
        if header and header[0] != 22:
            return result(NO_MATCH, "Expected initial TLS handshake record")
        if len(header) >= 2 and header[1] != 3:
            return result(NO_MATCH, "Invalid TLS record version")
        if len(header) >= 3 and header[2] not in (1, 2, 3):
            return result(NO_MATCH, "Unsupported TLS record version")
        if len(header) < 5:
            return result(NEED_MORE, "Waiting for TLS record header")
        size = int.from_bytes(header[3:5], "big")
        if not 1 <= size <= 16384:
            return result(NO_MATCH, "Invalid plaintext handshake record length")
        if len(data) < pos + 5 + size:
            return result(NEED_MORE, "Waiting for declared TLS record payload")
        handshake.extend(data[pos + 5:pos + 5 + size])
        pos += 5 + size
        if handshake[0] != 1:
            return result(NO_MATCH, "Demo expects ClientHello as first handshake")
        if len(handshake) < 4:
            continue
        hello_size = int.from_bytes(handshake[1:4], "big")
        if hello_size < 41 or hello_size > LIMIT:
            return result(NO_MATCH, "Invalid ClientHello length or demo limit exceeded")
        if len(handshake) < 4 + hello_size:
            continue
        if not _client_hello_valid(handshake[4:4 + hello_size]):
            return result(NO_MATCH, "Malformed ClientHello fields or vector lengths")
        return result(MATCH, "TLS record + ClientHello structural lengths; extension contents not validated")


def detect_all(data):
    """Return all evidence without forcing a winner or using port numbers."""
    return [detector(data) for detector in (detect_http, detect_ssh, detect_tls)]
