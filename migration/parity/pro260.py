"""PRO-260 (Lee, 2026-11-23): the approved Go-only divergence for TLS post-quantum hybrid key shares, as a model.

The frozen Python reference reports a TLS 1.3 ServerHello whose key_share selects a hybrid group, and a
HelloRetryRequest that asks for one, as unknown. The Go engine names the groups (IANA TLS Supported Groups,
draft-ietf-tls-ecdhe-mlkem) with their exact server-share lengths:

    0x11EB SecP256r1MLKEM768   65 + 1088 bytes, an uncompressed P-256 point first
    0x11EC X25519MLKEM768      1088 + 32 bytes, the ML-KEM ciphertext first (no fixed first byte)
    0x11ED SecP384r1MLKEM1024  97 + 1568 bytes, an uncompressed P-384 point first

and reports `selected_key_exchange` = `hybrid`. `with_hybrid_groups()` applies exactly that change to the
reference, in process and only while the context is open, so a differential can tell the approved divergence
from any other difference: a Go result that differs from the reference is accepted only when it equals the
reference under this model. No reference file changes. The model never parses on its own: it rewrites a
hybrid key_share into an X25519 stand-in of the same validity (a valid share becomes a valid 32-byte share, an
invalid one an invalid share), calls the reference's own parse_server_hello, so every other check runs in the
reference's order with the reference's messages, and maps the stand-in group and exchange class back.

    python3 -B migration/parity/pro260.py --self-test
"""
import contextlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

HYBRID_SHARES = {0x11eb: 65 + 1088, 0x11ec: 1088 + 32, 0x11ed: 97 + 1568}
POINT_FIRST = frozenset((0x11eb, 0x11ed))
STAND_IN = 29                                    # x25519: its 32-byte share has no fixed first byte
HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")


def _u16(data, pos):
    return int.from_bytes(data[pos:pos + 2], "big") if pos + 2 <= len(data) else None


def rewrite(body):
    """(rewritten body, hybrid group, retry) when the ServerHello's key_share names a hybrid group, else None.

    Only a well-framed extension block is rewritten; anything else is left to the reference unchanged."""
    if len(body) < 35:
        return None
    retry = body[2:34] == HRR_RANDOM
    pos = 35 + body[34]                          # past the session ID
    pos += 3                                     # cipher suite and compression
    if pos > len(body):
        return None
    if pos == len(body):
        return None
    block = _u16(body, pos)
    if block is None or pos + 2 + block != len(body):
        return None
    start, end, at = pos + 2, len(body), pos + 2
    extensions, found = [], None
    while at < end:
        kind, length = _u16(body, at), _u16(body, at + 2)
        if kind is None or length is None or at + 4 + length > end:
            return None
        value = body[at + 4:at + 4 + length]
        if kind == 51:
            if found is not None:
                return None                      # a duplicate: the reference rejects it unchanged
            found = len(extensions)
        extensions.append((kind, value))
        at += 4 + length
    if found is None:
        return None
    value = extensions[found][1]
    group = _u16(value, 0)
    if group not in HYBRID_SHARES:
        return None
    if retry:
        if len(value) != 2:
            return None
        stand_in = STAND_IN.to_bytes(2, "big")
    else:
        share = _u16(value, 2)
        if share is None or 4 + share != len(value):
            return None                          # bad framing: the reference reports it the same way
        key = value[4:]
        valid = len(key) == HYBRID_SHARES[group] and (group not in POINT_FIRST or key[:1] == b"\x04")
        key = bytes(32) if valid else bytes(31)  # an invalid share stays invalid: the reference's own message
        stand_in = STAND_IN.to_bytes(2, "big") + len(key).to_bytes(2, "big") + key
    extensions[found] = (51, stand_in)
    out = b"".join(kind.to_bytes(2, "big") + len(v).to_bytes(2, "big") + v for kind, v in extensions)
    return body[:start - 2] + len(out).to_bytes(2, "big") + out, group, retry


def hybrid_parse_server_hello(original):
    def parse(body, config, record_versions, record_remaining):
        changed = rewrite(bytes(body))
        if changed is None:
            return original(body, config, record_versions, record_remaining)
        new_body, group, retry = changed
        evidence, source, reason = original(new_body, config, record_versions, record_remaining)
        mapped = []
        for field, value, origin, strength in evidence:
            if field in ("selected_group", "requested_group") and value == str(STAND_IN):
                value = str(group)
            elif field == "selected_key_exchange" and value == "ecdhe" and not retry:
                value = "hybrid"
            mapped.append((field, value, origin, strength))
        return tuple(mapped), source, reason
    parse.pro260 = True
    return parse


@contextlib.contextmanager
def with_hybrid_groups():
    """The reference with the PRO-260 change, while the context is open (callers import the parser at call time)."""
    from protocol_engine import tls_server
    original = tls_server.parse_server_hello
    tls_server.parse_server_hello = hybrid_parse_server_hello(original)
    try:
        yield
    finally:
        tls_server.parse_server_hello = original


def self_test():
    from protocol_engine import Config, tls_server
    from protocol_engine.parsers import ParseError
    from protocol_engine.extended import UnsupportedPrefix

    def hello(extensions, cipher=0x1301, random=bytes(32)):
        block = b"".join(k.to_bytes(2, "big") + len(v).to_bytes(2, "big") + v for k, v in extensions)
        return b"\x03\x03" + random + b"\x00" + cipher.to_bytes(2, "big") + b"\x00" + len(block).to_bytes(2, "big") + block

    def run(body):
        try:
            return tls_server.parse_server_hello(body, Config(), 1 << 3, 0)
        except (ParseError, UnsupportedPrefix) as error:
            return type(error).__name__ + ": " + str(error)

    v13 = (43, b"\x03\x04")
    cases = []
    for group, size in sorted(HYBRID_SHARES.items()):
        key = (b"\x04" if group in POINT_FIRST else b"\x07") + bytes(size - 1)
        cases.append((group, hello((v13, (51, group.to_bytes(2, "big") + size.to_bytes(2, "big") + key)))))
    before = [run(body) for _, body in cases]
    with with_hybrid_groups():
        after = [run(body) for _, body in cases]
        short = run(hello((v13, (51, b"\x11\xec\x04\x5f" + bytes(1119)))))
        point = run(hello((v13, (51, b"\x11\xeb\x04\x81\x02" + bytes(1152)))))
        cipher = run(hello((v13, (51, b"\x11\xec\x04\x60" + bytes(1120))), cipher=0x1306))
        retry = run(hello((v13, (51, b"\x11\xed")), random=HRR_RANDOM))
        draft = run(hello((v13, (51, b"\x63\x99\x04\x60" + bytes(1120)))))
        classic = run(hello((v13, (51, b"\x00\x1d\x00\x20" + bytes(32)))))
    assert not hasattr(tls_server.parse_server_hello, "pro260")                                   # restored
    for (group, _), old, new in zip(cases, before, after):
        assert old == "UnsupportedPrefix: Server key share group outside supported profile", old
        rows = {field: value for field, value, _, _ in new[0]}
        assert rows["selected_group"] == str(group) and rows["selected_key_exchange"] == "hybrid", new
        assert rows["selected_tls_version"] == "1.3" and new[1] == "server_hello", new
    assert short == point == "ParseError: Server key share encoding length or point format invalid", (short, point)
    assert cipher == "UnsupportedPrefix: TLS 1.3 cipher outside RFC8446 profile", cipher        # the reference's order
    assert {f: v for f, v, _, _ in retry[0]}["requested_group"] == str(0x11ed), retry
    assert draft == "UnsupportedPrefix: Server key share group outside supported profile", draft
    assert {f: v for f, v, _, _ in classic[0]}["selected_key_exchange"] == "ecdhe", classic         # untouched
    assert rewrite(b"\x03\x03") is None and rewrite(hello((v13,))) is None
    print("pro260 self-test: ok (3 hybrid groups, bad length, bad point, check order, retry, draft group, classic group)")
    return 0


if __name__ == "__main__":
    if sys.argv[1:] != ["--self-test"]:
        sys.exit(__doc__)
    sys.exit(self_test())
