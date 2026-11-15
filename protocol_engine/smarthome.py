"""Smart-home LAN control datagrams: LIFX LAN, Tuya LAN discovery and TP-Link Smart Home.

LIFX LAN (lan.developer.lifx.com, header v1): the 36-byte little-endian header
must state the datagram size, protocol 1024, addressable 1 and origin 0, reserved fields zero; a
tagged (broadcast) message zeroes its target, and the target's two trailing
bytes are always zero. Known message types must carry their documented payload
size. Target MAC, source and sequence are never emitted.

Tuya LAN 3.3 framing: prefix 0x000055AA, sequence, command, length counting the
rest of the frame, payload, CRC32 over everything before it and suffix
0x0000AA55. The (AES-ECB) payload is neither decrypted nor emitted; device
identifiers live there. Version 3.4 HMAC trailers and the 3.5 0x00006699 GCM
framing are outside the profile.

TP-Link Smart Home (UDP 9999 discovery): the datagram is a JSON object
obfuscated with the published XOR autokey (initial key 171); there is no length
prefix on UDP. After undoing the obfuscation the text must be printable ASCII,
nest at most MAX_JSON_DEPTH levels and parse as one JSON object whose top-level
keys all belong to the documented module vocabulary. Only those fixed module
names are emitted: aliases, MAC addresses, device identifiers and locations in
the reply are never read into output.
"""
import json
import zlib
from .datagram_result import DatagramMatch
from .extended import UnsupportedPrefix
from .model import Evidence
from .parsers import ParseError

LIFX_HEADER = 36
LIFX_PROTOCOL = 1024
# Payload sizes of the discovery and query messages that dominate LAN traffic.
_LIFX_TYPES = {2: ("getservice", 0), 3: ("stateservice", 5), 14: ("gethostfirmware", 0), 15: ("statehostfirmware", 20),
               16: ("getwifiinfo", 0), 17: ("statewifiinfo", 14), 18: ("getwififirmware", 0), 19: ("statewififirmware", 20),
               20: ("getpower", 0), 21: ("setpower", 2), 22: ("statepower", 2), 23: ("getlabel", 0), 25: ("statelabel", 32),
               32: ("getversion", 0), 33: ("stateversion", 12), 34: ("getinfo", 0), 35: ("stateinfo", 24),
               45: ("acknowledgement", 0), 48: ("getlocation", 0), 50: ("statelocation", 56), 51: ("getgroup", 0),
               53: ("stategroup", 56), 58: ("echorequest", 64), 59: ("echoresponse", 64),
               101: ("get", 0), 102: ("setcolor", 13), 107: ("lightstate", 52), 116: ("lightgetpower", 0),
               117: ("lightsetpower", 6), 118: ("lightstatepower", 2)}

TUYA_PREFIX = b"\x00\x00\x55\xaa"
TUYA_SUFFIX = b"\x00\x00\xaa\x55"
TUYA_MIN = 24  # 16-byte header, CRC32 and suffix
# Commands seen on the LAN discovery and control ports; anything else is "other".
_TUYA_COMMANDS = {0x00: "udp", 0x07: "control", 0x08: "status", 0x09: "heartbeat", 0x0a: "dp-query",
                  0x0d: "control-new", 0x10: "dp-query-new", 0x12: "ap-config", 0x13: "udp-new",
                  0x14: "ap-config-new", 0x23: "broadcast-lpv34"}

KASA_KEY = 171
MAX_JSON_DEPTH = 8
# An integer literal of more than 4300 digits is not accepted (review R6, 2026-11-14). The bound used to be
# CPython's own int() digit limit, which json.loads hits on 3.11+ and on patched 3.9/3.10 but not on older patch
# releases (3.9.6 parsed such a literal), so the verdict depended on the interpreter. It is a profile limit now.
MAX_JSON_INTEGER_DIGITS = 4300


def _bounded_integer(literal):
    """json.loads parse_int hook: bound the literal's digits and never convert it; integer values are not read."""
    if len(literal) - literal.startswith("-") > MAX_JSON_INTEGER_DIGITS:
        raise ValueError("JSON integer literal exceeds the digit limit")
    return 0


# Module names from the TP-Link Smart Home (Kasa) local protocol; only these are ever emitted.
_KASA_MODULES = frozenset(("system", "emeter", "schedule", "count_down", "anti_theft", "time", "cnCloud", "netif",
                           "context", "smartlife.iot.common.emeter", "smartlife.iot.smartbulb.lightingservice",
                           "smartlife.iot.lightStrip", "smartlife.iot.dimmer", "smartlife.iot.common.schedule",
                           "smartlife.iot.common.timesetting", "smartlife.iot.common.cloud",
                           "smartlife.iot.common.softaponboarding", "smartlife.iot.LAS", "smartlife.iot.PIR"))


def lifx_probe(data):
    return (len(data) >= LIFX_HEADER and int.from_bytes(data[:2], "little") == len(data)
            and int.from_bytes(data[2:4], "little") & 0xdfff == 0x1000 | LIFX_PROTOCOL)   # tagged bit free


def lifx(data, config):
    if len(data) < LIFX_HEADER:
        raise ParseError("LIFX LAN header requires 36 bytes")
    if int.from_bytes(data[:2], "little") != len(data):
        raise ParseError("LIFX LAN size field must equal the datagram length")
    word = int.from_bytes(data[2:4], "little")
    if word & 0xfff != LIFX_PROTOCOL or not word & 0x1000 or word & 0xc000:
        raise UnsupportedPrefix("LIFX LAN requires protocol 1024, addressable 1 and origin 0")
    tagged = bool(word & 0x2000)
    if data[14:16] != b"\x00\x00" or (tagged and any(data[8:14])):
        raise ParseError("LIFX LAN target must end in two zero bytes and be zero when tagged")
    if data[22] & 0xfc or data[34:36] != b"\x00\x00":
        raise ParseError("LIFX LAN reserved flag bits and the reserved word after the type must be zero")
    kind = int.from_bytes(data[32:34], "little")
    if not kind:
        raise ParseError("LIFX LAN message type zero is undefined")
    known = _LIFX_TYPES.get(kind)
    if known is not None and len(data) - LIFX_HEADER != known[1]:
        raise ParseError("LIFX LAN payload size disagrees with its message type")
    return _match("lifx-lan", "LIFX LAN header (size, protocol 1024, addressable, origin, target, message payload size) validated; "
                  "target, source and payload never emitted",
                  (("lifx_message", known[0] if known else "other"), ("lifx_tagged", "yes" if tagged else "no")))


def tuya_probe(data):
    return len(data) >= TUYA_MIN and data[:4] == TUYA_PREFIX and data[-4:] == TUYA_SUFFIX


def tuya(data, config):
    if len(data) < TUYA_MIN or data[:4] != TUYA_PREFIX or data[-4:] != TUYA_SUFFIX:
        raise UnsupportedPrefix("Tuya LAN 3.3 framing requires the 0x000055AA prefix and 0x0000AA55 suffix")
    if 16 + int.from_bytes(data[12:16], "big") != len(data):
        raise ParseError("Tuya LAN length field must count the rest of the datagram")
    if zlib.crc32(data[:-8]) != int.from_bytes(data[-8:-4], "big"):
        raise ParseError("Tuya LAN CRC32 does not match (3.4 HMAC framing is outside the profile)")
    command = int.from_bytes(data[8:12], "big")
    return _match("tuya-lan", "Tuya LAN 3.3 frame (prefix, length, CRC32, suffix) validated; payload not decrypted or emitted",
                  (("tuya_command", _TUYA_COMMANDS.get(command, "other")),))


def kasa_probe(data):
    return len(data) >= 8 and data[:2] == b"\xd0\xf2"   # '{"' under the 171 autokey


def kasa(data, config):
    if len(data) < 8:
        raise UnsupportedPrefix("TP-Link Smart Home datagram is too short")
    text, key, depth, quoted, escaped = bytearray(), KASA_KEY, 0, False, False
    for byte in data:       # one pass: undo the autokey, check printable ASCII and bound nesting depth
        plain = byte ^ key
        key = byte
        if not 32 <= plain <= 126:
            raise UnsupportedPrefix("TP-Link Smart Home plaintext must be printable ASCII JSON")
        if escaped:
            escaped = False
        elif quoted:
            escaped, quoted = plain == 0x5c, plain != 0x22
        elif plain == 0x22:
            quoted = True
        elif plain in (0x7b, 0x5b):
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ParseError("TP-Link Smart Home JSON exceeds the nesting budget")
        elif plain in (0x7d, 0x5d):
            depth -= 1
        text.append(plain)
    try:
        message = json.loads(text.decode("ascii"), parse_int=_bounded_integer)
    except ValueError:
        raise ParseError("TP-Link Smart Home plaintext is not one JSON document") from None
    if not isinstance(message, dict) or not message or not all(isinstance(value, dict) for value in message.values()):
        raise ParseError("TP-Link Smart Home message must be an object of module objects")
    if not set(message) <= _KASA_MODULES:
        raise UnsupportedPrefix("TP-Link Smart Home message names a module outside the documented vocabulary")
    first = next(iter(message))
    return _match("tplink-smarthome", "TP-Link Smart Home JSON (autokey 171) parsed with documented module names; "
                  "values such as alias, MAC, device ID and location are never emitted",
                  (("tplink_module", first), ("tplink_modules", str(len(message)))))


def _match(protocol, reason, rows):
    return DatagramMatch(reason, application_protocol=protocol,
                         evidence=(Evidence("application_protocol", protocol, "wire", "structural"),)
                         + tuple(Evidence(field, value, "wire:header", "structural") for field, value in rows))
