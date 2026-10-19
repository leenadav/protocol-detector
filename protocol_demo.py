"""Readable offline protocol examples. Use --json for machine-readable details."""
import argparse
import json
from dataclasses import asdict
from protocol_engine import DatagramInspector, Inspector, supported_protocols
from protocol_fixtures import STREAM_CASES, DATAGRAM_CASES, HINTED_DATAGRAM_CASES, HINTED_STREAM_CASES
from protocol_engine.extended import H2_PREFACE
from proxy_demo import client_hello

HTTP2 = H2_PREFACE + b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
SOCKS5 = b"\x05\x01\x00\x05\x01\x00\x03\x0bexample.com\x01\xbb"

MQTT = b"\x10\x10\x00\x04MQTT\x04\x02\x00\x3c\x00\x04demo"
RESP = b"*2\r\n$4\r\nECHO\r\n$5\r\nhello\r\n"
AMQP_091 = b"AMQP\x00\x00\x09\x01"
AMQP_10 = b"AMQP\x00\x01\x00\x00"


def examples():
    return [
        ("HTTP/1.1", b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        ("HTTP/2", HTTP2),
        ("SOCKS5 client greeting + CONNECT", SOCKS5),
        ("SMTP client greeting", b"EHLO client.example.com\r\n"),
        ("SSH identification", b"SSH-2.0-Demo_1.0\r\n"),
        ("TLS ClientHello", client_hello()),
        ("MQTT 3.1.1 CONNECT", MQTT),
        ("RESP command array", RESP),
        ("AMQP 0-9-1 version header", AMQP_091),
        ("AMQP 1.0 version header", AMQP_10),
        *[("TCP " + protocol, payload) for payload, protocol in STREAM_CASES],
        ("HTTP/2 prefix without SETTINGS", H2_PREFACE),
        ("Ambiguous server greeting", b"220 mail.example.com ready\r\n"),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--list", action="store_true", help="List supported families and precise profiles")
    args = parser.parse_args()
    if args.list:
        for entry in supported_protocols():
            print(json.dumps(asdict(entry)) if args.json else "{} [{}]: {}".format(entry.family, "/".join(entry.transports), entry.profile))
        return
    if not args.json:
        print("Offline examples — synthetic data, no network connection\n")
    for label, data in examples():
        inspector = Inspector()
        # Deliberately split inputs: parsers must not depend on feed boundaries.
        for start in range(0, len(data), 7):
            inspector.feed(data[start:start + 7])
        result = inspector.observation
        if args.json:
            print(json.dumps({"example": label, "observation": asdict(result),
                              "metrics": asdict(inspector.metrics)}))
        else:
            identified = result.application_protocol or result.encryption or "not identified"
            print("{} -> {} | {}".format(label, result.status.upper(), identified))
            if result.status == "detecting":
                print("  More bytes are needed before identification.")
            else:
                print("  " + result.reason)
            print()


    for data, protocol, hint in HINTED_STREAM_CASES:
        inspector = Inspector(protocol_hint=hint)
        for start in range(0, len(data), 7):
            inspector.feed(data[start:start + 7])
        result = inspector.observation
        if args.json:
            print(json.dumps({'example': 'TCP ' + protocol, 'candidate_hint': hint,
                              'observation': asdict(result), 'metrics': asdict(inspector.metrics)}))
        else:
            print('TCP {} [candidate: {}] -> {} | {}'.format(protocol, hint, result.status.upper(), result.application_protocol or 'not identified'))
            print('  ' + result.reason + '\n')

    udp = DatagramInspector()
    for data, protocol, hint in tuple((data, protocol, None) for data, protocol in DATAGRAM_CASES) + HINTED_DATAGRAM_CASES:
        result = udp.inspect(data, hint)
        if args.json:
            print(json.dumps({"example": "UDP " + protocol, "candidate_hint": hint, "observation": asdict(result)}))
        else:
            print("UDP {} -> {} | {}".format(protocol, result.status.upper(), result.application_protocol or "not identified"))
            print("  " + result.reason + "\n")


if __name__ == "__main__":
    main()
