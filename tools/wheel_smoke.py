"""Classify two fixtures from an installed wheel, never from the working tree.

Run from any directory with the interpreter of the environment the wheel was
installed into: the engine must import from that environment's site-packages
(not from a checkout on sys.path), classify an HTTP request through the stream
API and a DNS query through the datagram API, and declare no dependency. Exit
status 1 on any failure. Usage: <venv>/bin/python tools/wheel_smoke.py
"""
import os
import sys


def main():
    sys.path = [entry for entry in sys.path if os.path.abspath(entry or os.getcwd()) != os.path.dirname(os.path.dirname(os.path.abspath(__file__)))]
    try:
        import protocol_engine
        from protocol_engine import DatagramInspector, Inspector, supported_protocols
    except ImportError as error:
        print("wheel smoke: no installed protocol_engine in this interpreter ({}); install the wheel first".format(error))
        return 1
    origin = os.path.abspath(protocol_engine.__file__)
    if "site-packages" not in origin.replace(os.sep, "/").split("/"):
        print("wheel smoke: protocol_engine imported from the tree, not an installed wheel:", origin)
        return 1
    inspector = Inspector()
    inspector.feed(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    if inspector.observation.application_protocol != "http/1.1":
        print("wheel smoke: HTTP request not identified:", inspector.observation)
        return 1
    dns = DatagramInspector().inspect(bytes.fromhex("123401000001000000000000") + b"\x03www\x07example\x03com\x00\x00\x01\x00\x01")
    if dns.application_protocol != "dns":
        print("wheel smoke: DNS query not identified:", dns)
        return 1
    print("wheel smoke: ok (python {}.{}.{}, {} families, engine at {})".format(sys.version_info[0], sys.version_info[1], sys.version_info[2],
                                                                                 len(list(supported_protocols())), origin))
    return 0


if __name__ == "__main__":
    sys.exit(main())
