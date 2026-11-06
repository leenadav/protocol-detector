"""Simulate a proxy supplying ClientHello, then already-decrypted HTTP.

No TLS decryption occurs here. The HTTP input is a separate synthetic fixture.
"""
import json
import ssl
from dataclasses import asdict
from protocol_engine import ApplicationRule, Inspector, RuleIndex


def client_hello():
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    context = ssl.create_default_context()
    context.set_alpn_protocols(["h2", "http/1.1"])
    connection = context.wrap_bio(incoming, outgoing, server_hostname="example.com")
    try:
        connection.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


def main():
    rules = RuleIndex([ApplicationRule("example.com", "Example demo service", "http_host")])
    inspector = Inspector(rules=rules)
    hello = client_hello()
    for offset in range(0, len(hello), 32):
        for event in inspector.feed(hello[offset:offset + 32]):
            print(json.dumps(asdict(event), ensure_ascii=False))
    # Integration contract: the host proxy supplies plaintext from its TLS stack.
    plaintext = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    for event in inspector.feed_decrypted(plaintext):
        print(json.dumps(asdict(event), ensure_ascii=False))
    print(json.dumps({"outer_metrics": asdict(inspector.metrics),
                      "decrypted_metrics": asdict(inspector.decrypted_metrics)}))


if __name__ == "__main__":
    main()
