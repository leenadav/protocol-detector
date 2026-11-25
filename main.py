"""Start the local demo page (Protocol Observatory) on the Go engine; `make serve` does the same.

PRO-402: the page is served by the Go binary's `protodetect serve` (presentation/launch.py finds it and opens the
browser on 127.0.0.1). No network connection is made beyond loopback, and no Python engine runs.
"""
import ssl


def make_tls_example():
    """Real ClientHello bytes from Python's TLS implementation, in memory (a fixture some tests import)."""
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = ssl.create_default_context().wrap_bio(incoming, outgoing, server_hostname="example.com")
    try:
        client.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


if __name__ == "__main__":
    from presentation.launch import main
    main()
