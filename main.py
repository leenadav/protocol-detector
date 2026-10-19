"""Offline examples: no network connection is made."""
import ssl
from detectors import detect_all


def make_tls_example():
    # Let Python's TLS implementation produce real ClientHello bytes in memory.
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = ssl.create_default_context().wrap_bio(
        incoming, outgoing, server_hostname="example.com"
    )
    try:
        client.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


def show(label, data):
    print("\n" + label)
    for result in detect_all(data):
        print("  {}: {} — {}".format(result.protocol, result.status, result.evidence))


if __name__ == "__main__":
    print("Protocol detector — offline payload examples")
    data = b"DELETE / HT"
    show("Partial HTTP", data)
    data += b"TP/1.1\r\nHost: example.com\r\n\r\n"
    show("Complete HTTP headers", data)
    show("HTTP response", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    show("SSH", b"SSH-2.0-Demo_1.0\r\n")
    show("TLS ClientHello (binary)", make_tls_example())
    show("Words alone are not evidence", b"File contains HTTP and SSH-2.0\r\n\r\n")
    from session_demo import run_demo
    print("\n--- Connection reassembly demo ---")
    run_demo()
