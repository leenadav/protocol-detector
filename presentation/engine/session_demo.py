"""Two simulated connections; no network capture or transmission."""
from sessions import SessionManager


def run_demo():
    manager = SessionManager()
    client = ("192.0.2.10", 52000)
    server = ("192.0.2.20", 8080)
    ssh_client = ("192.0.2.10", 52001)
    ssh_server = ("192.0.2.30", 443)
    manager.open_connection(client, server, 1000, 9000)
    manager.open_connection(ssh_client, ssh_server, 2000, 8000)

    events = [
        ("HTTP tail arrives first", client, server, 1011, b"TP/1.1\r\nHost: example.com\r\n\r\n"),
        ("Another connection: SSH on port 443", ssh_client, ssh_server, 2000, b"SSH-2.0-Demo_1.0\r\n"),
        ("HTTP beginning fills the gap", client, server, 1000, b"DELETE / HT"),
        ("Duplicate HTTP beginning", client, server, 1000, b"DELETE / HT"),
        ("HTTP response in reverse direction", server, client, 9000, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
    ]
    for label, source, destination, sequence, payload in events:
        snapshot = manager.feed(source, destination, sequence, payload)
        print("\n" + label)
        print("  {}:{} -> {}:{}".format(*source, *destination))
        print("  Contiguous: {}, pending: {}, next sequence: {}".format(
            snapshot.contiguous_bytes, snapshot.pending_bytes, snapshot.next_sequence))
        for result in snapshot.results:
            print("  {}: {} — {}".format(result.protocol, result.status, result.evidence))


if __name__ == "__main__":
    run_demo()
