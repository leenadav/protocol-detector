"""Opt-in real capture check: only synthetic loopback TCP port 45991."""
import socket
import threading
import time
from live_manager import LiveManager


def main():
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', 45991))
    listener.listen(1)
    listener.settimeout(8)

    def reply():
        connection, _ = listener.accept()
        with connection:
            connection.recv(4096)
            connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK')
        listener.close()

    manager = LiveManager()
    interface = 'lo0' if 'lo0' in manager.interfaces()['interfaces'] else 'lo'
    try:
        manager.start(interface, 10, 'synthetic')
        time.sleep(1)
        if manager.snapshot()['error']:
            raise RuntimeError(manager.snapshot()['error'])
        thread = threading.Thread(target=reply, daemon=True)
        thread.start()
        with socket.create_connection(('127.0.0.1', 45991), timeout=3) as client:
            client.sendall(b'GET /demo HTTP/1.1\r\nHost: example.test\r\n\r\n')
            client.recv(4096)
        thread.join(4)
        time.sleep(1)
        manager.stop()
        manager.thread.join(5)
        result = manager.snapshot()
        assert not result['error'], result['error']
        assert any(s['app'] == 'web-browsing' for s in result['sessions']), result
        assert result['state'] == 'stopped', result['state']
        print('PASS: real loopback capture classified synthetic HTTP and stopped cleanly.')
        print(result['summary'])
    finally:
        manager.stop()
        listener.close()


if __name__ == '__main__':
    main()
