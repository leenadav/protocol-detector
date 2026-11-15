"""Opt-in real capture check of live decryption: only a synthetic TLS exchange on loopback TCP port 45991.

The certificate, the traffic and the key log are generated here; the key log is a temporary file that is
removed afterwards. Needs tcpdump, capture permission on the loopback interface and the `cryptography` package
(for the throwaway certificate). Run from this directory with the repository root on PYTHONPATH.
"""
import datetime
import os
import socket
import ssl
import tempfile
import threading
import time
from pathlib import Path

from live_manager import LiveManager


def certificate(folder):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'demo.invalid')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    (folder / 'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (folder / 'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))


def main():
    with tempfile.TemporaryDirectory() as name:
        folder = Path(name)
        certificate(folder)
        keylog = folder / 'keys.log'
        keylog.touch(mode=0o600)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(str(folder / 'cert.pem'), str(folder / 'key.pem'))
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_context.check_hostname = False
        client_context.verify_mode = ssl.CERT_NONE          # a throwaway self-signed certificate on loopback
        client_context.keylog_filename = str(keylog)
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.0.0.1', 45991))
        listener.listen(1)
        listener.settimeout(8)

        def reply():
            connection, _ = listener.accept()
            with server_context.wrap_socket(connection, server_side=True) as secure:
                secure.recv(4096)
                secure.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK')
            listener.close()

        manager = LiveManager()
        interface = 'lo0' if 'lo0' in manager.interfaces()['interfaces'] else 'lo'
        try:
            manager.start(interface, 10, 'synthetic', keylog_path=str(keylog))
            time.sleep(1.5)
            if manager.snapshot()['error']:
                raise RuntimeError(manager.snapshot()['error'])
            thread = threading.Thread(target=reply, daemon=True)
            thread.start()
            with socket.create_connection(('127.0.0.1', 45991), timeout=3) as raw:
                with client_context.wrap_socket(raw, server_hostname='demo.invalid') as secure:
                    secure.sendall(b'GET /demo HTTP/1.1\r\nHost: demo.invalid\r\n\r\n')
                    secure.recv(4096)
            thread.join(4)
            time.sleep(2.5)
            manager.stop()
            manager.thread.join(8)
            result = manager.snapshot()
            assert not result['error'], result['error']
            report = result['decryption']['report']
            rows = report['connections']
            assert report['decrypted'] == 1 and rows[0]['status'] == 'decrypted' and rows[0]['application'] == 'web-browsing', report
            assert 'demo.invalid' not in str(report) and '/demo' not in str(report), 'a name or path left the worker'
            print('PASS: real loopback capture decrypted the synthetic TLS exchange (%s, %s) and stopped cleanly.' % (
                rows[0]['version'], rows[0]['inner_protocol']))
            print({key: report['counts'][key] for key in ('opened', 'closed', 'records_authenticated', 'plaintext_bytes')})
        finally:
            manager.stop()
            listener.close()
        assert not os.path.exists(str(keylog)) or keylog.unlink() is None


if __name__ == '__main__':
    main()
