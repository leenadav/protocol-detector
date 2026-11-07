"""Generate a real OpenSSL TLS 1.3 exchange in memory. No network traffic."""
import datetime
from pathlib import Path
import ssl
import tempfile


def fixture(version='1.3', cipher=None, request=None, response=None, client_port=51000):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from protocol_adapters.make_sample_pcap import frame, pcap_bytes
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'demo.invalid')])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
                   .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        (root / 'cert.pem').write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        (root / 'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        sc = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        selected = ssl.TLSVersion.TLSv1_2 if version == '1.2' else ssl.TLSVersion.TLSv1_3
        sc.minimum_version = sc.maximum_version = selected
        if cipher:
            sc.set_ciphers(cipher)
        sc.load_cert_chain(str(root / 'cert.pem'), str(root / 'key.pem'))
        cc = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cc.load_verify_locations(cadata=certificate.public_bytes(serialization.Encoding.PEM).decode())
        cc.minimum_version = cc.maximum_version = selected
        if cipher:
            cc.set_ciphers(cipher)
        cc.keylog_filename = str(root / 'keys.log')
        ci, co, si, so = [ssl.MemoryBIO() for _ in range(4)]
        c = cc.wrap_bio(ci, co, server_side=False, server_hostname='demo.invalid')
        s = sc.wrap_bio(si, so, server_side=True)
        chunks = [bytearray(), bytearray()]
        done = [False, False]
        def transfer():
            for index, out, dest in ((0, co, si), (1, so, ci)):
                data = out.read()
                chunks[index].extend(data)
                if data:
                    dest.write(data)
        for _ in range(20):
            for index, peer in enumerate((c, s)):
                if not done[index]:
                    try:
                        peer.do_handshake()
                        done[index] = True
                    except ssl.SSLWantReadError:
                        pass
                transfer()
            if all(done):
                break
        if not all(done):
            raise RuntimeError('Synthetic TLS handshake did not finish.')
        c.write(request or b'PROPFIND /documents HTTP/1.1\r\nHost: demo.invalid\r\nDepth: 0\r\nContent-Length: 0\r\n\r\n')
        transfer()
        s.read()
        s.write(response or b'HTTP/1.1 207 Multi-Status\r\nContent-Length: 0\r\n\r\n')
        transfer()
        c.read()
        keylog = (root / 'keys.log').read_text()
    client, server = ('192.0.2.10', client_port), ('198.51.100.20', 443)
    frames = [frame(client, server, 999, 0, 2), frame(server, client, 8999, 1000, 18)]
    for source, dest, seq, data in ((client, server, 1000, chunks[0]), (server, client, 9000, chunks[1])):
        # Reversed segments prove record reconstruction is independent of packet boundaries.
        pieces = [(offset, bytes(data[offset:offset + 700])) for offset in range(0, len(data), 700)]
        frames.extend(frame(source, dest, seq + offset, 0, 24, piece) for offset, piece in reversed(pieces))
        frames.append(frame(source, dest, seq + len(data), 0, 17))
    return pcap_bytes(frames), keylog, bytes(chunks[0]), bytes(chunks[1])


def showcase():
    """Three independent encrypted exchanges, classified by the real engine."""
    from .capture import analyze_capture
    cases = [
        dict(version='1.3'),
        dict(version='1.2',cipher='ECDHE-RSA-AES128-GCM-SHA256',
             request=b'GET / HTTP/1.1\r\nHost: demo.invalid\r\n\r\n',
             response=b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'),
        dict(version='1.2',cipher='ECDHE-RSA-AES256-GCM-SHA384',
             request=b'*1\r\n$4\r\nPING\r\n',response=b'+PONG\r\n')]
    result={'connections':[],'frames':0,'decrypted':0,'skipped':0,'synthetic':True}
    for index, options in enumerate(cases):
        cap, keys, _, _ = fixture(client_port=51000+index,**options)
        report=analyze_capture(cap,keys)
        result['connections'].extend(report['connections'])
        for field in ('frames','decrypted','skipped'):
            result[field]+=report[field]
    return result
