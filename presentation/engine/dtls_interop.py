"""Opt-in real DTLS ClientHello/cookie-retry check on IPv4 loopback only.

An installed OpenSSL/LibreSSL client talks to a synthetic cookie responder.
No certificate, full handshake, encryption or cookie-authentication claim.
Wire bytes are never printed/saved. Runs with Python3.9, no dependencies.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from protocol_engine import DatagramInspector


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--openssl', default='/usr/bin/openssl')
    args = parser.parse_args()
    binary = str(Path(args.openssl).resolve())
    environment = {k:v for k,v in os.environ.items() if not k.startswith(('OPENSSL_', 'SSL_'))}
    environment['OPENSSL_CONF'] = os.devnull
    version = subprocess.check_output([binary,'version'],env=environment,text=True,timeout=3).strip()
    cases = []
    cookie = b'synthetic-dtls-cookie'
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as listener:
        listener.bind(('127.0.0.1',0))
        listener.settimeout(3)
        command = [binary,'s_client','-dtls1_2','-connect','127.0.0.1:'+str(listener.getsockname()[1]),
                   '-servername','example.com','-alpn','h2,http/1.1','-cipher','ECDHE-RSA-AES128-GCM-SHA256']
        process = subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=environment)
        try:
            for attempt in range(4):
                data,peer = listener.recvfrom(65536)
                if peer[0]!='127.0.0.1': raise RuntimeError('Non-loopback peer')
                result = DatagramInspector().inspect(data)
                if result.status!='identified' or result.encryption!='dtls' or result.application_protocol is not None:
                    raise RuntimeError('DTLS canonical client classification failed: '+repr(result))
                if result.hostname!='example.com' or result.offered_alpn!=('h2','http/1.1'):
                    raise RuntimeError('DTLS asserted metadata mismatch')
                # Independent extraction verifies the second hello actually echoes
                # the challenge. The classifier does not check this correlation.
                sid_size=data[59]
                cookie_at=60+sid_size
                received_cookie=data[cookie_at+1:cookie_at+1+data[cookie_at]]
                stage='cookie_retry' if received_cookie==cookie else 'initial'
                cases.append({'stage':stage,'wire_bytes':len(data),'record_version_hex':data[1:3].hex(),
                              'message_sequence':int.from_bytes(data[17:19],'big'),
                              'status':result.status,'encryption':result.encryption,
                              'inner_protocol':result.application_protocol})
                if received_cookie==cookie: break
                if received_cookie: raise RuntimeError('Unexpected synthetic client cookie')
                body=b'\xfe\xff'+bytes((len(cookie),))+cookie
                handshake=b'\x03'+len(body).to_bytes(3,'big')+bytes(5)+len(body).to_bytes(3,'big')+body
                verify=b'\x16\xfe\xff\0\0'+data[5:11]+len(handshake).to_bytes(2,'big')+handshake
                listener.sendto(verify,peer)
            else:
                raise RuntimeError('DTLS cookie retry not received within four datagrams')
        finally:
            if process.poll() is None: process.terminate()
            try: process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=2)
            process.stdin.close()
    if not cases or cases[0]['stage']!='initial' or cases[-1]['stage']!='cookie_retry':
        raise RuntimeError('Missing initial or cookie-retry ClientHello')
    root=Path(__file__).resolve().parent
    digest=hashlib.sha256()
    paths=sorted((root/'protocol_engine').glob('*.py'))+[root/n for n in
           ('live_capture.py','capture_stream.py','link_packets.py','analyze_pcap.py','sessions.py','packets.py','detectors.py')]
    for path in paths: digest.update(str(path.relative_to(root)).encode()+b'\0'+path.read_bytes())
    print(json.dumps({'status':'passed','client':version,'python':sys.version.split()[0],
                      'scope':'Canonical DTLS1.2 client to synthetic IPv4 loopback cookie responder; no completed/authenticated handshake',
                      'source_sha256':digest.hexdigest(), 'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      'cases':cases},indent=2))


if __name__=='__main__': main()
