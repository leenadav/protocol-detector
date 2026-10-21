"""Opt-in in-memory TLS stack interoperability; no network sockets or user certs.

Creates one short-lived synthetic certificate/key in a temporary directory,
then exchanges MemoryBIO data. Keys and wire data are never written to reports.
Use --parser-python to validate generated hellos with a different Python runtime.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile


def verify(cases):
    from protocol_engine import Inspector
    result=[]
    for case in cases:
        data=bytes.fromhex(case['wire'])
        e=Inspector();e.feed(data)
        split=Inspector()
        for byte in data:split.feed(bytes([byte]))
        if e.observation!=split.observation or e.observation.status!='identified':
            raise RuntimeError('Canonical TLS server flight not recognized: '+repr(e.observation))
        if e.observation.scope!=case['scope']:
            raise RuntimeError('Server hello/retry scope mismatch')
        metadata={x.field:x.value for x in e.observation.evidence}
        if metadata.get('selected_tls_version')!=case['version']:
            raise RuntimeError('Selected version mismatch')
        if case['version']=='1.2' and metadata.get('selected_alpn')!='h2':
            raise RuntimeError('TLS 1.2 server ALPN not recognized')
        if case['version']=='1.3' and 'selected_alpn' in metadata:
            raise RuntimeError('Encrypted TLS 1.3 ALPN must not be inferred')
        if e.observation.application_protocol or e.observation.application or e.observation.hostname or e.observation.offered_alpn:
            raise RuntimeError('Untrusted server metadata was promoted')
        result.append({'version':case['version'],'status':'passed','flight_bytes':len(data),
                       'hello_bytes_inspected':e.metrics.bytes_inspected,'scope':e.observation.scope,
                       'selected_cipher':metadata['selected_cipher'],
                       'selected_alpn':metadata.get('selected_alpn')})
    return result


def exchange(version,cert,key,retry=False):
    server=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version=server.maximum_version=version
    server.load_cert_chain(cert,key)
    server.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')
    server.set_alpn_protocols(['h2'])
    server.set_ecdh_curve('prime256v1')  # Explicit covered group, not every TLS default.
    client=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.check_hostname=False
    client.verify_mode=ssl.CERT_NONE  # Only our synthetic in-memory endpoint.
    client.minimum_version=client.maximum_version=version
    client.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')
    client.set_alpn_protocols(['h2','http/1.1'])
    if not retry:client.set_ecdh_curve('prime256v1')
    ci,co,si,so=(ssl.MemoryBIO() for _ in range(4))
    c=client.wrap_bio(ci,co,server_hostname='synthetic.invalid')
    s=server.wrap_bio(si,so,server_side=True)
    wire=bytearray();cdone=sdone=False
    for _ in range(16):
        try:c.do_handshake();cdone=True
        except ssl.SSLWantReadError:pass
        if co.pending:si.write(co.read())
        try:s.do_handshake();sdone=True
        except ssl.SSLWantReadError:pass
        if so.pending:
            data=so.read();wire.extend(data);ci.write(data)
        if len(wire)>65536:raise RuntimeError('Synthetic TLS flight exceeded limit')
        if cdone and sdone:break
    else:raise RuntimeError('In-memory handshake did not complete')
    if c.selected_alpn_protocol()!='h2' or s.selected_alpn_protocol()!='h2':
        raise RuntimeError('Synthetic endpoints failed ALPN selection')
    return bytes(wire)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parser-python',default=sys.executable)
    parser.add_argument('--verify',action='store_true',help=argparse.SUPPRESS)
    args=parser.parse_args()
    if args.verify:
        print(json.dumps({'parser_python':sys.version.split()[0],'cases':verify(json.load(sys.stdin))}))
        return
    openssl=shutil.which('openssl')
    if not openssl:raise RuntimeError('openssl command is required for the synthetic certificate')
    cases=[]
    with tempfile.TemporaryDirectory(prefix='protocol-tls-interop-') as directory:
        root=Path(directory);cert=root/'cert.pem';key=root/'key.pem';conf=root/'openssl.cnf'
        conf.write_text('[req]\ndistinguished_name=dn\n[dn]\n')
        env=dict(os.environ);env['OPENSSL_CONF']=str(conf)
        subprocess.run([openssl,'req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                        '-subj','/CN=synthetic.invalid','-keyout',str(key),'-out',str(cert)],
                       env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,check=True,timeout=20)
        versions=[('1.2',ssl.TLSVersion.TLSv1_2)]
        if ssl.HAS_TLSv1_3:versions.append(('1.3',ssl.TLSVersion.TLSv1_3))
        for name,version in versions:
            cases.append({'version':name,'scope':'server_hello','wire':exchange(version,str(cert),str(key)).hex()})
        if ssl.HAS_TLSv1_3:
            cases.append({'version':'1.3','scope':'hello_retry_request',
                          'wire':exchange(ssl.TLSVersion.TLSv1_3,str(cert),str(key),retry=True).hex()})
    run=subprocess.run([args.parser_python,'-B',str(Path(__file__).resolve()),'--verify'],
                       input=json.dumps(cases),text=True,capture_output=True,timeout=15)
    if run.returncode:raise RuntimeError(run.stderr)
    result=json.loads(run.stdout)
    result.update(status='passed',generator_python=sys.version.split()[0],tls_library=ssl.OPENSSL_VERSION,
                  network='none; MemoryBIO only',key_exchange_profile='secp256r1',tls13_supported=ssl.HAS_TLSv1_3,
                  script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
