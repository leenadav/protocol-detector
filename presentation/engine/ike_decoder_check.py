"""Opt-in independent tcpdump dissection of synthetic IKE fixtures; no network.

This verifies decoder agreement on framing/fields, not a real peer handshake.
The temporary PCAP and verbose synthetic dissection are not saved or printed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from protocol_fixtures import IKEV2, IKEV2_MARKER
from make_sample_pcap import pcap_bytes, udp_frame


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tcpdump',default='/usr/sbin/tcpdump')
    args=parser.parse_args()
    binary=str(Path(args.tcpdump).resolve())
    version=subprocess.check_output([binary,'--version'],stderr=subprocess.STDOUT,text=True,timeout=3).splitlines()[0]
    frames=[udp_frame(('192.0.2.10',port),('192.0.2.20',port),data) for port,data in ((500,IKEV2),(4500,IKEV2_MARKER))]
    with tempfile.TemporaryDirectory() as directory:
        p=Path(directory)/'synthetic.pcap';p.write_bytes(pcap_bytes(frames))
        output=subprocess.check_output([binary,'-nn','-vv','-r',str(p)],stderr=subprocess.DEVNULL,text=True,timeout=3)
    checks={label:output.count(token)==expected for label,token,expected in (
        ('version2','isakmp 2.0',2),('initial_request','ikev2_init[I]',2),
        ('four_transforms','protoid=isakmp transform=4',2),
        ('aes128','type=encr id=aes (type=keylen value=0080)',2),
        ('modp2048','v2ke: len=256 group=modp2048',2),('nonce32','nonce: len=32',2),
        ('non_esp_marker','NONESP-encap:',1))}
    if not all(checks.values()) or '[|' in output:
        raise RuntimeError('Independent IKE dissection disagreed: '+repr(checks))
    root=Path(__file__).resolve().parent
    digest=hashlib.sha256()
    paths=sorted((root/'protocol_engine').glob('*.py'))+[root/n for n in
           ('live_capture.py','capture_stream.py','link_packets.py','analyze_pcap.py','sessions.py','packets.py','detectors.py')]
    for p in paths:digest.update(str(p.relative_to(root)).encode()+b'\0'+p.read_bytes())
    print(json.dumps({'status':'passed','decoder':version,'checks':checks,
                      'scope':'Independent dissection of two specification-derived synthetic fixtures, no peer interoperability or cryptographic validation',
                      'source_sha256':digest.hexdigest(),'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},indent=2))


if __name__=='__main__':main()
