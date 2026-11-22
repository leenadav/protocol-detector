"""Live verification of catalog host names (research method v2, item 1). Passive: DNS lookups and one TLS
handshake per name, no HTTP request, no sign-in, no content kept.

It must run from a vantage point whose DNS and TLS are not intercepted. In the research cloud session the
egress proxy re-terminates TLS (the handshake seen would be the proxy's) and direct DNS is not permitted, so
the script refuses to run there unless --doh is given for DNS-only mode against an approved DoH resolver.

usage:
  live_verify.py HOSTS.txt OUT.json                         # direct DNS (dnspython) + direct TLS
  live_verify.py HOSTS.txt OUT.json --doh https://RESOLVER/dns-query --dns-only

Output per host: date, A/AAAA, CNAME chain, HTTPS record (alpn, ech present), TLS version, ALPN accepted,
certificate subject CN and SAN list (from this client's own handshake), and flags:
  cdn       CNAME chain or certificate points into a shared CDN or cloud front end (name usable, IPs never)
  ech       HTTPS record carries an ech parameter (SNI may be replaced by an ECH outer name)
  h3        HTTPS record alpn includes h3 (QUIC path exists)
  nxdomain  the name does not exist (RCODE 3). Per RFC 8020 nothing below it exists either: recommend removal
  no-address  the name exists but has no A/AAAA (normal for an apex or suffix entry): NOT dead; the suffix is
            verified through a documented subdomain given as the line's second field
  tls-fail  DNS answers but the handshake fails (timeout, certificate mismatch): not removal on its own
            (the client requires TLS 1.2 or later, so a TLS 1.0/1.1-only server also shows as tls-fail)

HOSTS.txt lines: "NAME" or "NAME PROBE", where PROBE is a documented name under the suffix NAME.
"""
import base64
import datetime
import json
import os
import socket
import ssl
import struct
import sys
import urllib.request

# Shared CDN / cloud front-end suffixes (vendor documentation of each CDN's customer CNAME targets).
CDN_SUFFIXES = (
    "cloudfront.net", "akamai.net", "akamaiedge.net", "akamaized.net", "edgekey.net", "edgesuite.net",
    "fastly.net", "fastlylb.net", "azurefd.net", "azureedge.net", "trafficmanager.net", "t-msedge.net",
    "msedge.net", "cloudflare.net", "cdn.cloudflare.net", "ghs.googlehosted.com", "googlehosted.com",
    "l.google.com", "cdn77.org", "edgecastcdn.net", "llnwd.net", "amazonaws.com", "elb.amazonaws.com",
    "cloudapp.azure.com", "azurewebsites.net", "herokudns.com", "vercel-dns.com", "netlify.app",
)
TYPES = {"A": 1, "CNAME": 5, "AAAA": 28, "HTTPS": 65}


def is_cdn(name):
    name = name.rstrip(".").lower()
    return any(name == s or name.endswith("." + s) for s in CDN_SUFFIXES)


def build_query(name, qtype):
    q = os.urandom(2) + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for label in name.rstrip(".").split("."):
        q += bytes([len(label)]) + label.encode("ascii")
    return q + b"\x00" + struct.pack("!HH", qtype, 1)


def read_name(msg, off):
    labels, jumped, end = [], False, off
    while True:
        n = msg[off]
        if n & 0xC0 == 0xC0:
            if not jumped:
                end = off + 2
            off, jumped = ((n & 0x3F) << 8) | msg[off + 1], True
            continue
        off += 1
        if n == 0:
            break
        labels.append(msg[off:off + n].decode("ascii", "replace"))
        off += n
    return ".".join(labels), (end if jumped else off)


def parse_svcb(rdata):
    """HTTPS/SVCB RDATA (RFC 9460): priority, target, then key=value params; returns alpn list and ech flag."""
    out = {"alpn": [], "ech": False}
    priority = struct.unpack("!H", rdata[:2])[0]
    _, off = read_name(rdata, 2)
    out["priority"] = priority
    while off + 4 <= len(rdata):
        key, length = struct.unpack("!HH", rdata[off:off + 4])
        value = rdata[off + 4:off + 4 + length]
        off += 4 + length
        if key == 1:                        # alpn
            i = 0
            while i < len(value):
                n = value[i]
                out["alpn"].append(value[i + 1:i + 1 + n].decode("ascii", "replace"))
                i += 1 + n
        elif key == 5:                      # ech
            out["ech"] = True
    return out


def parse_response(msg):
    rcode = msg[3] & 0x0F
    qd, an = struct.unpack("!HH", msg[4:8])
    off = 12
    for _ in range(qd):
        _, off = read_name(msg, off)
        off += 4
    answers = []
    for _ in range(an):
        name, off = read_name(msg, off)
        rtype, _, _, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
        off += 10
        rdata = msg[off:off + rdlen]
        if rtype == 1:
            answers.append(("A", name, socket.inet_ntop(socket.AF_INET, rdata)))
        elif rtype == 28:
            answers.append(("AAAA", name, socket.inet_ntop(socket.AF_INET6, rdata)))
        elif rtype == 5:
            answers.append(("CNAME", name, read_name(msg, off)[0]))
        elif rtype == 65:
            answers.append(("HTTPS", name, parse_svcb(rdata)))
        off += rdlen
    return rcode, answers


def query_doh(resolver, name, qtype):
    wire = build_query(name, TYPES[qtype])
    if not resolver.startswith("https://"):
        raise ValueError("DoH resolver must be an https:// URL")
    url = resolver + "?dns=" + base64.urlsafe_b64encode(wire).rstrip(b"=").decode()
    req = urllib.request.Request(url, headers={"accept": "application/dns-message"})  # noqa: S310 - https only, checked above
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 - https only, checked above
        return parse_response(resp.read())


def query_direct(name, qtype):
    import dns.message
    import dns.query
    import dns.resolver
    server = dns.resolver.Resolver().nameservers[0]
    wire = dns.query.udp(dns.message.make_query(name, qtype), server, timeout=5).to_wire()
    return parse_response(wire)


def tls_probe(host):
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    with socket.create_connection((host, 443), timeout=8) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            cert = tls.getpeercert()
            subject = dict(x[0] for x in cert.get("subject", ()))
            issuer = dict(x[0] for x in cert.get("issuer", ()))
            return {"version": tls.version(), "alpn": tls.selected_alpn_protocol(),
                    "subject_cn": subject.get("commonName"), "subject_o": subject.get("organizationName"),
                    "issuer_o": issuer.get("organizationName"),
                    "san": sorted(v for k, v in cert.get("subjectAltName", ()) if k == "DNS")}


def verify(host, resolver=None, dns_only=False):
    rec = {"host": host, "date": datetime.date.today().isoformat(), "flags": []}
    lookup = (lambda n, t: query_doh(resolver, n, t)) if resolver else query_direct
    try:
        rcode, ans = lookup(host, "A")
        rec["rcode"] = rcode
        rec["cname_chain"] = [a[2] for a in ans if a[0] == "CNAME"]
        rec["a"] = [a[2] for a in ans if a[0] == "A"]
        rec["aaaa"] = [a[2] for a in lookup(host, "AAAA")[1] if a[0] == "AAAA"]
        rec["https"] = [a[2] for a in lookup(host, "HTTPS")[1] if a[0] == "HTTPS"]
    except Exception as exc:  # noqa: BLE001 - recorded, not raised
        rec["dns_error"] = type(exc).__name__
    if rec.get("rcode") == 3:
        rec["flags"].append("nxdomain")
    elif not rec.get("a") and not rec.get("aaaa") and "dns_error" not in rec:
        rec["flags"].append("no-address")
    if any(is_cdn(c) for c in rec.get("cname_chain", [])):
        rec["flags"].append("cdn")
    if any(h.get("ech") for h in rec.get("https", [])):
        rec["flags"].append("ech")
    if any("h3" in h.get("alpn", []) for h in rec.get("https", [])):
        rec["flags"].append("h3")
    if not dns_only and not {"nxdomain", "no-address"} & set(rec["flags"]):
        try:
            rec["tls"] = tls_probe(host)
        except Exception as exc:  # noqa: BLE001
            rec["tls_error"] = type(exc).__name__
            rec["flags"].append("tls-fail")
    return rec


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    resolver = argv[argv.index("--doh") + 1] if "--doh" in argv else None
    dns_only = "--dns-only" in argv
    if (os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")) and not dns_only:
        print("refusing: an HTTPS proxy is set, so a TLS handshake would show the proxy, not the server", file=sys.stderr)
        return 3
    out = []
    with open(argv[1]) as fh:
        lines = fh.readlines()
    for line in lines:
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split()
        rec = verify(fields[0], resolver, dns_only)
        if len(fields) > 1:
            rec["probe"] = verify(fields[1], resolver, dns_only)
        out.append(rec)
    with open(argv[2], "w") as fh:
        json.dump(out, fh, indent=1)
        fh.write("\n")
    flags = {}
    for r in out:
        for f in r["flags"] + ["probe-" + f for f in r.get("probe", {}).get("flags", [])]:
            flags[f] = flags.get(f, 0) + 1
    print(len(out), "hosts", flags)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
