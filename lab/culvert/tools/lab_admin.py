"""Create the lab admin on a build and install the lab's protocol-restriction rules through Culvert's own API.

Usage: lab_admin.py <ui_port> <build>. The generated password is stored in run/admin-<build>.secret (mode 0600)
and is never printed. Lab only: loopback, throwaway account."""
import http.cookiejar, json, os, secrets, ssl, sys, urllib.request

ui, build = int(sys.argv[1]), sys.argv[2]
scheme = sys.argv[3] if len(sys.argv) > 3 else "https"  # build G serves its UI over plain HTTP for the preview
base = f"{scheme}://127.0.0.1:{ui}"  # noqa: S310
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE  # lab self-signed UI cert on loopback
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx),
                                     urllib.request.HTTPCookieProcessor(jar))

def call(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, method=method, headers={"Content-Type": "application/json"})  # noqa: S310  (constant https URL on loopback, lab only)
    try:
        with opener.open(req, timeout=10) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw[:1] in (b"{", b"[") else raw.decode()[:200])
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]

secret = f"/home/user/culvert-lab/run/admin-{build}.secret"
st, status = call("GET", "/api/setup/status")
if status.get("needsSetup"):
    pw = "Lab-" + secrets.token_urlsafe(12) + "9aZ"
    fd = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, pw.encode()); os.close(fd)
    print("setup:", call("POST", "/api/setup/complete", {"user": "admin", "pass": pw})[0])
else:
    pw = open(secret).read()
print("login:", call("POST", "/api/auth/login", {"user": "admin", "pass": pw})[0])

st, pol = call("GET", "/api/policy")
rules = pol.get("rules") if isinstance(pol, dict) else pol
version = pol.get("version", 0) if isinstance(pol, dict) else 0
have = {r["name"] for r in (rules or [])}
print("policy: status", st, "version", version, "rules", sorted(have))
WANT = [
    {"name": "lab-secure-tls-only", "destFQDN": "secure.lab.test", "action": "Allow", "sslAction": "Bypass",
     "comment": "Lab: only TLS may use tunnels to secure.lab.test; anything else is blocked before a client byte reaches the server.",
     "appRestriction": {"mode": "enforce", "allow": ["tls"], "unknown": "block"}},
    {"name": "lab-monitor-tls-only", "destFQDN": "monitor.lab.test", "action": "Allow", "sslAction": "Bypass",
     "comment": "Lab: same restriction in monitor mode; traffic passes and the log records what enforce would do.",
     "appRestriction": {"mode": "monitor", "allow": ["tls"], "unknown": "block"}},
    {"name": "lab-allow-everything-else", "action": "Allow", "sslAction": "Bypass",
     "comment": "Lab: keeps the default-allow behaviour of the other scenarios once rules exist."},
]
for rule in WANT:
    if rule["name"] in have:
        continue
    st, pol = call("GET", "/api/policy")
    version = pol.get("version", 0) if isinstance(pol, dict) else 0
    st, out = call("POST", f"/api/policy?ifVersion={version}", rule)
    print("create", rule["name"], st, out if st >= 300 else "")
st, bad = call("POST", f"/api/policy?ifVersion={version + 99}", {"name": "x"})
st, pol = call("GET", "/api/policy")
ver = pol.get("version", 0)
st, bad = call("POST", f"/api/policy?ifVersion={ver}", {"name": "lab-invalid", "action": "Allow", "sslAction": "Bypass",
               "appRestriction": {"mode": "enforce", "allow": ["tls"], "unknown": ""}})
print("a restriction without an explicit unknown action is rejected:", st, str(bad)[:90])
