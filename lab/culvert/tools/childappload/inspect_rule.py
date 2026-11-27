"""Create a throw-away lab admin on a local Culvert build and install one rule: Allow + sslAction Inspect for
every destination, with traffic logging on. PRO-516 child-app load test; loopback only.

Usage: inspect_rule.py <ui_port> <secret_file> [--native-h2]. --native-h2 sets the rule's stripAlpn to false, so a
client that offers h2 is inspected over native HTTP/2 (handleInspectH2); without it the rule keeps Culvert's
default (strip ALPN: every inspected tunnel is HTTP/1.1, runH1InspectLoop). The generated password is written to <secret_file> (mode 0600)
and never printed. Exit status 0 when the rule is in place."""
import http.cookiejar
import json
import os
import secrets
import ssl
import sys
import urllib.error
import urllib.request

AUTH_RULE = {"name": "lab-exempt-loopback", "ruleType": "auth", "subjectMatch": {"schemaVersion": 1, "all": [{"type": "cidr", "values": ["127.0.0.1/32"]}]},
             "auth": {"outcome": "Exempt", "protocol": "connect", "owner": "lab", "reason": "PRO-516 local load test",
                      "broadExemption": True},
             "comment": "PRO-516 lab: the load generator on loopback needs no proxy credentials."}
RULE = {"name": "lab-inspect-all", "action": "Allow", "sslAction": "Inspect", "logTraffic": True,
        "comment": "PRO-516 lab: inspect every tunnel so each inner request reaches the decrypted path."}


def main(argv):
    if argv[1:] == ["--self-test"]:
        assert RULE["sslAction"] == "Inspect" and RULE["action"] == "Allow"
        print("inspect_rule self-test: ok")
        return 0
    ui, secret = int(argv[1]), argv[2]
    rule = dict(RULE)
    if "--native-h2" in argv[3:]:
        rule["stripAlpn"] = False
    base = "https://127.0.0.1:%d" % ui
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # the lab UI's self-signed certificate on loopback
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx),
                                         urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(method, path, body=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(base + path, data=data, method=method,  # noqa: S310 (loopback, lab only)
                                     headers={"Content-Type": "application/json"})
        try:
            with opener.open(req, timeout=10) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw[:1] in (b"{", b"[") else raw.decode()[:200])
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()[:300]

    pw = "Lab-" + secrets.token_urlsafe(12) + "9aZ"
    fd = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, pw.encode())
    os.close(fd)
    print("setup:", call("POST", "/api/setup/complete", {"user": "admin", "pass": pw})[0])
    print("login:", call("POST", "/api/auth/login", {"user": "admin", "pass": pw})[0])
    st, out = call("POST", "/api/authpolicy", AUTH_RULE)
    print("auth rule:", st, str(out)[:200])
    st, pol = call("GET", "/api/policy")
    version = pol.get("version", 0) if isinstance(pol, dict) else 0
    st, out = call("POST", "/api/policy?ifVersion=%d" % version, rule)
    print("rule:", st, str(out)[:160])
    st, pol = call("GET", "/api/policy")
    rules = pol.get("rules") if isinstance(pol, dict) else pol
    ok = any(r.get("name") == rule["name"] and r.get("sslAction") == "Inspect"
             and r.get("stripAlpn", True) == rule.get("stripAlpn", True) for r in (rules or []))
    print("inspect rule in place:", ok)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
