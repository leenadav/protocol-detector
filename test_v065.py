"""v0.65: built-in server-name application catalog (SNI, QUIC SNI, HTTP Host) refining generic carriers."""
import unittest

from protocol_engine import DatagramInspector, Inspector, RuleIndex
from protocol_engine.appid import classify, session_verdict
from protocol_engine.applications import APPLICATIONS, CATEGORIES, lookup
from protocol_engine.host_apps import APP_DOMAINS, HOST_SUFFIXES, application_for_host
from protocol_engine.model import ApplicationRule, normalize_hostname
from protocol_fixtures import QUIC_INITIAL, TLS_ECH_HELLO, client_hello_with


def sni(host):
    name = host.encode()
    return (0, (len(name) + 3).to_bytes(2, "big") + b"\x00" + len(name).to_bytes(2, "big") + name)


def tls(host, rules=None):
    inspector = Inspector(rules=rules) if rules is not None else Inspector()
    inspector.feed(client_hello_with((sni(host), (43, b"\x02\x03\x04"))))
    return inspector.observation


def http(host, extra=b""):
    inspector = Inspector()
    inspector.feed(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n" + extra + b"\r\n")
    return inspector.observation


class HostCatalogTests(unittest.TestCase):
    def test_label_boundary_longest_suffix(self):
        self.assertEqual(application_for_host("youtube.com"), "youtube")
        self.assertEqual(application_for_host("rr3---sn-abc.googlevideo.com"), "youtube")
        self.assertEqual(application_for_host("teams.microsoft.com"), "ms-teams")      # not a parent match
        self.assertEqual(application_for_host("eu.teams.microsoft.com"), "ms-teams")
        self.assertEqual(application_for_host("mail.google.com"), "gmail")              # longer suffix beats google.com
        self.assertEqual(application_for_host("www.google.com"), "google-base")
        for host in ("notyoutube.com", "youtube.com.example.net", "example.org", "com", "microsoft.com", "googlevideo.co"):
            self.assertIsNone(application_for_host(host), host)

    def test_catalog_integrity(self):
        for domain, name in HOST_SUFFIXES.items():
            self.assertEqual(normalize_hostname(domain), domain)                       # valid, lower-case, no IP literal
            self.assertIn(domain, APP_DOMAINS[name])
            entry = APPLICATIONS[name]
            self.assertIn(entry.subcategory, CATEGORIES[entry.category])
            self.assertEqual(lookup(name), entry)
        for shared in ("cloudfront.net", "akamaized.net", "amazonaws.com", "azureedge.net", "fastly.net", "cloudflare.com"):
            self.assertNotIn(shared, HOST_SUFFIXES)                                     # shared hosting names no application

    def test_carriers_are_refined_with_the_carrier_kept(self):
        verdict = classify(tls("www.youtube.com"), "tcp", 443)
        self.assertEqual((verdict.app, verdict.base_app, verdict.implicitly_uses, verdict.port_usage, verdict.category),
                         ("youtube", "ssl", ("ssl",), "standard", "media"))
        self.assertIn("client-asserted server name", verdict.reasons[-1])
        self.assertNotIn("youtube.com", " ".join(verdict.reasons))                     # no hostname in reasons
        self.assertEqual(classify(tls("www.youtube.com"), "tcp", 8443).port_usage, "nonstandard")
        web = classify(http("zoom.us"), "tcp", 80)
        self.assertEqual((web.app, web.base_app, web.implicitly_uses), ("zoom", "web-browsing", ("web-browsing",)))
        quic = DatagramInspector().inspect(QUIC_INITIAL)
        self.assertEqual(classify(quic, "udp", 443).app, application_for_host(quic.hostname) or "quic")
        self.assertEqual(classify(tls("example.org"), "tcp", 443).app, "ssl")           # unmapped names stay generic

    def test_precedence_and_exclusions(self):
        rules = RuleIndex((ApplicationRule("www.youtube.com", "corp-video", "tls_sni"),))
        self.assertEqual(classify(tls("www.youtube.com", rules), "tcp", 443).app, "corp-video")   # configured rule wins
        ech = Inspector()
        ech.feed(TLS_ECH_HELLO)
        self.assertEqual(ech.observation.hostname is not None, True)
        self.assertEqual(classify(ech.observation, "tcp", 443).app, "ssl")              # outer ECH name is never mapped
        doh = http("dns.google.com", b"Content-Type: application/dns-message\r\n")
        self.assertNotEqual(classify(doh, "tcp", 80).app, "google-base")                 # structural refinement wins
        connect = Inspector()
        connect.feed(b"CONNECT www.youtube.com:443 HTTP/1.1\r\nHost: www.youtube.com:443\r\n\r\n")
        self.assertEqual(classify(connect.observation, "tcp", 8080).app, "http-proxy")

    def test_session_and_policy_vocabulary(self):
        from protocol_fixtures import TLS_SERVER13
        server = Inspector()
        server.feed(TLS_SERVER13)
        verdict = session_verdict(tls("chatgpt.com"), server.observation, "tcp", 443, 500, 900)
        self.assertEqual((verdict.app, verdict.subcategory), ("openai-chatgpt", "generative-ai"))
        self.assertFalse(any(reason.startswith("Server direction identified") for reason in verdict.reasons))
        self.assertEqual(classify(server.observation, "tcp", 443).app, "ssl")           # a ServerHello carries no name


if __name__ == "__main__":
    unittest.main()
