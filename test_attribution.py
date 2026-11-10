"""D03: provider affiliation, application family and observed activity are separate facts.

A client-asserted server name affiliates a session with a provider; it does not show that the provider's
service was used (a marketing page is not a remote-control session), and tenant hosting names nobody.
"""
import unittest

from protocol_engine import Inspector, RuleIndex
from protocol_engine.appid import classify, session_verdict
from protocol_engine.applications import APPLICATIONS
from protocol_engine.host_apps import WEB_FRONTS, application_for_host, attribution_for_host
from protocol_engine.model import ApplicationRule
from protocol_adapters.layers import layered_view
from test_v065 import http, tls


class AttributionTests(unittest.TestCase):
    def test_marketing_site_affiliates_without_asserting_remote_control(self):
        for host in ("www.teamviewer.com", "teamviewer.com"):
            verdict = classify(tls(host), "tcp", 443)
            self.assertEqual(verdict.app, "ssl", host)                                   # the carrier, not the service
            self.assertEqual(verdict.attribution, {"provider": "teamviewer", "kind": "provider-web", "family": "remote-access",
                                                   "activity": "unobserved", "asserted_by": "client-server-name"})
            self.assertEqual(verdict.characteristics, APPLICATIONS["ssl"].characteristics)   # the carrier's, not TeamViewer's
            self.assertNotIn("prone-to-misuse", verdict.characteristics)
            self.assertTrue(any("no service activity is asserted" in reason for reason in verdict.reasons))
        service = classify(tls("router17.teamviewer.com"), "tcp", 5938)
        self.assertEqual((service.app, service.attribution["kind"], service.attribution["activity"]), ("teamviewer", "service", "unobserved"))
        self.assertTrue(any("activity was not observed" in reason for reason in service.reasons))

    def test_openai_web_platform_and_chatgpt_are_distinct(self):
        self.assertEqual(classify(tls("www.openai.com"), "tcp", 443).attribution["kind"], "provider-web")
        self.assertEqual(classify(tls("openai.com"), "tcp", 443).app, "ssl")
        platform = classify(tls("platform.openai.com"), "tcp", 443)
        self.assertEqual((platform.app, platform.attribution["provider"]), ("openai-platform", "openai-platform"))
        api = classify(tls("api.openai.com"), "tcp", 443)
        self.assertEqual(api.app, "openai-platform")
        self.assertNotEqual(api.app, "openai-chatgpt")
        chat = classify(tls("chatgpt.com"), "tcp", 443)
        self.assertEqual((chat.app, chat.attribution["family"], chat.attribution["activity"]), ("openai-chatgpt", "generative-ai", "unobserved"))
        self.assertIsNone(attribution_for_host("labs.openai.com"))                     # unknown subdomain: no affiliation
        self.assertIsNone(classify(tls("labs.openai.com"), "tcp", 443).attribution)

    def test_tenant_hosting_names_nobody_and_boundaries_hold(self):
        for host in ("someone.github.io", "github.io", "evil-github.com", "notteamviewer.com", "teamviewer.com.example"):
            self.assertIsNone(attribution_for_host(host), host)
            verdict = classify(tls(host), "tcp", 443)
            self.assertEqual((verdict.app, verdict.attribution), ("ssl", None), host)
        self.assertEqual(application_for_host("pages.github.com"), "github")
        self.assertIsNone(application_for_host("www.teamviewer.com"))                 # web fronts are not applications
        self.assertTrue(set(WEB_FRONTS.values()) <= set(APPLICATIONS))

    def test_configured_rules_and_structural_refinement_keep_precedence(self):
        rules = RuleIndex((ApplicationRule("www.teamviewer.com", "vendor-portal", "tls_sni"),))
        configured = classify(tls("www.teamviewer.com", rules), "tcp", 443)
        self.assertEqual(configured.app, "vendor-portal")
        self.assertEqual(configured.attribution["kind"], "provider-web")               # affiliation is still reported
        plain = classify(http("www.teamviewer.com"), "tcp", 80)
        self.assertEqual((plain.app, plain.attribution["activity"]), ("web-browsing", "http-request"))

    def test_activity_follows_observation_and_the_layered_view_carries_it(self):
        from protocol_fixtures import TLS_SERVER13, client_hello_with
        from test_v065 import sni
        client = Inspector()
        client.feed(client_hello_with((sni("api.openai.com"), (43, b"\x02\x03\x04"))))
        server = Inspector()
        server.feed(TLS_SERVER13)
        before = session_verdict(client.observation, server.observation, "tcp", 443, 500, 900)
        self.assertEqual((before.app, before.attribution["activity"]), ("openai-platform", "unobserved"))
        client.feed_decrypted(b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\n\r\n")
        layers, effective = layered_view("tcp", client.observation, server.observation, None, 443, 500, 900,
                                         decryption={"state": "complete", "reason_code": None, "authenticated_records": 4})
        self.assertEqual(layers["application"]["basis"], "authenticated_plaintext")
        self.assertEqual(layers["application"]["provider"], "openai-platform")
        self.assertEqual(layers["application"]["activity"], "authenticated-plaintext")
        self.assertEqual(layers["application"]["affiliation"], "service")
        plain = layered_view("tcp", tls("www.teamviewer.com"), None, None, 443)[0]["application"]
        self.assertEqual((plain["name"], plain["provider"], plain["affiliation"], plain["activity"]), ("ssl", "teamviewer", "provider-web", "unobserved"))


if __name__ == "__main__":
    unittest.main()
