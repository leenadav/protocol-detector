"""v0.48: the generated direction coverage matrix matches the fixtures and the catalog."""
import unittest
from pathlib import Path

from protocol_engine import DatagramInspector, Inspector, supported_protocols
from protocol_fixtures import DNS, DNS_RESPONSE, SMB2, SMB2_RESPONSE, TLS_SERVER13
from tools import coverage_matrix


class CoverageMatrixTests(unittest.TestCase):
    def test_table_covers_every_family_and_matches_the_document(self):
        table = coverage_matrix.build()
        families = {entry.family for entry in supported_protocols()}
        self.assertEqual(set(table), families)   # every family has at least one identifying fixture
        text = coverage_matrix.render(table)
        document = Path("PROTOCOLS.md").read_text(encoding="utf-8")
        self.assertEqual(coverage_matrix.splice(document, text), document, "run tools/coverage_matrix.py --write PROTOCOLS.md")
        for family in ("tls", "dns", "snmp", "smb2", "kerberos", "dcerpc", "postgresql", "ldap", "cql", "radius", "modbus", "giop",
                       "socks5", "tds", "tns", "http", "http2", "rdp", "iso-tsap", "mysql", "stomp", "nats", "pop3", "imap"):
            self.assertIn("server", table[family]["sides"], family)
        for family in coverage_matrix.SYMMETRIC | coverage_matrix.ONE_WAY:
            self.assertIn(family, families, family)
        self.assertEqual(coverage_matrix.main(["--check", "PROTOCOLS.md"]), 0)

    def test_side_rules(self):
        self.assertEqual(coverage_matrix.side_of(DatagramInspector().inspect(DNS)), "client")
        self.assertEqual(coverage_matrix.side_of(DatagramInspector().inspect(DNS_RESPONSE)), "server")
        request, response = Inspector(), Inspector()
        request.feed(SMB2)
        response.feed(SMB2_RESPONSE)
        self.assertEqual((coverage_matrix.side_of(request.observation), coverage_matrix.side_of(response.observation)), ("client", "server"))
        tls = Inspector()
        tls.feed(TLS_SERVER13)
        self.assertEqual(coverage_matrix.side_of(tls.observation), "server")   # tls_handshake evidence
        self.assertEqual(coverage_matrix.family_of(tls.observation), "tls")


if __name__ == "__main__":
    unittest.main()
