"""D08: detection content releases, provenance, lock gate and server-name catalog rollback."""
import json
import os
import tempfile
import unittest

from protocol_adapters.analyze_pcap import Analyzer
from protocol_adapters.link_packets import decode_frame
from protocol_adapters.live_capture import CaptureMonitor
from protocol_adapters.make_sample_pcap import frame
from protocol_engine import content
from protocol_engine.host_apps import APP_DOMAINS, HOST_SUFFIXES, WEB_FRONTS, application_for_host, attribution_for_host, build_tables
from tools import check_content, schema_check

CLIENT, SERVER = ("192.0.2.10", 52000), ("198.51.100.20", 80)


class HistoryAndLockTests(unittest.TestCase):
    def test_tables_history_and_lock_agree(self):
        self.assertEqual(content.check(), [])
        self.assertEqual(check_content.main([]), 0)
        lock = content.read_lock()
        self.assertEqual((lock["version"], lock["digest"]), (content.CURRENT, content.digest()))
        self.assertEqual(set(lock["components"]), {"host_catalog", "application_catalog", "families", "risks"})

    def test_releases_are_dated_and_ordered(self):
        versions = [item.version for item in content.releases()]
        self.assertEqual(versions, sorted(versions))
        for item in content.releases():
            self.assertRegex(item.released, r"^\d{4}-\d{2}-\d{2}$")
            self.assertRegex(item.reviewed, r"^\d{4}-\d{2}-\d{2}$")
            self.assertTrue(item.review and item.note)
        with self.assertRaises(content.ContentError):
            content.release("1999.01.0")

    def test_a_changed_table_without_a_new_release_fails_the_gate(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "lock.json")
            stale = dict(content.description())
            stale["digest"] = "0" * 16
            stale["components"] = dict(stale["components"], host_catalog="0" * 64)
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(stale, handle)
            problems = content.check(path)
            self.assertEqual(len(problems), 1)
            self.assertIn("host_catalog", problems[0])
            self.assertIn("without a new release entry", problems[0])
            self.assertIn("missing", content.check(os.path.join(folder, "none.json"))[0])

    def test_digest_follows_the_selected_release(self):
        self.assertNotEqual(content.digest("2025.10.0"), content.digest(content.CURRENT))
        components = content.component_digests("2025.10.0")
        self.assertNotEqual(components["host_catalog"], content.component_digests()["host_catalog"])
        for name in ("application_catalog", "families", "risks"):
            self.assertEqual(components[name], content.component_digests()[name])   # only the host catalog rolls back

    def test_provenance_names_first_release_and_review_date(self):
        provenance = content.host_provenance()
        self.assertEqual(provenance["openai-platform"]["since"], "2026.11.0")
        self.assertEqual(provenance["whatsapp"]["since"], "2025.10.0")
        self.assertEqual(provenance["whatsapp"]["reviewed"], content.release(content.CURRENT).reviewed)
        self.assertEqual(provenance["whatsapp"]["basis"], "operator-owned-domain")
        self.assertEqual(set(provenance), {entry["name"] for entry in content.host_entries()})
        self.assertNotIn("openai-platform", content.host_provenance("2025.10.0"))


class RollbackTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(content.select, content.CURRENT)

    def test_earlier_release_entries_differ_as_recorded(self):
        old = {entry["name"]: entry for entry in content.host_entries("2025.10.0")}
        new = {entry["name"]: entry for entry in content.host_entries()}
        self.assertEqual(len(old), 53)
        self.assertEqual(len(new), 54)
        self.assertNotIn("openai-platform", old)
        self.assertIn("github.io", old["github"]["domains"])
        self.assertNotIn("github.io", new["github"]["domains"])
        self.assertIn("openai.com", old["openai-chatgpt"]["domains"])
        self.assertEqual(old["teamviewer"]["web_fronts"], ())
        self.assertTrue(all(entry["web_fronts"] == () for entry in old.values()))     # web fronts arrived with D03
        self.assertEqual(old["whatsapp"], new["whatsapp"])

    def test_select_runs_the_earlier_catalog_and_restores(self):
        self.assertIsNone(application_for_host("pages.github.io"))
        self.assertEqual(application_for_host("api.openai.com"), "openai-platform")
        self.assertEqual(attribution_for_host("www.teamviewer.com"), ("teamviewer", "provider-web"))
        pin = content.select("2025.10.0")
        self.assertEqual(pin, {"version": "2025.10.0", "digest": content.digest("2025.10.0")})
        self.assertEqual(content.selected(), "2025.10.0")
        self.assertEqual(application_for_host("pages.github.io"), "github")
        self.assertEqual(application_for_host("api.openai.com"), "openai-chatgpt")
        self.assertEqual(attribution_for_host("www.teamviewer.com"), ("teamviewer", "service"))
        self.assertEqual(len(WEB_FRONTS), 0)
        self.assertNotIn("openai-platform", APP_DOMAINS)
        self.assertIn("github.io", HOST_SUFFIXES)
        content.select(content.CURRENT)
        self.assertIsNone(application_for_host("pages.github.io"))
        self.assertEqual(application_for_host("api.openai.com"), "openai-platform")
        self.assertEqual(content.pinned()["version"], content.CURRENT)

    def test_unknown_release_is_refused_and_duplicates_never_build(self):
        with self.assertRaises(content.ContentError):
            content.select("2030.01.0")
        self.assertEqual(content.selected(), content.CURRENT)
        with self.assertRaises(ValueError):
            build_tables([("a", 0, 0, 0, 1, "", (), ("x.example",)), ("b", 0, 0, 0, 1, "", (), ("x.example",))])
        with self.assertRaises(ValueError):
            build_tables([{"name": "a", "domains": ("a.example",), "web_fronts": ("w.example",)},
                          {"name": "b", "domains": ("b.example",), "web_fronts": ("w.example",)}])


class RecordTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(content.select, content.CURRENT)

    def connection(self, an, payload):
        def feed(when, source, destination, seq, ack, flags, data=b""):
            an.process(when, decode_frame(frame(source, destination, seq, ack, flags, data), 1))
        feed(0.0, CLIENT, SERVER, 999, 0, 2)
        feed(0.1, SERVER, CLIENT, 8999, 1000, 18)
        feed(0.2, CLIENT, SERVER, 1000, 9000, 16)
        feed(0.3, CLIENT, SERVER, 1000, 9000, 24, payload)
        an.finish("eof")

    def test_session_records_pin_the_content_release(self):
        records = []
        an = Analyzer(on_session=records.append, idle_timeout=1000)
        self.connection(an, b"GET / HTTP/1.1\r\nHost: api.openai.com\r\n\r\n")
        record = records[0]
        self.assertEqual(record["content"], {"version": content.CURRENT, "digest": content.digest()})
        self.assertEqual(record["app"], "openai-platform")
        self.assertEqual(schema_check.validate(json.loads(json.dumps(record)), schema_check.load("session")), [])
        # Rolled back before the run: the same bytes classify with the earlier catalog and say so.
        content.select("2025.10.0")
        records = []
        an = Analyzer(on_session=records.append, idle_timeout=1000)
        self.connection(an, b"GET / HTTP/1.1\r\nHost: api.openai.com\r\n\r\n")
        self.assertEqual((records[0]["app"], records[0]["content"]["version"]), ("openai-chatgpt", "2025.10.0"))
        self.assertEqual(schema_check.validate(json.loads(json.dumps(records[0])), schema_check.load("session")), [])

    def test_live_summary_carries_the_pin(self):
        monitor = CaptureMonitor(lambda event: None)
        summary = monitor.summary(1.0, final=True)
        self.assertEqual(summary["content"], {"version": content.CURRENT, "digest": content.digest()})
        self.assertEqual(schema_check.validate(json.loads(json.dumps(summary)), schema_check.load("live-event")), [])


if __name__ == "__main__":
    unittest.main()
