"""D08: detection content releases, provenance, lock gate and server-name catalog rollback."""
import json
import os
import tempfile
import unittest
from types import MappingProxyType
from unittest import mock

from protocol_adapters.analyze_pcap import Analyzer
from protocol_adapters.link_packets import decode_frame
from protocol_adapters.live_capture import CaptureMonitor
from protocol_adapters.make_sample_pcap import frame
from protocol_engine import content
from protocol_engine.host_apps import APP_DOMAINS, HOST_SUFFIXES, WEB_FRONTS, application_for_host, attribution_for_host, build_tables
from tools import check_content, schema_check

CLIENT, SERVER = ("192.0.2.10", 52000), ("198.51.100.20", 80)


def _numeric_version(version):
    """YYYY.MM.N as integers: 2026.11.9 sorts before 2026.11.10 (PRO-31)."""
    return tuple(int(part) for part in version.split("."))


class HistoryAndLockTests(unittest.TestCase):
    def test_tables_history_and_lock_agree(self):
        self.assertEqual(content.check(), [])
        self.assertEqual(check_content.main([]), 0)
        lock = content.read_lock()
        self.assertEqual((lock["version"], lock["digest"]), (content.CURRENT, content.digest()))
        self.assertEqual(set(lock["components"]), {"host_catalog", "application_catalog", "families", "risks"})

    def test_releases_are_dated_and_ordered(self):
        versions = [item.version for item in content.releases()]
        for version in versions:
            self.assertRegex(version, r"^\d{4}\.\d{1,2}\.\d+$")
        self.assertEqual(versions, sorted(versions, key=_numeric_version))  # PRO-31: numerically, not as strings
        self.assertEqual(len(set(versions)), len(versions))
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
        # Only the host catalog is rebuilt; it must equal the host component the release was published with. The
        # other components are stated as published (C11), not borrowed from the current release.
        self.assertEqual(components["host_catalog"], content._hash(list(content.host_entries("2025.10.0"))))
        self.assertEqual(dict(components), dict(content._RELEASED_COMPONENTS["2025.10.0"]))
        self.assertNotEqual(components["application_catalog"], content.component_digests()["application_catalog"])
        for name in ("families", "risks"):
            self.assertEqual(components[name], content.component_digests()[name])   # unchanged since 2025.10.0

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
        self.assertEqual(len(new), 442)
        previous = {entry["name"] for entry in content.host_entries("2026.11.0")}
        self.assertEqual(len(previous), 54)                         # 2026.11.1 added 115 services and changed none
        middle = {entry["name"] for entry in content.host_entries("2026.11.1")}
        self.assertEqual(len(middle), 169)                          # 2026.11.2 added 262 more
        self.assertTrue(previous < middle < set(new) and "crowdstrike" not in middle and "nordvpn" in middle)
        self.assertEqual(content.host_provenance()["crowdstrike"]["since"], "2026.11.2")
        self.assertTrue(previous < set(new) and "nordvpn" not in previous and "nordvpn" not in old)
        self.assertEqual(content.host_provenance()["nordvpn"]["since"], "2026.11.1")
        self.assertEqual(content.host_provenance()["youtube"]["since"], "2025.10.0")
        self.assertNotIn("openai-platform", old)
        self.assertIn("github.io", old["github"]["domains"])
        self.assertNotIn("github.io", new["github"]["domains"])
        self.assertIn("openai.com", old["openai-chatgpt"]["domains"])
        self.assertEqual(old["teamviewer"]["web_fronts"], ())
        self.assertTrue(all(entry["web_fronts"] == () for entry in old.values()))     # web fronts arrived with D03
        self.assertEqual(old["whatsapp"], new["whatsapp"])

    def test_earlier_releases_reproduce_their_published_digests(self):
        """C11 (2026-11-18): a record pinned to an earlier release carries the digest it was published with, so a
        rollback must reproduce it, also after the application catalog changed. 2026.11.0 and 2026.11.1 are
        their content_lock.json values while current; 2025.10.0 its first recorded value (799d358)."""
        from protocol_engine import applications
        published = {"2025.10.0": "9f8791749a940f5b", "2026.11.0": "991c007668d263d1", "2026.11.1": "c4020c2437f3de8d",
                     "2026.11.2": "e0d6e39533a6ae9c", "2026.11.3": "fef8f709d5615a85",
                     "2026.11.4": "c13a842d11873db6",
                     "2026.11.5": "39150de086799d99",
                     "2026.11.6": "d425b8adc87db36d",
                     "2026.11.7": "b2ccbc7842dcffcc",
                     "2026.11.8": "804f727352bc61e0"}
        for version, value in published.items():
            self.assertEqual(content.digest(version), value, version)
            self.assertEqual(content.select(version), {"version": version, "digest": value})
        content.select(content.CURRENT)
        # An application added after these releases moves the current digest only.
        current = content.digest()
        added = dict(applications.APPLICATIONS)
        added["c11-probe"] = next(iter(applications.APPLICATIONS.values()))
        saved = dict(content._DIGESTS)
        self.addCleanup(lambda: (content._DIGESTS.clear(), content._DIGESTS.update(saved)))
        with mock.patch.object(applications, "APPLICATIONS", added):
            content._DIGESTS.clear()
            self.assertNotEqual(content.digest(), current)
            for version, value in published.items():
                self.assertEqual(content.digest(version), value, version)
        # A rebuilt host catalog that no longer matches its release is refused, not re-pinned.
        changed = dict(content._PRIOR_HOST_STATE)
        changed["2026.11.1"] = MappingProxyType(dict(changed["2026.11.1"], **{"youtube": None}))
        with mock.patch.object(content, "_PRIOR_HOST_STATE", MappingProxyType(changed)):
            content._DIGESTS.clear()
            with self.assertRaisesRegex(content.ContentError, "no longer reproduces"):
                content.digest("2026.11.1")
            self.assertTrue(any("2026.11.1 no longer reproduces" in p for p in content.check()))

    def test_a_new_release_is_locked_only_after_its_predecessor_is_recorded(self):
        """C11: `check_content.py --update` for a new release refuses until the superseded release's locked
        components are in _RELEASED_COMPONENTS exactly."""
        recorded = dict(content._RELEASED_COMPONENTS["2026.11.1"])
        stale = {"version": "2026.11.1", "digest": "c4020c2437f3de8d", "components": dict(recorded, risks="0" * 64)}
        with mock.patch.object(content, "read_lock", return_value=stale), mock.patch.object(content, "write_lock") as write:
            self.assertEqual(check_content.main(["--update"]), 1)
            write.assert_not_called()
        exact = dict(stale, components=recorded)
        with mock.patch.object(content, "read_lock", return_value=exact), \
                mock.patch.object(content, "write_lock", return_value=content.description()) as write:
            self.assertEqual(check_content.main(["--update"]), 0)
            write.assert_called_once()

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


class VersionOrderTests(unittest.TestCase):
    """PRO-31: a release numbered past N = 9 (2026.11.10 after 2026.11.9).

    The reference (`content.host_entries` and `content.host_provenance`) compares release versions as strings, and
    `protocol_engine/content.py` is frozen reference code on this branch, so it is not changed here. These tests
    simulate a 2026.11.10 release over the real tables. The three marked expectedFailure reproduce the string
    comparison and turn into unexpected successes, which fail the suite, once the reference compares numerically,
    so their markers are removed with that fix."""

    NEXT = "2026.11.10"
    MARK = "pro31-rollback-marker.invalid"

    def _simulated(self):
        """HISTORY with a 2026.11.10 release whose predecessor 2026.11.9 carried one more `goto` domain."""
        current = content.CURRENT
        goto = next(entry for entry in content.host_entries() if entry["name"] == "goto")
        history = content.HISTORY + (content.Release(self.NEXT, "2026-11-20", "2026-11-20", "PRO-31 simulation", "test"),)
        prior = dict(content._PRIOR_HOST_STATE)
        prior[current] = MappingProxyType({"goto": {"domains": tuple(goto["domains"]) + (self.MARK,)}})
        return current, [mock.patch.object(content, "HISTORY", history),
                         mock.patch.object(content, "_PRIOR_HOST_STATE", MappingProxyType(prior))]

    def _run(self, patches, fn):
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        return fn()

    def test_numeric_order_places_ten_after_nine(self):
        self.assertLess(_numeric_version("2026.11.9"), _numeric_version(self.NEXT))
        self.assertGreater("2026.11.9", self.NEXT)  # the string order the reference uses today

    @unittest.expectedFailure
    def test_the_new_release_itself_keeps_the_current_catalog(self):
        """With string order every earlier release from 2026.11.9 down to 2026.11.2 compares as not less than
        "2026.11.10", so host_entries lays their prior states over the current catalog and the new release itself
        gets the 2026.11.2 catalog (no `goto` entry), silently."""
        _, patches = self._simulated()
        entries = self._run(patches, lambda: content.host_entries(self.NEXT))
        goto = next(entry for entry in entries if entry["name"] == "goto")
        self.assertNotIn(self.MARK, goto["domains"])

    @unittest.expectedFailure
    def test_rolling_back_to_nine_applies_its_prior_state(self):
        """C11 rollback: 2026.11.9 must carry the domain it had then. With string order the loop in host_entries
        stops at 2026.11.10 ("2026.11.10" < "2026.11.9") and 2026.11.9 gets the current catalog."""
        previous, patches = self._simulated()
        entries = self._run(patches, lambda: content.host_entries(previous))
        goto = next(entry for entry in entries if entry["name"] == "goto")
        self.assertIn(self.MARK, goto["domains"])

    @unittest.expectedFailure
    def test_provenance_of_the_new_release_covers_every_release(self):
        """With string order host_provenance stops at 2026.11.2 ("2026.11.2" > "2026.11.10") and raises KeyError
        for every entry added since."""
        _, patches = self._simulated()
        provenance = self._run(patches, lambda: content.host_provenance(self.NEXT))
        self.assertEqual(provenance["goto"]["since"], "2026.11.9")


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
