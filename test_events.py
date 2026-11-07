"""Stage 2 (A06): versioned event envelope, bounded log with cursors, retractions and the replayable reducer."""
import json
import sys
import unittest
from pathlib import Path

from protocol_adapters.events import (DEFAULT_RETENTION, Envelope, EventLog, public_state, reduce, session_identity, wrap)

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
import schema_check  # noqa: E402

CLIENT, SERVER = ["192.0.2.10", 52000], ["198.51.100.20", 443]


def session(app="ssl", client=CLIENT, server=SERVER, **extra):
    return dict({"type": "session", "transport": "tcp", "client": client, "server": server, "app": app,
                 "engine_status": "identified", "reasons": []}, **extra)


def classification(status="identified", client=CLIENT, server=SERVER):
    return {"type": "classification", "transport": "tcp", "source": client, "destination": server,
            "status": status, "protocol": "tls", "app": "ssl", "reason": "ClientHello"}


class EnvelopeTests(unittest.TestCase):
    def test_identity_is_direction_independent_and_carries_no_address(self):
        a = session_identity("tcp", CLIENT, SERVER)
        self.assertEqual(a, session_identity("tcp", SERVER, CLIENT))
        self.assertNotEqual(a, session_identity("udp", CLIENT, SERVER))
        self.assertEqual(len(a), 16)
        self.assertNotIn("192", a)
        self.assertNotIn("52000", a)

    def test_envelope_validates_against_its_schema_and_rejects_bad_fields(self):
        schema = schema_check.load("event-envelope")
        log = EventLog("cap")
        log.wrap_and_append(session())
        log.wrap_and_append(classification("budget_exhausted"))
        log.wrap_and_append({"type": "capture_gap", "reason": "Capture reported packet loss", "scope": "all_observations_this_capture"})
        for envelope in log.snapshot()["events"]:
            self.assertEqual(schema_check.validate(json.loads(json.dumps(envelope)), schema), [])
        self.assertEqual(log.snapshot()["events"][1]["budget"], {"exhausted": True, "scope": "inspection"})
        self.assertEqual(log.snapshot()["events"][2]["reason_code"], "capture.loss")
        for bad in (dict(layer="nope"), dict(quality="great"), dict(source="unknown"), dict(kind="other"), dict(extra=1)):
            fields = dict(capture_id="cap", session_id=None, layer="capture", kind="summary", source="capture",
                          quality="intact", payload={})
            fields.update(bad)
            with self.assertRaises(ValueError):
                Envelope(**fields)
        with self.assertRaises(ValueError):
            Envelope(capture_id="cap", session_id=None, layer="capture", kind="capture_gap", source="capture",
                     quality="degraded", payload={}, retracts=["x"] * 1025)


class EventLogTests(unittest.TestCase):
    def test_sequence_revision_and_capture_isolation(self):
        log = EventLog("cap")
        self.assertEqual(log.wrap_and_append(classification()), 1)
        self.assertEqual(log.wrap_and_append(session()), 2)
        events = log.snapshot()["events"]
        self.assertEqual([e["revision"] for e in events], [1, 2])           # one session generation, two revisions
        self.assertEqual(events[0]["session_id"], events[1]["session_id"])
        with self.assertRaises(ValueError):
            log.append(wrap(session(), "other-capture"))
        with self.assertRaises(ValueError):                                   # producers never number events
            log.append(Envelope(capture_id="cap", session_id=None, layer="capture", kind="summary",
                                source="capture", quality="intact", payload={}, sequence=99))

    def test_cursor_reads_repeat_nothing_and_report_reset_when_behind(self):
        log = EventLog("cap", retention=5)
        for index in range(3):
            log.wrap_and_append(classification(client=["192.0.2.1", 50000 + index]))
        first = log.read(0)
        self.assertEqual([e["sequence"] for e in first["events"]], [1, 2, 3])
        again = log.read(first["cursor"])
        self.assertEqual((again["events"], again["cursor"], again["reset_required"]), ([], 3, False))  # duplicate poll: nothing new
        for index in range(10):                                                    # overflow: the start moves
            log.wrap_and_append(classification(client=["192.0.2.2", 50000 + index]))
        behind = log.read(first["cursor"])
        self.assertTrue(behind["reset_required"])
        self.assertEqual(behind["events"], [])
        self.assertEqual(behind["cursor"], 13)
        snapshot = log.snapshot()
        self.assertEqual((len(snapshot["events"]), snapshot["dropped"], snapshot["start"]), (5, 8, 9))
        fresh = log.read(snapshot["cursor"] - 2)
        self.assertEqual([e["sequence"] for e in fresh["events"]], [12, 13])
        with self.assertRaises(ValueError):
            log.read(-1)
        with self.assertRaises(ValueError):
            EventLog("cap", retention=0)

    def test_generation_bumps_on_tuple_reuse(self):
        log = EventLog("cap")
        log.wrap_and_append(session("ssl"))
        sid = log.snapshot()["events"][0]["session_id"]
        log.generations.renew(sid)
        log.wrap_and_append(session("web-browsing"))
        events = log.snapshot()["events"]
        self.assertEqual([(e["generation"], e["revision"]) for e in events], [(0, 1), (1, 1)])
        self.assertEqual(log.retention, DEFAULT_RETENTION)


class ReducerTests(unittest.TestCase):
    def test_stale_revision_and_older_generation_never_overwrite(self):
        log = EventLog("cap")
        log.wrap_and_append(classification())
        log.wrap_and_append(session("ssl"))
        events = log.snapshot()["events"]
        state = reduce(events)
        view = next(iter(state["sessions"].values()))
        self.assertEqual((view["status"], view["session"]["app"], view["revision"], len(view["classifications"])), ("final", "ssl", 2, 1))
        stale = Envelope(**dict(events[1], sequence=99, revision=1, payload=session("telnet")))   # older revision, later delivery
        reduce([stale], state)
        self.assertEqual(view["session"]["app"], "ssl")
        older_generation = Envelope(**dict(events[1], sequence=100, generation=0, revision=5, payload=session("telnet")))
        log.generations.renew(events[1]["session_id"])
        renewed_sequence = log.wrap_and_append(session("web-browsing"))
        reduce([e for e in log.snapshot()["events"] if e["sequence"] == renewed_sequence], state)
        current = next(iter(state["sessions"].values()))
        self.assertEqual((current["generation"], current["session"]["app"]), (1, "web-browsing"))
        reduce([older_generation], state)
        self.assertEqual(state["sessions"][events[1]["session_id"]]["session"]["app"], "web-browsing")

    def test_retraction_withdraws_named_sessions_and_their_inner_evidence(self):
        log = EventLog("cap")
        other = ["203.0.113.5", 40000]
        log.wrap_and_append(session("ssl"))
        log.wrap_and_append(session("ssh", client=other))
        log.wrap_and_append({"type": "decryption", "transport": "tcp", "client": CLIENT, "server": SERVER, "application": "webdav"})
        target = session_identity("tcp", CLIENT, SERVER)
        log.wrap_and_append({"type": "capture_gap", "reason": "Capture truncation", "scope": "active_connections", "session_ids": [target]})
        state = reduce(log.snapshot()["events"])
        retracted, kept = state["sessions"][target], state["sessions"][session_identity("tcp", other, SERVER)]
        self.assertEqual((retracted["status"], retracted["decryption"], retracted["retracted_by"]["reason_code"]), ("retracted", None, "capture.gap"))
        self.assertEqual((kept["status"], kept["session"]["app"]), ("final", "ssh"))
        self.assertEqual((state["quality"], state["retracted_total"]), ("degraded", 1))
        log.wrap_and_append(session("ssl"))                                   # same generation after retraction
        reduce(log.snapshot()["events"][-1:], state)
        self.assertEqual(state["sessions"][target]["status"], "retracted")   # nothing revives a withdrawn generation
        log.wrap_and_append({"type": "capture_gap", "reason": "Capture reported packet loss", "scope": "all_observations_this_capture"})
        reduce(log.snapshot()["events"][-1:], state)
        self.assertTrue(all(v["status"] == "retracted" for v in state["sessions"].values()))
        self.assertEqual(state["retracted_total"], 2)

    def test_replay_reconstructs_the_same_state_and_duplicates_are_no_ops(self):
        log = EventLog("cap")
        for event in (classification(), session("ssl"), {"type": "summary", "counts": {"packets": 3}},
                      {"type": "error", "reason": "Capture failed"},
                      {"type": "capture_gap", "reason": "loss", "scope": "all_observations_this_capture"}):
            log.wrap_and_append(event)
        events = log.snapshot()["events"]
        live = reduce([])
        for e in events:                                                    # incremental, one at a time
            reduce([e], live)
            reduce([e], live)                                               # delivered twice: ignored
        replayed = reduce(json.loads(json.dumps(events)))                 # from a serialized log
        self.assertEqual(json.dumps(public_state(live), sort_keys=True), json.dumps(public_state(replayed), sort_keys=True))
        self.assertNotIn("_seen", public_state(live))
        self.assertEqual(live["summary"], {"type": "summary", "counts": {"packets": 3}})
        self.assertEqual(live["errors"][0]["reason_code"], "capture.error")
        self.assertEqual(live["last_sequence"], 5)


class ProducerTests(unittest.TestCase):
    def test_capture_gap_names_the_sessions_it_retracts(self):
        import time
        from protocol_adapters.capture_stream import PcapStreamDecoder
        from protocol_adapters.live_capture import CaptureMonitor
        from protocol_adapters.make_sample_pcap import frame, pcap_bytes
        client, server = ("192.0.2.10", 52000), ("198.51.100.20", 80)
        emitted = []
        monitor = CaptureMonitor(emitted.append, all_events=True)
        data = pcap_bytes([frame(client, server, 999, 0, 2), frame(server, client, 4999, 1000, 18),
                           frame(client, server, 1000, 5000, 24, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")])
        for record in PcapStreamDecoder().feed(data):
            monitor.accept(record, time.monotonic())
        monitor.invalidate_all("Capture truncation; active stream observations invalidated")
        gap = next(e for e in emitted if e.get("type") == "capture_gap")
        self.assertEqual(gap["session_ids"], [session_identity("tcp", client, server)])
        self.assertEqual(gap["active_connections"], 1)
        log = EventLog("cap")
        for event in emitted:
            log.wrap_and_append(event)
        state = reduce(log.snapshot()["events"])
        self.assertEqual([v["status"] for v in state["sessions"].values()], ["retracted"])


if __name__ == "__main__":
    unittest.main()
