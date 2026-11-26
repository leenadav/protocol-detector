"""SEC-SESS-1 (PRO-398, Lee's option B of 2026-11-25): the pinned Go-only divergences of the random parity suites.

The Go tracker gives half-open TCP connections and undecided UDP flows their own budget and a short lifetime, and
a retransmitted SYN no longer refreshes them (go/internal/session/tracker.go; migration/STATUS.md, "Security review
finding SEC-SESS-1"). The frozen Python reference keeps the old behaviour, and Lee decided on 2026-11-25 that it
gets no more fixes. So the cases of the seeded random suites where Go now evicts or expires a half-open state are
pinned here, one by one, in migration/parity/sec_sess1.json:

- the suite (`analyze`, `live`, `live-decrypt`) and the exact case id (seed, capture or script, and for `analyze`
  which comparison: the `analyze` command or the presentation result);
- the reason (SEC-SESS-1, PRO-398) and what differs: the first differing line of Go and of the frozen reference;
- the SHA-256 of the whole compared result of each side (output text and exit status).

One exception keeps the pins reproducible: a live-decrypt script that contains one of the real OpenSSL exchanges
(decrypt_diff.Generator.openssl, a fresh handshake each run, so key bytes and a record length can change between
runs) is `volatile`. The harness, not the pin, decides that; its digests are then taken over the text with every
number and every hexadecimal run of 8 or more characters masked (`mask`), so the keys, types, reasons and order of
every line are still pinned exactly. A pin's `volatile` must equal the harness's, so a reproducible case cannot be
pinned loosely.

A mismatch is approved only when its case is pinned and both digests are exactly the pinned ones: any other change
on either side, in any line, fails the suite. There is no blanket exemption: every other case must still match the
reference exactly, and a pinned case that no longer differs fails the run too (a stale pin), so the list cannot
outgrow the cases it names.

    python3 -B migration/parity/sec_sess1.py --self-test
"""
import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PINS = HERE / "sec_sess1.json"
LABEL = "SEC-SESS-1"
REASON = "SEC-SESS-1, PRO-398"
SUITES = ("analyze", "live", "live-decrypt")
EVICTED = "Half-open budget full; oldest unestablished state evicted"


VOLATILE = re.compile(r"[0-9a-f]{8,}|[0-9]+")


def mask(text):
    """A volatile case's text with every number and every hexadecimal run of 8 or more characters replaced by #."""
    return VOLATILE.sub("#", text)


def openssl_line():
    """`openssl-<major>.<minor>` of the OpenSSL that Python's ssl module runs: part of a live-decrypt case id, because
    the generated scripts hold real OpenSSL exchanges whose lengths change every later random draw (ubuntu-24.04 CI
    runs 3.0; other interpreters may run 3.5, which also offers the hybrid groups). An OpenSSL line with no pins fails
    on any divergence."""
    import ssl
    return "openssl-{}.{}".format(*ssl.OPENSSL_VERSION_INFO[:2])


def digest(output, status, volatile=False):
    """The SHA-256 of one side's compared result: its (normalized) output text and its exit status."""
    return hashlib.sha256(json.dumps([mask(output) if volatile else output, status]).encode("utf-8")).hexdigest()


def first_difference(go_output, frozen_output):
    """(line index, Go's line, the reference's line) of the first differing line; `<end>` past the last line."""
    go_lines, frozen_lines = go_output.splitlines(), frozen_output.splitlines()
    index = next((i for i, (a, b) in enumerate(zip(go_lines, frozen_lines)) if a != b), min(len(go_lines), len(frozen_lines)))
    return index, (go_lines[index:] or ["<end>"])[0], (frozen_lines[index:] or ["<end>"])[0]


def clip(line, limit=400):
    return line if len(line) <= limit else line[:limit] + "..."


def load(path=PINS):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    problems = validate(data)
    if problems:
        raise ValueError("{}: {}".format(path, "; ".join(problems)))
    return data


def validate(data):
    problems = []
    if set(data) - {"comment"} - set(SUITES):
        problems.append("unknown suites {}".format(sorted(set(data) - {"comment"} - set(SUITES))))
    for suite in SUITES:
        for case, pin in data.get(suite, {}).items():
            missing = {"reason", "go_sha256", "frozen_sha256", "line", "go", "frozen"} - set(pin)
            if missing:
                problems.append("{} {}: missing {}".format(suite, case, sorted(missing)))
            elif not pin["reason"].startswith(REASON + ":"):
                problems.append("{} {}: the reason must start with {!r}".format(suite, case, REASON + ":"))
            elif not isinstance(pin.get("volatile", False), bool) or (pin.get("volatile") and suite != "live-decrypt"):
                problems.append("{} {}: `volatile` is only for live-decrypt scripts with an OpenSSL exchange".format(suite, case))
            elif pin["go_sha256"] == pin["frozen_sha256"]:
                problems.append("{} {}: Go and the reference are pinned as equal".format(suite, case))
    return problems


class Pins:
    """The pins of one suite for one run. `approve` is asked only about a case whose two sides differ."""

    def __init__(self, suite, seed, record=None, path=PINS):
        if suite not in SUITES:
            raise ValueError("unknown suite {!r}".format(suite))
        self.suite, self.seed, self.record = suite, seed, record
        self.pins = load(path).get(suite, {})
        self.covered, self.approved, self.observed = set(), set(), {}

    def case_id(self, name):
        return "seed{}/{}".format(self.seed, name)

    def approve(self, name, go_output, go_status, frozen_output, frozen_status, options="", volatile=False):
        """True only when the case is pinned and both sides give exactly the pinned results."""
        case = self.case_id(name)
        go_hash, frozen_hash = digest(go_output, go_status, volatile), digest(frozen_output, frozen_status, volatile)
        line, go_line, frozen_line = first_difference(go_output, frozen_output)
        self.observed[case] = {"reason": REASON + ": ", "options": options, "line": line, "go_status": go_status,
                               "frozen_status": frozen_status, "go": clip(go_line), "frozen": clip(frozen_line),
                               "go_sha256": go_hash, "frozen_sha256": frozen_hash}
        for key, text in (("evicted", EVICTED), ("refused", "too many tracked connections"), ("udp_refused", "udp_flow_limit")):
            self.observed[case][key] = [go_output.count(text), frozen_output.count(text)]       # [Go, reference]
        if volatile:                                # the lines as pinned are masked too, so the record reproduces
            self.observed[case].update(volatile=True, go=clip(mask(go_line)), frozen=clip(mask(frozen_line)))
        pin = self.pins.get(case)
        if (self.record is None and pin and pin.get("volatile", False) == volatile
                and pin["go_sha256"] == go_hash and pin["frozen_sha256"] == frozen_hash):
            self.approved.add(case)
            return True
        return False

    def cover(self, name):
        """Record that this run compared the case, so a pinned case that now matches is reported as stale."""
        self.covered.add(self.case_id(name))

    def stale(self):
        return sorted(case for case in self.pins if case in self.covered and case not in self.approved)

    def finish(self):
        """Problems that fail the run: stale pins, and record mode (which never passes)."""
        problems = ["{} pin {} no longer differs as pinned (stale)".format(self.suite, case) for case in self.stale()]
        if self.record is not None:
            Path(self.record).write_text(json.dumps(self.observed, indent=1, sort_keys=True) + "\n", encoding="utf-8")
            problems.append("record mode: {} observed divergences written to {}; review each, then pin it by hand".format(
                len(self.observed), self.record))
        return problems


def self_test():
    """A pinned case passes only with both exact digests; anything else, and stale pins, fail."""
    import tempfile
    go, frozen = '{"a": 1}\n{"evicted": true}\n', '{"a": 1}\n{"evicted": false}\n'
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "pins.json"
        pin = {"reason": REASON + ": test", "line": 1, "go": '{"evicted": true}', "frozen": '{"evicted": false}',
               "go_sha256": digest(go, 0), "frozen_sha256": digest(frozen, 0)}
        path.write_text(json.dumps({"live": {"seed1/c-1": pin, "seed1/c-2": pin}}), encoding="utf-8")
        pins = Pins("live", 1, path=path)
        assert pins.approve("c-1", go, 0, frozen, 0)                       # exactly as pinned
        assert not pins.approve("c-1", go + "x\n", 0, frozen, 0)           # Go changed
        assert not pins.approve("c-1", go, 0, frozen + "x\n", 0)           # the reference changed
        assert not pins.approve("c-1", go, 1, frozen, 0)                   # exit status changed
        assert not pins.approve("c-3", go, 0, frozen, 0)                   # case not pinned
        assert not Pins("live", 2, path=path).approve("c-1", go, 0, frozen, 0)   # another seed
        assert not Pins("analyze", 1, path=path).approve("c-1", go, 0, frozen, 0)  # another suite
        assert not pins.approve("c-1", go, 0, frozen, 0, volatile=True)    # a reproducible pin is never masked
        loose = dict(pin, volatile=True, go_sha256=digest(go, 0, True), frozen_sha256=digest(frozen, 0, True))
        path.write_text(json.dumps({"live-decrypt": {"seed1/s-1": loose}}), encoding="utf-8")
        masked = Pins("live-decrypt", 1, path=path)
        assert masked.approve("s-1", go.replace("1", "7"), 0, frozen, 0, volatile=True)   # a number may vary
        assert not masked.approve("s-1", go.replace("true", "false"), 0, frozen, 0, volatile=True)  # nothing else
        assert not masked.approve("s-1", go, 0, frozen, 0)                 # only when the harness says volatile
        assert mask('{"n": 1426, "k": "85b93745ab", "x": "abc"}') == '{"n": #, "k": "#", "x": "abc"}'
        assert validate({"live": {"x": dict(loose)}})                       # volatile outside live-decrypt
        for name in ("c-1", "c-2"):
            pins.cover(name)
        assert pins.stale() == ["seed1/c-2"], pins.stale()                 # c-2 compared and matched: stale
        recorder = Pins("live", 1, record=str(Path(folder) / "out.json"), path=path)
        assert not recorder.approve("c-1", go, 0, frozen, 0)               # record mode approves nothing
        assert recorder.finish() and json.loads((Path(folder) / "out.json").read_text())["seed1/c-1"]["line"] == 1
        bad = dict(pin, reason="other")
        assert validate({"live": {"x": bad}}) and validate({"live": {"x": dict(pin, go_sha256=pin["frozen_sha256"])}})
        assert validate({"bogus": {}})
    load()                                                                  # the committed pins are well formed
    return 0


if __name__ == "__main__":
    if sys.argv[1:] != ["--self-test"]:
        sys.exit(__doc__)
    self_test()
    counts = {suite: len(load().get(suite, {})) for suite in SUITES}
    print("sec_sess1 self-test: ok (pins: {})".format(", ".join("{} {}".format(s, counts[s]) for s in SUITES)))
