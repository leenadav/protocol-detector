"""Frozen reference answers for the Go differentials (PRO-401; Lee, 2026-11-25).

The differential gates of `make go-check-parity` (analyze, decrypt, live, live-decrypt, control, server, schema,
adversarial and the randomized differential) used to run the Python reference as their oracle on every run. Each
of them now has two modes beside the original one:

  --record FILE   the original run (the Python reference is the oracle, the Go binary must agree), which also
                  writes every generated input and the answer Go was judged against to FILE. A recording run that
                  finds a single mismatch writes nothing, so a golden file only ever holds answers Go agreed with.
                  Where a recorded divergence is approved (PRO-189, PRO-260), the answer stored is the reference's
                  answer with that one change modelled: exactly what Go was required to give.
  --golden FILE   the gate itself: no generator and no reference run. The inputs are read back from FILE, the Go
                  binary answers them, and its answers are compared with the stored ones by the same comparison
                  the original run uses. Nothing in this mode imports protocol_engine or protocol_adapters.

The files live in migration/fixtures/golden/<tool>.json.gz: gzip (fixed mtime, so a re-recording of the same
answers is byte-identical) over compact JSON (keys in their recorded order). Byte strings are base64. The temporary folder a run used is
written as `{dir}` in paths, arguments and answers, and put back on replay. They hold synthetic inputs only, the
generated captures and the generators' own TLS key logs among them (seeded throwaway keys for seeded synthetic
sessions; nothing is ever captured), which is why they are compressed rather than plain text.

    python3 -B migration/parity/golden.py --summary migration/fixtures/golden/*.json.gz
Standard library only; Python 3.9 syntax.
"""
import base64
import gzip
import hashlib
import io
import json
import sys
from pathlib import Path

FORMAT = 1
ROOT = Path(__file__).resolve().parents[2]
FOLDER = ROOT / "migration/fixtures/golden"
DIR = "{dir}"


def default_path(tool):
    return FOLDER / "{}.json.gz".format(tool)


def b64(data):
    return base64.b64encode(bytes(data)).decode("ascii")


def unb64(text):
    return base64.b64decode(text.encode("ascii"), validate=True)


def encode(document):
    """The file bytes of a golden document: compact JSON under a fixed-mtime gzip. Keys keep their order, because
    some answers are compared as JSON text (the presentation result, server bodies), where order is part of it."""
    raw = json.dumps(document, separators=(",", ":"), allow_nan=False).encode("utf-8")
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buffer, mtime=0, compresslevel=9) as stream:
        stream.write(raw)
    return buffer.getvalue()


def write(path, tool, header, entries):
    """Write a golden file: {format, tool, ..header, entries}."""
    document = dict(header, format=FORMAT, tool=tool, entries=entries)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encode(document))
    print("golden: wrote {} ({} entries, {} bytes)".format(path, len(entries), path.stat().st_size))


def read(path, tool):
    """The golden document of one tool; a wrong tool or format is refused, never half-read."""
    document = json.loads(gzip.decompress(Path(path).read_bytes()).decode("utf-8"))
    if not isinstance(document, dict) or document.get("format") != FORMAT or document.get("tool") != tool:
        raise ValueError("{}: not a format-{} golden file of {} (format {!r}, tool {!r})".format(
            path, FORMAT, tool, (document or {}).get("format"), (document or {}).get("tool")))
    if not isinstance(document.get("entries"), list) or not document["entries"]:
        raise ValueError("{}: a golden file needs at least one entry".format(path))
    return document


def relative(value, folder):
    """Every occurrence of the run's temporary folder in a value (strings, lists, dicts) written as {dir}."""
    folder = str(folder)
    if isinstance(value, str):
        return value.replace(folder, DIR)
    if isinstance(value, list):
        return [relative(item, folder) for item in value]
    if isinstance(value, tuple):
        return [relative(item, folder) for item in value]
    if isinstance(value, dict):
        return {key: relative(item, folder) for key, item in value.items()}
    return value


def absolute(value, folder):
    """The inverse of relative(): {dir} becomes the replay's own temporary folder."""
    folder = str(folder)
    if isinstance(value, str):
        return value.replace(DIR, folder)
    if isinstance(value, list):
        return [absolute(item, folder) for item in value]
    if isinstance(value, dict):
        return {key: absolute(item, folder) for key, item in value.items()}
    return value


LONG = 4096


def text_or_digest(text):
    """A recorded answer line: itself, or for a line over LONG characters (the control plane's full snapshots run to
    megabytes) its SHA-256 with its length and first characters, which pins it exactly at a fraction of the size."""
    if len(text) <= LONG:
        return text
    return {"sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(), "length": len(text), "head": text[:200]}


def matches(actual, recorded):
    """Whether an answer line equals a recorded one (text_or_digest)."""
    if isinstance(recorded, str):
        return actual == recorded
    return len(actual) == recorded["length"] and hashlib.sha256(actual.encode("utf-8")).hexdigest() == recorded["sha256"]


def shown(recorded):
    return recorded if isinstance(recorded, str) else "<sha256 {} of {} characters: {}...>".format(
        recorded["sha256"][:16], recorded["length"], recorded["head"][:120])


class Recorder:
    """Collects the entries of one recording run; write() refuses when the run had failures."""

    def __init__(self, path, tool, header=None):
        self.path, self.tool, self.header, self.entries = path, tool, dict(header or {}), []

    def add(self, entry):
        self.entries.append(entry)

    def finish(self, failed):
        if failed:
            print("golden: {} not written: the recording run had failures".format(self.path))
            return
        write(self.path, self.tool, self.header, self.entries)


def recorder(path, tool, header=None):
    return Recorder(path, tool, header) if path else None


def self_test():
    folder = "/run/folder-123"     # a placeholder path; nothing is created
    value = {"argv": ["--signatures", folder + "/s.json"], "out": "Capture error: " + folder + "/c: bad", "n": 3}
    assert absolute(relative(value, folder), "/r") == {"argv": ["--signatures", "/r/s.json"], "out": "Capture error: /r/c: bad", "n": 3}
    assert unb64(b64(b"\x00\xff")) == b"\x00\xff"
    once, twice = encode({"b": 1, "a": [1, 2]}), encode({"b": 1, "a": [1, 2]})
    assert once == twice, "the file bytes must not depend on the clock"
    assert list(json.loads(gzip.decompress(once))) == ["b", "a"], "key order is kept"
    long = "x" * (LONG + 1)
    assert matches("ab", text_or_digest("ab")) and not matches("ac", text_or_digest("ab"))
    assert matches(long, text_or_digest(long)) and not matches(long[:-1] + "y", text_or_digest(long))
    assert isinstance(text_or_digest(long), dict) and len(json.dumps(text_or_digest(long))) < 400
    print("golden self-test: ok (digests of long lines, folder substitution, base64, fixed bytes, key order)")
    return 0


def summary(paths):
    for path in paths:
        document = json.loads(gzip.decompress(Path(path).read_bytes()).decode("utf-8"))
        extra = {key: value for key, value in document.items() if key not in ("entries", "format", "tool") and not isinstance(value, (dict, list))}
        print("{}: tool {}, {} entries, {}".format(path, document.get("tool"), len(document.get("entries") or ()), extra))
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        sys.exit(self_test())
    if sys.argv[1:2] == ["--summary"]:
        sys.exit(summary(sys.argv[2:]))
    print(__doc__)
    sys.exit(2)
