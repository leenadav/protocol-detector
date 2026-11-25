"""Generate the shared ledger sections from per-task notes, so parallel pull requests never conflict on them.

Lee, 2026-11-24 (PRO-347): almost every pull-request conflict came from lanes editing the same shared ledgers
(the lane briefs, migration/STATUS.md, the README/REVIEW-SCOPE test counts). Now a task adds its own file,
`migration/notes/PRO-<n>.md`, and never edits a generated section. Two branches that each add a notes file touch
different paths, so git merges them without a conflict; this tool then rewrites the generated sections from the
notes on the merged tree.

A notes file (`migration/notes/README.md` documents it for authors):

    ---
    task: PRO-347
    lane: platform
    date: 2026-11-24
    title: Shared ledgers generated from per-task notes
    prs: 119
    shas: 0123abc, 4567def
    ---
    One paragraph: what changed and why, the evidence and anything left open.

`prs` and `shas` are optional, comma-separated lists (a pull request number is not known before it is opened);
the pull request that merged the note is read from git log. A generated section sits between two markers that
name what fills it:

    <!-- BEGIN GENERATED: recent-work lane=engine limit=15 -->
    ...
    <!-- END GENERATED: recent-work -->
    <!-- BEGIN GENERATED: test-count -->895<!-- END GENERATED: test-count -->

`recent-work` lists the notes of one lane (`lane=a+b`: several, `lane=all`: every lane), newest first (date, then task number), at most
`limit` of them. Each entry ends with what git log says about the note: `merged in #N` (the oldest
`Merge pull request #N` commit that contains the commit adding the note), `committed, not merged yet`, or
`not committed yet`. `test-count` is the test count `tools/check_docs_counts.py` computes. Everything outside the
markers stays hand-written.

The output depends only on the notes, the ledgers, the test suite and git history: the same inputs give the same
bytes. Reading the merge history needs a full clone, so `--write` and `--strict` refuse a shallow one.

    build_ledgers.py --write            rewrite every generated section in place
    build_ledgers.py --check            the pull-request check (below)
    build_ledgers.py --check --strict   every generated section equals a fresh build (main, nightly, release)
    build_ledgers.py --diff             print the --write change as a unified diff, change nothing
    build_ledgers.py --self-test        offline self-test, including a two-branch merge in a scratch repository
    [--summary FILE] appends the report to a job summary; [--root DIR] runs on another checkout.

`--check` is what a pull request must pass. Pull requests do not regenerate (that is what made them conflict),
so a section may lag behind: a note the section does not list yet, or a test count that moved, is reported as
behind and passes. It fails on what a lagging section cannot explain: a missing or broken marker, a malformed or
misnamed notes file, an entry that is not exactly what its note renders to (a hand edit), an entry with no notes
file, a duplicate, an entry out of order, more entries than the limit, or a count that is not a number. Every
failure prints the command that fixes it. Standard library only; Python 3.9 syntax.
"""
import difflib
import os
import re
import shutil
import subprocess  # noqa: S404  (argv-only git invocation, no shell)
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOTES_DIR = os.path.join("migration", "notes")
LEDGERS = ("migration/LANE-BRIEF.md", "migration/STATUS.md", "docs/LANE-BRIEF-platform.md",
           "docs/integration/LANE-BRIEF-culvert.md", "research/LANE-BRIEF.md", "README.md", "REVIEW-SCOPE.md")
LANES = ("engine", "platform", "app-research", "research-lab", "culvert", "qa", "docs", "security", "hermes",
         "deputy")
FIELDS = ("task", "lane", "date", "title", "prs", "shas")
REQUIRED = ("task", "lane", "date", "title")
NOTE_NAME = re.compile(r"^PRO-([1-9][0-9]{0,5})\.md$")
TASK = re.compile(r"^PRO-([1-9][0-9]{0,5})$")
DATE = re.compile(r"^20[0-9]{2}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$")
SHA = re.compile(r"^[0-9a-f]{7,40}$")
PR = re.compile(r"^#?([1-9][0-9]{0,6})$")
MAX_TITLE, MAX_SUMMARY, MAX_NOTE_BYTES = 120, 1200, 8192
BEGIN = re.compile(r"<!-- BEGIN GENERATED: ([a-z-]+)((?: [a-z]+=[A-Za-z0-9+-]+)*) -->")
END = "<!-- END GENERATED: {} -->"
HEADER = ("<!-- tools/build_ledgers.py writes this section from migration/notes/PRO-<n>.md. Do not edit it: "
          "add a notes file instead (migration/notes/README.md). -->")
GIT_STATE = re.compile(r" \((merged in #[1-9][0-9]*|committed, not merged yet|not committed yet)\)$")
MERGE_SUBJECT = re.compile(r"^Merge pull request #([1-9][0-9]*) ")
FIX = "python3 -B tools/build_ledgers.py --write"
FIX_HINT = "run `{}` (a full clone: `git fetch --unshallow` first if needed)".format(FIX)


class LedgerError(Exception):
    """A ledger or notes file this tool cannot read safely."""


# --- notes -----------------------------------------------------------------------------------------------

def parse_note(name, text):
    """A notes file's fields and its one-paragraph summary, or LedgerError naming what is wrong."""
    match = NOTE_NAME.match(name)
    if not match:
        raise LedgerError("{}: a notes file is named PRO-<n>.md".format(name))
    if len(text.encode("utf-8")) > MAX_NOTE_BYTES:
        raise LedgerError("{}: longer than {} bytes; a note is one paragraph".format(name, MAX_NOTE_BYTES))
    lines = text.replace("\r\n", "\n").split("\n")
    if not lines or lines[0] != "---" or "---" not in lines[1:]:
        raise LedgerError("{}: must start with a front matter block between two `---` lines".format(name))
    end = lines.index("---", 1)
    note = {}
    for raw in lines[1:end]:
        if not raw.strip():
            continue
        key, sep, value = raw.partition(":")
        key, value = key.strip(), value.strip()
        if not sep or key not in FIELDS:
            raise LedgerError("{}: unknown front matter line {!r} (fields: {})".format(name, raw, ", ".join(FIELDS)))
        if key in note:
            raise LedgerError("{}: `{}` appears twice".format(name, key))
        note[key] = value
    for key in REQUIRED:
        if not note.get(key):
            raise LedgerError("{}: `{}` is required".format(name, key))
    if note["task"] != "PRO-" + match.group(1):
        raise LedgerError("{}: task {} does not match the file name".format(name, note["task"]))
    if note["lane"] not in LANES:
        raise LedgerError("{}: lane {!r} is not one of {}".format(name, note["lane"], ", ".join(LANES)))
    if not DATE.match(note["date"]):
        raise LedgerError("{}: date {!r} is not YYYY-MM-DD".format(name, note["date"]))
    prs, shas = split_list(note.get("prs", "")), split_list(note.get("shas", ""))
    for value in prs:
        if not PR.match(value):
            raise LedgerError("{}: pull request {!r} is not a number".format(name, value))
    for value in shas:
        if not SHA.match(value):
            raise LedgerError("{}: SHA {!r} is not 7-40 lowercase hex digits".format(name, value))
    body = [line.strip() for line in lines[end + 1:]]
    while body and not body[0]:
        body.pop(0)
    while body and not body[-1]:
        body.pop()
    if not body:
        raise LedgerError("{}: the summary paragraph is missing".format(name))
    if "" in body:
        raise LedgerError("{}: the summary must be one paragraph (no blank line inside it)".format(name))
    summary = " ".join(body)
    title = note["title"]
    for label, value, limit in (("title", title, MAX_TITLE), ("summary", summary, MAX_SUMMARY)):
        if len(value) > limit:
            raise LedgerError("{}: the {} is longer than {} characters".format(name, label, limit))
        if "<!--" in value or "-->" in value or "GENERATED" in value:
            raise LedgerError("{}: the {} may not contain comment markers or the word GENERATED".format(name, label))
    return {"task": note["task"], "number": int(match.group(1)), "lane": note["lane"], "date": note["date"],
            "title": title, "prs": [PR.match(value).group(1) for value in prs], "shas": shas, "summary": summary,
            "path": NOTES_DIR.replace(os.sep, "/") + "/" + name}


def split_list(value):
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    return [item.strip() for item in value.split(",") if item.strip()]


def read_notes(root):
    directory = os.path.join(root, NOTES_DIR)
    notes = {}
    if not os.path.isdir(directory):
        return notes
    for name in sorted(os.listdir(directory)):
        if name == "README.md":
            continue
        if not name.endswith(".md"):
            raise LedgerError("{}/{}: only PRO-<n>.md notes and README.md belong in {}".format(NOTES_DIR, name, NOTES_DIR))
        with open(os.path.join(directory, name), encoding="utf-8") as handle:
            note = parse_note(name, handle.read())
        notes[note["task"]] = note
    return notes


def order_key(note):
    """Newest first: the later date, then the higher task number."""
    return (note["date"], note["number"])


def render_note(note):
    """An entry without its git state: everything the notes file alone decides."""
    parts = ["- {} · **{}** · {} · {}: {}".format(note["date"], note["task"], note["lane"], note["title"], note["summary"])]
    if note["prs"]:
        parts.append("PRs: {}.".format(", ".join("#" + value for value in note["prs"])))
    if note["shas"]:
        parts.append("SHAs: {}.".format(", ".join("`{}`".format(value) for value in note["shas"])))
    return " ".join(parts)


# --- git ---------------------------------------------------------------------------------------------------

def git(root, *args):
    if not shutil.which("git"):
        raise LedgerError("git is not installed")
    result = subprocess.run(["git", "-C", root] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,  # noqa: S603,S607
                            universal_newlines=True, check=False)
    if result.returncode != 0:
        raise LedgerError("git {} failed: {}".format(" ".join(args), result.stderr.strip()))
    return result.stdout


def require_history(root):
    if git(root, "rev-parse", "--is-shallow-repository").strip() != "false":
        raise LedgerError("a shallow clone cannot show which pull request merged each note; "
                          "run `git fetch --unshallow` (CI: fetch-depth: 0)")


def git_state(root, note):
    """`merged in #N`, `committed, not merged yet` or `not committed yet`, from the history of HEAD."""
    added = git(root, "log", "--diff-filter=A", "--format=%H", "HEAD", "--", note["path"]).split()
    if not added:
        return "not committed yet"
    first = added[-1]
    merges = git(root, "log", "--merges", "--topo-order", "--reverse", "--ancestry-path", "--format=%s",
                 "{}..HEAD".format(first)).splitlines()
    for subject in merges:
        match = MERGE_SUBJECT.match(subject)
        if match:
            return "merged in #" + match.group(1)
    return "committed, not merged yet"


# --- sections ----------------------------------------------------------------------------------------------

def sections(path, text):
    """[(kind, options, start, end)] for each generated section; start/end bound the text between the markers."""
    found, position = [], 0
    while True:
        match = BEGIN.search(text, position)
        if not match:
            break
        kind = match.group(1)
        options = dict(item.split("=", 1) for item in match.group(2).split())
        end = text.find(END.format(kind), match.end())
        nested = BEGIN.search(text, match.end())
        if end < 0 or (nested and nested.start() < end):
            raise LedgerError("{}: `{}` has no matching `{}`".format(path, match.group(0), END.format(kind)))
        found.append((kind, options, match.end(), end))
        position = end + len(END.format(kind))
    stray = text.count("<!-- END GENERATED:") - len(found)
    if stray:
        raise LedgerError("{}: {} END GENERATED marker(s) without a BEGIN".format(path, stray))
    for kind, options, _start, _end in found:
        if kind == "recent-work":
            lanes, limit = options.get("lane", "").split("+"), options.get("limit", "")
            if set(options) != {"lane", "limit"} or (lanes != ["all"] and not set(lanes) <= set(LANES)) \
                    or not limit.isdigit() or not 1 <= int(limit) <= 200:
                raise LedgerError("{}: recent-work needs lane=<all|a lane|lane+lane> (lanes: {}) and limit=<1-200>, "
                                  "got {}".format(path, ", ".join(LANES), options))
        elif kind == "test-count":
            if options:
                raise LedgerError("{}: test-count takes no options".format(path))
        else:
            raise LedgerError("{}: unknown generated section kind {!r}".format(path, kind))
    return found


def in_lane(note, lane):
    """`lane` is `all`, one lane, or several joined by `+`."""
    return lane == "all" or note["lane"] in lane.split("+")


def selected(notes, lane, limit):
    chosen = [note for note in notes.values() if in_lane(note, lane)]
    return sorted(chosen, key=order_key, reverse=True)[:int(limit)]


def render_recent(notes, options, states):
    entries = ["{} ({})".format(render_note(note), states[note["task"]])
               for note in selected(notes, options["lane"], options["limit"])]
    return "\n" + HEADER + "\n\n" + ("\n".join(entries) if entries else "_No notes for this lane yet._") + "\n"


def build(root, notes, counts):
    """{path: (old text, new text)} for every ledger; `counts()` gives the test count on demand."""
    states = {task: git_state(root, note) for task, note in notes.items()}
    result, test_count = {}, None
    for path in LEDGERS:
        old = read_ledger(root, path)
        new, last = [], 0
        for kind, options, start, end in sections(path, old):
            new.append(old[last:start])
            if kind == "recent-work":
                new.append(render_recent(notes, options, states))
            else:
                if test_count is None:
                    test_count = counts()
                new.append(str(test_count))
            last = end
        new.append(old[last:])
        result[path] = (old, "".join(new))
    return result


def read_ledger(root, path):
    full = os.path.join(root, path)
    if not os.path.isfile(full):
        raise LedgerError("{} is missing".format(path))
    with open(full, encoding="utf-8", newline="") as handle:
        return handle.read()


def consistency(root, notes):
    """(failures, behind): the --check verdict, needing no git history and no test run."""
    failures, behind, seen = [], [], set()
    for path in LEDGERS:
        text = read_ledger(root, path)
        try:
            found = sections(path, text)
        except LedgerError as error:
            failures.append(str(error))
            continue
        kinds = [kind for kind, _options, _start, _end in found]
        if not found:
            failures.append("{}: no generated section (the BEGIN/END GENERATED markers were removed)".format(path))
        for kind, options, start, end in found:
            seen.add(kind)
            body = text[start:end]
            if kind == "test-count":
                if not re.match(r"^[1-9][0-9]{0,5}$", body):
                    failures.append("{}: test-count holds {!r}, not a number".format(path, body))
                continue
            failures.extend(check_recent(path, body, notes, options, behind))
        if kinds.count("test-count") > 1:
            failures.append("{}: more than one test-count section".format(path))
    for kind in ("recent-work", "test-count"):
        if kind not in seen:
            failures.append("no ledger has a {} section".format(kind))
    return failures, behind


def check_recent(path, body, notes, options, behind):
    failures = []
    label = "{} (recent-work lane={})".format(path, options["lane"])
    lines = body.split("\n")
    if lines[:3] != ["", HEADER, ""] or lines[-1] != "":
        return ["{}: the section header was edited".format(label)]
    entries = [line for line in lines[3:-1]]
    if entries == ["_No notes for this lane yet._"]:
        entries = []
    tasks = []
    for entry in entries:
        match = re.match(r"^- \S+ · \*\*(PRO-[0-9]+)\*\* · ", entry)
        state = GIT_STATE.search(entry)
        if not match or not state:
            failures.append("{}: not a generated entry: {!r}".format(label, entry[:80]))
            continue
        task = match.group(1)
        note = notes.get(task)
        if note is None:
            failures.append("{}: {} is listed but {}/{}.md does not exist".format(label, task, NOTES_DIR, task))
            continue
        if not in_lane(note, options["lane"]):
            failures.append("{}: {} belongs to lane {}".format(label, task, note["lane"]))
        if entry[:state.start()] != render_note(note):
            failures.append("{}: the entry for {} differs from its notes file (a hand edit, or the note changed)".format(
                label, task))
        if task in tasks:
            failures.append("{}: {} is listed twice".format(label, task))
        tasks.append(task)
    if len(entries) > int(options["limit"]):
        failures.append("{}: {} entries, more than limit={}".format(label, len(entries), options["limit"]))
    known = [notes[task] for task in tasks if task in notes]
    if known != sorted(known, key=order_key, reverse=True):
        failures.append("{}: entries are not newest first (date, then task number)".format(label))
    expected = [note["task"] for note in selected(notes, options["lane"], options["limit"])]
    missing = [task for task in expected if task not in tasks]
    if missing:
        behind.append("{}: behind by {} note(s): {}".format(label, len(missing), ", ".join(missing)))
    return failures


# --- command line ------------------------------------------------------------------------------------------

def docs_test_count(root):
    sys.path.insert(0, os.path.join(root, "tools"))
    import check_docs_counts  # noqa: E402  (imports the engine from ROOT, so only when a count is needed)
    return check_docs_counts.actual()["tests"]


def report(lines, summary):
    for line in lines:
        print(line)
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write("### ledgers (tools/build_ledgers.py)\n\n```\n" + "\n".join(lines) + "\n```\n")


def main(arguments, root=ROOT, counts=None):
    counts = counts or (lambda: docs_test_count(root))
    summary = None
    if "--summary" in arguments:
        summary = arguments[arguments.index("--summary") + 1]
    if "--root" in arguments:
        root = os.path.abspath(arguments[arguments.index("--root") + 1])
    modes = [mode for mode in ("--write", "--check", "--diff") if mode in arguments]
    if len(modes) != 1:
        print(__doc__)
        return 2
    try:
        notes = read_notes(root)
        if modes[0] == "--check" and "--strict" not in arguments:
            failures, behind = consistency(root, notes)
            lines = ["ledgers: FAILED: " + failure for failure in failures]
            lines += ["ledgers: behind (refreshed after merge, not a failure here): " + item for item in behind]
            if failures:
                lines.append("ledgers: {} failure(s); a pull request adds migration/notes/PRO-<n>.md and leaves the "
                             "generated sections alone. To rebuild them: {}".format(len(failures), FIX_HINT))
            else:
                lines.append("ledgers: ok ({} notes, {} ledgers{})".format(
                    len(notes), len(LEDGERS), ", {} section(s) behind".format(len(behind)) if behind else ""))
            report(lines, summary)
            return 1 if failures else 0
        require_history(root)
        if modes[0] == "--check":
            failures, _behind = consistency(root, notes)
            if failures:
                report(["ledgers: FAILED: " + failure for failure in failures] + ["ledgers: fix: " + FIX_HINT], summary)
                return 1
        changes = {path: pair for path, pair in build(root, notes, counts).items() if pair[0] != pair[1]}
    except LedgerError as error:
        report(["ledgers: FAILED: {}".format(error)], summary)
        return 1
    if modes[0] == "--write":
        for path, (_old, new) in sorted(changes.items()):
            with open(os.path.join(root, path), "w", encoding="utf-8", newline="") as handle:
                handle.write(new)
        report(["ledgers: wrote {} ({} notes)".format(", ".join(sorted(changes)) or "nothing, already current",
                                                     len(notes))], summary)
        return 0
    if modes[0] == "--diff":
        for path, (old, new) in sorted(changes.items()):
            sys.stdout.writelines(difflib.unified_diff(old.splitlines(True), new.splitlines(True), "a/" + path, "b/" + path))
        return 0
    if changes:
        report(["ledgers: FAILED: {} is not current".format(path) for path in sorted(changes)]
               + ["ledgers: fix: " + FIX_HINT], summary)
        return 1
    report(["ledgers: current ({} notes, {} ledgers)".format(len(notes), len(LEDGERS))], summary)
    return 0


# --- self-test ---------------------------------------------------------------------------------------------

NOTE = "---\ntask: PRO-{n}\nlane: {lane}\ndate: {date}\ntitle: Task {n}\n---\nDid task {n}.\n"


def scratch_repo(directory):
    for path in LEDGERS:
        full = os.path.join(directory, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        if path == "migration/LANE-BRIEF.md":
            body = "# brief\n\n<!-- BEGIN GENERATED: recent-work lane=engine limit=2 --><!-- END GENERATED: recent-work -->\n"
        elif path.endswith("LANE-BRIEF-platform.md"):
            body = "# brief\n\n<!-- BEGIN GENERATED: recent-work lane=platform limit=5 --><!-- END GENERATED: recent-work -->\n"
        elif path.startswith("research/"):
            body = "# brief\n\n<!-- BEGIN GENERATED: recent-work lane=app-research+research-lab limit=5 --><!-- END GENERATED: recent-work -->\n"
        elif path.endswith("LANE-BRIEF-culvert.md"):
            body = "# brief\n\n<!-- BEGIN GENERATED: recent-work lane=culvert limit=5 --><!-- END GENERATED: recent-work -->\n"
        elif path.endswith("STATUS.md"):
            body = "# status\n\n<!-- BEGIN GENERATED: recent-work lane=all limit=10 --><!-- END GENERATED: recent-work -->\ntail\n"
        else:
            body = "We have <!-- BEGIN GENERATED: test-count -->1<!-- END GENERATED: test-count --> tests.\n"
        with open(full, "w", encoding="utf-8") as handle:
            handle.write(body)
    os.makedirs(os.path.join(directory, NOTES_DIR))
    for args in (["init", "-q", "-b", "main"], ["config", "user.email", "t@example.invalid"],
                 ["config", "user.name", "t"], ["config", "commit.gpgsign", "false"], ["add", "-A"],
                 ["commit", "-q", "-m", "base"]):
        git(directory, *args)


def add_note(directory, n, lane, date, message):
    os.makedirs(os.path.join(directory, NOTES_DIR), exist_ok=True)
    with open(os.path.join(directory, NOTES_DIR, "PRO-{}.md".format(n)), "w", encoding="utf-8") as handle:
        handle.write(NOTE.format(n=n, lane=lane, date=date))
    git(directory, "add", "-A")
    git(directory, "commit", "-q", "-m", message)


def run_quiet(arguments, root, count=7):
    import contextlib
    import io
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        code = main(arguments, root=root, counts=lambda: count)
    return code, captured.getvalue()


def swap(text, first, second):
    """`text` with the two lines holding `first` and `second` exchanged."""
    lines = text.split("\n")
    one = next(index for index, line in enumerate(lines) if first in line)
    two = next(index for index, line in enumerate(lines) if second in line)
    lines[one], lines[two] = lines[two], lines[one]
    return "\n".join(lines)


def self_test():
    good = NOTE.format(n=5, lane="engine", date="2026-11-24")
    assert parse_note("PRO-5.md", good)["summary"] == "Did task 5."
    bad = {
        "PRO-6.md": good,                                                 # task does not match the name
        "notes.md": good,
        "PRO-5.md ": good,
    }
    for name, text in bad.items():
        try:
            parse_note(name, text)
        except LedgerError:
            continue
        raise AssertionError("accepted " + name)
    for broken in (good.replace("lane: engine", "lane: kitchen"), good.replace("2026-11-24", "24/11/2026"),
                   good.replace("Did task 5.", "One.\n\nTwo."), good.replace("Did task 5.", ""),
                   good.replace("title: Task 5", "title: <!-- END GENERATED: x -->"), good.replace("---\ntask", "task"),
                   good.replace("title: Task 5\n", "title: Task 5\nowner: me\n"), good.replace("title", "prs: x\ntitle"),
                   good.replace("title", "shas: XYZ\ntitle"), good.replace("lane: engine\n", "lane: engine\nlane: qa\n")):
        try:
            parse_note("PRO-5.md", broken)
        except LedgerError:
            continue
        raise AssertionError("accepted a broken note: " + broken)
    listed = parse_note("PRO-5.md", good.replace("title", "prs: [#12, 13]\nshas: abcdef1\ntitle"))
    assert render_note(listed).endswith("Did task 5. PRs: #12, #13. SHAs: `abcdef1`."), render_note(listed)

    with tempfile.TemporaryDirectory() as directory:
        scratch_repo(directory)
        # Before any refresh the sections are empty placeholders: --check fails on the hand-written stubs.
        code, out = run_quiet(["--check"], directory)
        assert code == 1 and "header was edited" in out and FIX in out, out
        assert run_quiet(["--write"], directory)[0] == 0
        git(directory, "commit", "-q", "-am", "refresh")
        assert run_quiet(["--check", "--strict"], directory) == (0, "ledgers: current (0 notes, 7 ledgers)\n")

        # Two branches from the same base each add a notes file; both merge with no conflict.
        git(directory, "checkout", "-q", "-b", "lane-a")
        add_note(directory, 101, "engine", "2026-11-24", "a: note")
        git(directory, "checkout", "-q", "main")
        git(directory, "checkout", "-q", "-b", "lane-b")
        add_note(directory, 102, "platform", "2026-11-24", "b: note")
        code, out = run_quiet(["--check"], directory)
        assert code == 0 and "behind by 1 note(s): PRO-102" in out, out    # a PR's own note: behind, not a failure
        git(directory, "checkout", "-q", "main")
        git(directory, "merge", "-q", "--no-ff", "-m", "Merge pull request #1 from x/lane-a", "lane-a")
        git(directory, "merge", "-q", "--no-ff", "-m", "Merge pull request #2 from x/lane-b", "lane-b")  # raises on conflict
        code, out = run_quiet(["--check", "--strict"], directory)
        assert code == 1 and "is not current" in out and FIX in out, out
        assert run_quiet(["--write"], directory)[0] == 0
        status = read_ledger(directory, "migration/STATUS.md")
        assert status.index("**PRO-102**") < status.index("**PRO-101**"), status   # same date: higher task first
        assert "Did task 101. (merged in #1)" in status and "(merged in #2)" in status, status
        brief = read_ledger(directory, "migration/LANE-BRIEF.md")
        assert "PRO-101" in brief and "PRO-102" not in brief, brief
        assert "_No notes for this lane yet._" in read_ledger(directory, "research/LANE-BRIEF.md")
        assert "test-count -->7<!--" in read_ledger(directory, "README.md")
        first = {path: read_ledger(directory, path) for path in LEDGERS}
        assert run_quiet(["--write"], directory)[0] == 0                  # deterministic: same input, same bytes
        assert first == {path: read_ledger(directory, path) for path in LEDGERS}
        git(directory, "commit", "-q", "-am", "refresh")
        assert run_quiet(["--check", "--strict"], directory)[0] == 0
        assert run_quiet(["--check", "--strict"], directory, count=8)[0] == 1   # a moved count fails strict ...
        assert run_quiet(["--check"], directory, count=8)[0] == 0               # ... and lags in a pull request

        # The limit keeps the newest entries; an uncommitted note says so.
        add_note(directory, 103, "engine", "2026-11-25", "direct commit")
        add_note(directory, 105, "research-lab", "2026-11-25", "direct commit")
        with open(os.path.join(directory, NOTES_DIR, "PRO-104.md"), "w", encoding="utf-8") as handle:
            handle.write(NOTE.format(n=104, lane="engine", date="2026-11-23"))
        assert run_quiet(["--write"], directory)[0] == 0
        brief = read_ledger(directory, "migration/LANE-BRIEF.md")
        assert "(committed, not merged yet)" in brief and "PRO-101" in brief and "PRO-104" not in brief, brief
        assert "PRO-104** · engine · Task 104: Did task 104. (not committed yet)" in read_ledger(directory, "migration/STATUS.md")
        assert "**PRO-105** · research-lab" in read_ledger(directory, "research/LANE-BRIEF.md")

        # What --check rejects in a pull request.
        path = os.path.join(directory, "migration/STATUS.md")
        clean = read_ledger(directory, "migration/STATUS.md")
        tampered = {
            "a hand edit": clean.replace("Did task 101.", "Did task 101 and more."),
            "an entry without a note": clean.replace("**PRO-101**", "**PRO-999**"),
            "a duplicate": clean.replace("- 2026-11-24 · **PRO-101**", "- 2026-11-24 · **PRO-102** · platform · Task 102: "
                                         "Did task 102. (merged in #2)\n- 2026-11-24 · **PRO-101**"),
            "an out-of-order entry": swap(clean, "**PRO-101**", "**PRO-102**"),
            "a missing END": clean.replace("<!-- END GENERATED: recent-work -->", ""),
            "a removed section": "# status\n",
            "a hand-written row": clean.replace("(not committed yet)", "(not committed yet)\n| PRO-9 | row |"),
        }
        for label, text in tampered.items():
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text)
            code, out = run_quiet(["--check"], directory)
            assert code == 1 and "FAILED" in out and FIX in out, (label, out)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(clean)
        readme = os.path.join(directory, "README.md")
        with open(readme, "w", encoding="utf-8") as handle:
            handle.write("We have <!-- BEGIN GENERATED: test-count -->many<!-- END GENERATED: test-count --> tests.\n")
        assert run_quiet(["--check"], directory)[0] == 1
        with open(readme, "w", encoding="utf-8") as handle:
            handle.write("We have <!-- BEGIN GENERATED: test-count -->7<!-- END GENERATED: test-count --> tests.\n")
        assert run_quiet(["--check"], directory)[0] == 0

        # A shallow clone cannot name the merging pull request: --write and --strict refuse it.
        shallow = os.path.join(directory, "shallow")
        git(directory, "clone", "-q", "--depth", "1", "file://" + directory, shallow)
        code, out = run_quiet(["--write"], shallow)
        assert code == 1 and "git fetch --unshallow" in out, out
        assert run_quiet(["--check"], shallow)[0] == 0
    print("build_ledgers self-test: ok (notes parser, two-branch merge without conflict, ordering, limit, git state, "
          "determinism, strict and lagging checks, seven tampering cases, shallow clone refused)")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        sys.exit(self_test())
    sys.exit(main(sys.argv[1:]))
