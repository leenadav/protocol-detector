"""PreToolUse guard for Claude Code sessions in this repository (PRO-75).

Claude Code runs this before every Bash, file-writing and GitHub MCP tool call (`.claude/settings.json`). It reads
the hook payload (JSON) on stdin and exits 0 to allow the call, or 2 to block it; on a block the reason and the
approval route go to stderr, which Claude Code shows to the agent. It enforces rules that otherwise exist only as
instructions (CLAUDE.md, AGENTS.md, the Paperclip lane rules):

  (a) no `git push --force` / `--force-with-lease` / `+refspec`, no push to `main` (named, `HEAD` or the current
      branch), no `--mirror` / `--all` / tag pushes, and no `git rebase`, `git pull --rebase` or `git reset --hard`
      of a shared `claude/*` branch (one on `origin` that this session did not create);
  (b) no `gh pr merge`, `gh pr review --approve`, `gh pr close`, repository-settings, secret, variable or release
      changes (`gh repo edit|delete|rename|archive`, `gh api` writes to `repos/...` settings, merges and approvals,
      their GraphQL mutations), and the GitHub MCP equivalents (merge, auto-merge, approve, close, writes to main);
  (c) no likely secret written into the tree or a command: private-key headers, `ghp_`-style GitHub tokens,
      `github_pat_`, `sk-ant-`, `AKIA`/`ASIA` access keys, and high-entropy literals assigned to `*_TOKEN` /
      `*_KEY` / `*_SECRET` names. Files under `go/**/testdata/` are allowed (synthetic test fixtures).

Branches the session creates (`git checkout -b`, `git switch -c`, `git branch <name>`, `git worktree add -b`) and
that do not yet exist on `origin` are recorded per session id under the git common directory
(`claude-hooks/branches-<session>.json`), so a session may still rebase or reset its own branches.

This is a guardrail, not a sandbox: a determined bypass (a git alias, a script file, an interpreter) is out of its
reach, and the instructions still apply. Parse failures and internal errors fail closed when the call looks risky.

    guard.py              read one hook payload on stdin (what Claude Code runs)
    guard.py --self-test  run the unit tests in test_guard.py
Standard library only; Python 3.9 syntax.
"""
import json
import math
import os
import re
import subprocess
import sys
from pathlib import Path

ROUTE = ("Approval route: only Lee's explicit approval, relayed by Hermes on the Paperclip task, authorizes this. "
         "Ask with `ASK Hermes: ...` (or a CODEX_ACTION_REQUEST on the lane mailbox); Lee merges and changes settings "
         "himself. Do not work around this hook.")
LEAK_ROUTE = ("Approval route: never put credentials in the repository or a command. Use the environment's "
                "credential store; a synthetic fixture belongs under go/**/testdata/. A false positive goes to the "
                "Platform & CI lane as a change to .claude/hooks/guard.py with a test.")

PROTECTED_BRANCHES = {"main"}
SHARED_PREFIX = "claude/"


class Blocked(Exception):
    """A policy violation; the message is the reason shown to the agent."""

    def __init__(self, reason, route=ROUTE):
        Exception.__init__(self, reason)
        self.reason = reason
        self.route = route


# ---------------------------------------------------------------------------------------------------------------
# (c) secrets

PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")
TOKEN_PATTERNS = (
    ("a GitHub token (gh?_)", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("a GitHub fine-grained token (github_pat_)", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}")),
    ("an Anthropic API key (sk-ant-)", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("an AWS access key id (AKIA/ASIA)", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
)
ASSIGNMENT = re.compile(
    r"""(?i)\b([A-Za-z0-9_]*_(?:TOKEN|KEY|SECRET))\b["']?\s*(?::=|=|:)\s*[bru]?(["']?)([A-Za-z0-9+/=_\-.]{20,})\2""")
MIN_ENTROPY = 3.5


def entropy(value):
    """Shannon entropy of a string, in bits per character."""
    counts = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def find_secret(text):
    """The kind of the first likely secret in text, or None."""
    if PRIVATE_KEY.search(text):
        return "a private-key header"
    for kind, pattern in TOKEN_PATTERNS:
        if pattern.search(text):
            return kind
    for match in ASSIGNMENT.finditer(text):
        value = match.group(3)
        mixed = all(re.search(chars, value) for chars in ("[0-9]", "[a-z]", "[A-Z]"))
        hexadecimal = re.fullmatch(r"[0-9a-fA-F]{32,}", value) and re.search(r"[0-9]", value)
        if entropy(value) >= MIN_ENTROPY and (mixed or hexadecimal):
            return "a high-entropy literal assigned to {}".format(match.group(1))
    return None


def allowlisted(path, root):
    """True for synthetic fixtures: files under a testdata directory of the Go module (go/**/testdata/)."""
    if not path:
        return False
    try:
        relative = Path(os.path.normpath(os.path.join(root, path))).relative_to(Path(os.path.normpath(root)))
    except ValueError:
        return False
    parts = relative.parts
    return len(parts) > 2 and parts[0] == "go" and "testdata" in parts[1:-1]


def check_secret(text, path, root, where):
    if not text or allowlisted(path, root):
        return
    kind = find_secret(text)
    if kind:
        raise Blocked("{} looks like it contains {}.".format(where, kind), LEAK_ROUTE)


# ---------------------------------------------------------------------------------------------------------------
# shell parsing

OPERATORS = ("&&", "||", ";;", "|&", ">>", "<<<", "<<", ">&", "<&", "&>", ";", "&", "|", "(", ")", "<", ">", "\n")
SEPARATORS = {"&&", "||", ";;", "|&", ";", "&", "|", "(", ")", "\n"}
REDIRECTS = {">>", "<<<", "<<", ">&", "<&", "&>", "<", ">"}
HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
WRAPPERS = {"sudo", "command", "builtin", "exec", "nohup", "time", "nice", "stdbuf", "doas"}
RISKY = re.compile(r"\b(?:push|rebase|reset|merge|review|api|repo|secret|variable|release|close)\b")


class ParseError(Exception):
    pass


def strip_heredocs(text):
    """The script without heredoc bodies, and the bodies fed to a shell (to be checked as commands)."""
    lines, kept, scripts = text.split("\n"), [], []
    index = 0
    while index < len(lines):
        line = lines[index]
        kept.append(line)
        index += 1
        for match in HEREDOC.finditer(line):
            delimiter, body = match.group(2), []
            while index < len(lines) and lines[index].strip() != delimiter:
                body.append(lines[index])
                index += 1
            index += 1
            if any(os.path.basename(word) in SHELLS for word in line[:match.start()].split()):
                scripts.append("\n".join(body))
    return "\n".join(kept), scripts


def matching(text, start, opener, closer):
    """Index of the closer that balances text[start] (an opener), skipping quoted text."""
    depth, index = 0, start
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == "'":
            end = text.find("'", index + 1)
            if end < 0:
                raise ParseError("unbalanced single quote")
            index = end + 1
            continue
        if char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return index
        index += 1
    raise ParseError("unbalanced " + opener)


def tokenize(text):
    """Words and operators of a shell script, plus the scripts of its command substitutions."""
    tokens, subs, word, in_word, index = [], [], [], False, 0

    def flush():
        if in_word:
            tokens.append("".join(word))
        del word[:]

    while index < len(text):
        char = text[index]
        if char == "\\":
            if text[index + 1:index + 2] == "\n":
                index += 2
                continue
            word.append(text[index + 1:index + 2])
            in_word, index = True, index + 2
            continue
        if char == "'":
            end = text.find("'", index + 1)
            if end < 0:
                raise ParseError("unbalanced single quote")
            word.append(text[index + 1:end])
            in_word, index = True, end + 1
            continue
        if char == '"':
            index += 1
            while True:
                if index >= len(text):
                    raise ParseError("unbalanced double quote")
                char = text[index]
                if char == '"':
                    index += 1
                    break
                if char == "\\" and index + 1 < len(text):
                    word.append(text[index + 1])
                    index += 2
                    continue
                if text.startswith("$(", index):
                    end = matching(text, index + 1, "(", ")")
                    subs.append(text[index + 2:end])
                    word.append(text[index:end + 1])
                    index = end + 1
                    continue
                if char == "`":
                    end = text.find("`", index + 1)
                    if end < 0:
                        raise ParseError("unbalanced backquote")
                    subs.append(text[index + 1:end])
                    index = end + 1
                    continue
                word.append(char)
                index += 1
            in_word = True
            continue
        if text.startswith("$(", index):
            end = matching(text, index + 1, "(", ")")
            subs.append(text[index + 2:end])
            word.append(text[index:end + 1])
            in_word, index = True, end + 1
            continue
        if char == "`":
            end = text.find("`", index + 1)
            if end < 0:
                raise ParseError("unbalanced backquote")
            subs.append(text[index + 1:end])
            in_word, index = True, end + 1
            continue
        if char == "#" and not in_word:
            end = text.find("\n", index)
            index = len(text) if end < 0 else end
            continue
        if char in " \t\r":
            flush()
            in_word, index = False, index + 1
            continue
        operator = next((op for op in OPERATORS if text.startswith(op, index)), None)
        if operator:
            flush()
            in_word = False
            tokens.append(operator)
            index += len(operator)
            continue
        word.append(char)
        in_word, index = True, index + 1
    flush()
    return tokens, subs


def simple_commands(text, depth=0):
    """Every simple command (a list of words) in a shell script, nested scripts included."""
    if depth > 8:
        raise ParseError("nesting too deep")
    text, scripts = strip_heredocs(text)
    tokens, subs = tokenize(text)
    commands, current, skip = [], [], False
    for token in tokens:
        if skip:
            skip = False
            continue
        if token in SEPARATORS:
            if current:
                commands.append(current)
            current = []
        elif token in REDIRECTS:
            skip = True
            if current and re.fullmatch(r"[0-9]+", current[-1]):
                current.pop()
        else:
            current.append(token)
    if current:
        commands.append(current)
    result = []
    for command in commands:
        command = unwrap(command)
        if not command:
            continue
        name = os.path.basename(command[0])
        if name in SHELLS:
            for position, arg in enumerate(command[1:], 1):
                if arg.startswith("-") and "c" in arg[1:] and not arg.startswith("--") and position + 1 < len(command):
                    result.extend(simple_commands(command[position + 1], depth + 1))
                    break
            continue
        if name == "eval":
            result.extend(simple_commands(" ".join(command[1:]), depth + 1))
            continue
        result.append([name] + command[1:])
    for script in subs + scripts:
        result.extend(simple_commands(script, depth + 1))
    return result


def unwrap(command):
    """The command without leading assignments and wrappers such as sudo, env and timeout."""
    command = list(command)
    while command:
        head = command[0]
        name = os.path.basename(head)
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", head):
            command.pop(0)
        elif name in WRAPPERS:
            command.pop(0)
            while command and command[0].startswith("-"):
                option = command.pop(0)
                if name == "sudo" and option in ("-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U") and command:
                    command.pop(0)
        elif name == "env":
            command.pop(0)
            while command and (command[0].startswith("-") or "=" in command[0]):
                option = command.pop(0)
                if option in ("-u", "-C", "-S", "--unset", "--chdir") and command:
                    command.pop(0)
        elif name == "timeout":
            command.pop(0)
            while command and command[0].startswith("-"):
                option = command.pop(0)
                if option in ("-s", "-k", "--signal", "--kill-after") and command:
                    command.pop(0)
            if command:
                command.pop(0)
        else:
            break
    return command


# ---------------------------------------------------------------------------------------------------------------
# git context

def git(cwd, *args):
    try:
        done = subprocess.run(["git"] + list(args), cwd=cwd,  # noqa: S603 - fixed argv, no shell
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True, timeout=5,
                              check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.strip() if done.returncode == 0 else None


class Context:
    """Where a command runs: the working directory, the session id and the git repository it would touch."""

    def __init__(self, cwd, session):
        self.cwd = cwd if cwd and os.path.isdir(cwd) else os.getcwd()
        self.session = re.sub(r"[^A-Za-z0-9_.-]", "_", session or "unknown")

    def current_branch(self, cwd):
        return git(cwd, "symbolic-ref", "--quiet", "--short", "HEAD")

    def on_origin(self, cwd, branch):
        return git(cwd, "rev-parse", "--verify", "--quiet", "refs/remotes/origin/" + branch) is not None

    def state_file(self, cwd):
        common = git(cwd, "rev-parse", "--git-common-dir")
        if not common:
            return None
        return Path(cwd, common, "claude-hooks", "branches-{}.json".format(self.session))

    def created(self, cwd):
        path = self.state_file(cwd)
        try:
            return set(json.loads(path.read_text())) if path else set()
        except (OSError, ValueError, TypeError):
            return set()

    def record(self, cwd, branch):
        path = self.state_file(cwd)
        if not path or self.on_origin(cwd, branch):
            return
        names = self.created(cwd) | {branch}
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(sorted(names)))
        except OSError as error:
            # Fail safe: an unrecorded branch counts as not created here, so its rewrite stays blocked.
            sys.stderr.write("guard.py: could not record branch {} ({}); it stays guarded\n".format(branch, error))


# ---------------------------------------------------------------------------------------------------------------
# (a) git

GIT_VALUE_OPTIONS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env"}
PUSH_VALUE_OPTIONS = {"-o", "--push-option", "--repo", "--receive-pack", "--exec"}


def split_git(args, cwd):
    """(directory, subcommand, arguments) of a git command line."""
    index = 0
    while index < len(args) and args[index].startswith("-"):
        option = args[index]
        if option in GIT_VALUE_OPTIONS and index + 1 < len(args):
            if option == "-C":
                cwd = os.path.join(cwd, args[index + 1])
            index += 2
            continue
        index += 1
    if index >= len(args):
        return cwd, None, []
    return cwd, args[index], args[index + 1:]


def ref_name(ref):
    return ref[len("refs/heads/"):] if ref.startswith("refs/heads/") else ref


def check_push(args, cwd, context):
    positionals, index = [], 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            positionals.extend(args[index + 1:])
            break
        if arg.startswith("--"):
            name = arg.split("=", 1)[0]
            if name in ("--force", "--force-with-lease"):
                raise Blocked("`git push {}` rewrites history on the remote (force-push is forbidden).".format(name))
            if name in ("--mirror", "--all", "--branches", "--prune"):
                raise Blocked("`git push {}` pushes or deletes every branch, main included.".format(name))
            if name in ("--tags", "--follow-tags"):
                raise Blocked("`git push {}` publishes tags (creating tags is forbidden).".format(name))
            if name in PUSH_VALUE_OPTIONS and "=" not in arg:
                index += 1
            index += 1
            continue
        if arg.startswith("-") and len(arg) > 1:
            letters = arg[1:]
            for position, letter in enumerate(letters):
                if letter == "f":
                    raise Blocked("`git push -f` rewrites history on the remote (force-push is forbidden).")
                if letter == "o":
                    if position == len(letters) - 1:
                        index += 1
                    break
            index += 1
            continue
        positionals.append(arg)
        index += 1
    refspecs = positionals[1:]
    current = context.current_branch(cwd)
    if not refspecs:
        if current in PROTECTED_BRANCHES:
            raise Blocked("`git push` from the `{}` branch would push to `{}`.".format(current, current))
        return
    for refspec in refspecs:
        if refspec.startswith("+"):
            raise Blocked("`git push {}`: a `+` refspec force-pushes (force-push is forbidden).".format(refspec))
        source, _, destination = refspec.partition(":")
        if not _:
            destination = source
        if destination == "HEAD" or (not _ and source == "HEAD"):
            destination = current or ""
        if destination.startswith("refs/tags/"):
            raise Blocked("`git push {}` publishes a tag (creating tags is forbidden).".format(refspec))
        if ref_name(destination) in PROTECTED_BRANCHES:
            raise Blocked("`git push {}` pushes to `{}` (changing main is forbidden; open a PR).".format(
                refspec, ref_name(destination)))


def check_history_rewrite(what, branch, cwd, context):
    if not branch or not branch.startswith(SHARED_PREFIX):
        return
    if branch in context.created(cwd) or not context.on_origin(cwd, branch):
        return
    raise Blocked("`{}` rewrites `{}`, a shared branch on origin that this session did not create "
                  "(merge the base branch in instead; never rebase or reset shared history).".format(what, branch))


def positional(args, value_options=()):
    result, index = [], 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            result.extend(args[index + 1:])
            break
        if arg.startswith("-"):
            if arg in value_options:
                index += 1
        else:
            result.append(arg)
        index += 1
    return result


def check_git(args, context):
    cwd, sub, rest = split_git(args, context.cwd)
    if sub == "push":
        check_push(rest, cwd, context)
    elif sub == "rebase":
        if any(arg in ("--abort", "--quit", "--continue", "--skip", "--edit-todo", "--show-current-patch")
               for arg in rest):
            return
        names = positional(rest, ("-s", "--strategy", "-X", "--strategy-option", "--onto", "-x", "--exec"))
        branch = names[1] if len(names) > 1 else context.current_branch(cwd)
        check_history_rewrite("git rebase", branch, cwd, context)
    elif sub == "pull":
        if any(arg in ("-r", "--rebase") or arg.startswith("--rebase=") and arg != "--rebase=false" for arg in rest):
            check_history_rewrite("git pull --rebase", context.current_branch(cwd), cwd, context)
    elif sub == "reset":
        if "--hard" in rest:
            check_history_rewrite("git reset --hard", context.current_branch(cwd), cwd, context)
    elif sub in ("checkout", "switch"):
        flags = ("-b", "-B") if sub == "checkout" else ("-c", "-C", "--create", "--force-create")
        for index, arg in enumerate(rest):
            if arg in flags and index + 1 < len(rest):
                context.record(cwd, rest[index + 1])
    elif sub == "branch":
        if rest and not any(arg.startswith("-") for arg in rest):
            context.record(cwd, rest[0])
    elif sub == "worktree" and rest[:1] == ["add"]:
        for index, arg in enumerate(rest):
            if arg in ("-b", "-B") and index + 1 < len(rest):
                context.record(cwd, rest[index + 1])


# ---------------------------------------------------------------------------------------------------------------
# (b) gh and the GitHub MCP tools

GH_API_VALUE_OPTIONS = {"-X", "--method", "-H", "--header", "-f", "-F", "--field", "--raw-field", "--input", "-q",
                        "--jq", "-t", "--template", "--hostname", "--cache", "-p", "--preview"}
SETTINGS_POST = re.compile(r"^(?:rulesets|hooks|keys|collaborators|merges|transfer|environments|forks"
                           r"|branches/.+/protection.*|actions/(?:secrets|variables|permissions).*|releases.*"
                           r"|git/refs.*|pulls/\d+/merge)$")
GRAPHQL_MUTATIONS = re.compile(r"\b(?:mergePullRequest|enablePullRequestAutoMerge|closePullRequest|updateRepository"
                               r"|(?:create|update|delete)BranchProtectionRule|(?:create|update|delete)RepositoryRuleset"
                               r"|deleteRepository|archiveRepository|transferRepository|createRef|updateRef|deleteRef)\b"
                               r"|\baddPullRequestReview\b[\s\S]*\bAPPROVE\b|\bsubmitPullRequestReview\b[\s\S]*\bAPPROVE\b")


def check_gh_api(args):
    method, endpoint, fields, index = None, None, False, 0
    while index < len(args):
        arg = args[index]
        name, has_value, value = arg.partition("=") if arg.startswith("--") else (arg, False, "")
        if arg.startswith("-X") and len(arg) > 2:
            method = arg[2:]
        elif name in ("-X", "--method"):
            method = value if has_value else (args[index + 1] if index + 1 < len(args) else "")
            index += 0 if has_value else 1
        elif name in GH_API_VALUE_OPTIONS:
            if name in ("-f", "-F", "--field", "--raw-field", "--input"):
                fields = True
            index += 0 if has_value else 1
        elif arg.startswith("-f") or arg.startswith("-F"):
            fields = True
        elif not arg.startswith("-") and endpoint is None:
            endpoint = arg
        index += 1
    method = (method or ("POST" if fields else "GET")).upper()
    endpoint = (endpoint or "").lstrip("/")
    text = " ".join(args)
    if endpoint == "graphql":
        if GRAPHQL_MUTATIONS.search(text):
            raise Blocked("`gh api graphql` with a merge, approval, close, ref or repository-settings mutation.")
        return
    match = re.match(r"^repos/[^/]+/[^/]+(?:/(.*))?$", endpoint.split("?", 1)[0])
    if not match or method in ("GET", "HEAD"):
        return
    suffix = match.group(1) or ""
    if method in ("PATCH", "PUT", "DELETE"):
        if re.match(r"^(?:issues|pulls)/\d+/comments$|^(?:issues|pulls)/comments/\d+(?:/reactions)?$", suffix) \
                and method == "PATCH":
            return
        raise Blocked("`gh api -X {} {}` changes repository settings, refs or merges.".format(method, endpoint))
    if SETTINGS_POST.match(suffix):
        raise Blocked("`gh api -X POST {}` changes repository settings, refs, releases or merges.".format(endpoint))
    if re.match(r"^pulls/\d+/reviews(?:/\d+/events)?$", suffix) and "APPROVE" in text:
        raise Blocked("`gh api` submitting an APPROVE review (agents never approve pull requests).")


def check_gh(args):
    words = [arg for arg in args if not arg.startswith("-")]
    group, action = (words + ["", ""])[:2]
    if group == "pr" and action == "merge":
        raise Blocked("`gh pr merge`: agents never merge; Lee merges by a click on the board.")
    if group == "pr" and action == "close":
        raise Blocked("`gh pr close`: closing pull requests is forbidden.")
    if group == "pr" and action == "review" and any(arg in ("--approve", "-a") for arg in args):
        raise Blocked("`gh pr review --approve`: agents never approve pull requests.")
    if group == "repo" and action in ("edit", "delete", "rename", "archive", "unarchive"):
        raise Blocked("`gh repo {}` changes repository settings.".format(action))
    if group in ("secret", "variable") and action in ("set", "delete", "remove"):
        raise Blocked("`gh {} {}` changes repository settings and credentials.".format(group, action))
    if group == "release" and action in ("create", "edit", "delete", "upload", "delete-asset"):
        raise Blocked("`gh release {}`: creating or changing releases is forbidden.".format(action))
    if group == "ruleset" and action not in ("list", "view", "check", "ls", ""):
        raise Blocked("`gh ruleset {}` changes branch rules.".format(action))
    if group == "api":
        check_gh_api(args[args.index("api") + 1:])


def check_github_mcp(tool, payload, root):
    name = tool.rsplit("__", 1)[-1]
    if name in ("merge_pull_request", "enable_pr_auto_merge"):
        raise Blocked("`{}`: agents never merge; Lee merges by a click on the board.".format(name))
    if name == "pull_request_review_write" and str(payload.get("event", "")).upper() == "APPROVE":
        raise Blocked("`{}` with event APPROVE: agents never approve pull requests.".format(name))
    if name == "update_pull_request" and str(payload.get("state", "")).lower() == "closed":
        raise Blocked("`update_pull_request` with state closed: closing pull requests is forbidden.")
    if name in ("create_or_update_file", "push_files", "delete_file"):
        if ref_name(str(payload.get("branch", ""))) in PROTECTED_BRANCHES:
            raise Blocked("`{}` writes to main (changing main is forbidden; open a PR).".format(name))
        check_secret(payload.get("content"), payload.get("path"), root, "`{}` content".format(name))
        for item in payload.get("files") or []:
            if isinstance(item, dict):
                check_secret(item.get("content"), item.get("path"), root, "`push_files` file {}".format(item.get("path")))


# ---------------------------------------------------------------------------------------------------------------
# dispatch

def check_bash(command, context):
    check_secret(command, None, context.cwd, "The command")
    try:
        commands = simple_commands(command)
    except ParseError as error:
        if RISKY.search(command):
            raise Blocked("the command could not be parsed ({}) and names a guarded operation; "
                          "simplify it so the guard can read it.".format(error))
        return
    for words in commands:
        if words[0] == "git":
            check_git(words[1:], context)
        elif words[0] == "gh":
            check_gh(words[1:])


def evaluate(payload):
    """Raise Blocked when the tool call breaks a rule."""
    tool = payload.get("tool_name") or ""
    arguments = payload.get("tool_input") or {}
    root = os.environ.get("CLAUDE_PROJECT_DIR") or payload.get("cwd") or os.getcwd()
    context = Context(payload.get("cwd"), payload.get("session_id"))
    if tool == "Bash":
        check_bash(str(arguments.get("command", "")), context)
    elif tool == "Write":
        check_secret(arguments.get("content"), arguments.get("file_path"), root, arguments.get("file_path"))
    elif tool == "Edit":
        check_secret(arguments.get("new_string"), arguments.get("file_path"), root, arguments.get("file_path"))
    elif tool == "MultiEdit":
        for edit in arguments.get("edits") or []:
            if isinstance(edit, dict):
                check_secret(edit.get("new_string"), arguments.get("file_path"), root, arguments.get("file_path"))
    elif tool == "NotebookEdit":
        check_secret(arguments.get("new_source"), arguments.get("notebook_path"), root, arguments.get("notebook_path"))
    elif "github" in tool.lower() and tool.startswith("mcp__"):
        check_github_mcp(tool, arguments, root)


def main(stdin=sys.stdin, stderr=sys.stderr):
    raw = stdin.read()
    try:
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("payload is not an object")
        evaluate(payload)
    except Blocked as blocked:
        stderr.write("BLOCKED by .claude/hooks/guard.py (PRO-75): {}\n{}\n".format(blocked.reason, blocked.route))
        return 2
    except Exception as error:  # a guard bug must not open a guarded operation
        if RISKY.search(raw) or find_secret(raw):
            stderr.write("BLOCKED by .claude/hooks/guard.py (PRO-75): internal error ({}: {}) on a call that "
                         "looks guarded; fail closed.\n{}\n".format(type(error).__name__, error, ROUTE))
            return 2
        stderr.write("guard.py: internal error ({}), call allowed\n".format(type(error).__name__))
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        import unittest
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        suite = unittest.defaultTestLoader.loadTestsFromName("test_guard")
        result = unittest.TextTestRunner(verbosity=1).run(suite)
        print("guard self-test: {} tests, {} failures, {} errors".format(
            result.testsRun, len(result.failures), len(result.errors)))
        sys.exit(0 if result.wasSuccessful() and result.testsRun else 1)
    sys.exit(main())
