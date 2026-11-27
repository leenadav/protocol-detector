"""Unit tests for guard.py (PRO-75). Run: python3 -B .claude/hooks/guard.py --self-test

Secret-shaped strings are assembled at run time, so this file itself holds no literal token for gitleaks or the
guard to flag. Standard library only; Python 3.9 syntax.
"""
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import guard

GHP = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
PAT = "github" + "_pat_" + "11ABCDEFG0123456789_abcdefghijklmnop"
ANT = "sk-" + "ant-" + "api03-AbCdEf0123456789XyZ"
AWS = "AK" + "IA" + "IOSFODNN7EXAMPLE"
PEM = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----"
OPENSSH = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
ASSIGNED = "DEPLOY" + "_TOKEN = \"" + "q8Zr4LmX2vT9wKp7Yb3NcH6s" + "\""
ASSIGNED_YAML = "api" + "_key: '" + "Zx9Qw3Er7Ty1Ui5Op2As8Df4" + "'"
ASSIGNED_HEX = "SIGNING" + "_KEY=" + "0123456789abcdef" * 2
GHS = "gh" + "s_" + "Q" * 18 + "1" * 18


def run(payload):
    """(exit code, stderr) of the guard for one payload."""
    stderr = io.StringIO()
    code = guard.main(io.StringIO(json.dumps(payload)), stderr)
    return code, stderr.getvalue()


class Repo:
    """A throwaway repository: `main`, a shared `claude/shared` that exists on origin, and the session's branches."""

    def __init__(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = self.temp.name
        env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
        for args in (["init", "-q", "-b", "main"], ["-c", "user.name=t", "-c", "user.email=t@example.invalid",
                                                    "commit", "-q", "--allow-empty", "-m", "base"],
                     ["branch", "claude/shared"], ["update-ref", "refs/remotes/origin/claude/shared", "HEAD"],
                     ["update-ref", "refs/remotes/origin/main", "HEAD"]):
            subprocess.run(["git"] + args, cwd=self.path, check=True, env=env, stdout=subprocess.DEVNULL)

    def checkout(self, branch, create=False):
        args = ["checkout", "-q"] + (["-b"] if create else []) + [branch]
        subprocess.run(["git"] + args, cwd=self.path, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def bash(self, command, session="s1"):
        return run({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": self.path, "session_id": session})

    def close(self):
        self.temp.cleanup()


class RepoTest(unittest.TestCase):
    def setUp(self):
        self.repo = Repo()
        self.repo.checkout("claude/shared")

    def tearDown(self):
        self.repo.close()

    def blocked(self, command, session="s1"):
        code, message = self.repo.bash(command, session)
        self.assertEqual(code, 2, "not blocked: " + command)
        self.assertIn("Approval route", message)
        return message

    def allowed(self, command, session="s1"):
        code, message = self.repo.bash(command, session)
        self.assertEqual(code, 0, "blocked: {}\n{}".format(command, message))


class ForcePushTest(RepoTest):
    def test_force_spellings_block(self):
        for command in ("git push --force", "git push -f origin claude/shared", "git push -uf origin x",
                        "git push --force-with-lease origin claude/shared", "git push --force-with-lease=x:y",
                        "git push origin +claude/shared", "git push origin +HEAD:claude/x",
                        "git -C . push --force", "sudo git push --force", "env A=b git push -f",
                        "cd x && git push --force", "echo hi; git push -f", "bash -c 'git push --force'",
                        "sh -lc \"git push --force\"", "echo $(git push --force)", "eval git push --force",
                        "timeout 30 git push -f", "/usr/bin/git push -f", "true\ngit push --force",
                        "GIT_TRACE=1 git push --force", "bash <<'EOF'\ngit push --force\nEOF",
                        "echo `git push -f`", "(git push -f)"):
            self.blocked(command)

    def test_mirror_all_and_tags_block(self):
        for command in ("git push --mirror", "git push --all origin", "git push --tags", "git push --follow-tags",
                        "git push origin refs/tags/v1", "git push --prune origin"):
            self.blocked(command)

    def test_ordinary_push_allowed(self):
        for command in ("git push -u origin claude/platform-PRO-75-hooks", "git push origin HEAD",
                        "git push", "git push -o ci.skip origin claude/x", "git push --dry-run origin claude/x",
                        "git push --force-if-includes origin claude/x", "git status && git log --oneline -3"):
            self.allowed(command)

    def test_quoted_text_is_not_a_command(self):
        self.allowed("git commit -m 'never run git push --force'")
        self.allowed("echo \"git push -f\"")
        self.allowed("cat > notes.md <<'EOF'\ngit push --force\nEOF")
        self.allowed("grep -n 'push --force' AGENTS.md  # git push --force")


class MainPushTest(RepoTest):
    def test_push_to_main_blocks(self):
        for command in ("git push origin main", "git push origin HEAD:main", "git push origin claude/x:main",
                        "git push origin HEAD:refs/heads/main", "git push origin :main",
                        "git push origin --delete main", "git push -d origin main"):
            self.blocked(command)

    def test_bare_push_on_main_blocks(self):
        self.repo.checkout("main")
        self.blocked("git push")
        self.blocked("git push origin")
        self.blocked("git push origin HEAD")

    def test_mainline_lookalikes_allowed(self):
        self.allowed("git push origin claude/main-fix")
        self.allowed("git fetch origin main && git merge --no-edit FETCH_HEAD")


class HistoryRewriteTest(RepoTest):
    def test_shared_branch_rewrite_blocks(self):
        for command in ("git rebase origin/main", "git rebase -i HEAD~3", "git pull --rebase",
                        "git pull -r origin main", "git reset --hard origin/main", "git reset --hard",
                        "git rebase main claude/shared"):
            message = self.blocked(command)
            self.assertIn("claude/shared", message)

    def test_rebase_control_and_soft_reset_allowed(self):
        for command in ("git rebase --abort", "git rebase --continue", "git reset --soft HEAD~1",
                        "git reset HEAD file", "git pull --rebase=false", "git pull origin main"):
            self.allowed(command)

    def test_branch_created_by_the_session_may_be_rewritten(self):
        self.allowed("git checkout -b claude/platform-PRO-75-hooks origin/main")
        self.repo.checkout("claude/platform-PRO-75-hooks", create=True)
        subprocess.run(["git", "update-ref", "refs/remotes/origin/claude/platform-PRO-75-hooks", "HEAD"],
                       cwd=self.repo.path, check=True)
        self.allowed("git reset --hard origin/main")
        self.allowed("git rebase origin/main")
        self.blocked("git reset --hard origin/main", session="other")

    def test_taking_over_an_existing_branch_does_not_record_it(self):
        self.allowed("git checkout -b claude/shared origin/claude/shared")
        self.blocked("git reset --hard")

    def test_other_creation_spellings_record(self):
        for command, branch in (("git switch -c claude/a", "claude/a"), ("git branch claude/b", "claude/b"),
                                ("git worktree add -b claude/c ../c", "claude/c")):
            self.allowed(command)
            self.assertIn(branch, guard.Context(self.repo.path, "s1").created(self.repo.path))

    def test_unwritable_record_fails_safe(self):
        common = Path(self.repo.path, ".git", "claude-hooks")
        common.write_text("not a directory")
        self.allowed("git checkout -b claude/unrecorded")
        self.assertNotIn("claude/unrecorded", guard.Context(self.repo.path, "s1").created(self.repo.path))
        self.repo.checkout("claude/unrecorded", create=True)
        subprocess.run(["git", "update-ref", "refs/remotes/origin/claude/unrecorded", "HEAD"],
                       cwd=self.repo.path, check=True)
        self.blocked("git reset --hard")

    def test_unshared_branches_are_free(self):
        self.repo.checkout("main")
        self.allowed("git reset --hard origin/main")
        self.repo.checkout("claude/local-only", create=True)
        self.allowed("git rebase main")


class GhTest(RepoTest):
    def test_merge_approve_close_and_settings_block(self):
        for command in ("gh pr merge 12 --merge", "gh pr merge --auto --squash", "gh pr review 12 --approve",
                        "gh pr review -a 12", "gh pr close 12", "gh repo edit --default-branch x",
                        "gh repo delete o/r --yes", "gh repo rename x",
                        "gh secret set X", "gh variable delete Y", "gh release create v1",
                        "gh api -X PATCH repos/o/r -f allow_auto_merge=true",
                        "gh api --method PUT repos/o/r/branches/main/protection --input p.json",
                        "gh api -XDELETE repos/o/r/git/refs/heads/claude/x",
                        "gh api --method=PUT repos/o/r/pulls/12/merge",
                        "gh api repos/o/r/rulesets -f name=x", "gh api /repos/o/r/hooks --input h.json",
                        "gh api repos/o/r/pulls/12/reviews -f event=APPROVE",
                        "gh api graphql -f query='mutation { mergePullRequest(input: {}) { clientMutationId } }'",
                        "gh api graphql -f query='mutation { updateRepository(input: {}) { clientMutationId } }'"):
            self.blocked(command)

    def test_reads_and_pr_work_allowed(self):
        for command in ("gh pr view 12 --json reviews,comments", "gh pr checks 12 --watch",
                        "gh pr create --title t --body b", "gh pr list", "gh repo view",
                        "gh api repos/o/r/pulls/12/comments",
                        "gh api -X GET search/code -f q='hooks repo:o/r' --paginate",
                        "gh api repos/o/r/pulls -f title=t -f head=h -f base=main",
                        "gh api repos/o/r/pulls/12/reviews -f event=COMMENT -f body=x",
                        "gh api graphql -f query='{ viewer { login } }'", "gh release list", "gh ruleset list"):
            self.allowed(command)


class SecretTest(unittest.TestCase):
    def write(self, path, content, tool="Write"):
        root = tempfile.gettempdir()
        tool_input = {"file_path": os.path.join(root, path)}
        if tool == "Write":
            tool_input["content"] = content
        elif tool == "Edit":
            tool_input.update(old_string="x", new_string=content)
        else:
            tool_input["edits"] = [{"old_string": "a", "new_string": "fine"}, {"old_string": "b", "new_string": content}]
        old = os.environ.get("CLAUDE_PROJECT_DIR")
        os.environ["CLAUDE_PROJECT_DIR"] = root
        try:
            return run({"tool_name": tool, "tool_input": tool_input, "cwd": root})
        finally:
            if old is None:
                del os.environ["CLAUDE_PROJECT_DIR"]
            else:
                os.environ["CLAUDE_PROJECT_DIR"] = old

    def test_each_pattern_blocks_in_each_write_tool(self):
        for secret in (GHP, PAT, ANT, AWS, PEM, OPENSSH, ASSIGNED, ASSIGNED_YAML, ASSIGNED_HEX, GHS):
            for tool in ("Write", "Edit", "MultiEdit"):
                code, message = self.write("tools/x.py", "before\n" + secret + "\nafter", tool)
                self.assertEqual(code, 2, "{} {}".format(tool, secret[:12]))
                self.assertIn("Approval route", message)

    def test_go_testdata_is_allowlisted(self):
        for path in ("go/testdata/keys.pem", "go/internal/x509x/testdata/key.pem"):
            self.assertEqual(self.write(path, PEM)[0], 0, path)

    def test_lookalike_paths_are_not_allowlisted(self):
        for path in ("go/testdata.go", "testdata/key.pem", "tools/go/testdata/key.pem", "go/../testdata/key.pem",
                     "go/internal/testdata_test.go"):
            self.assertEqual(self.write(path, PEM)[0], 2, path)

    def test_ordinary_code_allowed(self):
        for text in ("GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}", "API_KEY = os.environ['API_KEY']",
                     "SORT_KEY = 'aaaaaaaaaaaaaaaaaaaaaaaa'", "CACHE_KEY = 'go-build-cache-v1-linux-amd64'",
                     "sha256 = 023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757",
                     "-----BEGIN CERTIFICATE-----", "use ghp_ prefixed tokens", "TOKEN_KEY = short"):
            self.assertEqual(self.write("tools/x.py", text)[0], 0, text)

    def test_secret_in_a_command_blocks(self):
        code, _ = run({"tool_name": "Bash", "tool_input": {"command": "export GH_TOKEN=" + GHP}, "cwd": "/"})
        self.assertEqual(code, 2)
        code, _ = run({"tool_name": "Bash", "tool_input": {"command": "printf '%s' '" + PEM + "' > k"}, "cwd": "/"})
        self.assertEqual(code, 2)

    def test_notebook(self):
        code, _ = run({"tool_name": "NotebookEdit", "tool_input": {"notebook_path": "/tmp/n.ipynb", "new_source": AWS}})
        self.assertEqual(code, 2)


class McpTest(unittest.TestCase):
    def call(self, name, **arguments):
        return run({"tool_name": "mcp__github__" + name, "tool_input": arguments, "cwd": "/"})[0]

    def test_blocks(self):
        self.assertEqual(self.call("merge_pull_request", owner="o", repo="r", pullNumber=1), 2)
        self.assertEqual(self.call("enable_pr_auto_merge", owner="o", repo="r", pullNumber=1), 2)
        self.assertEqual(self.call("pull_request_review_write", method="create", event="APPROVE"), 2)
        self.assertEqual(self.call("update_pull_request", pullNumber=1, state="closed"), 2)
        self.assertEqual(self.call("push_files", branch="main", files=[{"path": "a", "content": "x"}]), 2)
        self.assertEqual(self.call("create_or_update_file", branch="refs/heads/main", path="a", content="x"), 2)
        self.assertEqual(self.call("delete_file", branch="main", path="a"), 2)
        self.assertEqual(self.call("push_files", branch="claude/x", files=[{"path": "a.py", "content": GHP}]), 2)
        self.assertEqual(self.call("create_or_update_file", branch="claude/x", path="a.py", content=ANT), 2)

    def test_allows(self):
        self.assertEqual(self.call("pull_request_review_write", method="create", event="COMMENT"), 0)
        self.assertEqual(self.call("update_pull_request", pullNumber=1, title="t"), 0)
        self.assertEqual(self.call("create_pull_request", head="claude/x", base="main"), 0)
        self.assertEqual(self.call("push_files", branch="claude/x", files=[{"path": "a", "content": "x"}]), 0)
        self.assertEqual(self.call("pull_request_read", method="get"), 0)
        code, _ = run({"tool_name": "mcp__other__merge_pull_request", "tool_input": {}})
        self.assertEqual(code, 0)


class RobustnessTest(unittest.TestCase):
    def test_unparseable_risky_command_fails_closed(self):
        code, message = run({"tool_name": "Bash", "tool_input": {"command": "git push 'origin"}, "cwd": "/"})
        self.assertEqual(code, 2)
        self.assertIn("could not be parsed", message)

    def test_unparseable_harmless_command_passes(self):
        self.assertEqual(run({"tool_name": "Bash", "tool_input": {"command": "echo 'oops"}, "cwd": "/"})[0], 0)

    def test_bad_payloads(self):
        self.assertEqual(guard.main(io.StringIO("not json"), io.StringIO()), 0)
        self.assertEqual(guard.main(io.StringIO("[]"), io.StringIO()), 0)
        self.assertEqual(guard.main(io.StringIO('{"tool_name": "Read", "tool_input": {}}'), io.StringIO()), 0)
        self.assertEqual(guard.main(io.StringIO('{"tool_name": "Bash", "tool_input": 5, "x": "git push"}'),
                                    io.StringIO()), 2)

    def test_nesting_is_bounded(self):
        command = "bash -c \"sh -c 'git push -f'\""
        self.assertEqual(run({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": "/"})[0], 2)
        deep = "echo " + "$(" * 20 + "x" + ")" * 20
        self.assertEqual(run({"tool_name": "Bash", "tool_input": {"command": deep}, "cwd": "/"})[0], 0)
        deep = "echo " + "$(" * 20 + "git push -f" + ")" * 20
        code, message = run({"tool_name": "Bash", "tool_input": {"command": deep}, "cwd": "/"})
        self.assertEqual(code, 2)
        self.assertIn("nesting too deep", message)

    def test_settings_wire_the_guard(self):
        settings = json.loads((Path(__file__).resolve().parents[1] / "settings.json").read_text())
        entries = settings["hooks"]["PreToolUse"]
        self.assertEqual(len(entries), 1)
        matcher = entries[0]["matcher"].split("|")
        for tool in ("Bash", "Write", "Edit", "MultiEdit", "NotebookEdit", "mcp__.*github.*"):
            self.assertIn(tool, matcher)
        self.assertIn(".claude/hooks/guard.py", entries[0]["hooks"][0]["command"])

    def test_cli_exit_code(self):
        script = Path(__file__).resolve().parent / "guard.py"
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "gh pr merge 1"}, "cwd": "/"})
        done = subprocess.run(["python3", "-B", str(script)], input=payload, universal_newlines=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(done.returncode, 2)
        self.assertIn("BLOCKED", done.stderr)


if __name__ == "__main__":
    unittest.main()
