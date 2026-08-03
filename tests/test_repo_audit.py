#!/usr/bin/env python3
"""Tests for hooks/repo_audit.py -- the SessionStart repository-execution audit.

Plain assert script, like every other suite here: runs top to bottom, stops at
the first failure.

Two properties carry most of the weight, and both are about *not* crying wolf:

1. An empty audit must emit nothing at all. A hook that prints a clean bill of
   health on every session start is noise, and noise is what teaches a reader to
   skip the one report that mattered.
2. An ordinary installed hook must not read as an alert, while a `.gitmodules`
   exploit signature must be unmistakably more serious -- in the emitted text,
   in which channel it uses, and in the severity of the record it logs.

The suite drives the hook both ways: in-process for the grading and rendering,
and as a subprocess fed real SessionStart JSON for the end-to-end shape, the
fail-open paths, and everything that depends on the cwd (the allowlist is read
from there, and `allowlist._cache` is process-global, so those cases only mean
something in a fresh process).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

import _isolated_home  # noqa: F401  MUST precede every hook import

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOKS = os.path.join(ROOT, "hooks")
GUARD = os.path.join(HOOKS, "repo_audit.py")
sys.path.insert(0, HOOKS)

# The allowlist and the tiered config are both read from the cwd. Pin it to an
# empty directory before the first import-time read so a `.claude/` in whatever
# directory the suite was launched from cannot reach the in-process cases.
_NEUTRAL_CWD = tempfile.mkdtemp(prefix="forcefield-repo-audit-cwd-")
os.chdir(_NEUTRAL_CWD)

import allowlist  # noqa: E402
import git_forensics as gf  # noqa: E402
import repo_audit as ra  # noqa: E402

_count = 0


def check(condition, label):
    global _count
    _count += 1
    assert condition, "FAILED: %s" % label


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

CR_ATTACK = '[submodule "x"]\n\tpath = sub\r\n\turl = https://e.com/x.git\n'
BENIGN_MODULES = '[submodule "lib"]\n\tpath = vendor/lib\n\turl = https://e.com/lib.git\n'

_repos = []


def make_repo(*, gitmodules=None, hooks=(), samples=(), config=None,
              agent_hooks=False, allowlist_json=None):
    """Build a throwaway repository with exactly the artifacts named."""
    repo = tempfile.mkdtemp(prefix="forcefield-repo-audit-")
    _repos.append(repo)
    hooks_dir = os.path.join(repo, ".git", "hooks")
    os.makedirs(hooks_dir)

    if gitmodules is not None:
        with open(os.path.join(repo, ".gitmodules"), "w") as handle:
            handle.write(gitmodules)
    if config is not None:
        with open(os.path.join(repo, ".git", "config"), "w") as handle:
            handle.write(config)
    for name in list(hooks) + list(samples):
        path = os.path.join(hooks_dir, name)
        with open(path, "w") as handle:
            handle.write("#!/bin/sh\necho hi\n")
        os.chmod(path, 0o755)
    if agent_hooks or allowlist_json is not None:
        os.makedirs(os.path.join(repo, ".claude"), exist_ok=True)
    if agent_hooks:
        with open(os.path.join(repo, ".claude", "settings.json"), "w") as handle:
            handle.write('{"hooks": {"PreToolUse": []}}')
    if allowlist_json is not None:
        with open(os.path.join(repo, ".claude", "hook-allowlist.json"), "w") as handle:
            handle.write(json.dumps(allowlist_json))
    return repo


def run_hook(cwd, event=None, raw=None):
    """Run the hook as a real subprocess. Returns (parsed_stdout, proc)."""
    if raw is None:
        raw = json.dumps({"hook_event_name": "SessionStart", "source": "startup"}
                         if event is None else event)
    proc = subprocess.run(
        [sys.executable, GUARD], input=raw, capture_output=True, text=True, cwd=cwd,
    )
    text = proc.stdout.strip()
    return (json.loads(text) if text else {}, proc)


def session_event(cwd):
    return {"hook_event_name": "SessionStart", "source": "startup", "cwd": cwd}


def context_of(response):
    return response.get("hookSpecificOutput", {}).get("additionalContext", "")


def log_records(guard="repo_audit"):
    """Every *finding* this guard wrote to the (diverted) security log.

    The record class is part of the filter, not decoration. Section 9 groups
    records by `file.path` and asserts a decision on each group; a lifecycle
    record carries `forcefield.decision` too -- as the rung it was written at,
    not as a claim that anything was decided -- so one landing in this list would
    be read as a verdict on a repository.
    """
    path = os.path.join(os.environ["HOME"], ".claude", "hooks", "security.log")
    if not os.path.exists(path):
        return []
    records = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            attributes = record.get("Attributes", {})
            if (attributes.get("forcefield.guard") == guard
                    and attributes.get("forcefield.record_class") == "finding"):
                records.append(record)
    return records


# ---------------------------------------------------------------------------
# 1. A clean repository says nothing at all
# ---------------------------------------------------------------------------

clean = make_repo()
findings, root = ra.audit_session(clean)
check(root == os.path.abspath(clean), "clean repo resolves its root")
check(not ra.has_findings(findings), "clean repo has no findings")
check(ra.build_response(findings, root) == {}, "clean repo builds an empty response")
check(ra.finding_names(findings) == [], "clean repo names nothing")

# A benign .gitmodules and a .sample hook are both invisible: neither is an
# artifact that executes, and reporting them would be the clean-bill-of-health
# noise this hook exists to avoid.
quiet = make_repo(gitmodules=BENIGN_MODULES, samples=("pre-commit.sample", "update.sample"))
findings, _ = ra.audit_session(quiet)
check(not ra.has_findings(findings), "benign .gitmodules and .sample hooks stay silent")

# ---------------------------------------------------------------------------
# 2. An ordinary installed hook is reported, and does not read as an alert
# ---------------------------------------------------------------------------

ordinary = make_repo(hooks=("pre-commit",), samples=("pre-push.sample",))
findings, root = ra.audit_session(ordinary)
check(len(findings["hooks"]) == 1, "the live hook is found")
check(not any("sample" in h for h in findings["hooks"]), ".sample hooks are ignored")
check(findings["indicators"] == [], "an installed hook is not an exploit indicator")

response = ra.build_response(findings, root)
context = context_of(response)
check(context, "an installed hook produces context")
check("pre-commit" in context, "the context names the hook")
check("runs on the next git operation" in context or
      "run on the next git operation" in context,
      "the context says when the hook runs")
check("inventory, not an alert" in context, "the hook finding is worded as an inventory")
check("EXPLOIT" not in context, "no exploit wording for an ordinary hook")
check("nothing above requires action" in context,
      "an inventory-only report signs off as needing no action")
check("systemMessage" not in response,
      "an ordinary hook does not interrupt the human")
check(ra.finding_names(findings) == ["git_hook:pre-commit"], "hook finding name shape")

# ---------------------------------------------------------------------------
# 3. An exploit indicator is unmistakably more serious
# ---------------------------------------------------------------------------

hostile = make_repo(gitmodules=CR_ATTACK, hooks=("pre-commit",))
findings, root = ra.audit_session(hostile)
check("submodule_path_trailing_cr" in findings["indicators"], "the CR signature is found")

response = ra.build_response(findings, root)
context = context_of(response)
check("submodule_path_trailing_cr" in context, "the context names the indicator")
check("CVE-2025-48384" in context, "the context carries the indicator's risk text")
check(gf.INDICATOR_RISKS["submodule_path_trailing_cr"] in context,
      "the risk text is the one git_forensics wrote, not a paraphrase")
check("systemMessage" in response, "an exploit signature reaches the human")
check("submodule_path_trailing_cr" in response["systemMessage"],
      "the human-facing line names the indicator")
check("Nothing has been blocked" in response["systemMessage"],
      "the human-facing line says nothing was blocked")

# Ranked: the exploit signature comes before the hook inventory in the text.
check(context.index("EXPLOIT SIGNATURE") < context.index("pre-commit"),
      "the exploit signature is ranked above the ordinary hook")

# The sign-off must not talk the reader back out of the report above it: a fixed
# "no action is required" is the last line a skimmer keeps.
check("nothing above requires action" not in context,
      "an exploit report does not sign off as needing no action")
check("needs a decision" in context, "an exploit report says a decision is needed")

# Every deny-tier indicator renders with its explanation, not just the CR one.
for indicator in sorted(gf.DENY_INDICATORS):
    rendered = ra.render_context({"indicators": [indicator]}, "/tmp/x")
    check(indicator in rendered and gf.INDICATOR_RISKS[indicator] in rendered,
          "indicator explains itself in the report: %s" % indicator)

# ---------------------------------------------------------------------------
# 4. Config keys and a repo-shipped agent config
# ---------------------------------------------------------------------------

configured = make_repo(
    config="[core]\n\thooksPath = .githooks\n[alias]\n\tpwn = !touch /tmp/x\n\tco = checkout\n",
    agent_hooks=True,
)
findings, root = ra.audit_session(configured)
check("core.hookspath" in findings["config_keys"], "core.hooksPath is reported")
check("alias.pwn" in findings["config_keys"], "a shell alias is reported")
check("alias.co" not in findings["config_keys"], "an ordinary alias is not reported")
check(".claude/settings.json" in findings["agent_config"], "repo-shipped agent hooks reported")

context = context_of(ra.build_response(findings, root))
check("core.hookspath" in context and "alias.pwn" in context, "the context names the keys")
check("git runs as a command" in context, "the context says why the keys matter")
check(".claude/settings.json" in context, "the context names the agent config")
check("CVE-2025-59536" in context, "the agent-config finding cites its surface")
check("systemMessage" not in ra.build_response(findings, root),
      "config keys alone do not interrupt the human")
check(set(ra.finding_names(findings)) ==
      {"git_config:core.hookspath", "git_config:alias.pwn",
       "agent_config:.claude/settings.json"},
      "config/agent finding name shapes")

# A settings.json with no "hooks" key executes nothing and is not reported.
no_hooks = make_repo()
os.makedirs(os.path.join(no_hooks, ".claude"))
with open(os.path.join(no_hooks, ".claude", "settings.json"), "w") as _fh:
    _fh.write('{"permissions": {"allow": []}}')
findings, _ = ra.audit_session(no_hooks)
check(not ra.has_findings(findings), "an agent config without hooks stays silent")

# ---------------------------------------------------------------------------
# 5. Missing, unreadable, and oversized repositories
# ---------------------------------------------------------------------------

findings, root = ra.audit_session("/nonexistent/forcefield/probe")
check(root == "" and not ra.has_findings(findings), "a missing repo yields no root")
check(ra.build_response(findings, root) == {}, "a missing repo builds an empty response")

not_a_repo = tempfile.mkdtemp(prefix="forcefield-not-a-repo-")
_repos.append(not_a_repo)
_, root = ra.audit_session(not_a_repo)
check(root == "" or root != os.path.abspath(not_a_repo),
      "a plain directory is not reported as a repo")

# Unreadable: the .git directory and the .gitmodules exist but cannot be opened.
# Verified rather than assumed -- root bypasses the permission bits entirely, so
# `chmod 000` builds nothing at all when the suite runs as root (a container is
# the ordinary way to hit that). Asserting through it would report a pass for a
# case that was never constructed.
unreadable = make_repo(gitmodules=CR_ATTACK, hooks=("pre-commit",))
os.chmod(os.path.join(unreadable, ".gitmodules"), 0o000)
os.chmod(os.path.join(unreadable, ".git", "hooks"), 0o000)
try:
    try:
        with open(os.path.join(unreadable, ".gitmodules"), "rb"):
            denied = False
    except OSError:
        denied = True

    findings, root = ra.audit_session(unreadable)
    check(root == os.path.abspath(unreadable), "an unreadable repo still resolves")
    if denied:
        check(findings["indicators"] == [] and findings["hooks"] == [],
              "an unreadable repo reports nothing rather than raising")
    else:
        print("  NOTE: this user bypasses permission bits (root?), so the "
              "unreadable-repository case\n        cannot be built here. Skipped.")
finally:
    os.chmod(os.path.join(unreadable, ".gitmodules"), 0o644)
    os.chmod(os.path.join(unreadable, ".git", "hooks"), 0o755)

# The listing is bounded: SessionStart context is charged to every later turn.
many = {"hooks": [".git/hooks/h%02d" % i for i in range(40)]}
rendered = ra.render_context(many, "/tmp/x")
check(".git/hooks/h00" in rendered, "the bounded listing shows the first entries")
check(".git/hooks/h39" not in rendered, "the bounded listing stops")
check("and %d more" % (40 - ra.MAX_LISTED) in rendered, "the listing says how many it dropped")
check(rendered.count(".git/hooks/h") == ra.MAX_LISTED, "exactly MAX_LISTED entries listed")

# ---------------------------------------------------------------------------
# 6. The allowlist lock mirrors git_forensics, and cannot drift
# ---------------------------------------------------------------------------

check(allowlist._NEVER_SUPPRESSIBLE["repo_audit"] == gf.DENY_INDICATORS,
      "the never-suppressible set is exactly git_forensics.DENY_INDICATORS")
check(allowlist.is_pattern_suppressed("repo_audit", "submodule_path_trailing_cr") is False,
      "an exploit indicator is never reported suppressed")

# ---------------------------------------------------------------------------
# 7. End to end, as a subprocess fed real SessionStart JSON
# ---------------------------------------------------------------------------

out, proc = run_hook(clean, session_event(clean))
check(out == {}, "clean repo emits nothing end to end")
check(proc.returncode == 0 and proc.stderr == "", "clean repo exits silently")

out, proc = run_hook(ordinary, session_event(ordinary))
check(context_of(out), "an installed hook produces context end to end")
check("systemMessage" not in out, "an installed hook is quiet for the human end to end")
check(proc.returncode == 0 and proc.stderr == "", "the inventory run is clean")

out, proc = run_hook(hostile, session_event(hostile))
check("submodule_path_trailing_cr" in context_of(out), "the exploit signature reaches context")
check("systemMessage" in out, "the exploit signature reaches the human end to end")
check(proc.returncode == 0 and proc.stderr == "", "the exploit run is clean")

# The cwd field is authoritative; without one the hook falls back to os.getcwd().
out, _ = run_hook(hostile, {"hook_event_name": "SessionStart", "source": "startup"})
check("submodule_path_trailing_cr" in context_of(out), "falls back to the process cwd")

# A subdirectory of the repo resolves to the repo root.
_sub = os.path.join(hostile, "src", "deep")
os.makedirs(_sub)
out, _ = run_hook(_sub, session_event(_sub))
check("submodule_path_trailing_cr" in context_of(out), "cwd below the root still audits it")

# Fail-open: nothing on stdin, malformed stdin, a non-object payload, a cwd that
# does not exist, and a directory outside any repository.
for label, raw in (
    ("empty stdin", ""),
    ("malformed stdin", "{ not valid json"),
    ("non-object payload", '["SessionStart"]'),
    ("non-string cwd", '{"hook_event_name":"SessionStart","cwd":42}'),
    ("missing cwd path", '{"hook_event_name":"SessionStart","cwd":"/nonexistent/pc/probe"}'),
):
    out, proc = run_hook(not_a_repo, raw=raw)
    check(out == {}, "fail-open response: %s" % label)
    check(proc.returncode == 0, "fail-open exit code: %s" % label)
    check(proc.stderr == "", "fail-open emits no traceback: %s" % label)

out, proc = run_hook(not_a_repo, session_event(not_a_repo))
check(out == {} and proc.stderr == "", "outside a repository the hook says nothing")

# ---------------------------------------------------------------------------
# 8. Allowlist suppression (subprocess only: the cache is process-global)
# ---------------------------------------------------------------------------

suppressed_pattern = make_repo(
    hooks=("pre-commit",),
    allowlist_json={"repo_audit": {"suppress_patterns": ["git_hook:pre-commit"]}},
)
out, _ = run_hook(suppressed_pattern, session_event(suppressed_pattern))
check(out == {}, "a project can suppress a hook finding it has accepted")

suppressed_path = make_repo(
    hooks=("pre-commit", "pre-push"),
    allowlist_json={"repo_audit": {"suppress_paths": [".git/hooks/*"]}},
)
out, _ = run_hook(suppressed_path, session_event(suppressed_path))
check(out == {}, "suppress_paths globs work for hooks")

suppressed_config = make_repo(
    config="[core]\n\thooksPath = .githooks\n",
    agent_hooks=True,
    allowlist_json={"repo_audit": {"suppress_patterns": [
        "git_config:core.hookspath", "agent_config:.claude/settings.json"]}},
)
out, _ = run_hook(suppressed_config, session_event(suppressed_config))
check(out == {}, "config keys and agent config are suppressible")

# But the repository cannot suppress the report of its own exploit signature:
# the allowlist is read from the repo, so that would be shipping a blindfold.
self_blinding = make_repo(
    gitmodules=CR_ATTACK,
    hooks=("pre-commit",),
    allowlist_json={"repo_audit": {
        "suppress_patterns": ["submodule_path_trailing_cr", "git_hook:pre-commit"],
        "suppress_paths": ["*"],
    }},
)
out, _ = run_hook(self_blinding, session_event(self_blinding))
check("submodule_path_trailing_cr" in context_of(out),
      "an exploit signature survives a repo-shipped allowlist")
check("systemMessage" in out, "and still reaches the human")
check("pre-commit" not in context_of(out),
      "while the ordinary hook it also listed is still suppressed")

# A malformed allowlist suppresses nothing rather than crashing the hook.
broken_allowlist = make_repo(hooks=("pre-commit",))
os.makedirs(os.path.join(broken_allowlist, ".claude"))
with open(os.path.join(broken_allowlist, ".claude", "hook-allowlist.json"), "w") as _fh:
    _fh.write("{ not json at all")
out, proc = run_hook(broken_allowlist, session_event(broken_allowlist))
check("pre-commit" in context_of(out), "a malformed allowlist suppresses nothing")
check(proc.stderr == "", "a malformed allowlist does not crash the hook")

# ---------------------------------------------------------------------------
# 9. The log carries the same ranking the report does
# ---------------------------------------------------------------------------

records = log_records()
check(records, "the hook writes security records")
by_root = {}
for record in records:
    by_root.setdefault(record["Attributes"].get("file.path"), []).append(record)

hostile_records = by_root.get(os.path.abspath(hostile), [])
check(hostile_records, "the exploit repo is logged")
check(any(r["SeverityText"] == "WARN" and
          r["Attributes"]["forcefield.decision"] == "warn"
          for r in hostile_records),
      "an exploit signature logs at warn")
check(any("submodule_path_trailing_cr" in (r["Attributes"].get("forcefield.pattern") or "")
          for r in hostile_records),
      "the log record names the indicator")

ordinary_records = by_root.get(os.path.abspath(ordinary), [])
check(ordinary_records, "the ordinary repo is logged")
check(all(r["Attributes"]["forcefield.decision"] == "warn_low" for r in ordinary_records),
      "an ordinary hook logs at warn_low, below a real warning")
check(all(r["SeverityText"] == "INFO" for r in ordinary_records),
      "and at INFO severity, so a log reader can separate the two")

clean_records = by_root.get(os.path.abspath(clean), [])
check(clean_records, "a clean repo still leaves an audit-trail record")
check(all(r["Attributes"]["forcefield.decision"] == "allow" for r in clean_records),
      "a clean repo logs allow")

check(all(r["Attributes"]["forcefield.guard"] == "repo_audit" for r in records),
      "every record is attributed to repo_audit")

print("test_repo_audit.py: %d assertions passed" % _count)
