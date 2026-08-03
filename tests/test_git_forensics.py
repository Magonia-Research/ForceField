#!/usr/bin/env python3
"""Tests for hooks/git_forensics.py — the git guard's evidence layer.

Plain assert script, like every other suite here: runs top to bottom, stops at
the first failure.

The load-bearing cases are the ones that keep a *hard deny* zero-false-positive.
`.gitmodules` written on Windows has a carriage return on every line and is
entirely benign; the CVE-2025-48384 signature is a CR that singles out a path
line. Confusing the two would hard-deny ordinary repositories, so both
directions are asserted below.
"""

from __future__ import annotations

import os
import socket
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolated_home  # noqa: E402,F401 - diverts $HOME and mutes the native sinks

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "hooks"))

import git_forensics as gf  # noqa: E402

_count = 0


def check(condition, label):
    global _count
    _count += 1
    assert condition, "FAILED: %s" % label


# ---------------------------------------------------------------------------
# 1. Host preconditions — maintenance-branch version comparison
# ---------------------------------------------------------------------------

check(gf._is_patched((2, 45, 1), gf._CVE_2024_32002_FIXED), "2.45.1 patched for 32002")
check(not gf._is_patched((2, 45, 0), gf._CVE_2024_32002_FIXED), "2.45.0 unpatched for 32002")
check(gf._is_patched((2, 39, 4), gf._CVE_2024_32002_FIXED), "2.39.4 patched on its own branch")
check(not gf._is_patched((2, 39, 3), gf._CVE_2024_32002_FIXED), "2.39.3 unpatched on its own branch")
check(not gf._is_patched((2, 38, 0), gf._CVE_2024_32002_FIXED), "pre-branch 2.38 unpatched")
check(gf._is_patched((2, 51, 0), gf._CVE_2024_32002_FIXED), "newer-than-any-branch is patched")

# The two advisories disagree on the 2.45 branch: 2.45.1 fixes 32002, 2.45.4 fixes 48384.
# A single ">= newest" comparison would wrongly call 2.45.2 patched for both.
check(gf._is_patched((2, 45, 2), gf._CVE_2024_32002_FIXED), "2.45.2 patched for 32002")
check(not gf._is_patched((2, 45, 2), gf._CVE_2025_48384_FIXED), "2.45.2 NOT patched for 48384")
check(gf._is_patched((2, 50, 1), gf._CVE_2025_48384_FIXED), "2.50.1 patched for 48384")
check(not gf._is_patched((2, 50, 0), gf._CVE_2025_48384_FIXED), "2.50.0 unpatched for 48384")

version = gf.git_version()
check(version is None or (isinstance(version, tuple) and len(version) == 3), "git_version shape")

exposure = gf.clone_cve_exposure()
check(exposure["exposed"] in (True, False, None), "exposure tri-state")
check(isinstance(exposure["reason"], str) and exposure["reason"], "exposure carries a reason")

check(gf.fs_case_insensitive() in (True, False, None), "case probe tri-state")

# ---------------------------------------------------------------------------
# 2. .gitmodules indicators
# ---------------------------------------------------------------------------

BENIGN = '[submodule "lib"]\n\tpath = vendor/lib\n\turl = https://github.com/org/lib.git\n'
check(gf.scan_gitmodules(BENIGN) == [], "benign .gitmodules is clean")
check(gf.scan_gitmodules("") == [], "empty .gitmodules is clean")
check(gf.scan_gitmodules("not ini content at all") == [], "garbage is clean")

# Windows line endings on EVERY line: benign, must not fire.
CRLF_BENIGN = '[submodule "lib"]\r\n\tpath = vendor/lib\r\n\turl = https://github.com/org/lib.git\r\n'
check("submodule_path_trailing_cr" not in gf.scan_gitmodules(CRLF_BENIGN),
      "uniform CRLF file does not trip the CR indicator")
check(gf.scan_gitmodules(CRLF_BENIGN) == [], "uniform CRLF file is clean overall")

# A CR that singles out the path line: the CVE-2025-48384 signature.
CR_ATTACK = '[submodule "x"]\n\tpath = sub\r\n\turl = https://e.com/x.git\n'
check("submodule_path_trailing_cr" in gf.scan_gitmodules(CR_ATTACK), "isolated CR on path is caught")

# Mixed file where only the path line carries a CR is still the attack.
CR_MIXED = '[submodule "x"]\n\tpath = sub\r\n\turl = https://e.com/x.git\n[submodule "y"]\n\tpath = t\n'
check("submodule_path_trailing_cr" in gf.scan_gitmodules(CR_MIXED), "mixed endings, CR on path is caught")

for variant, label in (
    (".git", "literal"), (".GIT", "uppercase"), (".Git", "mixed case"),
    (".git​", "zero-width suffix"), (".git.", "trailing dot"),
):
    text = '[submodule "a"]\n\tpath = %s/modules/x\n\turl = https://e.com/a.git\n' % variant
    check("submodule_path_dotgit_collision" in gf.scan_gitmodules(text),
          "dotgit collision: %s" % label)

check("submodule_path_dotgit_collision" not in gf.scan_gitmodules(
    '[submodule "a"]\n\tpath = gitmodules/x\n\turl = https://e.com/a.git\n'),
    "a path merely containing 'git' is not a collision")

check("submodule_path_traversal" in gf.scan_gitmodules(
    '[submodule "t"]\n\tpath = ../../outside\n\turl = https://e.com/t.git\n'), "traversal caught")

check("submodule_url_ext_transport" in gf.scan_gitmodules(
    '[submodule "e"]\n\tpath = ok\n\turl = ext::sh -c payload\n'), "ext:: url caught")
check("submodule_url_ext_transport" in gf.scan_gitmodules(
    '[submodule "e"]\n\tpath = ok\n\turl =   EXT::sh -c payload\n'), "ext:: is case-insensitive")
check("submodule_url_ext_transport" not in gf.scan_gitmodules(
    '[submodule "e"]\n\tpath = ok\n\turl = https://e.com/ext.git\n'), "'ext' in a path is not ext::")

# The two sets must agree in BOTH directions, and this is the assertion that
# makes `git_guard._deny_signatures` a contract rather than a formality. Callers
# hard-block on what this scanner emits; today every indicator it can produce is
# on the deny list, so the filter looks like a no-op. Pin it, because the first
# advisory-only indicator added to `scan_gitmodules` would otherwise inherit a
# hard block in silence — and a deny is the one decision with no prompt to catch
# it.
EVERY_ATTACK = "".join((
    CR_ATTACK,
    '[submodule "a"]\n\tpath = .git/modules/x\n\turl = https://e.com/a.git\n',
    '[submodule "t"]\n\tpath = ../../outside\n\turl = https://e.com/t.git\n',
    '[submodule "e"]\n\tpath = ok\n\turl = ext::sh -c payload\n',
))
emitted = set(gf.scan_gitmodules(EVERY_ATTACK))
check(emitted <= gf.DENY_INDICATORS, "scan_gitmodules emits nothing outside the deny tier")
check(emitted == set(gf.DENY_INDICATORS), "every deny indicator is actually reachable")
for indicator in gf.DENY_INDICATORS:
    check(indicator in gf.INDICATOR_RISKS, "every deny indicator explains itself: %s" % indicator)

# ---------------------------------------------------------------------------
# 3. Repository audit
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as repo:
    os.makedirs(os.path.join(repo, ".git", "hooks"))
    os.makedirs(os.path.join(repo, ".claude"))

    with open(os.path.join(repo, ".gitmodules"), "w") as fh:
        fh.write(CR_ATTACK)
    with open(os.path.join(repo, ".git", "config"), "w") as fh:
        fh.write("[core]\n\thooksPath = .githooks\n\trepositoryformatversion = 0\n"
                 "[alias]\n\tpwn = !touch /tmp/x\n\tco = checkout\n")
    sample = os.path.join(repo, ".git", "hooks", "pre-commit.sample")
    with open(sample, "w") as fh:
        fh.write("#!/bin/sh\n")
    os.chmod(sample, 0o755)
    live = os.path.join(repo, ".git", "hooks", "post-checkout")
    with open(live, "w") as fh:
        fh.write("#!/bin/sh\necho hi\n")
    os.chmod(live, 0o755)
    with open(os.path.join(repo, ".claude", "settings.json"), "w") as fh:
        fh.write('{"hooks": {"PreToolUse": []}}')

    audit = gf.audit_repo(repo)
    check("submodule_path_trailing_cr" in audit["indicators"], "audit surfaces .gitmodules indicators")
    check(any("post-checkout" in h for h in audit["hooks"]), "audit finds the live hook")
    check(not any("sample" in h for h in audit["hooks"]), "audit ignores .sample hooks")
    check("core.hookspath" in audit["config_keys"], "audit finds core.hooksPath")
    check("alias.pwn" in audit["config_keys"], "audit finds a shell alias")
    check("alias.co" not in audit["config_keys"], "audit ignores an ordinary alias")
    check(".claude/settings.json" in audit["agent_config"], "audit finds repo-shipped agent hooks")
    check(gf.find_repo_root(repo) == os.path.abspath(repo), "repo root resolves")

with tempfile.TemporaryDirectory() as clean:
    os.makedirs(os.path.join(clean, ".git", "hooks"))
    audit = gf.audit_repo(clean)
    check(audit["indicators"] == [] and audit["hooks"] == [], "clean repo audits clean")
    check(audit["config_keys"] == [] and audit["agent_config"] == [], "clean repo has no config findings")

check(gf.audit_repo("/nonexistent/forcefield/probe")["indicators"] == [], "missing repo does not raise")
check(gf.find_repo_root("/nonexistent/forcefield/probe") is None, "missing root returns None")

# ---------------------------------------------------------------------------
# 4. Remote parsing and the fetch allowlist
# ---------------------------------------------------------------------------

check(gf.parse_remote("https://github.com/o/r.git") == ("github.com", "o", "r"), "https remote")
check(gf.parse_remote("https://github.com/o/r") == ("github.com", "o", "r"), "https without .git")
check(gf.parse_remote("git@github.com:o/r.git") == ("github.com", "o", "r"), "scp-like remote")
check(gf.parse_remote("ssh://git@gitlab.com/o/r.git") == ("gitlab.com", "o", "r"), "ssh remote")
check(gf.parse_remote("https://GitHub.com/o/r.git")[0] == "github.com", "host is lowercased")
check(gf.parse_remote("") is None and gf.parse_remote("not a url") is None, "junk is rejected")
check(gf.parse_remote("https://github.com/onlyowner") is None, "single-segment path rejected")

# The trusted-domain bypass: a suffix or substring check would accept this.
sneaky = gf.fetch_remote_gitmodules("https://evil.example.com/.github.com/o/r.git")
check(sneaky["status"] == "unsupported", "lookalike host is not on the allowlist")
check(gf.fetch_remote_gitmodules("https://git.internal.corp/o/r.git")["status"] == "unsupported",
      "unknown host yields no verdict rather than a guess")
check(gf.fetch_remote_gitmodules("garbage")["status"] == "unsupported", "unparseable yields no verdict")

# Two different defenses stop a query string reaching the constructed target.
# In a URL form, urlsplit routes it to .query and only .path is ever read, so
# the repo name comes out clean. In the scp-like form there is no query to
# split, so the character check is what rejects it. Assert both, because a
# change to either parser would otherwise silently drop one of them.
check(gf.parse_remote("https://github.com/o/r?x=1") == ("github.com", "o", "r"),
      "url form: query is discarded, never reaches the target")
check(gf.fetch_remote_gitmodules("git@github.com:o/r?x=1.git")["status"] == "unsupported",
      "scp-like form: query characters in the repo path are rejected")
check(gf.fetch_remote_gitmodules("git@github.com:o/r\\evil.git")["status"] == "unsupported",
      "scp-like form: backslash in the repo path is rejected")

check("github.com" in gf._RAW_ENDPOINTS, "github is allowlisted")
check(all(t.startswith("https://") for t in gf._RAW_ENDPOINTS.values()), "every endpoint is https")
check(gf.FETCH_TIMEOUT_S <= 2.0, "fetch timeout stays inside the 5s hook budget")


# ---------------------------------------------------------------------------
# 5. The fetch deadline is on the wall clock, not on urlopen
# ---------------------------------------------------------------------------
#
# The assertion directly above this one is the reason this section exists. It
# read `FETCH_TIMEOUT_S <= 2.0` and passed for as long as the constant has
# existed, while the operation it names really took 10.035 s — because
# `urlopen(timeout=)` bounds neither name resolution nor the per-address connect
# loop. A constant is not a bound. Only the clock is.
#
# So: hang the call where it really hangs. `socket.getaddrinfo` takes no timeout
# argument in any Python, which is precisely why it was the hole, and a test
# that patched `urlopen` instead would pass over a fix that only bounded the
# HTTP layer.

_real_getaddrinfo = socket.getaddrinfo


def _never_resolves(*args, **kwargs):
    time.sleep(30)
    return _real_getaddrinfo(*args, **kwargs)


socket.getaddrinfo = _never_resolves
try:
    _started = time.monotonic()
    _hung = gf.fetch_remote_gitmodules("https://github.com/o/r.git")
    _elapsed = time.monotonic() - _started
finally:
    socket.getaddrinfo = _real_getaddrinfo

# The security property, stated as the number that matters: Claude Code kills a
# hook at 5 s, a killed hook returns no verdict, and git_guard's verdict on this
# path can be a hard deny. Slow must never become allow.
check(_elapsed < 5.0,
      "a hung resolver cannot run the hook past its 5 s timeout (took %.3f s)" % _elapsed)
check(_elapsed < gf.FETCH_TIMEOUT_S + 1.0,
      "the deadline is FETCH_TIMEOUT_S, not merely 'under 5 s' (took %.3f s)" % _elapsed)
check(_hung["status"] == "error",
      "giving up yields no verdict, so the caller still prompts")
check("exceed" in _hung.get("reason", ""),
      "the reason names the deadline rather than a network error: %r" % _hung.get("reason"))

# A deadline that fires unconditionally would satisfy every check above while
# disabling the whole remote-inspection feature. Nothing here reaches the
# network: an unparseable remote is refused before any thread starts.
check(gf.fetch_remote_gitmodules("garbage")["status"] == "unsupported",
      "the deadline did not swallow the paths that never fetch at all")

print("test_git_forensics.py: %d assertions passed" % _count)
