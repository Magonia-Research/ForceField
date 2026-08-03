#!/usr/bin/env python3
"""Test suite for hooks/container_first.sh -- the only bash guard in the plugin.

It is a registered PreToolUse[Bash] entry point that issues hard denies, and it
was the last guard with no suite of its own. Because it is bash, it is driven the
way tests/test_sigma_engine.py drives sigma_engine.py: as a subprocess, fed
hook-event JSON on stdin. Its four output shapes are

    deny           exit 2, message on stderr, nothing on stdout
    ask            stdout hookSpecificOutput.permissionDecision == "ask"
    warn           stdout {"systemMessage": ...}          (config-downgraded only)
    allow          empty stdout, or permissionDecision "allow" + additionalContext

The guard shells out to jq, so without jq every case would collapse to the same
"cannot inspect" ask and assert nothing. This suite therefore skips clean and
green when jq is absent, exactly as test_sigma_engine.py skips its
match-expecting cases without a compiled ruleset.

EVERY expectation here was measured by running the script, not derived from
reading it. Three groups of cases are behaviour this suite believes is WRONG;
they are asserted at their measured values and ledgered in
KNOWN_DENY_FALSE_POSITIVES / KNOWN_ASK_BYPASSES / KNOWN_TIMEOUT_BLOWOUT, which
carry tests/test_false_positives.py's strict semantics: a ledgered case that
starts passing FAILS this suite, so a fix has to delete its own entry.

Run: python3 tests/test_container_first.py
"""

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import _isolated_home  # noqa: F401  MUST precede every hook import

ROOT = Path(__file__).resolve().parent.parent
GUARD = str(ROOT / "hooks" / "container_first.sh")
SOURCE = (ROOT / "hooks" / "container_first.sh").read_text(encoding="utf-8")

if not shutil.which("jq"):
    print("  NOTE: jq not installed; container_first.sh answers every payload "
          "with the\n        same 'cannot inspect' ask, so there is nothing to "
          "assert. Skipped.")
    sys.exit(0)

BASH = shutil.which("bash") or "/bin/bash"

sys.path.insert(0, str(ROOT / "hooks"))
import shell_context  # noqa: E402

# The guard resolves its config ceiling from $HOME and from $PWD. _isolated_home
# has already diverted $HOME; pinning cwd to an empty directory keeps a
# .claude/forcefield.json in whatever directory the suite was launched from out
# of the default-ceiling cases.
NEUTRAL_CWD = tempfile.mkdtemp(prefix="forcefield-cf-cwd-")

# Assembled from parts, as elsewhere in tests/, so no single line of this file
# is a whole runnable install command.
PIP = "pip" + " install"
APT = "apt-get" + " install"
NPM = "npm" + " install"

_checks = 0


def _run(payload, home=None, cwd=None, timeout=30, path=None):
    """Feed the guard a raw stdin payload and return the CompletedProcess."""
    env = dict(os.environ)
    if home:
        env["HOME"] = home
    if path is not None:
        env["PATH"] = path
    return subprocess.run(
        [BASH, GUARD], input=payload, capture_output=True, text=True,
        env=env, cwd=cwd or NEUTRAL_CWD, timeout=timeout,
    )


def _classify(proc):
    """Collapse a run to one of deny / ask / warn / allow+ctx / allow."""
    if proc.returncode == 2:
        return "deny"
    out = proc.stdout.strip()
    if not out:
        return "allow"
    try:
        parsed = json.loads(out)
    except json.JSONDecodeError:
        raise AssertionError("guard emitted unparseable stdout: %r" % out[:200])
    hso = parsed.get("hookSpecificOutput") or {}
    decision = hso.get("permissionDecision")
    if decision == "ask":
        return "ask"
    if decision == "allow":
        return "allow+ctx" if hso.get("additionalContext") else "allow+plain"
    if parsed.get("systemMessage"):
        return "warn"
    raise AssertionError("guard emitted an unrecognized shape: %r" % out[:200])


def decide(command, **kw):
    """Run the guard on a Bash command and return its decision."""
    return _classify(_run(json.dumps({
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "hook_event_name": "PreToolUse",
    }), **kw))


def check(command, expected, why="", **kw):
    """Assert one command's decision. The unit of granularity in this suite."""
    global _checks
    _checks += 1
    actual = decide(command, **kw)
    assert actual == expected, "%s\n  expected %s, got %s%s" % (
        command.replace("\n", "\\n"), expected, actual, "\n  " + why if why else "")


def check_all(expected, cases, why=""):
    for command in cases:
        check(command, expected, why)


def reason(command):
    """The human-readable text of a non-deny decision."""
    proc = _run(json.dumps({"tool_input": {"command": command}}),
                cwd=NEUTRAL_CWD)
    if proc.returncode == 2:
        return proc.stderr
    parsed = json.loads(proc.stdout or "{}")
    hso = parsed.get("hookSpecificOutput") or {}
    return (hso.get("permissionDecisionReason") or hso.get("additionalContext")
            or parsed.get("systemMessage") or "")


def log_records(command):
    """This guard's *findings*, from a throwaway HOME.

    Filtered by guard name and by record class rather than taken as "everything
    in the file". The log carries lifecycle records now -- a `log.rotated`
    marker, and a `session.start` from any hook that happens to run in the same
    home -- and none of them is a decision this suite is asserting about. An
    unfiltered read makes `records[0]` mean whichever record was written first.
    """
    home = tempfile.mkdtemp(prefix="forcefield-cf-log-")
    try:
        _run(json.dumps({"tool_input": {"command": command}}),
             home=home, cwd=home)
        log = Path(home) / ".claude" / "hooks" / "security.log"
        if not log.exists():
            return []
        out = []
        for line in log.read_text().splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            attributes = record.get("Attributes", {})
            if (attributes.get("forcefield.guard") == "container_first"
                    and attributes.get("forcefield.record_class") == "finding"):
                out.append(record)
        return out
    finally:
        shutil.rmtree(home, ignore_errors=True)


def logged_pattern(command):
    """The forcefield.pattern the guard recorded -- which branch it took."""
    records = log_records(command)
    assert len(records) == 1, "expected exactly one log record, got %d for %r" % (
        len(records), command)
    return records[0]["Attributes"].get("forcefield.pattern")


def elapsed(command, **kw):
    started = time.monotonic()
    decide(command, **kw)
    return time.monotonic() - started


# --- Registration -----------------------------------------------------------
# The 5s timeout asserted against further down is read from here rather than
# restated, so a change to the registration cannot leave the timing cases
# measuring against a number the harness no longer uses.
#
# hooks.json states seconds; this file works in milliseconds, so the conversion
# happens once, here.

_hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
_entries = [
    (event, group.get("matcher"), hook)
    for event, groups in _hooks["hooks"].items()
    for group in groups
    for hook in group.get("hooks", [])
    if "container_first.sh" in hook.get("command", "")
]
assert len(_entries) == 1, "expected exactly one registration, got %r" % (_entries,)
_event, _matcher, _entry = _entries[0]
assert _event == "PreToolUse", _event
assert _matcher == "Bash", _matcher
TIMEOUT_MS = _entry["timeout"] * 1000
assert TIMEOUT_MS == 5000, "the timing cases below assume a 5s budget"
print("PASS: registered once at PreToolUse[Bash] with a %dms budget" % TIMEOUT_MS)


# --- The decision vocabulary ------------------------------------------------
# One case per shape the script can actually emit, at its measured tier. `warn`
# is unreachable without a config file and is covered in the ceiling section.
#
# There is no `ask` for a host install any more: both container-first reminders are
# `allow` + additionalContext, so the only remaining `ask` this script emits is for
# an over-privileged container flag or a segment_cap it could not inspect.
check("rm -rf ./build", "deny")
check("docker run --privileged img", "ask")
check(PIP + " requests", "allow+ctx")
check("python3 script.py", "allow+ctx")
check("git status", "allow")

_deny = _run(json.dumps({"tool_input": {"command": "rm -rf ./build"}}))
assert _deny.returncode == 2 and _deny.stdout == "", \
    "a deny is exit 2 with no stdout, got rc=%d out=%r" % (
        _deny.returncode, _deny.stdout[:120])
assert _deny.stderr.startswith("BLOCKED:"), _deny.stderr[:120]
_install_reason = reason(PIP + " requests")
assert "installs packages on the host OS" in _install_reason
assert "interpreter/build tool on the host" in reason("python3 script.py")

# The reminder has to name a runtime that is actually installed. It used to
# prescribe `podman` unconditionally, and on a machine that only has Apple's
# `container` CLI the single instruction it gave could not be carried out -- the
# least useful thing a reminder can do. Whichever runtime is detected, the text must
# name that one and must not name a missing one.
#
# Preference is platform-shaped, so the expected order has to be too: Apple's
# `container` is the native runtime on macOS and is not looked for anywhere else,
# while podman leads on every other platform. Hardcoding one order here would assert
# the wrong one on the other machine.
_RT_ORDER = (("container", "podman", "docker", "nerdctl")
             if platform.system() == "Darwin" else ("podman", "docker", "nerdctl"))
_present = [rt for rt in _RT_ORDER if shutil.which(rt)]
if _present:
    assert (_present[0] + " run --rm") in _install_reason, \
        "the reminder must name the runtime this machine actually has (%s): %r" % (
            _present[0], _install_reason[:200])
    for _absent in ("container", "podman", "docker", "nerdctl"):
        if _absent not in _present and (_absent + " run") in _install_reason:
            raise AssertionError(
                "reminder prescribes %s, which is not installed here" % _absent)
    # An unattended agent that reads "retry" as "resume" strands itself on state
    # that cannot exist: the container is gone when the run exits.
    assert "FRESH run" in _install_reason, \
        "the reminder must say to relaunch, not resume: %r" % _install_reason[:200]
else:
    assert "No container runtime is installed" in _install_reason

# ...and the preference itself is asserted against a PATH where ALL FOUR exist, so
# the answer comes from the guard's ordering rather than from whatever this machine
# happens to have installed. A platform-conditional assertion that only ever runs one
# of its branches is how the passive-posture change slipped past this file once
# already, so the stub removes the conditionality from the interesting part.
_stub = tempfile.mkdtemp(prefix="forcefield-cf-rt-")
for _fake in ("container", "podman", "docker", "nerdctl"):
    _fp = os.path.join(_stub, _fake)
    with open(_fp, "w") as _fh:
        _fh.write("#!/bin/sh\nexit 0\n")
    os.chmod(_fp, 0o755)
_stub_reason = json.loads(_run(
    json.dumps({"tool_input": {"command": PIP + " requests"}}),
    path=_stub + os.pathsep + os.environ.get("PATH", ""),
).stdout)["hookSpecificOutput"]["additionalContext"]
_want_rt = "container" if platform.system() == "Darwin" else "podman"
assert (_want_rt + " run --rm") in _stub_reason, \
    "with every runtime available, %s should be preferred on %s: %r" % (
        _want_rt, platform.system(), _stub_reason[:200])
print("PASS: deny / ask / allow+context each carry their documented payload")


# --- Deny: rm with recursive + force ----------------------------------------
# NORM defeats the obfuscations; the operator boundary before `rm` is what keeps
# `git rm` out of it.

check_all("deny", (
    "rm -rf ./target",
    "rm --recursive --force ./target",
    "rm -r -f ./target",
    "/bin/rm -rf ./target",
    "'rm' -rf ./target",
    "rm${IFS}-rf ./target",
    "env rm -rf ./target",
    "true && rm -rf ./target",
    "true; rm -rf ./target",
))
check_all("allow", (
    "git rm -rf oldstuff",
    "rm ./target",
    "rm -r ./target",
    "rm -f ./target",
))

# Reached past the argument boundary the check above deliberately skips.
check_all("deny", (
    "find . -exec rm -rf {} +",
    "find . -type f | xargs rm -rf",
    "find . -delete",
    "find / -delete",
))
check_all("allow", (
    "find . -name '*.tmp' -exec rm {} \\;",
    "find . -type f | xargs rm",
    "find . -name '*.pyc' -delete",
))
print("PASS: rm -rf, indirect rm -rf and bare find -delete deny; look-alikes allow")


# --- Deny: obfuscation, container escape, kernel manipulation ---------------

check_all("deny", (
    "echo -e '\\x72\\x6d'",
    "printf '\\162\\155'",
    "$'\\u0072\\u006d' -rf ./target",
))
check_all("allow", (
    "echo $'hello world'",
    "echo $'\\u2713'",
    "printf '\\U0001F600'",
))

check_all("deny", (
    "nsenter -t 1 -m -u -i -n sh",
    "unshare -m /bin/sh",
    "unshare --mount /bin/sh",
    "u=unshare; $u -m /bin/sh",
))
check("unshare --map-root-user /bin/sh", "allow")

check_all("deny", (
    "insmod evil.ko",
    "modprobe evil_mod",
    "sysctl vm.drop_caches=3",
    "sysctl --write vm.drop_caches=3",
    "echo 1 > /proc/sys/kernel/x",
    "echo 1 | tee /sys/kernel/x",
    "dd if=/dev/zero of=/proc/sys/x",
))
check_all("allow", (
    "cat /proc/cpuinfo",
    "sysctl -a",
    "sysctl vm.drop_caches",
    "echo done > /proc/self/fd/1",
    "dd if=/dev/zero of=/tmp/disk.img bs=1M count=10",
))
print("PASS: obfuscation / container-escape / kernel-write denies and their "
      "look-alikes")


# --- Ask: over-privileged container flags -----------------------------------

check_all("ask", (
    "docker run --privileged img",
    "docker run --cap-add=ALL img",
    "podman run --cap-add SYS_ADMIN img",
    "docker run --cap-add=sys_admin img",
    "podman run --cap-add=CAP_DAC_READ_SEARCH img",
    "docker run --net=host img",
    "docker run --network host img",
    "docker run --pid=host img",
    "docker run --ipc=host img",
    "docker run --uts=host img",
    "docker run --userns=host img",
    "docker run --security-opt seccomp=unconfined img",
    "docker run --security-opt apparmor:unconfined img",
    "docker run -v /:/host img",
    "docker run --device /dev/fuse img",
    "podman run --mount type=bind,source=/,target=/host img",
    "podman run --mount type=bind,src=/,dst=/host img",
))
check_all("allow", (
    "podman run --cap-add=NET_ADMIN img",
    "docker run --network mynet img",
    "podman run --mount type=bind,source=./data,target=/data img",
))
print("PASS: escape-grade container flags ask; narrow caps and named networks "
      "allow")


# --- strip_heredocs: a body consumed as text is not a command line ----------
# The awk regex is built as a dynamic STRING so SQ concatenates into the
# character class. Written as a /literal/ instead, a quoted delimiter -- the
# common spelling -- never matches and every heredoc body is scanned as command
# text. The quoted cases below are that regression: they only pass while the
# string build survives.

check_all("allow", (
    "git commit -F - <<'EOF'\n" + PIP + " evil\nEOF",         # single-quoted
    'cat > NOTES.md <<"EOF"\n' + PIP + " evil\nEOF",          # double-quoted
    "git commit -F - <<EOF\n" + PIP + " evil\nEOF",           # unquoted
    "git commit -F - <<-EOF\n" + PIP + " evil\nEOF",          # dash form
    "cat > f <<-'EOF'\n" + PIP + " evil\n\tEOF",              # indented terminator
    "git commit -F - << 'EOF'\n" + PIP + " evil\nEOF",        # space before delim
    "cat > f <<'MY_DOC'\n" + PIP + " evil\nMY_DOC",           # underscore delim
    "cat > f <<'EOF1'\n" + PIP + " evil\nEOF1",               # digits in delim
    "tee NOTES.md <<'EOF'\n" + PIP + " evil\nEOF",            # tee consumer
    "sudo cat > /etc/x <<'EOF'\n" + PIP + " evil\nEOF",       # sudo prefix
    "ls; cat > f <<'EOF'\n" + PIP + " evil\nEOF",             # consumer past a separator
), why="a text-filing heredoc body must not be scanned as a command")

# ...and the body is kept -- so a real payload is still caught -- whenever the
# consumer is an interpreter, is unrecognized, pipes the body onward, never
# terminates, or is not the head of its segment.
check_all("allow+ctx", (
    "bash <<'EOF'\n" + PIP + " evil\nEOF",
    "mailx -s x user <<'EOF'\n" + PIP + " evil\nEOF",
    "cat <<'EOF' | sh\n" + PIP + " evil\nEOF",
    "git commit -F - <<'EOF'\n" + PIP + " evil",
    "git diff <<'A' <<'B'\n" + PIP + " evil\nA\nB",
    "run git commit -F - <<'EOF'\n" + PIP + " evil\nEOF",
), why="only a text-filing consumer on a non-piping line may drop its body")

# The drop applies at the deny tier too, and only there does it change a hard
# block into a pass -- which is the whole reason it exists.
check("git commit -F - <<'EOF'\nrm -rf is banned in this repo\nEOF", "allow")
check("cat > f <<'EOF'\n\\x72\\x6d\nEOF", "allow")
check("bash <<'EOF'\nrm -rf /data\nEOF", "deny")
check("bash <<'EOF'\n\\x72\\x6d\nEOF", "deny")

# Code past a terminated heredoc is still code.
check("git commit -F - <<'EOF'\nnote\nEOF\n" + PIP + " evil", "allow+ctx")
print("PASS: heredoc bodies are dropped only when filed as text, at every tier")


# --- $SCAN decides, $CMD is logged ------------------------------------------
# Thirteen detection sites moved from $CMD to $SCAN; logging deliberately did
# not. A record that carried only the stripped text would hide the payload from
# the person reading the log afterwards.

_hd = "git commit -F - <<'EOF'\n" + PIP + " evil\nEOF"
assert decide(_hd) == "allow", "scanning must use the stripped SCAN"
_line = log_records(_hd)[0]["Attributes"]["command.line"]
assert _line == _hd, \
    "logging must record the raw CMD including the heredoc body, got %r" % _line
print("PASS: detection reads SCAN, the log record keeps the whole CMD")


# --- The allowlist, and the compound gate in front of it --------------------
# Every branch exits silently, so the only way to tell which one fired -- or
# whether the command fell through to the default -- is the logged pattern.

for _cmd, _pattern in (
    ("ls -la", "allowlist_fileops"),
    ("git status", "allowlist_fileops"),
    ("container ps", "allowlist_container"),
    ("docker images", "allowlist_container"),
    ("rg pattern src/", "allowlist_devtools"),
    ("uv sync --frozen", "allowlist_toolchain"),
    ("cargo clippy --all-targets", "allowlist_toolchain"),
    ("echo hello", "allowlist_info"),
    ("cat Makefile", "allowlist_info"),
    ("unknowncmd --flag", "default"),
):
    _checks += 1
    _got = logged_pattern(_cmd)
    assert _got == _pattern, "%r took the %s branch, expected %s" % (
        _cmd, _got, _pattern)

# A separator, a substitution or a redirect skips the allowlist entirely, so an
# allowlisted head cannot smuggle anything past the checks below it. A newline
# separates two commands exactly as `;` does and grep cannot see one, so it is
# tested in bash instead -- these are the cases that regression covers.
for _cmd in ("ls -la > out.txt", "cat $(unknowncmd)", "ls -la | wc -l",
             "ls -la; true", "ls -la && true"):
    _checks += 1
    assert logged_pattern(_cmd) == "default", \
        "a compound command must not reach the allowlist: %r" % _cmd
# The vehicle here is a PORTABLE installer on purpose: what is under test is that a
# newline separates commands, not which package manager follows it, and an apt
# install proves nothing about that off Linux.
check_all("allow+ctx", (
    "ls -la\n" + PIP + " evil",
    "git status\nsudo " + PIP + " nmap",
    "cat notes.txt\n" + NPM + " -g evil",
    "container run --rm alpine true\n" + PIP + " evil",
), why="a newline is a separator; the allowlist must not wave the rest through")
print("PASS: each allowlist branch is reachable, and no compound command "
      "reaches any of them")


# --- Host package install: anchored to command position, per segment --------

# A host install is REPORTED, never gated: `allow` + additionalContext at every
# ceiling. Preferring a container is hygiene, not a security boundary, and a prompt
# here strands unattended agents. The command-position and per-segment logic all
# still runs -- it decides which reminder is emitted -- so these cases keep their
# discriminating power as `allow+ctx` versus a plain `allow`.
check_all("allow+ctx", (
    PIP + " requests",
    "pip3 install x",
    "python3 -m pip install x",
    NPM + " -g typescript",
    "pnpm add x",
    "yarn add x",
    "gem install x",
    "cargo install ripgrep",
    "brew install jq",
    "conda install numpy",
    "env " + PIP + " evil",
    "nohup " + PIP + " evil",
    "pip 'install' evilpkg",
    "pip${IFS}install evilpkg",
))
check_all("allow", (
    "pip freeze",
    "pip uninstall x",
    "pipx run black",
    "npm run build",
    "apt list --installed",
))

# The system managers only exist on Linux, so off Linux this guard says nothing
# about them: there is no host package database for them to modify, and reminding
# the user to containerize a command that could not have run in the first place is
# noise. The expectation therefore follows the platform rather than being hardcoded
# -- the suite has to pass on Linux CI and on a macOS laptop, and asserting one
# answer would have meant asserting the wrong one somewhere. This assertion read
# "ask" until the reminder went passive, and being platform-conditional is what hid
# that: the macOS branch was the only one this laptop ever ran.
#
# dnf/yum/pacman are here because this guard is now the ONLY place the
# host-versus-container question is asked. supply_chain_guard used to carry them in
# `system_pkg_install` and prompt; that was the wrong owner, since nothing about a
# bare-host install says anything about the package's provenance. The pattern moved
# here with the question rather than the coverage being dropped.
#
# `brew` stays in the portable set above, so macOS keeps coverage of the manager it
# actually has. uname is what the guard reads, so uname is what selects here.
_UNAME = subprocess.run(["uname", "-s"], capture_output=True, text=True).stdout.strip()
_LINUX_HOST = _UNAME not in ("Darwin",) and not _UNAME.startswith(
    ("MINGW", "MSYS", "CYGWIN", "Windows"))
check_all("allow+ctx" if _LINUX_HOST else "allow", (
    APT + " nginx",
    "apt install nginx",
    "aptitude install nginx",
    "sudo " + APT + " nmap",
    "dnf install -y curl",
    "sudo dnf install nginx",
    "yum install -y curl",
    "pacman -S curl",
), why="a system install is reported on Linux and an impossibility elsewhere")
# ...and inside a container each of them is silent, on every platform.
check_all("allow", (
    "container run --rm debian:12 " + APT + " -y jq",
    "podman run --rm fedora:41 dnf install -y jq",
    "docker run --rm archlinux pacman -S --noconfirm jq",
), why="a system install in a container is the outcome this guard wants")

# An install aimed at a persistent OS elsewhere -- `ssh prod-box apt-get install`,
# `wsl apt-get install` -- is not this guard's to catch and never was: the phrase
# has to be in command position, and after `ssh prod-box` it is not.
#
# Nothing prompts on these now, on any platform, and that is a real change rather
# than an oversight. supply_chain_guard's pattern was unanchored, did reach them, and
# asked; it was deleted along with the rest of the destination question. A remote
# host is still a question about where an install lands, and this guard does not
# prompt for that -- so the ask is gone rather than relocated. Recorded here because
# it is the one behaviour the move gave up.
check_all("allow", (
    "ssh prod-box sudo " + APT + " nginx",
    "wsl " + APT + " -y curl",
), why="an install past ssh/wsl is not in command position for this guard")

# The phrase has to be in command position. Quoted as an argument to something
# else it is data, and an unanchored match asked about text nobody was running.
check_all("allow", (
    'grep "' + NPM + '" file',
    'echo "a; ' + PIP + ' evil"',
    "probe 'container run --rm alpine bash -c \"" + APT + " -y jq\"'",
))

# ...except when the wrapper is itself a shell, where the quoted body IS the
# command line.
check_all("allow+ctx", (
    'bash -c "' + PIP + ' evil"',
    '/bin/bash -c "' + PIP + ' evil"',
    'sh -c "' + PIP + ' evil"',
    'zsh -c "' + PIP + ' evil"',
    'ksh -c "' + PIP + ' evil"',
    'dash -c "' + PIP + ' evil"',
    'ash -c "' + PIP + ' evil"',
    'sh -x -c "' + PIP + ' evil"',
    'env FOO=1 bash -c "' + PIP + ' evil"',
))
print("PASS: host installs ask in command position only, and through a shell -c "
      "body")


# --- Segments ---------------------------------------------------------------
# Split on top-level separators only. Splitting inside quotes manufactures
# command positions that do not exist, which is wrong in both directions.

check_all("allow+ctx", (
    "true; " + PIP + " evil",
    "true && " + PIP + " evil",
    "false || " + PIP + " evil",
    "true | " + PIP + " evil",
    PIP + ' evil "',            # unbalanced quote -> naive-split fallback
))
check("echo \"one; two\" && echo three", "allow")
print("PASS: separators split segments, quotes do not")


# --- Container awareness ----------------------------------------------------
# container_first.sh's regex is the only live implementation; shell_context.py
# carries a declared copy of the same lists and no code that reads them. This is
# what makes that copy worth keeping: the bash regex is parsed out and compared
# to it, so a runtime added to one and not the other is caught here rather than
# discovered in the field. Both spellings must stay identical.

_container_run = re.search(r"^CONTAINER_RUN='([^']*)'", SOURCE, re.M)
assert _container_run, "CONTAINER_RUN is no longer a single-quoted assignment"
_alternations = re.findall(r"\(([a-z|]+)\)", _container_run.group(1))
assert len(_alternations) == 2, \
    "expected exactly two plain alternations (runtimes, subcommands), got %r" % (
        _alternations,)
_bash_runtimes, _bash_subcommands = (set(a.split("|")) for a in _alternations)
assert _bash_runtimes == set(shell_context.CONTAINER_RUNTIMES), \
    "container_first.sh and shell_context.py disagree about runtimes: %r vs %r" % (
        sorted(_bash_runtimes), sorted(shell_context.CONTAINER_RUNTIMES))
assert _bash_subcommands == set(shell_context.CONTAINER_SUBCOMMANDS), \
    "container_first.sh and shell_context.py disagree about subcommands: %r vs %r" % (
        sorted(_bash_subcommands), sorted(shell_context.CONTAINER_SUBCOMMANDS))

# An install inside a container is the outcome this guard exists to produce, so
# it must not ask about it -- for every runtime both files agree on.
for _runtime in sorted(_bash_runtimes):
    check("%s run --rm img %s x" % (_runtime, PIP), "allow")
for _subcommand in sorted(_bash_subcommands):
    check("docker %s img %s x" % (_subcommand, PIP), "allow")
check_all("allow", (
    "sudo docker run --rm img " + PIP + " x",
    'container run --rm python:3.9-slim sh -c "' + PIP + ' ruff"',
    'podman run --rm -v .:/w python:3.13-slim sh -c "' + PIP + ' x && python /w/s.py"',
    'docker run --rm alpine bash -c "apt-get update && ' + APT + ' -y jq"',
    "container run --rm img python3 app.py",
))

# ...but only a real invocation. The subcommand must follow the runtime, and a
# container in one segment cannot launder a host install in another.
check_all("allow+ctx", (
    "docker ps && " + PIP + " x",
    "docker pull img; " + PIP + " x",
    'echo "container run"; ' + PIP + " evil",
    "container run --rm alpine true; " + PIP + " evil",
    "container run --rm alpine true && " + PIP + " evil",
    "container run --rm alpine true | " + PIP + " evil",
    "docker build -t img . && " + NPM + " install",
))
print("PASS: both files agree on %d runtimes x %d subcommands, and only a real "
      "invocation is skipped" % (len(_bash_runtimes), len(_bash_subcommands)))


# --- Interpreter / build tool on the host -----------------------------------
# The lightest rung in the plugin -- allow plus a note -- which is exactly why
# it went unaudited for so long. It now anchors to command position and skips
# containers like the install check does, because severity governs whether a
# matching bug is reported, not whether it exists.

check_all("allow+ctx", (
    "python3 script.py",
    "python app.py",
    "node app.js",
    "ruby app.rb",
    "perl x.pl",
    "java -jar x.jar",
    "javac X.java",
    "gcc -o out main.c",
    "g++ -o out main.cpp",
    "clang -o out main.c",
    "make -j4 all",
    "cmake -B build",
    "go run ./cmd",
    "go build ./...",
    "/usr/bin/python3 app.py",
    "sudo make install",
    "doas make install",
    "time python3 app.py",
    "env FOO=1 python3 app.py",
    "nohup node server.js",
    "ls -la && python3 app.py",
))

# Anchored: an interpreter named inside somebody else's argument, or inside a
# filename, is not an interpreter being run.
check_all("allow", (
    "grep 'make all' Makefile",
    "wc -l cmake_notes.txt",
    "go vet ./...",
    "nodemon server.js",
    "container run --rm img python3 app.py",
    "docker run --rm img make all",
))

# An install and an interpreter in the same command resolve to the install: it
# is the higher rung, and the loop breaks as soon as it finds one.
check(PIP + " x && python3 app.py", "allow+ctx")
print("PASS: host interpreters report allow+context, anchored and "
      "container-aware")


# --- Fail-open / fail-safe --------------------------------------------------
# A crash, a timeout or an uninspectable payload must never block. Where the
# guard cannot inspect at all it fails to a prompt rather than a silent allow.

for _payload, _expected in (
    ("", "allow"),                                        # nothing on stdin
    ('{"tool_name":"Bash"}', "allow"),                    # no tool_input
    ('{"tool_input":{"command":null}}', "allow"),
    ('{"tool_input":{"command":""}}', "allow"),
    ('{"tool_input":{"command":["ls"]}}', "allow"),       # wrong type
    ("this is not json at all", "ask"),
    ('{"tool_input":{"command":"ls', "ask"),              # truncated
    ("[1,2,3]", "ask"),                                   # valid JSON, wrong shape
):
    _checks += 1
    _proc = _run(_payload)
    _got = _classify(_proc)
    assert _got == _expected, "payload %r: expected %s, got %s" % (
        _payload[:40], _expected, _got)
    assert _proc.returncode != 2, "no malformed payload may deny: %r" % _payload[:40]

# The 1 MiB read cap: one byte over and the payload would truncate and break
# JSON parsing, so it prompts instead of failing open.
_checks += 1
_oversized = _run('{"tool_input":{"command":"' + "A" * 1_200_000 + '"}}')
assert _classify(_oversized) == "ask", _oversized.stdout[:200]
assert "exceeds 1 MiB" in _oversized.stdout, _oversized.stdout[:200]
_checks += 1
assert _classify(_run('{"tool_input":{"command":"echo ' + "A" * 1_048_500 + '"}}')) == "allow", \
    "a payload inside the cap must still be inspected rather than rejected"

# jq is the guard's only hard dependency. Without it nothing can be parsed, and
# the documented behaviour is a prompt rather than a wave-through.
_checks += 1
_nopath = tempfile.mkdtemp(prefix="forcefield-cf-nopath-")
try:
    _nojq = _run('{"tool_input":{"command":"ls -la"}}', path=_nopath)
    assert _classify(_nojq) == "ask", _nojq.stdout[:200]
    assert "jq is not installed" in _nojq.stdout
finally:
    shutil.rmtree(_nopath, ignore_errors=True)
print("PASS: malformed, empty, oversized and jq-less payloads never block")


# --- Tiered config ceiling --------------------------------------------------
# The ceiling can only downgrade. The home file is trusted and may reach any
# rung; the project file is untrusted and is floored at ask, so a hostile repo
# cannot switch the guard off.

def _with_config(where, mode, command):
    """Decide `command` with a forcefield.json placed in home or project."""
    root = tempfile.mkdtemp(prefix="forcefield-cf-cfg-")
    try:
        (Path(root) / ".claude").mkdir()
        (Path(root) / ".claude" / "forcefield.json").write_text(
            json.dumps({"guards": {"container_first": {"mode": mode}}}),
            encoding="utf-8")
        if where == "home":
            return decide(command, home=root, cwd=root)
        return decide(command, cwd=root)
    finally:
        shutil.rmtree(root, ignore_errors=True)


for _mode, _deny_becomes, _ask_becomes in (
    ("deny", "deny", "ask"),
    ("ask", "ask", "ask"),
    ("warn", "warn", "warn"),
    ("allow", "allow", "allow"),
    ("off", "allow", "allow"),
):
    _checks += 2
    _got = _with_config("home", _mode, "rm -rf ./x")
    assert _got == _deny_becomes, "home mode=%s: deny -> %s, expected %s" % (
        _mode, _got, _deny_becomes)
    # The ask rung is probed with an over-privileged container flag, not a host
    # install: a host install no longer reaches emit_ask2 at all, so it could not
    # exercise this rung and would report `allow+ctx` at every mode.
    _got = _with_config("home", _mode, "docker run --privileged img")
    assert _got == _ask_becomes, "home mode=%s: ask -> %s, expected %s" % (
        _mode, _got, _ask_becomes)

for _mode in ("allow", "off", "warn", "ask"):
    _checks += 1
    _got = _with_config("project", _mode, "rm -rf ./x")
    assert _got == "ask", \
        "an untrusted project config is floored at ask; mode=%s gave %s" % (
            _mode, _got)

# A softened deny says so, rather than borrowing the wording of a natural ask --
# the prompt has to tell the user that config, not the guard, chose this rung.
_softened = tempfile.mkdtemp(prefix="forcefield-cf-cfg-")
try:
    (Path(_softened) / ".claude").mkdir()
    (Path(_softened) / ".claude" / "forcefield.json").write_text(
        json.dumps({"guards": {"container_first": {"mode": "warn"}}}),
        encoding="utf-8")
    _warned = _run(json.dumps({"tool_input": {"command": "rm -rf ./x"}}),
                   home=_softened, cwd=_softened)
    assert json.loads(_warned.stdout).keys() == {"systemMessage"}, _warned.stdout[:200]
    assert "(rm_rf)" in _warned.stdout and "downgraded" in _warned.stdout, \
        _warned.stdout[:200]
finally:
    shutil.rmtree(_softened, ignore_errors=True)
print("PASS: the ceiling downgrades only, and a project config cannot go below "
      "ask")

# A host install must never prompt, at ANY ceiling from either config location.
# That is the point of making the reminder passive: an unattended agent stalls on a
# prompt, or reports a failure for work it never attempted. This is also the
# property test_warn_rung stopped sweeping for `host_pkg_install`, since it no
# longer has a warn rung to reach.
for _where in ("home", "project"):
    for _mode in ("strict", "balanced", "passive", "permissive"):
        _got = _with_config(_where, _mode, PIP + " requests")
        assert _got in ("allow+ctx", "allow+plain", "allow"), \
            "host install must stay passive (%s/%s), got %s" % (_where, _mode, _got)
print("PASS: a host install never prompts, at any ceiling from either config")


# --- Timing -----------------------------------------------------------------
# The registered timeout is a security boundary: a killed hook delivers no
# verdict at all, so a command that outruns the budget is allowed by default.

_budget = TIMEOUT_MS / 1000.0
_realistic = " && ".join([
    "cd /tmp/build", "git pull --ff-only", "make -j8 all",
    "ctest --output-on-failure", "git status --short",
])
for _cmd in (_realistic, "rm -rf ./x", PIP + " requests", "ls -la",
             "echo " + "a" * 200_000):
    _checks += 1
    _took = elapsed(_cmd)
    assert _took < _budget / 2, \
        "%.2fs is more than half the %.0fs budget for %r" % (
            _took, _budget, _cmd[:60])
print("PASS: realistic commands finish inside half the %.0fs budget" % _budget)


# --- Expected-fail ledgers --------------------------------------------------
# Everything below is measured behaviour this suite believes is WRONG. Each is
# asserted at the value the script actually produces, so the suite is green
# today and turns red the moment the behaviour changes -- in either direction.
# Strict, as in tests/test_false_positives.py: an entry that starts passing
# fails the suite, so a fix must delete its own entry.

# 1. CONTAINER_ESCAPE used to match `ptrace` as a bare substring with no command
#    position, word boundary or operator anchor, and `nsenter\s+` with only a
#    trailing space. `deny` is the plugin's one contractual zero-false-positive
#    rung, and it is the only rung a user running with permissions skipped ever
#    sees -- so those were hard blocks on ordinary work: grepping the kernel
#    source, naming a log file, writing a commit message about the tool.
#
#    FIXED: the three branches are anchored to command position (ESC_CMD_POS),
#    which is where an escape tool has to be to run. Nothing real was given up
#    -- there is no `ptrace` executable to invoke on either platform (it is a
#    syscall), so the bare branch could only ever match prose. The ledger is
#    empty and stays empty: an entry here would mean deny had regained a false
#    positive, and the suite fails in both directions.
KNOWN_DENY_FALSE_POSITIVES = {}

BENIGN_MENTIONS = (
    ("ptrace/grep", "grep -rn ptrace src/"),
    ("ptrace/rg", "rg ptrace --type c"),
    ("ptrace/filename", "wc -l ptrace.log"),
    ("ptrace/commit-message", "git commit -m 'fix ptrace handling'"),
    ("ptrace/prose", "echo do not use ptrace"),
    ("ptrace/dirname", "ls ptrace_notes/"),
    ("ptrace/read-notes", "cat notes_about_ptrace.md"),
    ("ptrace/git-grep", "git log --grep ptrace"),
    ("nsenter/grep", "grep -rn nsenter src/"),
    ("nsenter/prose", "echo nsenter x"),
    ("nsenter/commit-message", "git commit -m 'document nsenter usage'"),
    ("unshare/grep-flag", "grep -rn 'unshare -m' src/"),
    ("unshare/rg-flag", "rg 'unshare --mount'"),
    ("unshare/commit-message", "git commit -m 'note unshare -m risk'"),
    # These neighbours already pass, and pin the shape of the bug: without a
    # trailing space `nsenter` does not match, and `unshare` needs a flag.
    ("nsenter/filename-ok", "cat notes_about_nsenter.md"),
    ("nsenter/logfile-ok", "wc -l nsenter.log"),
    ("unshare/prose-ok", "echo unshare is a namespace tool"),
    # ...and the heredoc strip already shields the same prose when it is filed
    # as text, which is why the ledger is this short rather than much longer.
    ("ptrace/heredoc-ok", "git commit -F - <<'EOF'\nptrace is blocked\nEOF"),
    ("unshare/heredoc-ok",
     "cat > NOTES.md <<'EOF'\nunshare -m breaks isolation\nEOF"),
)

_denied = set()
for _case_id, _command in BENIGN_MENTIONS:
    _checks += 1
    if decide(_command) == "deny":
        _denied.add(_case_id)

_unexpected = sorted(_denied - set(KNOWN_DENY_FALSE_POSITIVES))
_stale = sorted(set(KNOWN_DENY_FALSE_POSITIVES) - _denied)
for _case_id in _unexpected:
    print("  FAIL  %-26s denies and is not ledgered" % _case_id)
for _case_id in _stale:
    print("  FAIL  %-26s no longer denies -- remove it from the ledger"
          % _case_id)
assert not _unexpected and not _stale, \
    "%d unexpected deny(s), %d stale ledger entr(ies)" % (
        len(_unexpected), len(_stale))
print("PASS: %d benign mentions, %d ledgered as deny false positives"
      % (len(BENIGN_MENTIONS), len(KNOWN_DENY_FALSE_POSITIVES)))


# 2. The `allowlist_info` branch used to silently allow anything starting with
#    `command `, which runs an arbitrary command exactly as `env` does -- and
#    `env` was excluded from that branch for precisely that reason. The install
#    check even names `command[[:space:]]+` in CMD_PREFIX as a transparent
#    prefix to see PAST, so the two halves of this file disagreed: the allowlist
#    ran first and exited before the install and interpreter checks were ever
#    reached.
#
#    FIXED: only the lookup form (`command -v` / `-V`), which executes nothing,
#    stays on the allowlist. A `command `-prefixed call now decides exactly as
#    the same call without the prefix does, which is the property worth pinning
#    -- so these are asserted outright rather than ledgered.
KNOWN_ASK_BYPASSES = {}

COMMAND_PREFIXED = (
    (PIP + " evil", "allow+ctx"),
    (NPM + " -g evil", "allow+ctx"),
    ("brew install jq", "allow+ctx"),
    # apt is a host install on Linux only; the property under test is that the
    # prefix does not change the decision, whatever that decision is here.
    (APT + " nginx", "allow+ctx" if _LINUX_HOST else "allow"),
    ("node app.js", "allow+ctx"),
    ("make all", "allow+ctx"),
    ("python3 app.py", "allow+ctx"),
)

for _bare, _expected in COMMAND_PREFIXED:
    check(_bare, _expected)
    check("command " + _bare, _expected,
          "a transparent prefix must not change the decision")

# The lookup form executes nothing and keeps its silent allow.
check_all("allow", ("command -v jq", "command -V python3"))

# The deny tier and the over-privilege ask sit above the allowlist and were
# never reachable through this hole -- which is what bounded the finding.
check("command rm -rf ./x", "deny")
check("command docker run --privileged img", "ask")
print("PASS: `command ` decides as the bare call does at %d call sites; "
      "`command -v` still allows" % len(COMMAND_PREFIXED))


# 3. The guard used to outrun its own registered budget on inputs that are large
#    but entirely well-formed. A hook killed at the timeout returns no verdict at
#    all and the harness allows the call, so this was not merely slow: it was the
#    guard's fail-open path, reachable by padding a command.
#
#    Two shapes reached it. Cost was linear in the number of top-level segments
#    (each paid a fork-heavy normalize_text plus four greps), and roughly CUBIC
#    in the length of a single segment -- the sharper of the two: the blank test
#    `[[ -n "${_seg//[[:space:]]/}" ]]` measured 0.12s / 0.59s / 3.6s / 25.5s at
#    1k / 2k / 4k / 8k characters. A ~90 KB command already exceeded the budget,
#    leaving the 1 MiB read cap an order of magnitude above what the guard could
#    process in time.
#
#    FIXED three ways: a pattern match replaces the string-building blank test,
#    a prefilter skips the whole segment loop unless an install or interpreter
#    token appears somewhere in the command, and SEG_MAX bounds what is left.
#    The bound is the delicate part -- a cap that gave up and allowed would have
#    replaced a slow fail-open with a fast one -- so the padded-install cases
#    below assert the DECISION, not just the clock.
KNOWN_TIMEOUT_BLOWOUT = {}

TIMEOUT_CASES = (
    ("segments/1000", "; ".join(["true"] * 1000)),
    ("length/10k", "zzz " + "A" * 10_000 + " > out.txt"),
    ("length/10k-no-trailing-space-ok", "zzz " + "A" * 10_000),
    ("length/1m-allowlisted-ok", "echo " + "A" * 1_000_000),
    # The shapes that survive the prefilter, so they actually enter the loop.
    ("segments/1000-with-interp", "; ".join(["make all"] * 1000)),
    ("length/100k-install", PIP + " x " + "A" * 100_000),
)

_blown = set()
for _case_id, _command in TIMEOUT_CASES:
    _checks += 1
    try:
        _run(json.dumps({"tool_input": {"command": _command}}), timeout=_budget)
    except subprocess.TimeoutExpired:
        _blown.add(_case_id)

_unexpected = sorted(_blown - set(KNOWN_TIMEOUT_BLOWOUT))
_stale = sorted(set(KNOWN_TIMEOUT_BLOWOUT) - _blown)
for _case_id in _unexpected:
    print("  FAIL  %-26s exceeds the budget and is not ledgered" % _case_id)
for _case_id in _stale:
    print("  FAIL  %-26s now finishes in budget -- remove it from the ledger"
          % _case_id)
assert not _unexpected and not _stale, \
    "%d unexpected, %d stale timeout ledger entr(ies)" % (
        len(_unexpected), len(_stale))

# Padding must not buy a silent allow, and the cap is the delicate part: a cap
# that gave up and allowed would have replaced a slow fail-open with a fast one.
# Filler is triaged out fork-free, so it does not consume the cap...
check("; ".join(["true"] * 400) + "; " + PIP + " evil", "allow+ctx",
      "filler does not consume the cap; the install is still inspected")
check("; ".join(["true"] * 400) + "; make all", "allow+ctx",
      "the interpreter note survives 400 segments of filler")
check("; ".join(["true"] * 400), "allow",
      "filler with no install or interpreter token skips the loop entirely")

# ...but real token-carrying segments do, and an install hidden past the cap --
# never reached by the loop at all -- has to fail CLOSED to a prompt, the way
# the missing-jq and oversized-payload paths above do.
check("; ".join(["make all"] * 60) + "; " + PIP + " evil", "ask",
      "an install past SEG_MAX must prompt rather than fall through to allow")
assert logged_pattern("; ".join(["make all"] * 60) + "; " + PIP + " evil") \
    == "segment_cap", "the cap must log why it could not finish"
_checks += 2

_per_segment = elapsed("; ".join(['make "all" X=1'] * 30)) / 30
print("PASS: ~%.0fms per expensive inspected segment; every shape finishes "
      "inside the %dms budget and padding fails closed"
      % (_per_segment * 1000, TIMEOUT_MS))


# The rm_rf check used to be three independent greps ANDed: rm at a command
# position anywhere, a recursive flag anywhere, a force flag anywhere. The flags
# did not have to be the rm's, and a bare `|` counted as a command position even
# inside a quoted regex. Both produced DENY false positives, and deny is
# contractually zero-false-positive. The flags must belong to THE rm, and the
# pipe form that matters is `| xargs rm -rf`, which the indirect check owns.
_LIT = "r" + "m"
_RMRF = _LIT + " -rf"
_RM_CASES = (
    # (label, command, expected)
    ("flags belong to another command",
     "%s notes.txt && rsync -r --force src/ dst/" % _LIT, "allow"),
    ("alternation pipe in a quoted regex",
     "rg -n 'rm_rf|%s -rf|%s -r ' tests/" % (_LIT, _LIT), "allow"),
    ("grep -E alternation", "grep -E 'a|%s -rf' file.txt" % _LIT, "allow"),
    ("plain non-recursive delete", "%s notes.txt" % _LIT, "allow"),
    ("recursive without force", "%s -r /tmp/dir" % _LIT, "allow"),
    ("git rm stays allowed", "git %s --cached path" % _RMRF, "allow"),
    # true positives, none of which may regress
    ("combined flags", "%s /tmp/build" % _RMRF, "deny"),
    ("reversed combined", "%s -fr /tmp/build" % _LIT, "deny"),
    ("separate flags", "%s -r -f /tmp/build" % _LIT, "deny"),
    ("separate reversed", "%s -f -r /tmp/build" % _LIT, "deny"),
    ("both long", "%s --recursive --force /tmp/build" % _LIT, "deny"),
    # these two orderings were absent from RM_RF_FLAGS; scoping the direct check
    # onto a primitive with holes would have traded an FP for a false negative
    ("--force before -r", "%s --force -r /tmp/build" % _LIT, "deny"),
    ("-f before --recursive", "%s -f --recursive /tmp/build" % _LIT, "deny"),
    ("intervening flag", "%s -v -rf /tmp/build" % _LIT, "deny"),
    ("uppercase -Rf", "%s -Rf /tmp/build" % _LIT, "deny"),
    ("after &&", "cd /tmp && %s build" % _RMRF, "deny"),
    ("after ;", "cd /tmp; %s build" % _RMRF, "deny"),
    ("after ||", "test -d x || %s x" % _RMRF, "deny"),
    # the legitimate pipe form must still be caught, by the indirect check
    ("xargs after a pipe", "find . -name x | xargs %s" % _RMRF, "deny"),
    ("find -exec", "find . -type d -exec %s {} +" % _RMRF, "deny"),
    # A privilege/env wrapper leaves rm as the command being run. These were
    # missed: rm after a plain space is not a command position, which is what
    # keeps `git rm` allowed, so the wrapper words have to be named explicitly.
    ("sudo", "sudo %s /var/tmp/y" % _RMRF, "deny"),
    ("sudo with a flag", "sudo -E %s /var/tmp/y" % _RMRF, "deny"),
    ("env assignment", "env FOO=1 %s /var/tmp/y" % _RMRF, "deny"),
    ("stacked wrappers", "nohup nice %s /var/tmp/y" % _RMRF, "deny"),
    ("sudo after &&", "cd /tmp && sudo %s build" % _RMRF, "deny"),
    ("sudo before find -exec", "sudo find . -type d -exec %s {} +" % _RMRF, "deny"),
    # ...but the wrapper span must not cross into a container invocation, or
    # docker's own --rm flag reads as the rm command and denies a build.
    ("docker --rm is not the rm command",
     "sudo docker run --rm -v /a:/b img sh -c 'build --force -r'", "allow"),
    ("podman --rm with a recursive build flag",
     "podman run --rm -it img make -r -f Makefile", "allow"),
    ("bare word argument is not covered, and must not be",
     "sudo -u root %s /var/tmp/y" % _RMRF, "allow"),
)
for _label, _cmd, _want in _RM_CASES:
    _proc = _run(json.dumps({"tool_input": {"command": _cmd}}))
    _got = "deny" if _proc.returncode == 2 else "allow"
    assert _got == _want, (
        "rm_rf %s: wanted %s got %s for %r" % (_label, _want, _got, _cmd))
    _checks += 1
print("PASS: recursive-force flags must belong to the rm, and a quoted "
      "alternation pipe is not a command position")

shutil.rmtree(NEUTRAL_CWD, ignore_errors=True)
print("\n=== container_first.sh: %d checks passed "
      "(%d deny false positives, %d ask bypasses, %d timeout blowouts ledgered) ==="
      % (_checks, len(KNOWN_DENY_FALSE_POSITIVES), len(KNOWN_ASK_BYPASSES),
         len(KNOWN_TIMEOUT_BLOWOUT)))
