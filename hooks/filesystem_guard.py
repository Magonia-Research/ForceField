#!/usr/bin/env python3
"""Filesystem destination/source guard for Claude Code.

Closes the gap where ``credential_guard`` inspects only the *content* of a Write/
Edit: it never checks *where* the write lands. A payload with no credential in it
can still drop a backdoor by writing to ``~/.ssh/authorized_keys``, a shell rc
file, ``.git/hooks/pre-commit``, a launchd/cron unit, or ForceField's own config.

This guard judges the PATH:

* ``Write`` / ``Edit`` / ``MultiEdit`` / ``NotebookEdit`` — ask before writing to a
  sensitive sink (credential stores, shell/login init, auto-run/persistence
  locations, system paths) or to security-config that could disable ForceField
  itself (``.claude/settings.json``, ``hook-allowlist.json``, ``forcefield.json``,
  or the installed plugin under ``$CLAUDE_PLUGIN_ROOT``).
* ``Read`` — ask before reading a credential store, so the secret is never dumped
  into the transcript (the Bash side is covered by ``credential_access_guard``).

Every finding is ``ask`` (never a hard block): each of these paths has some
legitimate use, so the user confirms per call and a per-project allowlist
(``filesystem_guard``) can suppress a pattern or path outright. Paths are
canonicalized (``~`` / ``$VAR`` expansion, ``..`` normalization, symlink
resolution) before matching, so ``../../.ssh`` and symlink tricks do not slip by.

Fail-open: any crash or malformed input allows the tool call.

Input: JSON on stdin (Claude Code PreToolUse hook format)
Output: JSON on stdout (hook response)
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from patterns import MAX_STDIN_BYTES  # noqa: E402
from hook_event import (  # noqa: E402
    context_from_event, parse_event, read_stdin_text,
)
from allowlist import is_suppressed  # noqa: E402
from hook_logging import (  # noqa: E402
    clamp_and_emit, defer_log, emit, log_guard_ran,
)
from credential_access_guard import CREDENTIAL_ACCESS_PATTERNS  # noqa: E402

_WRITE_TOOLS = frozenset(["Write", "Edit", "MultiEdit", "NotebookEdit"])

# Sensitive write sinks, matched against the canonical absolute path. Sources are
# compiled with re.IGNORECASE: on darwin/Windows the filesystem is case-insensitive
# and os.path.realpath preserves the as-typed case, so ``~/.SSH/authorized_keys``
# writes the same file as ``~/.ssh/authorized_keys`` and must match too.
_WRITE_SINK_SOURCES: dict[str, str] = {
    "ssh_authorized_keys": r"/\.ssh/authorized_keys$",
    "ssh_dir": r"/\.ssh/",
    "aws_dir": r"/\.aws/",
    "gnupg_dir": r"/\.gnupg/",
    "gcloud_dir": r"/\.config/gcloud/",
    "kube_dir": r"/\.kube/",
    "docker_config": r"/\.docker/config\.json$",
    "npmrc": r"/\.npmrc$",
    "pypirc": r"/\.pypirc$",
    "netrc": r"/\.netrc$",
    "git_credentials": r"/\.git-credentials$",
    "shell_init": r"/\.(?:bashrc|zshrc|bash_profile|zprofile|profile|bash_login|bash_logout|zshenv|zlogin|zlogout|bash_aliases)$",
    "fish_init": r"/\.config/fish/(?:config\.fish$|conf\.d/)",
    "git_hooks": r"/\.git/hooks/",
    "git_config_file": r"/\.git/config$",
    "git_global_config": r"/\.gitconfig$|/\.config/git/config$",
    "launch_agents": r"/Library/(?:LaunchAgents|LaunchDaemons)/",
    "autostart": r"/\.config/autostart/",
    "cron": r"/(?:etc/cron|etc/crontab|var/at/|var/spool/cron)",
    "systemd_unit": r"/(?:etc|lib|usr/lib)/systemd/system/|/systemd/user/",
    "rc_local": r"/etc/rc\.local$",
    "etc_sensitive": (
        r"/etc/(?:sudoers|sudoers\.d/|passwd|shadow|hosts|profile|environment|"
        r"pam\.d/|ld\.so\.preload|ld\.so\.conf)"
    ),
}
WRITE_SINK_PATTERNS: dict[str, re.Pattern[str]] = {
    name: re.compile(src, re.IGNORECASE) for name, src in _WRITE_SINK_SOURCES.items()
}

# Security-config self-protection: writing these could suppress or disable
# ForceField. Matched (case-insensitively) against the canonical path.
_CONFIG_SINK_SOURCES: dict[str, str] = {
    "claude_settings": r"/\.claude/settings(?:\.local)?\.json$",
    "hook_allowlist": r"/\.claude/hook-allowlist\.json$",
    "forcefield_config": r"/\.claude/forcefield\.json$",
    # ForceField's own runtime state. Remembered approvals (memos.json) turn a
    # guard's ask into an allow; the spawn counters under state/ are what the
    # agent rate limit is enforced from — a subagent that can zero its own budget
    # does not have one; and sigma/ holds the compiled detection rules plus the
    # venv python that sigma_update.sh executes at every SessionStart, which is
    # the one entry here that is outright code execution. Covering the whole
    # directory rather than the files known at the time is what made sigma/
    # protected the day it was added, with no edit to this list.
    "forcefield_memos": r"/\.claude/forcefield/",
    "mcp_config": r"/\.mcp\.json$",
}
CONFIG_SINK_PATTERNS: dict[str, re.Pattern[str]] = {
    name: re.compile(src, re.IGNORECASE) for name, src in _CONFIG_SINK_SOURCES.items()
}

# The same sinks, matched in a *Bash command string* rather than a canonical
# path. This hook registers only for Write/Edit/MultiEdit/NotebookEdit/Read, so
# every sink above was reachable from the shell with no guard at all:
# ``echo '{}' > ~/.claude/forcefield/memos.json`` self-granted a remembered
# approval, and a write to ``~/.claude/forcefield.json`` sets the *trusted*
# config tier, which may loosen any guard to allow/off. Consumed by
# ``security_dispatcher`` on the Bash path.
#
# The two dicts stay separate — they are consumed by different code and match
# genuinely different domains — but the regex BODIES are not independent
# knowledge, so they are derived rather than hand-copied: adding a sixth sink
# must not be a two-place edit. Only the path anchors differ (a leading ``/``
# and a trailing ``$`` are meaningless inside raw shell text). The order is
# named here rather than inherited because ``check_bash_config_write`` reports
# the FIRST sink that matches and one command can name two.
_BASH_SINK_ORDER = (
    "forcefield_config", "forcefield_memos", "hook_allowlist",
    "claude_settings", "mcp_config",
)
_BASH_SINK_SOURCES: dict[str, str] = {
    name: _CONFIG_SINK_SOURCES[name].lstrip("/").rstrip("$")
    for name in _BASH_SINK_ORDER
}
BASH_SINK_PATTERNS: dict[str, re.Pattern[str]] = {
    name: re.compile(src, re.IGNORECASE) for name, src in _BASH_SINK_SOURCES.items()
}

# Kept as a separate, deliberately simple membership test rather than one
# correlated regex: two linear searches cannot backtrack against each other, and
# this file's whole job is to be the thing that still works when something else
# has gone wrong.
_BASH_WRITE_VERB = re.compile(
    r">>?|\btee\b|\bcp\b|\bmv\b|\bln\b|\binstall\b|\bdd\b|\bof="
    r"|\btruncate\b|\bsed\b|\bpatch\b|\bprintf\b|\becho\b|\bcat\b"
    r"|\bpython[0-9.]*\b|\bperl\b|\bruby\b|\bnode\b|\btouch\b|\bchmod\b",
    re.IGNORECASE,
)


def check_bash_config_write(command: str) -> tuple[str, str] | None:
    """Return (sink_name, matched_text) for a shell write to ForceField's own
    control surface, or None.

    Never a hard deny — a legitimate ``/forcefield:remember`` run and a hostile
    ``echo >`` are the same syscall, so the user is the only one who can tell
    them apart.
    """
    if not command or not _BASH_WRITE_VERB.search(command):
        return None
    for name, pattern in BASH_SINK_PATTERNS.items():
        match = pattern.search(command)
        if match:
            return (name, match.group(0))
    return None

# Credential stores read via the Read tool that the shared CREDENTIAL_ACCESS_PATTERNS
# (tuned for Bash command strings) does not carry. Anchored to the canonical path so
# a Read never dumps these secrets into the transcript; kept dotfile-precise so plain
# project files named ``my.cnf`` do not over-ask.
_READ_SINK_SOURCES: dict[str, str] = {
    "mysql_cnf": r"/\.my\.cnf$",
    "terraform_credentials": r"/\.terraform\.d/credentials\.tfrc\.json$",
    "git_credentials_xdg": r"/\.config/git/credentials$",
}
READ_SINK_PATTERNS: dict[str, re.Pattern[str]] = {
    name: re.compile(src, re.IGNORECASE) for name, src in _READ_SINK_SOURCES.items()
}

# All findings are "ask" — every one of these paths has a legitimate use, so a
# hard block would violate the zero-false-positive rule.
HARD_DENY_PATTERNS: frozenset[str] = frozenset()

PATTERN_RISKS = {
    "ssh_authorized_keys": "Writing authorized_keys installs a persistent SSH backdoor",
    "ssh_dir": "Writing into ~/.ssh can alter keys or SSH config",
    "aws_dir": "Writing AWS config can hijack cloud credentials",
    "gnupg_dir": "Writing GnuPG data can alter private keys / trust",
    "gcloud_dir": "Writing gcloud config can hijack cloud credentials",
    "kube_dir": "Writing kube config can redirect cluster access",
    "docker_config": "Writing Docker config can inject registry auth",
    "npmrc": "Writing .npmrc can inject an npm auth token or registry",
    "pypirc": "Writing .pypirc can inject PyPI upload credentials",
    "netrc": "Writing .netrc can inject stored login credentials",
    "git_credentials": "Writing .git-credentials can inject stored git passwords",
    "shell_init": "Writing a shell init file runs code on every new shell",
    "fish_init": "Writing a fish init/conf.d file runs code on every new fish shell",
    "git_hooks": "Writing a .git/hooks script runs code on git operations",
    "git_config_file": "Writing .git/config can set hooks/aliases that execute code",
    "git_global_config": "Writing global git config can run code via aliases on any git command",
    "launch_agents": "Writing a Launch Agent/Daemon installs persistence",
    "autostart": "Writing an autostart entry installs persistence",
    "cron": "Writing a cron/at job installs scheduled execution",
    "systemd_unit": "Writing a systemd unit installs persistence",
    "rc_local": "Writing /etc/rc.local installs a boot-time persistence script",
    "etc_sensitive": "Writing to a sensitive /etc file alters system auth/identity",
    "claude_settings": "Writing Claude Code settings can disable security hooks",
    "hook_allowlist": "Writing hook-allowlist.json can suppress security guards",
    "forcefield_config": "Writing forcefield.json can loosen or disable guards",
    "forcefield_memos": (
        "Writing ForceField state can grant a remembered approval, reset a "
        "subagent's spawn budget, or replace the sigma rules and the venv "
        "python run at every session start"
    ),
    "mcp_config": "Writing .mcp.json registers MCP server commands Claude Code can spawn",
    "forcefield_plugin": "Writing into the installed ForceField plugin tampers with the guards themselves",
    "mysql_cnf": "Reading ~/.my.cnf exposes stored MySQL/MariaDB credentials",
    "terraform_credentials": "Reading the Terraform credentials file exposes cloud API tokens",
    "git_credentials_xdg": "Reading the XDG git credential store exposes stored git passwords",
}


def _canonical(path: str) -> str:
    """Expand ~ / $VARs, normalize ``..``, and resolve symlinks where possible.

    Returns an absolute path. For a not-yet-existing write target, symlinks in the
    existing parent prefix are still resolved, so ``../../.ssh/authorized_keys``
    and symlinked directories cannot hide the true destination.
    """
    if not path:
        return ""
    expanded = os.path.expanduser(os.path.expandvars(path))
    if not os.path.isabs(expanded):
        expanded = os.path.join(os.getcwd(), expanded)
    try:
        return os.path.realpath(expanded)
    except OSError:
        return os.path.normpath(expanded)


def _plugin_root_real() -> str:
    """Canonical path of the installed ForceField plugin, or '' if unknown."""
    root = os.environ.get("CLAUDE_PLUGIN_ROOT", "")
    return _canonical(root) if root else ""


def check_write_path(path: str) -> tuple[str, str] | None:
    """Return ``(pattern_name, matched_path)`` for a sensitive write, else None."""
    canonical = _canonical(path)
    if not canonical:
        return None

    plugin_root = _plugin_root_real()
    if plugin_root and (canonical == plugin_root or canonical.startswith(plugin_root + os.sep)):
        return ("forcefield_plugin", canonical)

    for name, pattern in CONFIG_SINK_PATTERNS.items():
        if pattern.search(canonical):
            return (name, canonical)
    for name, pattern in WRITE_SINK_PATTERNS.items():
        if pattern.search(canonical):
            return (name, canonical)
    return None


def check_read_path(path: str) -> tuple[str, str] | None:
    """Return ``(pattern_name, matched_path)`` for a credential-store read, else None."""
    canonical = _canonical(path)
    if not canonical:
        return None
    for name, pattern in CREDENTIAL_ACCESS_PATTERNS.items():
        if pattern.search(canonical) or pattern.search(path):
            return (name, canonical)
    for name, pattern in READ_SINK_PATTERNS.items():
        if pattern.search(canonical) or pattern.search(path):
            return (name, canonical)
    return None


def format_alert(pattern_name: str, matched_path: str, action: str) -> str:
    """Build the ask-reason message for a sensitive filesystem access."""
    risk = PATTERN_RISKS.get(pattern_name, "Sensitive filesystem access")
    msg = f"FILESYSTEM GUARD: {pattern_name}\n\n"
    msg += f"Action: {action}\n"
    msg += f"Path: {matched_path[:200]}\n"
    msg += f"Risk: {risk}\n\n"
    msg += "Before approving:\n"
    msg += "- Does the task genuinely require touching this path?\n"
    msg += "- Could this install persistence, exfiltrate a secret, or weaken security?\n"
    msg += "- Suppress in .claude/hook-allowlist.json (filesystem_guard) if routine here."
    return msg


def _correlation(session_id: str, canonical: str) -> dict | None:
    """An earlier blocked command in this session that named this same path.

    The bypass shape: refused through one tool, performed through another. It is
    detectable at high precision and carries **no** information about intent —
    measured over two weeks of this project's own logs, all 26 occurrences were
    the author routing around a false positive while building the tool. So it is
    recorded always and gates never on its own.

    Bounded and caught: this runs before the verdict reaches stdout, so an
    unreadable ledger must cost a correlation rather than a decision.
    """
    if not canonical:
        return None
    try:
        from write_ledger import correlate  # noqa: PLC0415

        return correlate(session_id, canonical)
    except Exception:  # noqa: BLE001 - never let the ledger block a tool call
        return None


def _correlation_extra(correlation: dict) -> dict:
    return {
        "correlated_block": "%s:%s" % (correlation.get("guard", ""),
                                       correlation.get("pattern", "")),
        "correlated_decision": correlation.get("decision", ""),
        "correlated_age_s": correlation.get("age_s"),
    }


def _correlation_note(correlation: dict) -> str:
    return (
        "\n\nAlso: this exact path was named by a command ForceField %s "
        "%.1fs ago (%s/%s). Approving this write completes what that block "
        "refused."
        % (correlation.get("decision", "blocked"), correlation.get("age_s") or 0.0,
           correlation.get("guard", ""), correlation.get("pattern", ""))
    )


def _record_gate(session_id: str, canonical: str, tool_name: str) -> None:
    """Tell the ledger a gate saw this write, so ``file_watch_guard`` can
    attribute the filesystem event that follows it.

    Writes only, never reads: attribution answers "what changed this file", and
    a Read changes nothing. Called strictly after the verdict is on stdout.
    """
    if tool_name not in _WRITE_TOOLS or not canonical:
        return
    try:
        from write_ledger import record_gate  # noqa: PLC0415

        record_gate(session_id, canonical, tool_name)
    except Exception:  # noqa: BLE001 - the decision is already delivered
        pass


def _log_correlation_only(canonical: str, tool_name: str, context: dict | None,
                          correlation: dict) -> None:
    """Record a bypass-shaped write whose target is not itself a protected sink.

    ``natural="warn"`` with an ``allow`` decision, which is exactly what the two
    fields mean: something was detected, nothing was enforced.
    """
    extra = {"tool": tool_name}
    extra.update(_correlation_extra(correlation))
    defer_log(
        "filesystem_guard", "allow",
        pattern_matched="blocked_command_rerouted", command=canonical,
        context=context, extra=extra, natural="warn",
    )


def _emit(pattern_name: str, matched_path: str, action: str, tool_name: str,
          context: dict | None = None, correlation: dict | None = None) -> None:
    """Log and emit the ask decision (respecting the per-project allowlist)."""
    if is_suppressed("filesystem_guard", pattern_name=pattern_name, file_path=matched_path):
        extra = {"tool": tool_name, "suppressed": True}
        if correlation:
            extra.update(_correlation_extra(correlation))
        defer_log(
            "filesystem_guard", "allow",
            pattern_matched=pattern_name, command=matched_path, context=context,
            extra=extra,
        )
        emit({})
        return

    natural = "deny" if pattern_name in HARD_DENY_PATTERNS else "ask"
    reason = format_alert(pattern_name, matched_path, action)
    extra = {"tool": tool_name}
    if correlation:
        reason += _correlation_note(correlation)
        extra.update(_correlation_extra(correlation))
    response = clamp_and_emit(
        "filesystem_guard", natural, reason,
        pattern_matched=pattern_name, command=matched_path, context=context,
        extra=extra,
    )
    emit(response)


def main() -> None:
    """Read stdin, judge the file path for the tool, emit a decision."""
    raw = read_stdin_text(MAX_STDIN_BYTES)
    input_data = parse_event(raw)
    if input_data is None:
        emit({})
        return

    context = context_from_event(input_data)
    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})
    if not isinstance(tool_input, dict):
        emit({})
        return
    path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""

    if not path:
        emit({})
        return

    if tool_name in _WRITE_TOOLS:
        result = check_write_path(path)
        action = f"{tool_name} to a sensitive path"
    elif tool_name == "Read":
        result = check_read_path(path)
        action = "Read of a credential store"
    else:
        emit({})
        return

    session_id = input_data.get("session_id", "")
    canonical = _canonical(path)
    correlation = (
        _correlation(session_id, canonical) if tool_name in _WRITE_TOOLS else None
    )

    if result is None:
        if correlation is not None:
            # Recorded, never gated. The user's decision was to escalate only
            # when the re-routed target is itself a protected sink, and that is
            # the branch below. Over the measured period this branch fired 26
            # times and the escalating one zero times, which is the ratio that
            # made "log always, ask sometimes" the right split.
            _log_correlation_only(canonical, tool_name, context, correlation)
        else:
            # The clean path. This guard returns silently far more often than it
            # fires, so without this record "the path was fine" and "the guard
            # never ran" are the same observation.
            log_guard_ran("filesystem_guard", context)
        emit({})
        _record_gate(session_id, canonical, tool_name)
        return

    pattern_name, matched_path = result
    _emit(pattern_name, matched_path, action, tool_name, context, correlation)
    # After the verdict, always: a hook killed at the 5 s timeout must lose a
    # ledger entry, never a decision. An ``ask`` is recorded as a gated write
    # because the gate is what ran, not what the user then chose — Claude Code
    # never tells a hook the outcome of its own prompt.
    _record_gate(session_id, matched_path, tool_name)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        emit({})
