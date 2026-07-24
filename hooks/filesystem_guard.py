#!/usr/bin/env python3
"""Filesystem destination/source guard for Claude Code.

Closes the gap where ``credential_guard`` inspects only the *content* of a Write/
Edit: it never checks *where* the write lands. A payload with no credential in it
can still drop a backdoor by writing to ``~/.ssh/authorized_keys``, a shell rc
file, ``.git/hooks/pre-commit``, a launchd/cron unit, or Portcullis' own config.

This guard judges the PATH:

* ``Write`` / ``Edit`` / ``MultiEdit`` / ``NotebookEdit`` — ask before writing to a
  sensitive sink (credential stores, shell/login init, auto-run/persistence
  locations, system paths) or to security-config that could disable Portcullis
  itself (``.claude/settings.json``, ``hook-allowlist.json``, ``portcullis.json``,
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

import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from patterns import MAX_STDIN_BYTES  # noqa: E402
from allowlist import is_suppressed  # noqa: E402
from hook_logging import log_security_event, clamp_and_emit  # noqa: E402
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
# Portcullis. Matched (case-insensitively) against the canonical path.
_CONFIG_SINK_SOURCES: dict[str, str] = {
    "claude_settings": r"/\.claude/settings(?:\.local)?\.json$",
    "hook_allowlist": r"/\.claude/hook-allowlist\.json$",
    "portcullis_config": r"/\.claude/portcullis\.json$",
    "mcp_config": r"/\.mcp\.json$",
}
CONFIG_SINK_PATTERNS: dict[str, re.Pattern[str]] = {
    name: re.compile(src, re.IGNORECASE) for name, src in _CONFIG_SINK_SOURCES.items()
}

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
    "portcullis_config": "Writing portcullis.json can loosen or disable guards",
    "mcp_config": "Writing .mcp.json registers MCP server commands Claude Code can spawn",
    "portcullis_plugin": "Writing into the installed Portcullis plugin tampers with the guards themselves",
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
    """Canonical path of the installed Portcullis plugin, or '' if unknown."""
    root = os.environ.get("CLAUDE_PLUGIN_ROOT", "")
    return _canonical(root) if root else ""


def check_write_path(path: str) -> tuple[str, str] | None:
    """Return ``(pattern_name, matched_path)`` for a sensitive write, else None."""
    canonical = _canonical(path)
    if not canonical:
        return None

    plugin_root = _plugin_root_real()
    if plugin_root and (canonical == plugin_root or canonical.startswith(plugin_root + os.sep)):
        return ("portcullis_plugin", canonical)

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


def _emit(pattern_name: str, matched_path: str, action: str, tool_name: str) -> None:
    """Log and emit the ask decision (respecting the per-project allowlist)."""
    if is_suppressed("filesystem_guard", pattern_name=pattern_name, file_path=matched_path):
        log_security_event(
            "filesystem_guard", "allow",
            pattern_matched=pattern_name, command=matched_path,
            extra={"tool": tool_name, "suppressed": True},
        )
        json.dump({}, sys.stdout)
        return

    natural = "deny" if pattern_name in HARD_DENY_PATTERNS else "ask"
    response = clamp_and_emit(
        "filesystem_guard", natural,
        format_alert(pattern_name, matched_path, action),
        pattern_matched=pattern_name, command=matched_path,
    )
    json.dump(response if response else {}, sys.stdout)


def main() -> None:
    """Read stdin, judge the file path for the tool, emit a decision."""
    try:
        raw = sys.stdin.read(MAX_STDIN_BYTES)
        input_data = json.loads(raw)
    except (json.JSONDecodeError, OSError, ValueError):
        json.dump({}, sys.stdout)
        return

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})
    if not isinstance(tool_input, dict):
        json.dump({}, sys.stdout)
        return
    path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""

    if not path:
        json.dump({}, sys.stdout)
        return

    if tool_name in _WRITE_TOOLS:
        result = check_write_path(path)
        action = f"{tool_name} to a sensitive path"
    elif tool_name == "Read":
        result = check_read_path(path)
        action = "Read of a credential store"
    else:
        json.dump({}, sys.stdout)
        return

    if result is None:
        json.dump({}, sys.stdout)
        return

    pattern_name, matched_path = result
    _emit(pattern_name, matched_path, action, tool_name)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        json.dump({}, sys.stdout)
