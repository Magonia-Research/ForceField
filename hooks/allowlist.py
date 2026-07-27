"""Per-project allowlist loader for Claude Code security hooks.

Reads `.claude/hook-allowlist.json` from the current working directory
and provides suppression checks for patterns and file paths.

Schema:
{
  "exfil_guard": {
    "suppress_patterns": ["curl_post_data"],
    "suppress_paths": ["src/api/client.py"]
  },
  "credential_guard": {
    "suppress_paths": ["tests/fixtures/**", "**/*.example"],
    "suppress_patterns": ["generic_secret"]
  },
  "supply_chain_guard": {
    "suppress_patterns": ["global_install"]
  }
}
"""

from __future__ import annotations

import json
import os
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

_MAX_ALLOWLIST_BYTES = 65_536  # 64 KiB — allowlists should be small

_cache: dict[str, Any] | None = None

# Patterns a project-local allowlist may NEVER suppress. The allowlist is read
# from the current working directory, which under Portcullis's threat model is a
# possibly-untrusted repo. Without this lock a malicious project could ship a
# `.claude/hook-allowlist.json` that blinds the very guards defending against its
# own payloads — silencing a `cat .env` secret read or a `git -c core.pager=...`
# RCE primitive the moment its directory becomes the cwd. Suppression of these is
# ignored, so the guard's ask decision still stands. A value of None locks every
# pattern of that guard (and any path-based suppression); a frozenset locks only
# the named patterns, leaving the rest suppressible for legitimate use.
_NEVER_SUPPRESSIBLE: dict[str, frozenset[str] | None] = {
    # Every credential-access pattern reads a secret store into the transcript;
    # none of them may be silenced by a file the untrusted repo itself ships.
    "credential_access_guard": None,
    # Git primitives that hand a repo code execution: config `-c core.pager`/
    # `sshCommand`, a '!'-prefixed alias, a GIT_*_COMMAND env var, a hooks-dir
    # write, or a write to a git config file that arms any of the above. The
    # benign-but-noisy submodule/recursive-clone patterns stay suppressible.
    "git_guard": frozenset({
        "git_config_rce_primitive",
        "git_alias_shell",
        "git_env_rce",
        "git_hooks_dir_write",
        "git_config_file_write",
    }),
}


def _is_never_suppressible(hook_name: str, pattern_name: str | None) -> bool:
    """Report whether suppression is forbidden for this hook/pattern.

    A hook mapped to ``None`` is locked wholesale (every pattern, and any
    path-based suppression); a hook mapped to a frozenset locks only the named
    patterns. An unlisted hook is never locked here.
    """
    if hook_name not in _NEVER_SUPPRESSIBLE:
        return False
    protected = _NEVER_SUPPRESSIBLE[hook_name]
    if protected is None:
        return True
    return pattern_name is not None and pattern_name in protected


def _load_allowlist() -> dict[str, Any]:
    """Load allowlist from .claude/hook-allowlist.json in cwd."""
    global _cache  # noqa: PLW0603
    if _cache is not None:
        return _cache

    allowlist_path = Path(os.getcwd()) / ".claude" / "hook-allowlist.json"
    if not allowlist_path.exists():
        _cache = {}
        return _cache

    try:
        raw = allowlist_path.read_text(encoding="utf-8")[:_MAX_ALLOWLIST_BYTES]
        data = json.loads(raw)
        _cache = data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError, ValueError):
        _cache = {}

    return _cache


def is_pattern_suppressed(hook_name: str, pattern_name: str) -> bool:
    """Check if a pattern is suppressed for a given hook.

    A malformed allowlist (a non-dict hook value, or a non-list
    ``suppress_patterns``) reports "not suppressed" rather than crashing —
    suppression is opt-in, so ambiguous config must never wave a danger through.

    A pattern in ``_NEVER_SUPPRESSIBLE`` is never reported suppressed, so a
    repo-shipped allowlist cannot silence a secret read or a git RCE primitive.
    """
    if _is_never_suppressible(hook_name, pattern_name):
        return False
    allowlist = _load_allowlist()
    hook_config = allowlist.get(hook_name, {})
    if not isinstance(hook_config, dict):
        return False
    suppressed = hook_config.get("suppress_patterns", [])
    if not isinstance(suppressed, list):
        return False
    return pattern_name in suppressed


def is_path_suppressed(hook_name: str, file_path: str) -> bool:
    """Check if a file path is suppressed for a given hook (glob match).

    Fails safe on a malformed allowlist the same way ``is_pattern_suppressed``
    does: a non-dict hook value or a non-list ``suppress_paths`` is "not
    suppressed", never a crash.

    A guard locked wholesale in ``_NEVER_SUPPRESSIBLE`` (value ``None``) also
    rejects path-based suppression, so a repo cannot re-open it via a path glob.
    """
    if _is_never_suppressible(hook_name, None):
        return False
    allowlist = _load_allowlist()
    hook_config = allowlist.get(hook_name, {})
    if not isinstance(hook_config, dict):
        return False
    suppressed_paths = hook_config.get("suppress_paths", [])
    if not isinstance(suppressed_paths, list):
        return False

    for glob_pattern in suppressed_paths:
        if fnmatch(file_path, glob_pattern):
            return True

    return False


def is_suppressed(
    hook_name: str,
    pattern_name: str | None = None,
    file_path: str | None = None,
) -> bool:
    """Check if either pattern or path is suppressed.

    Never raises: a malformed allowlist must not crash the calling guard, which
    would ride up to the dispatcher's outer handler and fail the ENTIRE
    dispatcher open. On any unexpected error it reports "not suppressed", so the
    guard proceeds to its ask/deny decision.
    """
    try:
        if pattern_name and is_pattern_suppressed(hook_name, pattern_name):
            return True
        if file_path and is_path_suppressed(hook_name, file_path):
            return True
    except Exception:  # pragma: no cover - defensive fail-safe
        return False
    return False
