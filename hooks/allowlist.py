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
  }
}

Every gating guard is keyed the same way, by its own name. The example above stops at
two; it used to carry a third naming `supply_chain_guard`'s `global_install`, which no
longer exists as a pattern -- whether an install lands on the host is now
`container_first.sh`'s passive reminder rather than an ask that could need relief.
"""

from __future__ import annotations

import json
import os
import sys
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from hook_event import read_regular_text  # noqa: E402

_MAX_ALLOWLIST_BYTES = 65_536  # 64 KiB — allowlists should be small

_cache: dict[str, Any] | None = None

# Patterns a project-local allowlist may NEVER suppress. The allowlist is read
# from the current working directory, which under ForceField's threat model is a
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
    # ForceField's own control surface, plus the OS-level persistence sinks. A
    # write to any of these edits what the guards will do next, so allowing one
    # to be suppressed — or remembered via /forcefield:remember, which defers to
    # this table — lets a single approval disarm the tool permanently. The memo
    # path made that concrete: `forcefield_memos` is a write to ForceField's own
    # stored decisions, and it was memoizable.
    "filesystem_guard": frozenset({
        "forcefield_memos",
        "forcefield_config",
        "forcefield_plugin",
        "hook_allowlist",
        "claude_settings",
        "mcp_config",
        "ssh_authorized_keys",
        "shell_init",
        "launch_agents",
        "cron",
        "git_hooks",
    }),
    # Detectors for a subagent prompt that tries to talk its way past the hooks.
    "agent_guard": frozenset({
        "hook_bypass",
        "security_bypass",
    }),
    # A credential arriving in a subagent's response is the same finding as one
    # arriving from a secret store, one boundary further in, and it is the only
    # check here that blocks. The advisory three stay suppressible.
    "subagent_stop_guard": frozenset({"output_credential"}),
    # The `.gitmodules` exploit signatures the SessionStart repo audit reports.
    # This allowlist is read from the cwd — the very repository being audited —
    # so a repo that could suppress the report of its own CVE-2025-48384 entry
    # would be shipping its own blindfold. Mirrors
    # `git_forensics.DENY_INDICATORS`, restated as literals rather than imported
    # so this module stays dependency-free for the guards that import it on
    # every tool call; `tests/test_repo_audit.py` asserts the two sets are
    # identical, so they cannot drift apart unnoticed. The audit's inventory
    # findings (installed hooks, config keys, a repo-shipped agent config) stay
    # suppressible — those are the ones a project legitimately accepts.
    "repo_audit": frozenset({
        "submodule_path_trailing_cr",
        "submodule_path_dotgit_collision",
        "submodule_path_traversal",
        "submodule_url_ext_transport",
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
    """Load allowlist from .claude/hook-allowlist.json in cwd.

    ``read_regular_text`` rather than ``Path.read_text``, and no ``exists()``
    pre-check: this path lives inside the *untrusted repository* that is the
    hook's cwd, ``exists()`` is True for a FIFO, and ``open()`` on a FIFO in
    read mode blocks until a writer appears — forever, raising nothing, with no
    deadline for any ``except`` to catch. ``is_suppressed`` is imported by 13
    guards and runs BEFORE the verdict is emitted, so unlike a Resource-block
    read the emit-before-log ordering cannot rescue it. Measured with the plain
    read: one ``mkfifo .claude/hook-allowlist.json`` in a repo hung 10 of 19
    guards past the 5 s timeout with zero bytes of stdout and no record —
    ``webfetch_guard``'s hard deny on a tunnelling domain simply absent, and
    ``security.log`` never even created. It also bounds the read rather than the
    parse: the old form read the whole file and sliced afterwards.
    """
    global _cache  # noqa: PLW0603
    if _cache is not None:
        return _cache

    allowlist_path = Path(os.getcwd()) / ".claude" / "hook-allowlist.json"
    raw = read_regular_text(allowlist_path, _MAX_ALLOWLIST_BYTES)
    if not raw:
        _cache = {}
        return _cache

    try:
        data = json.loads(raw)
        _cache = data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, ValueError):
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
