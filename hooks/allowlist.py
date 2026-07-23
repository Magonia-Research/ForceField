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
    """Check if a pattern is suppressed for a given hook."""
    allowlist = _load_allowlist()
    hook_config = allowlist.get(hook_name, {})
    suppressed = hook_config.get("suppress_patterns", [])
    return pattern_name in suppressed


def is_path_suppressed(hook_name: str, file_path: str) -> bool:
    """Check if a file path is suppressed for a given hook (glob match)."""
    allowlist = _load_allowlist()
    hook_config = allowlist.get(hook_name, {})
    suppressed_paths = hook_config.get("suppress_paths", [])

    for glob_pattern in suppressed_paths:
        if fnmatch(file_path, glob_pattern):
            return True

    return False


def is_suppressed(
    hook_name: str,
    pattern_name: str | None = None,
    file_path: str | None = None,
) -> bool:
    """Check if either pattern or path is suppressed."""
    if pattern_name and is_pattern_suppressed(hook_name, pattern_name):
        return True
    if file_path and is_path_suppressed(hook_name, file_path):
        return True
    return False
