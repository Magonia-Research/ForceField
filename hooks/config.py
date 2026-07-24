"""Tiered strictness config for Portcullis security hooks.

Resolves, per guard, a decision *ceiling* that can only DOWNGRADE a guard's
natural decision. The effective decision is ``clamp(natural, ceiling)`` on the
severity ladder::

    deny > ask > redact > warn > allow > off

Because ``clamp`` is downgrade-only, config can only ever *loosen* a guard, never
fabricate a stricter block. This keeps Portcullis' zero-false-positive-deny
guarantee intact through configuration.

Default is full strength
------------------------

With NO config file, every guard resolves to its ``NATURAL_MAX`` -- the strictest
decision it actually emits -- so the clamp is a no-op and shipped behavior is
preserved exactly. A security plugin must never silently weaken itself, so
loosening is strictly opt-in: a preset or per-guard override in a config file.

Two sources, separated by trust
-------------------------------

* ``~/.claude/portcullis.json`` -- the machine owner's HOME config. **Trusted:**
  only the user can write their home directory. It may loosen any guard to any
  rung, including fully disabling a blocking guard (``allow`` / ``off``). It may
  scope overrides to specific projects with a ``"projects"`` map keyed by an
  absolute path prefix, so "disable webfetch for /path/to/foo" lives here.

* ``<cwd>/.claude/portcullis.json`` -- the PROJECT config. **Untrusted:** the cwd
  is a possibly-hostile repo under Portcullis' threat model, so this file may be
  shipped by the very code the guards defend against. It may fully disable an
  *advisory* guard, but a *blocking* guard can only be softened to ``ask`` (and a
  block-only guard not at all). This mirrors ``allowlist.py``'s
  ``_NEVER_SUPPRESSIBLE`` lock: a cloned repo cannot blind the guard standing
  between it and exfiltration. To fully disable a blocking guard for a project,
  put it in your HOME config (optionally under ``projects``).

Schema (both files share it; ``projects`` is honored in the HOME file only)::

    {
      "preset": "strict" | "balanced" | "permissive",
      "guards": {
        "<guard_name>": {
          "mode": "deny" | "ask" | "warn" | "allow" | "off",
          "severity_floor": "low" | "medium" | "high"   // sigma_engine only
        }
      },
      "projects": {                                       // HOME file only
        "/abs/path/prefix": { "preset": ..., "guards": ... }
      }
    }

Precedence (low -> high): built-in natural-max < project config (floored) <
home config < home per-project entry matching cwd.

Fail-open invariant: any missing file, invalid JSON, unknown preset, or
malformed entry falls back (that layer is ignored). Nothing here ever raises or
blocks a tool call. Intentionally decoupled from ``hook_logging`` so it stays
importable and side-effect-free.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

_MAX_CONFIG_BYTES = 65_536  # 64 KiB — the config should be tiny

# Severity/intrusiveness ladder used only for clamping. A higher rank is stricter.
# `redact` (output scanners) sits above `warn` and below `ask`: it silently
# rewrites output rather than interrupting, so it is less intrusive than a prompt.
_RANK = {"off": 0, "allow": 1, "warn": 2, "redact": 3, "ask": 4, "deny": 5}

# Each guard's inherent maximum decision == the strictest thing it actually emits
# (verified 2026-07-24 against the guard source). This is the no-config default:
# resolve_ceiling starts here, so an unconfigured guard is never downgraded. The
# cap also lets a too-loud override be a harmless no-op.
NATURAL_MAX = {
    "container_first": "deny",            # container_first.sh blocks (exit 2)
    "sigma_engine": "deny",               # emits permissionDecision "deny" on match
    "exfil_guard": "deny",                # HARD_DENY_PATTERNS non-empty
    "supply_chain_guard": "deny",         # HARD_DENY_PATTERNS non-empty
    "git_guard": "ask",                   # HARD_DENY_PATTERNS empty
    "credential_access_guard": "ask",     # HARD_DENY_PATTERNS empty
    "credential_guard": "ask",            # emits only "ask"
    "mcp_guard": "ask",                   # emits only "ask"
    "agent_guard": "deny",                # emits "deny" for high-confidence
    "webfetch_guard": "deny",             # HARD_DENY_PATTERNS = {"exfil_domain"}
    "filesystem_guard": "ask",            # HARD_DENY_PATTERNS empty
    "injection_defense": "warn",          # PostToolUse systemMessage, cannot block
    "prompt_credential_guard": "deny",    # top-level {"decision": "block"}
    "output_credential_scanner": "redact",  # rewrites output, systemMessage
    "agent_output_guard": "warn",         # systemMessage to parent, cannot block
    "subagent_stop_guard": "deny",        # top-level {"decision": "block"}
}

# Blocking guards: an untrusted (repo) config may soften these only to ``ask``,
# never below. They gate a tool call, so silencing one from a repo-shipped file
# would let hostile code run unguarded.
_BLOCKING_GUARDS = frozenset({
    "container_first",
    "sigma_engine",
    "exfil_guard",
    "supply_chain_guard",
    "git_guard",
    "credential_access_guard",
    "credential_guard",
    "mcp_guard",
    "agent_guard",
    "webfetch_guard",
    "filesystem_guard",
})

# Block-only guards emit a top-level ``{"decision": "block"}`` and have no "ask"
# rung -- softening them below deny just means "do not block". An untrusted config
# therefore cannot soften them at all (floor == their natural max). The user can
# still disable them from the trusted HOME config.
_BLOCK_ONLY_GUARDS = frozenset({
    "prompt_credential_guard",
    "subagent_stop_guard",
})

# Advisory guards (everything not in the two sets above): output redaction,
# lifecycle and PostToolUse warnings. They never block a tool call, so an
# untrusted config may lower them freely, including off.

# Preset x guard ceilings. `strict` == NATURAL_MAX by construction (an explicit
# "full strength", identical to the no-config default). `balanced` and
# `permissive` are progressively looser and apply only when a config selects them.
PRESETS = {
    "strict": {
        "container_first": "deny",
        "sigma_engine": "deny",
        "exfil_guard": "deny",
        "supply_chain_guard": "deny",
        "git_guard": "ask",
        "credential_access_guard": "ask",
        "credential_guard": "ask",
        "mcp_guard": "ask",
        "agent_guard": "deny",
        "webfetch_guard": "deny",
        "filesystem_guard": "ask",
        "injection_defense": "warn",
        "prompt_credential_guard": "deny",
        "output_credential_scanner": "redact",
        "agent_output_guard": "warn",
        "subagent_stop_guard": "deny",
    },
    "balanced": {
        "container_first": "deny",
        "sigma_engine": "warn",
        "exfil_guard": "deny",
        "supply_chain_guard": "ask",
        "git_guard": "ask",
        "credential_access_guard": "ask",
        "credential_guard": "ask",
        "mcp_guard": "ask",
        "agent_guard": "deny",
        "webfetch_guard": "deny",
        "filesystem_guard": "ask",
        "injection_defense": "warn",
        "prompt_credential_guard": "deny",
        "output_credential_scanner": "redact",
        "agent_output_guard": "warn",
        "subagent_stop_guard": "deny",
    },
    "permissive": {
        "container_first": "ask",
        "sigma_engine": "warn",
        "exfil_guard": "ask",
        "supply_chain_guard": "ask",
        "git_guard": "ask",
        "credential_access_guard": "ask",
        "credential_guard": "ask",
        "mcp_guard": "ask",
        "agent_guard": "ask",
        "webfetch_guard": "ask",
        "filesystem_guard": "ask",
        "injection_defense": "warn",
        "prompt_credential_guard": "ask",
        "output_credential_scanner": "warn",
        "agent_output_guard": "warn",
        "subagent_stop_guard": "ask",
    },
}

# Sigma severity floor per preset (only knob beyond `mode`). Lower floor = more
# rules fire. The no-config default is ``medium``.
_PRESET_SEVERITY_FLOOR = {"strict": "low", "balanced": "medium", "permissive": "high"}
DEFAULT_SEVERITY_FLOOR = "medium"
_VALID_FLOORS = frozenset(_PRESET_SEVERITY_FLOOR.values())

_home_cache: dict[str, Any] | None = None
_project_cache: dict[str, Any] | None = None


def _read_config(path: Path) -> dict[str, Any]:
    """Read one JSON config file; fail-open to ``{}`` on anything unexpected."""
    try:
        if not path.exists():
            return {}
        raw = path.read_text(encoding="utf-8")[:_MAX_CONFIG_BYTES]
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError, ValueError):
        return {}


def _home_config() -> dict[str, Any]:
    """Load and cache the trusted ``~/.claude/portcullis.json``."""
    global _home_cache  # noqa: PLW0603
    if _home_cache is None:
        _home_cache = _read_config(Path.home() / ".claude" / "portcullis.json")
    return _home_cache


def _project_config() -> dict[str, Any]:
    """Load and cache the untrusted ``<cwd>/.claude/portcullis.json``.

    If the project file resolves to the very same path as the home file (the
    user is working inside their home dir), it is ignored here so the trusted
    home layer handles it once rather than being double-counted as untrusted.
    """
    global _project_cache  # noqa: PLW0603
    if _project_cache is None:
        project_path = Path(os.getcwd()) / ".claude" / "portcullis.json"
        home_path = Path.home() / ".claude" / "portcullis.json"
        try:
            same = project_path.resolve() == home_path.resolve()
        except OSError:
            same = False
        _project_cache = {} if same else _read_config(project_path)
    return _project_cache


def _guard_override(config: dict[str, Any], guard_name: str) -> dict[str, Any]:
    """Return the per-guard override object, or ``{}`` if absent/malformed."""
    guards = config.get("guards")
    if not isinstance(guards, dict):
        return {}
    override = guards.get(guard_name)
    return override if isinstance(override, dict) else {}


def _home_project_entry(home: dict[str, Any], cwd: str) -> dict[str, Any]:
    """Return the home ``projects`` entry whose path prefix best matches cwd.

    Longest matching absolute-path prefix wins; ``{}`` when none match or the map
    is malformed. This is the only place a project-scoped *full* disable can come
    from, and it lives in the trusted home file.
    """
    projects = home.get("projects")
    if not isinstance(projects, dict):
        return {}
    best: dict[str, Any] = {}
    best_len = -1
    for prefix, entry in projects.items():
        if not isinstance(prefix, str) or not isinstance(entry, dict):
            continue
        normalized = prefix.rstrip("/")
        if (cwd == normalized or cwd.startswith(normalized + "/")) and len(prefix) > best_len:
            best, best_len = entry, len(prefix)
    return best


def clamp(decision: str, ceiling: str) -> str:
    """Downgrade ``decision`` to ``ceiling`` if it is stricter; never upgrade.

    Returns ``decision`` unchanged when either value is outside the known ladder,
    so a guard's own novel decision or a malformed ceiling can never make a call
    stricter or raise.
    """
    if decision not in _RANK or ceiling not in _RANK:
        return decision
    return decision if _RANK[decision] <= _RANK[ceiling] else ceiling


def _floor_untrusted(guard_name: str, ceiling: str) -> str:
    """Raise an untrusted ceiling back up to the floor its guard class allows.

    Blocking guard -> at least ``ask``; block-only guard -> at least its natural
    max (a repo cannot soften it at all); advisory guard -> unchanged.
    """
    if guard_name in _BLOCK_ONLY_GUARDS:
        floor = NATURAL_MAX.get(guard_name, "deny")
    elif guard_name in _BLOCKING_GUARDS:
        floor = "ask"
    else:
        return ceiling
    return ceiling if _RANK.get(ceiling, 5) >= _RANK[floor] else floor


def _ceiling_from(config: dict[str, Any], guard_name: str) -> str | None:
    """Ceiling this config specifies for the guard, or ``None`` if it says nothing.

    A valid per-guard ``mode`` override wins over the config's preset value.
    """
    override_mode = _guard_override(config, guard_name).get("mode")
    if override_mode in _RANK:
        return override_mode
    preset = config.get("preset")
    if preset in PRESETS:
        return PRESETS[preset].get(guard_name)
    return None


def resolve_ceiling(guard_name: str) -> str:
    """Resolve the effective decision ceiling for a guard.

    Starts at the guard's natural max (full strength), then layers project
    (untrusted, floored) < home (trusted) < home per-project entry, and caps the
    result back at the natural max. With no config, returns the natural max, so
    the clamp is a no-op and shipped behavior is preserved.
    """
    natural_max = NATURAL_MAX.get(guard_name, "deny")
    cwd = os.getcwd()
    home = _home_config()

    ceiling = natural_max

    project_ceiling = _ceiling_from(_project_config(), guard_name)
    if project_ceiling is not None:
        ceiling = _floor_untrusted(guard_name, project_ceiling)

    home_ceiling = _ceiling_from(home, guard_name)
    if home_ceiling is not None:
        ceiling = home_ceiling

    entry_ceiling = _ceiling_from(_home_project_entry(home, cwd), guard_name)
    if entry_ceiling is not None:
        ceiling = entry_ceiling

    if _RANK.get(ceiling, 0) > _RANK.get(natural_max, 5):
        ceiling = natural_max
    return ceiling


def resolve_severity_floor(guard_name: str = "sigma_engine") -> str:
    """Resolve the Sigma severity floor (per-guard override else preset default).

    Sigma is advisory for this knob, so both sources may set it; home wins over
    project, and a per-project home entry wins over the global home value. With no
    config, returns ``DEFAULT_SEVERITY_FLOOR``.
    """
    home = _home_config()
    cwd = os.getcwd()
    for cfg in (_home_project_entry(home, cwd), home, _project_config()):
        floor = _guard_override(cfg, guard_name).get("severity_floor")
        if floor in _VALID_FLOORS:
            return floor
    for cfg in (_home_project_entry(home, cwd), home, _project_config()):
        preset = cfg.get("preset")
        if preset in _PRESET_SEVERITY_FLOOR:
            return _PRESET_SEVERITY_FLOOR[preset]
    return DEFAULT_SEVERITY_FLOOR


def effective_decision(guard_name: str, decision: str) -> str:
    """Clamp a guard's natural ``decision`` by its resolved ceiling."""
    return clamp(decision, resolve_ceiling(guard_name))
