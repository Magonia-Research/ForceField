"""Tiered strictness config for Portcullis security hooks.

Reads `.claude/portcullis.json` from the project root and resolves, per guard, a
decision *ceiling* that can only DOWNGRADE a guard's natural decision. The effective
decision is ``clamp(natural, ceiling)`` on the severity ladder::

    deny > ask > redact > warn > allow > off

Because ``clamp`` is downgrade-only, config can only ever *loosen* a guard, never
fabricate a stricter block. This keeps Portcullis' zero-false-positive-deny guarantee
intact through configuration.

Precedence (low -> high):

1. Built-in ``balanced`` preset (constant below; equals today's shipped behavior).
2. Project preset (``portcullis.json`` -> ``"preset"``).
3. Per-guard override (``portcullis.json`` -> ``"guards".<name>.mode``).

The per-project allowlist (``hook-allowlist.json``) stays a separate, most-specific
layer applied by the guards/dispatcher AFTER this clamp; it is not handled here.

Schema::

    {
      "preset": "strict" | "balanced" | "permissive",
      "guards": {
        "<guard_name>": {
          "mode": "deny" | "ask" | "warn" | "allow" | "off",
          "severity_floor": "low" | "medium" | "high"   // sigma_engine only
        }
      }
    }

Fail-open invariant: any missing file, invalid JSON, unknown preset, or malformed
entry falls back to ``balanced`` (or ignores just the bad entry). Nothing here ever
raises or blocks a tool call.

NOTE: this module is intentionally decoupled from ``hook_logging`` so it stays
importable and side-effect-free; diagnostics on a bad config are emitted by the
caller when the clamp is wired into the dispatcher.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

_MAX_CONFIG_BYTES = 65_536  # 64 KiB — the config should be tiny

# Severity/intrusiveness ladder used only for clamping. A higher rank is stricter.
# `redact` (output scanners) sits above `warn` and below `ask`: it silently rewrites
# output rather than interrupting, so it is less intrusive than a prompt.
_RANK = {"off": 0, "allow": 1, "warn": 2, "redact": 3, "ask": 4, "deny": 5}

DEFAULT_PRESET = "balanced"

# Each guard's inherent maximum decision. An override can never raise a guard above
# this (clamp already prevents it; the cap also lets us flag a no-op override).
# PROVISIONAL for sigma_engine / agent_output_guard / subagent_stop_guard — verify
# against real guard emits when wiring the clamp into the dispatcher.
NATURAL_MAX = {
    "container_first": "deny",
    "sigma_engine": "ask",
    "exfil_guard": "deny",
    "supply_chain_guard": "deny",
    "git_guard": "ask",
    "credential_access_guard": "ask",
    "credential_guard": "deny",
    "mcp_guard": "ask",
    "agent_guard": "deny",
    "webfetch_guard": "deny",
    "injection_defense": "warn",
    "prompt_credential_guard": "deny",
    "output_credential_scanner": "redact",
    "agent_output_guard": "redact",
    "subagent_stop_guard": "ask",
}

# Preset x guard ceilings (R2 matrix). `balanced` == current shipped behavior by
# construction, so a wrong cell is harmless (clamp only downgrades) but the label
# should still match reality — verify the three PROVISIONAL guards above at wiring.
PRESETS = {
    "strict": {
        "container_first": "deny",
        "sigma_engine": "ask",
        "exfil_guard": "deny",
        "supply_chain_guard": "deny",
        "git_guard": "ask",
        "credential_access_guard": "ask",
        "credential_guard": "deny",
        "mcp_guard": "ask",
        "agent_guard": "deny",
        "webfetch_guard": "deny",
        "injection_defense": "warn",
        "prompt_credential_guard": "deny",
        "output_credential_scanner": "redact",
        "agent_output_guard": "redact",
        "subagent_stop_guard": "ask",
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
        "injection_defense": "warn",
        "prompt_credential_guard": "deny",
        "output_credential_scanner": "redact",
        "agent_output_guard": "warn",
        "subagent_stop_guard": "warn",
    },
    "permissive": {
        "container_first": "ask",
        "sigma_engine": "warn",
        "exfil_guard": "ask",
        "supply_chain_guard": "ask",
        "git_guard": "ask",
        "credential_access_guard": "ask",
        "credential_guard": "ask",
        "mcp_guard": "warn",
        "agent_guard": "ask",
        "webfetch_guard": "ask",
        "injection_defense": "warn",
        "prompt_credential_guard": "ask",
        "output_credential_scanner": "warn",
        "agent_output_guard": "warn",
        "subagent_stop_guard": "warn",
    },
}

# Sigma severity floor per preset (only knob beyond `mode`). Lower floor = more rules
# fire. permissive floor is the least noisy.
_PRESET_SEVERITY_FLOOR = {"strict": "low", "balanced": "medium", "permissive": "high"}
_VALID_FLOORS = frozenset(_PRESET_SEVERITY_FLOOR.values())

_cache: dict[str, Any] | None = None


def _load_config() -> dict[str, Any]:
    """Load and cache `.claude/portcullis.json` from cwd; fail-open to ``{}``."""
    global _cache  # noqa: PLW0603
    if _cache is not None:
        return _cache

    config_path = Path(os.getcwd()) / ".claude" / "portcullis.json"
    if not config_path.exists():
        _cache = {}
        return _cache

    try:
        raw = config_path.read_text(encoding="utf-8")[:_MAX_CONFIG_BYTES]
        data = json.loads(raw)
        _cache = data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError, ValueError):
        _cache = {}

    return _cache


def _active_preset(config: dict[str, Any]) -> str:
    """Return the configured preset name, or the default if absent/unknown."""
    preset = config.get("preset")
    return preset if preset in PRESETS else DEFAULT_PRESET


def _guard_override(config: dict[str, Any], guard_name: str) -> dict[str, Any]:
    """Return the per-guard override object, or ``{}`` if absent/malformed."""
    guards = config.get("guards")
    if not isinstance(guards, dict):
        return {}
    override = guards.get(guard_name)
    return override if isinstance(override, dict) else {}


def clamp(decision: str, ceiling: str) -> str:
    """Downgrade ``decision`` to ``ceiling`` if it is stricter; never upgrade.

    Returns ``decision`` unchanged when either value is outside the known ladder, so a
    guard's own novel decision or a malformed ceiling can never make a call stricter or
    raise.
    """
    if decision not in _RANK or ceiling not in _RANK:
        return decision
    return decision if _RANK[decision] <= _RANK[ceiling] else ceiling


def resolve_ceiling(guard_name: str) -> str:
    """Resolve the effective decision ceiling for a guard.

    Applies precedence built-in < preset < per-guard override, then caps the result at
    the guard's natural maximum. Unknown guards get their natural max (a no-op ceiling).
    """
    config = _load_config()
    preset = _active_preset(config)
    natural_max = NATURAL_MAX.get(guard_name, "deny")
    base = PRESETS[preset].get(guard_name, natural_max)

    override_mode = _guard_override(config, guard_name).get("mode")
    ceiling = override_mode if override_mode in _RANK else base

    # An override can never exceed the guard's natural max.
    if _RANK.get(ceiling, 0) > _RANK.get(natural_max, 5):
        ceiling = natural_max
    return ceiling


def resolve_severity_floor(guard_name: str = "sigma_engine") -> str:
    """Resolve the Sigma severity floor (per-guard override else preset default)."""
    config = _load_config()
    override_floor = _guard_override(config, guard_name).get("severity_floor")
    if override_floor in _VALID_FLOORS:
        return override_floor
    return _PRESET_SEVERITY_FLOOR.get(_active_preset(config), "medium")


def effective_decision(guard_name: str, decision: str) -> str:
    """Clamp a guard's natural ``decision`` by its resolved ceiling."""
    return clamp(decision, resolve_ceiling(guard_name))
