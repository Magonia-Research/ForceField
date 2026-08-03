"""Tiered strictness config for ForceField security hooks.

Resolves, per guard, a decision *ceiling* that can only DOWNGRADE a guard's
natural decision. The effective decision is ``clamp(natural, ceiling)`` on the
severity ladder::

    deny > ask > redact > warn > allow > off

Because ``clamp`` is downgrade-only, config can only ever *loosen* a guard, never
fabricate a stricter block. This keeps ForceField's zero-false-positive-deny
guarantee intact through configuration.

Scope: the enforcement guards
-----------------------------

Config governs the eleven guards that gate or prompt on a tool call (Bash /
Write / Read / WebFetch / MCP / Agent) -- the ones that create friction worth
tuning. That includes ``sigma_engine``, which prompts (``ask``) on a SigmaHQ
rule match and whose severity floor is separately tunable per preset. The
advisory and output guards (injection_defense, agent_output_guard,
output_credential_scanner, the prompt/subagent credential guards) are
intentionally always-on and NOT configurable here: they warn or redact rather
than block, so there is no friction to relax, and a repo should never be able to
silence a security warning or secret redaction.

The default posture
-------------------

With NO config file, guards resolve through ``DEFAULT_PRESET`` (``balanced``).
Measured against the previous ``NATURAL_MAX`` default, that changes exactly one
decision: a SigmaHQ rule match drops from a prompt to a non-blocking warning.
Every blocking guard keeps its full ceiling, so nothing that blocked before
stops blocking, and a guard the default preset does not name still falls back to
its ``NATURAL_MAX``. Loosening past the default stays strictly opt-in: a preset
or a per-guard override in a config file.

Two sources, separated by trust
-------------------------------

* ``~/.claude/forcefield.json`` -- the machine owner's HOME config. **Trusted:**
  only the user can write their home directory. It may loosen any guard to any
  rung, including fully disabling one (``allow`` / ``off``). It may scope
  overrides to specific projects with a ``"projects"`` map keyed by an absolute
  path prefix, so "disable webfetch for /path/to/foo" lives here.

* ``<cwd>/.claude/forcefield.json`` -- the PROJECT config. **Untrusted:** the cwd
  is a possibly-hostile repo under ForceField's threat model, so this file may be
  shipped by the very code the guards defend against. It may soften a guard only
  to ``ask`` -- never to ``warn`` / ``allow`` / ``off``. This mirrors
  ``allowlist.py``'s ``_NEVER_SUPPRESSIBLE`` lock: a cloned repo cannot blind the
  guard standing between it and exfiltration. To fully disable a guard for a
  project, put it in your HOME config (optionally under ``projects``).

Schema (both files share it; ``projects`` is honored in the HOME file only)::

    {
      "preset": "strict" | "balanced" | "permissive" | "passive",
      "guards": {
        "<guard_name>": {
          "mode": "deny" | "ask" | "warn" | "allow" | "off"
                | {"deny": "deny", "ask": "warn"},     // per-rung map
          "severity_floor": "low" | "medium" | "high"   // sigma_engine only
        }
      },
      "log_level": "debug" | "info" | "warn" | "error",   // HOME file only
      "log_free_text": "admin" | "owner",                 // HOME file only
      "projects": {                                       // HOME file only
        "/abs/path/prefix": { "preset": ..., "guards": ... }
      }
    }

``log_level`` and ``log_free_text`` are read from the HOME file (and its
``projects`` entries) only -- see ``_resolve_home_only``.

A ``mode`` is either a single rung, which clamps every decision at or above it,
or a per-rung map, which clamps each natural decision independently and leaves
unmentioned rungs alone. The map exists for the ``passive`` posture: "never
prompt, but still block a known exploit" is ``{"deny": "deny", "ask": "warn"}``
and cannot be written as a single ceiling, because a ``warn`` ceiling takes
``deny`` down with it and leaves nothing blocking.

The untrusted floor applies per rung, so a repo cannot select ``passive`` (or
hand-write its rung map) to silence its own prompts -- ``ask -> warn`` is below
the floor and is raised straight back to ``ask``.

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
import stat
from pathlib import Path
from typing import Any

_MAX_CONFIG_BYTES = 65_536  # 64 KiB — the config should be tiny

# Severity/intrusiveness ladder used only for clamping. A higher rank is stricter.
# `redact` sits above `warn` and below `ask`; kept in the ladder so a guard's own
# novel decision clamps sanely, even though no enforcement guard emits it.
_RANK = {"off": 0, "allow": 1, "warn": 2, "redact": 3, "ask": 4, "deny": 5}

# What a user may actually write as a ``mode``. ``redact`` is in the ladder for
# clamping arithmetic but is NOT settable: ``hook_logging`` maps deny/ask to a
# permission decision and warn to a systemMessage, and returns None for anything
# else — so configuring the "stricter" redact silenced a guard completely while
# the weaker warn still surfaced a message. The ladder and the emitted behaviour
# have to agree, and the honest way to fix that is to stop offering the rung.
SETTABLE_MODES = ("deny", "ask", "warn", "allow", "off")

# Each enforcement guard's inherent maximum decision == the strictest thing it
# actually emits (verified 2026-07-24 against the guard source). This is the
# no-config default: resolve_ceiling starts here, so an unconfigured guard is
# never downgraded. The cap also lets a too-loud override be a harmless no-op.
# A guard NOT listed here is not config-governed (it is always-on).
NATURAL_MAX = {
    "container_first": "deny",          # container_first.sh blocks (exit 2)
    "exfil_guard": "deny",              # HARD_DENY_PATTERNS non-empty
    "supply_chain_guard": "deny",       # HARD_DENY_PATTERNS non-empty
    "git_guard": "deny",                # HARD_DENY_PATTERNS = {"git_ext_transport_rce"}
    "credential_access_guard": "ask",   # HARD_DENY_PATTERNS empty
    "credential_guard": "ask",          # emits only "ask"
    "mcp_guard": "ask",                 # emits only "ask"
    "agent_guard": "deny",              # emits "deny" for high-confidence
    "webfetch_guard": "deny",           # HARD_DENY_PATTERNS = {"exfil_domain"}
    "filesystem_guard": "ask",          # HARD_DENY_PATTERNS empty
    "sigma_engine": "ask",              # prompts on a SigmaHQ rule match (never deny)
    "subagent_stop_guard": "deny",      # blocks a subagent response carrying a credential
}

# The passive posture: never prompt, always record, keep working -- except for
# the well-known-exploit rung, which still blocks outright.
#
# This is the one posture a single ceiling cannot express. A ceiling clamps every
# decision at or above it, so `warn` would take `deny` down to `warn` along with
# `ask` and leave nothing blocking at all. A per-rung MAP clamps each natural
# decision independently: `deny` is left alone, `ask` becomes a logged warning.
#
# `deny` is exactly the right thing to leave standing. A guard emits it only for
# a pattern in its own HARD_DENY_PATTERNS -- the zero-false-positive,
# known-exploit set -- while everything heuristic emits `ask`. So "block the
# well-known exploit, never prompt for anything else" is already the line the
# guards draw internally; passive just stops converting the rest into questions.
PASSIVE_RUNGS = {"deny": "deny", "ask": "warn", "redact": "warn"}

# Preset x guard ceilings. `strict` == NATURAL_MAX by construction (an explicit
# "full strength"). `balanced` is the shipped default (DEFAULT_PRESET below) and
# differs from strict in exactly one place: the heuristic sigma_engine drops from
# a prompt to a non-blocking warn. It deliberately does NOT soften the blocking
# guards. Their `deny` fires only on a HARD_DENY_PATTERNS hit, and a plain `ask`
# ceiling clamps every rung at or above it -- so softening them to "ask" took the
# known-exploit rung down too, and left the default blocking strictly less than
# `passive`, which keeps that rung via a per-rung map. `permissive` prompts for
# everything and blocks nothing, except the noisy sigma_engine which it also
# drops to warn. `passive` never prompts at all. All values stay <= NATURAL_MAX.
#
# A preset value is either a single rung (clamps everything at or above it) or a
# per-rung map (clamps each natural decision independently).
PRESETS = {
    "strict": {
        "container_first": "deny",
        "exfil_guard": "deny",
        "supply_chain_guard": "deny",
        "git_guard": "deny",
        "credential_access_guard": "ask",
        "credential_guard": "ask",
        "mcp_guard": "ask",
        "agent_guard": "deny",
        "webfetch_guard": "deny",
        "filesystem_guard": "ask",
        "sigma_engine": "ask",
    },
    "balanced": {
        "container_first": "deny",
        "exfil_guard": "deny",
        "supply_chain_guard": "deny",
        "git_guard": "deny",
        "credential_access_guard": "ask",
        "credential_guard": "ask",
        "mcp_guard": "ask",
        "agent_guard": "deny",
        "webfetch_guard": "deny",
        "filesystem_guard": "ask",
        "sigma_engine": "warn",
    },
    "permissive": {
        "container_first": "ask",
        "exfil_guard": "ask",
        "supply_chain_guard": "ask",
        "git_guard": "ask",
        "credential_access_guard": "ask",
        "credential_guard": "ask",
        "mcp_guard": "ask",
        "agent_guard": "ask",
        "webfetch_guard": "ask",
        "filesystem_guard": "ask",
        "sigma_engine": "warn",
    },
    # Every guard keeps its hard-deny floor and stops prompting. sigma_engine is
    # the exception that proves the rule: it never emits `deny` (its rules are
    # broad heuristics), so a rung map would leave it at `ask` -- it is pinned to
    # `warn` outright, which is what "never prompt" means for a guard with no
    # known-exploit tier.
    "passive": {
        "container_first": PASSIVE_RUNGS,
        "exfil_guard": PASSIVE_RUNGS,
        "supply_chain_guard": PASSIVE_RUNGS,
        "git_guard": PASSIVE_RUNGS,
        "credential_access_guard": PASSIVE_RUNGS,
        "credential_guard": PASSIVE_RUNGS,
        "mcp_guard": PASSIVE_RUNGS,
        "agent_guard": PASSIVE_RUNGS,
        "webfetch_guard": PASSIVE_RUNGS,
        "filesystem_guard": PASSIVE_RUNGS,
        "sigma_engine": "warn",
    },
}

# The preset every guard resolves through when no config file names one. This is
# what "shipped behaviour" means from here on: read the `balanced` row above, not
# NATURAL_MAX. NATURAL_MAX remains the ceiling nothing may exceed and the value
# resolve_ceiling falls back to when a config cannot be parsed -- that fallback is
# deliberately STRICTER than the default, so an unreadable file loses the ability
# to loosen instead of gaining the ability to switch a guard off.
DEFAULT_PRESET = "balanced"

# Sigma severity floor per preset, consumed by sigma_engine at evaluation time to
# drop compiled rules below the floor (permissive -> ``high`` quiets the noisiest
# guard without a recompile). A separate knob from the decision clamp above:
# the clamp decides deny/ask/warn on a match, the floor decides which rules can
# match at all. Lower floor = more rules fire. Default is ``medium``.
_PRESET_SEVERITY_FLOOR = {
    "strict": "low",
    "balanced": "medium",
    "permissive": "high",
    # passive keeps balanced's floor: a sigma match costs a log line rather than
    # a prompt, so there is no friction to buy back by raising it.
    "passive": "medium",
}
# Tied to the default preset so the two cannot drift apart: the floor that
# applies with no config is by definition the default preset's floor.
DEFAULT_SEVERITY_FLOOR = _PRESET_SEVERITY_FLOOR[DEFAULT_PRESET]
_VALID_FLOORS = frozenset(_PRESET_SEVERITY_FLOOR.values())

_home_cache: dict[str, Any] | None = None
_project_cache: dict[str, Any] | None = None


def _read_config(path: Path) -> dict[str, Any]:
    """Read one JSON config file; fail-open to ``{}`` on anything unexpected.

    "Anything unexpected" has to include *a path that is not a file*, and that
    is why this does not use ``Path.read_text``. Both config paths are writable
    by the account the hook runs as, and ``open()`` on a FIFO in read mode
    blocks until a writer appears — indefinitely, raising nothing, with no
    deadline. Measured: with ``~/.claude/forcefield.json`` replaced by a FIFO,
    ``security_dispatcher`` went from 0.124 s and a 337-byte deny to being
    killed at its 5 s hook timeout having written **zero bytes**. The clamp is
    resolved before any verdict reaches stdout, so this open is upstream of
    every ordering guarantee the logging path has: nothing downstream can
    recover a verdict that was never produced.

    ``O_NONBLOCK`` makes the open return; ``S_ISREG`` on the *descriptor* (not a
    prior ``stat`` of the path, which races) rejects everything that is not an
    ordinary file. Duplicated from ``hook_event.read_regular_text`` rather than
    imported: ``config.py`` imports nothing from ``hooks/``, which is what keeps
    it in-process importable for ``test_docs.py`` and off every guard's cost.
    """
    descriptor = None
    try:
        flags = (os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
                 | getattr(os, "O_BINARY", 0))
        descriptor = os.open(str(path), flags)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            return {}
        chunks = []
        remaining = _MAX_CONFIG_BYTES
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = json.loads(b"".join(chunks).decode("utf-8", "replace"))
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError, ValueError):
        return {}
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _home_config() -> dict[str, Any]:
    """Load and cache the trusted ``~/.claude/forcefield.json``."""
    global _home_cache  # noqa: PLW0603
    if _home_cache is None:
        _home_cache = _read_config(Path.home() / ".claude" / "forcefield.json")
    return _home_cache


def _project_config() -> dict[str, Any]:
    """Load and cache the untrusted ``<cwd>/.claude/forcefield.json``.

    If the project file resolves to the very same path as the home file (the
    user is working inside their home dir), it is ignored here so the trusted
    home layer handles it once rather than being double-counted as untrusted.
    """
    global _project_cache  # noqa: PLW0603
    if _project_cache is None:
        project_path = Path(os.getcwd()) / ".claude" / "forcefield.json"
        home_path = Path.home() / ".claude" / "forcefield.json"
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


def _valid_rung_map(value: Any) -> bool:
    """True when ``value`` is a per-rung ceiling map with known rungs throughout."""
    return (
        isinstance(value, dict)
        and bool(value)
        and all(
            isinstance(k, str) and k in _RANK and isinstance(v, str) and v in _RANK
            for k, v in value.items()
        )
    )


def rung_of(ceiling: Any, decision: str) -> str:
    """Reduce a ceiling to the single rung governing ``decision``.

    A plain-string ceiling governs every decision. A per-rung map governs each
    natural decision independently; a decision the map does not mention is left
    alone (no downgrade), which is what lets ``passive`` name only the rungs it
    changes. A malformed ceiling reduces to ``decision``, i.e. no downgrade --
    config's failure direction is always "lose the ability to loosen".
    """
    if isinstance(ceiling, dict):
        value = ceiling.get(decision)
        return value if isinstance(value, str) and value in _RANK else decision
    return ceiling if isinstance(ceiling, str) else decision


def _floor_untrusted(guard_name: str, ceiling: Any) -> Any:
    """Raise an untrusted (repo) ceiling back up to ``ask`` for a known guard.

    A repo-shipped config may soften an enforcement guard to a prompt but no
    further; it can never take one to warn/allow/off. An unknown guard is
    returned unchanged (config does not govern it anyway).

    Applied per rung, so the floor survives the arrival of per-rung maps. This is
    the check that stops a hostile repo from shipping ``{"preset": "passive"}``
    and turning every prompt on the machine into a log line it can then ignore:
    passive's ``ask -> warn`` is below the floor and comes straight back up to
    ``ask``, leaving the repo exactly where it started.
    """
    if guard_name not in NATURAL_MAX:
        return ceiling
    if isinstance(ceiling, dict):
        return {k: ("ask" if _RANK.get(v, 5) < _RANK["ask"] else v) for k, v in ceiling.items()}
    if _RANK.get(ceiling, 5) < _RANK["ask"]:
        return "ask"
    return ceiling


def _ceiling_from(config: dict[str, Any], guard_name: str) -> Any:
    """Ceiling this config specifies for the guard, or ``None`` if it says nothing.

    A valid per-guard ``mode`` override wins over the config's preset value. The
    override may be a single rung or a per-rung map, matching what a preset may
    hold, so "passive everywhere except webfetch" is expressible without needing
    a second preset.
    """
    override_mode = _guard_override(config, guard_name).get("mode")
    if isinstance(override_mode, str) and override_mode in SETTABLE_MODES:
        return override_mode
    if _valid_rung_map(override_mode):
        return override_mode
    preset = config.get("preset")
    # ``isinstance`` first, and not merely for tidiness: ``{} in PRESETS`` raises
    # TypeError on an unhashable value, and that exception propagated all the way
    # out through resolve_ceiling -> clamp_and_emit to the dispatcher's fail-open
    # handler. A repo shipping `.claude/forcefield.json` containing `{"preset":{}}`
    # — the *untrusted* tier — silently disabled every Bash guard at once. Config
    # is only ever allowed to loosen a ceiling; it must never be able to remove
    # the guard.
    if isinstance(preset, str) and preset in PRESETS:
        value = PRESETS[preset].get(guard_name)
        if isinstance(value, str) or _valid_rung_map(value):
            return value
    return None


def resolve_ceiling(guard_name: str, decision: str = "deny") -> str:
    """Resolve the effective decision ceiling for a guard's natural ``decision``.

    Starts at the ``DEFAULT_PRESET`` ceiling (or the guard's natural max if that
    preset does not name it), then layers project (untrusted, floored) < home
    (trusted) < home per-project entry, and caps the result back at the natural
    max. With no config, returns the default preset's ceiling.

    ``decision`` selects which rung to report when the resolved ceiling is a
    per-rung map. It defaults to ``deny`` -- the strictest rung and the one every
    caller predating the map was implicitly asking about -- so a single-rung
    ceiling answers identically no matter what is passed.

    Never raises. The module docstring has always promised that, but it rested on
    every reachable path happening to be total — and one was not, which is how a
    repo-shipped config came to disable the Bash dispatcher outright. The failure
    direction here is deliberate: fall back to the guard's *natural max*, the
    strictest thing it emits, so a config ForceField cannot parse loses its
    ability to loosen rather than gaining the ability to switch a guard off.
    """
    natural_max = NATURAL_MAX.get(guard_name, "deny")
    try:
        return _resolve_ceiling_uncaught(guard_name, natural_max, decision)
    except Exception:  # noqa: BLE001 - a malformed config must never kill a guard
        return natural_max


def _resolve_ceiling_uncaught(guard_name: str, natural_max: str, decision: str) -> str:
    """Layer the config tiers. Wrapped by ``resolve_ceiling``; see its docstring."""
    cwd = os.getcwd()
    home = _home_config()

    # The floor of the stack is the default preset, not the natural max. A guard
    # the preset does not name (subagent_stop_guard) keeps its natural max.
    default_ceiling = PRESETS[DEFAULT_PRESET].get(guard_name)
    ceiling: Any = natural_max if default_ceiling is None else default_ceiling

    project_ceiling = _ceiling_from(_project_config(), guard_name)
    if project_ceiling is not None:
        ceiling = _floor_untrusted(guard_name, project_ceiling)

    home_ceiling = _ceiling_from(home, guard_name)
    if home_ceiling is not None:
        ceiling = home_ceiling

    entry_ceiling = _ceiling_from(_home_project_entry(home, cwd), guard_name)
    if entry_ceiling is not None:
        ceiling = entry_ceiling

    # Reduced to a single rung only now, so every layer above could carry a map.
    rung = rung_of(ceiling, decision)
    if _RANK.get(rung, 0) > _RANK.get(natural_max, 5):
        rung = natural_max
    return rung


def resolve_severity_floor(guard_name: str = "sigma_engine") -> str:
    """Resolve the Sigma severity floor (per-guard override else preset default).

    Home wins over project, and a per-project home entry wins over the global home
    value. With no config, returns ``DEFAULT_SEVERITY_FLOOR``. Never raises: an
    unreadable config falls back to the default floor, so a malformed file cannot
    quietly raise the floor and drop every rule below it.
    """
    try:
        home = _home_config()
        cwd = os.getcwd()
        for cfg in (_home_project_entry(home, cwd), home, _project_config()):
            floor = _guard_override(cfg, guard_name).get("severity_floor")
            if isinstance(floor, str) and floor in _VALID_FLOORS:
                return floor
        for cfg in (_home_project_entry(home, cwd), home, _project_config()):
            preset = cfg.get("preset")
            if isinstance(preset, str) and preset in _PRESET_SEVERITY_FLOOR:
                return _PRESET_SEVERITY_FLOOR[preset]
    except Exception:  # noqa: BLE001 - a malformed config must never kill a guard
        return DEFAULT_SEVERITY_FLOOR
    return DEFAULT_SEVERITY_FLOOR


def effective_decision(guard_name: str, decision: str) -> str:
    """Clamp a guard's natural ``decision`` by the ceiling governing that rung."""
    return clamp(decision, resolve_ceiling(guard_name, decision))


# How much of what the guards decide reaches the log. This file resolves the
# level *name* only; ``hook_logging`` owns the name -> SeverityNumber floor map
# and the one severity ladder, so no import is added here and there is still
# exactly one ordering in this module (``_RANK``, which is the *clamp* ladder and
# is never consulted for a logging decision).
#
# ``_RANK`` used to double as the logging ladder, and that reuse was a measured
# defect: at the old ``gating`` level a live ``ghp_`` token found in tool output
# and rewritten out of the transcript logged NOTHING, while a ``warn_low``
# heuristic that redacted nothing WAS logged -- the level model kept the weaker
# evidence and discarded the stronger. Ordering by OTel SeverityNumber fixes it.
#
# ``info`` is the default and is exactly as complete as the old ``all``: every
# decision including the routine ``allow`` per Bash call, and ``off``. Turning
# the audit trail down is opt-in for the same reason loosening a guard is.
LOG_LEVELS = ("debug", "info", "warn", "error")
DEFAULT_LOG_LEVEL = "info"

# Free-text disclosure policy. The *only* thing this key can do is TIGHTEN what
# reaches a shared sink -- there is no value that widens disclosure beyond what
# the per-sink measurement already licenses -- so it is the mirror of the
# "config may only loosen enforcement" rule rather than an exception to it.
#
# The integers mirror ``log_sinks.CONF_*``. They are restated rather than
# imported because this module deliberately imports nothing from ``hooks/``:
# ``test_docs.py`` imports it in-process, and an import edge here is an import
# edge on every hook. A test pins the two sets equal so they cannot drift.
_CONF_OWNER = 3
_CONF_ADMIN = 2
LOG_FREE_TEXT_LEVELS = ("admin", "owner")
DEFAULT_LOG_FREE_TEXT = "admin"
_FREE_TEXT_CONFIDENTIALITY = {"admin": _CONF_ADMIN, "owner": _CONF_OWNER}


def _resolve_home_only(key: str, valid, default: str) -> str:
    """Read one string setting from the trusted HOME config only.

    Deliberately NOT readable from the project file. Every other knob here is
    safe to expose to an untrusted repo because ``_floor_untrusted`` keeps it
    from removing a guard -- but neither of these is a guard. One is the record
    of what the guards did, the other is how much of that record reaches a
    sink other accounts can read, and a repo that could turn either down could
    act less observed. There is no floor that makes that safe, so the project
    tier simply does not participate.

    Never raises; an unreadable or malformed config yields the default.
    """
    try:
        home = _home_config()
        for cfg in (_home_project_entry(home, os.getcwd()), home):
            value = cfg.get(key)
            if isinstance(value, str) and value in valid:
                return value
    except Exception:  # noqa: BLE001 - a malformed config must never kill a guard
        return default
    return default


def resolve_log_level() -> str:
    """Resolve the log level. Trusted (HOME) config only. Never raises."""
    return _resolve_home_only("log_level", LOG_LEVELS, DEFAULT_LOG_LEVEL)


def resolve_log_free_text() -> str:
    """Resolve the free-text disclosure policy name. HOME only. Never raises."""
    return _resolve_home_only(
        "log_free_text", LOG_FREE_TEXT_LEVELS, DEFAULT_LOG_FREE_TEXT,
    )


def resolve_free_text_confidentiality() -> int:
    """The minimum sink confidentiality that may carry free text.

    ``admin`` (the default) lets ``command.line`` reach the file sink, the macOS
    unified log and the systemd journal. ``owner`` restricts it to the 0600 file
    sink alone -- today's macOS behaviour, and it additionally tightens the Linux
    ``/dev/log`` path. Never raises: an unreadable config yields the default,
    which is the same answer a machine with no config gets.
    """
    try:
        return _FREE_TEXT_CONFIDENTIALITY[resolve_log_free_text()]
    except Exception:  # noqa: BLE001 - a malformed config must never kill a guard
        return _CONF_ADMIN
