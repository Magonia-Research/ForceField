#!/usr/bin/env python3
"""Assertion tests for hooks/config.py (tiered strictness config).

Plain executable assert script, like test_plugin.py: runs top to bottom, stops at
the first failed assert. Exercises the clamp ladder, the full-strength default,
preset resolution, per-guard overrides, the natural-max cap, the Sigma severity
floor, every fail-open path, and the two-source trust model (untrusted project
file vs trusted home file).

The home file (~/.claude/portcullis.json) is pinned to an in-memory value via
``config._home_cache`` so a real home config on the test machine cannot leak in.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "hooks"))

import config  # noqa: E402

_n = 0


def check(cond: bool, msg: str) -> None:
    global _n  # noqa: PLW0603
    assert cond, msg
    _n += 1


@contextmanager
def project(cfg=None):
    """chdir into a temp project whose (untrusted) .claude/portcullis.json is `cfg`.

    Yields the temp dir path. The trusted home layer is pinned empty; a test that
    needs a home config reassigns ``config._home_cache`` inside the block (keying
    any ``projects`` map by the yielded path).

    `cfg` may be a dict (serialized to JSON), a raw string (written verbatim, to
    test malformed input), or None (no file written, to test the missing path).
    """
    prev = os.getcwd()
    with tempfile.TemporaryDirectory() as d:
        real = str(Path(d).resolve())
        claude = Path(real) / ".claude"
        claude.mkdir()
        if cfg is not None:
            body = cfg if isinstance(cfg, str) else json.dumps(cfg)
            (claude / "portcullis.json").write_text(body, encoding="utf-8")
        os.chdir(real)
        config._project_cache = None
        config._home_cache = {}
        try:
            yield real
        finally:
            os.chdir(prev)
            config._project_cache = None
            config._home_cache = None


# --- clamp ladder: downgrade-only, never upgrade, fail-open on unknowns ---
check(config.clamp("deny", "ask") == "ask", "deny clamped to ask")
check(config.clamp("ask", "deny") == "ask", "ceiling above natural leaves natural")
check(config.clamp("deny", "deny") == "deny", "equal ceiling is identity")
check(config.clamp("deny", "off") == "off", "off ceiling suppresses deny")
check(config.clamp("warn", "off") == "off", "off ceiling suppresses warn")
check(config.clamp("allow", "deny") == "allow", "already below ceiling stays")
check(config.clamp("redact", "warn") == "warn", "redact downgraded to warn")
check(config.clamp("redact", "redact") == "redact", "redact identity")
check(config.clamp("redact", "ask") == "redact", "redact ranks below ask")
check(config.clamp("ask", "redact") == "redact", "ask downgraded to redact")
check(config.clamp("deny", "bogus") == "deny", "unknown ceiling -> unchanged")
check(config.clamp("mystery", "ask") == "mystery", "unknown decision -> unchanged")

# --- no file == full strength (each guard at its natural max) ---
with project(None):
    check(config.resolve_ceiling("exfil_guard") == "deny", "default exfil deny")
    check(config.resolve_ceiling("supply_chain_guard") == "deny", "default supply deny (shipped)")
    check(config.resolve_ceiling("sigma_engine") == "deny", "default sigma deny (real emit)")
    check(config.resolve_ceiling("git_guard") == "ask", "default git ask")
    check(config.resolve_ceiling("credential_guard") == "ask", "default credential_guard ask")
    check(config.resolve_ceiling("filesystem_guard") == "ask", "default filesystem ask")
    check(config.resolve_ceiling("subagent_stop_guard") == "deny", "default subagent_stop deny")
    check(config.effective_decision("supply_chain_guard", "deny") == "deny", "default supply hard-deny preserved")
    check(config.resolve_severity_floor("sigma_engine") == "medium", "default sigma floor medium")
    check(config.effective_decision("some_future_guard", "deny") == "deny", "unknown guard no-op ceiling")

# --- strict preset == full-strength default ---
with project({"preset": "strict"}):
    check(config.resolve_ceiling("supply_chain_guard") == "deny", "strict supply deny")
    check(config.resolve_ceiling("credential_guard") == "ask", "strict credential_guard ask")
    check(config.resolve_ceiling("exfil_guard") == "deny", "strict exfil deny")
    check(config.resolve_severity_floor("sigma_engine") == "low", "strict sigma floor low")

# --- balanced from a PROJECT (untrusted) file: softens to ask; sub-ask floored ---
with project({"preset": "balanced"}):
    check(config.resolve_ceiling("supply_chain_guard") == "ask", "balanced softens supply to ask")
    check(config.resolve_ceiling("sigma_engine") == "ask", "project balanced sigma floored to ask (not warn)")
    check(config.resolve_ceiling("exfil_guard") == "deny", "balanced keeps exfil deny")
    check(config.effective_decision("supply_chain_guard", "deny") == "ask", "balanced supply effective ask")
    check(config.resolve_severity_floor("sigma_engine") == "medium", "balanced sigma floor medium")

# --- balanced from HOME (trusted): full softening, incl sub-ask sigma -> warn ---
with project(None):
    config._home_cache = {"preset": "balanced"}
    check(config.resolve_ceiling("sigma_engine") == "warn", "home balanced softens sigma to warn")
    check(config.resolve_ceiling("supply_chain_guard") == "ask", "home balanced supply ask")

# --- permissive: deny -> ask, nothing disabled ---
with project({"preset": "permissive"}):
    check(config.resolve_ceiling("exfil_guard") == "ask", "permissive exfil ask")
    check(config.resolve_ceiling("container_first") == "ask", "permissive container ask")
    check(config.resolve_ceiling("agent_guard") == "ask", "permissive agent ask")
    check(config.effective_decision("exfil_guard", "deny") == "ask", "permissive exfil effective ask")
    check(config.resolve_severity_floor("sigma_engine") == "high", "permissive sigma floor high")
    check(all(m != "off" for m in config.PRESETS["permissive"].values()), "permissive disables nothing")

# --- untrusted (project) config: blocking guards floored at ask, never off ---
with project({"guards": {"webfetch_guard": {"mode": "off"}}}):
    check(config.resolve_ceiling("webfetch_guard") == "ask", "repo cannot disable webfetch, floored to ask")
    check(config.effective_decision("webfetch_guard", "deny") == "ask", "repo webfetch effective ask")
    check(config.resolve_ceiling("exfil_guard") == "deny", "other guards unaffected by override")

with project({"guards": {"exfil_guard": {"mode": "allow"}, "sigma_engine": {"mode": "off"}}}):
    check(config.resolve_ceiling("exfil_guard") == "ask", "repo cannot allow exfil, floored to ask")
    check(config.resolve_ceiling("sigma_engine") == "ask", "repo cannot disable sigma, floored to ask")

# --- untrusted (project) config: block-only guards cannot be softened at all ---
with project({"guards": {"subagent_stop_guard": {"mode": "off"}, "prompt_credential_guard": {"mode": "ask"}}}):
    check(config.resolve_ceiling("subagent_stop_guard") == "deny", "repo cannot soften block-only subagent_stop")
    check(config.resolve_ceiling("prompt_credential_guard") == "deny", "repo cannot soften block-only prompt_credential")

# --- untrusted (project) config: advisory guards MAY be fully disabled ---
with project({"guards": {"injection_defense": {"mode": "off"}, "agent_output_guard": {"mode": "off"}}}):
    check(config.resolve_ceiling("injection_defense") == "off", "repo may disable advisory injection_defense")
    check(config.resolve_ceiling("agent_output_guard") == "off", "repo may disable advisory agent_output")
    check(config.effective_decision("injection_defense", "warn") == "off", "advisory disabled -> off")

with project({"guards": {"output_credential_scanner": {"mode": "warn"}}}):
    check(config.resolve_ceiling("output_credential_scanner") == "warn", "repo may lower output scanner to warn")

# --- trusted (home) config: may fully disable ANY guard, blocking or block-only ---
with project(None):
    config._home_cache = {"guards": {
        "webfetch_guard": {"mode": "off"},
        "exfil_guard": {"mode": "allow"},
        "subagent_stop_guard": {"mode": "off"},
    }}
    check(config.resolve_ceiling("webfetch_guard") == "off", "home may fully disable webfetch")
    check(config.effective_decision("webfetch_guard", "deny") == "off", "home webfetch effective off")
    check(config.resolve_ceiling("exfil_guard") == "allow", "home may allow exfil")
    check(config.resolve_ceiling("subagent_stop_guard") == "off", "home may disable block-only subagent_stop")

# --- home cap: cannot exceed natural max even from the trusted file ---
with project(None):
    config._home_cache = {"guards": {"git_guard": {"mode": "deny"}}}
    check(config.resolve_ceiling("git_guard") == "ask", "home deny on ask-only guard capped to ask")

# --- home per-project entry: full disable scoped to a specific project path ---
with project(None) as d:
    config._home_cache = {"projects": {d: {"guards": {"webfetch_guard": {"mode": "off"}}}}}
    check(config.resolve_ceiling("webfetch_guard") == "off", "home projects entry disables webfetch here")
    check(config.resolve_ceiling("exfil_guard") == "deny", "unscoped guard stays full strength")

with project(None):
    config._home_cache = {"projects": {"/some/other/path": {"guards": {"webfetch_guard": {"mode": "off"}}}}}
    check(config.resolve_ceiling("webfetch_guard") == "deny", "non-matching projects entry does not apply")

# --- precedence: trusted home overrides the untrusted project floor ---
with project({"guards": {"webfetch_guard": {"mode": "off"}}}) as d:
    check(config.resolve_ceiling("webfetch_guard") == "ask", "project alone floors to ask")
    config._home_cache = {"guards": {"webfetch_guard": {"mode": "off"}}}
    check(config.resolve_ceiling("webfetch_guard") == "off", "home override beats the project floor")
    config._home_cache = {"projects": {d: {"guards": {"webfetch_guard": {"mode": "warn"}}}}}
    check(config.resolve_ceiling("webfetch_guard") == "warn", "home per-project entry beats global + project")

# --- per-guard override: tighten a softened preset back within natural max ---
with project({"preset": "permissive", "guards": {"supply_chain_guard": {"mode": "deny"}}}):
    check(config.resolve_ceiling("supply_chain_guard") == "deny", "override tightens permissive supply to deny")

# --- override cannot exceed natural max (git_guard is ask-only) ---
with project({"guards": {"git_guard": {"mode": "deny"}}}):
    check(config.resolve_ceiling("git_guard") == "ask", "deny override on ask-only guard capped to ask")
    check(config.effective_decision("git_guard", "ask") == "ask", "capped override yields ask")

# --- sigma severity_floor override (advisory knob: project may set it) ---
with project({"preset": "balanced", "guards": {"sigma_engine": {"severity_floor": "high"}}}):
    check(config.resolve_severity_floor("sigma_engine") == "high", "floor override wins")

# --- fail-open paths ---
with project("{ this is not valid json"):
    check(config.resolve_ceiling("exfil_guard") == "deny", "invalid JSON -> full strength")
    check(config.resolve_severity_floor("sigma_engine") == "medium", "invalid JSON floor -> medium")

with project({"preset": "paranoid"}):
    check(config.resolve_ceiling("exfil_guard") == "deny", "unknown preset -> full strength")

with project({"preset": "balanced", "guards": {"exfil_guard": {"mode": "banana"}}}):
    check(config.resolve_ceiling("exfil_guard") == "deny", "bad mode ignored -> preset value")
    check(config.resolve_ceiling("totally_unknown_guard") == "deny", "unknown guard -> natural-max default")

with project("[1, 2, 3]"):
    check(config.resolve_ceiling("exfil_guard") == "deny", "non-dict config -> full strength")

# malformed home config must also fail open (never raises, never blocks)
with project(None):
    config._home_cache = {"projects": "not-a-map", "guards": [1, 2]}
    check(config.resolve_ceiling("exfil_guard") == "deny", "malformed home config -> full strength")

print(f"test_config.py: {_n} assertions passed")
