#!/usr/bin/env python3
"""Assertion tests for hooks/config.py (tiered strictness config).

Plain executable assert script, like test_plugin.py: runs top to bottom, stops at the
first failed assert. Exercises the clamp ladder, preset resolution, per-guard overrides,
the natural-max cap, the Sigma severity floor, and every fail-open path.
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
def project_config(cfg):
    """chdir into a temp project whose .claude/portcullis.json is `cfg`.

    `cfg` may be a dict (serialized to JSON), a raw string (written verbatim, to test
    malformed input), or None (no file written, to test the missing-file path).
    """
    prev = os.getcwd()
    with tempfile.TemporaryDirectory() as d:
        claude = Path(d) / ".claude"
        claude.mkdir()
        if cfg is not None:
            body = cfg if isinstance(cfg, str) else json.dumps(cfg)
            (claude / "portcullis.json").write_text(body, encoding="utf-8")
        os.chdir(d)
        config._cache = None
        try:
            yield
        finally:
            os.chdir(prev)
            config._cache = None


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

# --- no file == balanced (today's behavior) ---
with project_config(None):
    check(config.resolve_ceiling("exfil_guard") == "deny", "balanced exfil deny")
    check(config.resolve_ceiling("supply_chain_guard") == "ask", "balanced supply ask")
    check(config.resolve_ceiling("git_guard") == "ask", "balanced git ask")
    check(config.resolve_ceiling("sigma_engine") == "warn", "balanced sigma warn")
    check(config.effective_decision("exfil_guard", "deny") == "deny", "balanced exfil effective deny")
    check(config.resolve_severity_floor("sigma_engine") == "medium", "balanced sigma floor medium")
    check(config.effective_decision("some_future_guard", "deny") == "deny", "unknown guard no-op ceiling")

# --- explicit balanced == default ---
with project_config({"preset": "balanced"}):
    check(config.resolve_ceiling("exfil_guard") == "deny", "explicit balanced == default")

# --- strict: tighter knobs, still never above natural max ---
with project_config({"preset": "strict"}):
    check(config.resolve_ceiling("supply_chain_guard") == "deny", "strict supply deny")
    check(config.resolve_ceiling("credential_guard") == "deny", "strict credential_guard deny")
    check(config.resolve_severity_floor("sigma_engine") == "low", "strict sigma floor low")

# --- permissive: deny -> ask, noisy -> warn, nothing disabled ---
with project_config({"preset": "permissive"}):
    check(config.resolve_ceiling("exfil_guard") == "ask", "permissive exfil ask")
    check(config.resolve_ceiling("container_first") == "ask", "permissive container ask")
    check(config.resolve_ceiling("agent_guard") == "ask", "permissive agent ask")
    check(config.effective_decision("exfil_guard", "deny") == "ask", "permissive exfil effective ask")
    check(config.resolve_severity_floor("sigma_engine") == "high", "permissive sigma floor high")
    check(all(m != "off" for m in config.PRESETS["permissive"].values()), "permissive disables nothing")

# --- per-guard override: disable one guard entirely ---
with project_config({"preset": "balanced", "guards": {"webfetch_guard": {"mode": "off"}}}):
    check(config.resolve_ceiling("webfetch_guard") == "off", "override webfetch off")
    check(config.effective_decision("webfetch_guard", "deny") == "off", "override webfetch effective off")
    check(config.resolve_ceiling("exfil_guard") == "deny", "other guards unaffected by override")

# --- per-guard override: tighten within natural max ---
with project_config({"preset": "balanced", "guards": {"supply_chain_guard": {"mode": "deny"}}}):
    check(config.resolve_ceiling("supply_chain_guard") == "deny", "override tighten supply to deny")

# --- override cannot exceed natural max (git_guard is ask-only) ---
with project_config({"guards": {"git_guard": {"mode": "deny"}}}):
    check(config.resolve_ceiling("git_guard") == "ask", "deny override on ask-only guard capped to ask")
    check(config.effective_decision("git_guard", "ask") == "ask", "capped override yields ask")

# --- sigma severity_floor override ---
with project_config({"preset": "balanced", "guards": {"sigma_engine": {"severity_floor": "high"}}}):
    check(config.resolve_severity_floor("sigma_engine") == "high", "floor override wins")

# --- fail-open paths ---
with project_config("{ this is not valid json"):
    check(config.resolve_ceiling("exfil_guard") == "deny", "invalid JSON -> balanced")
    check(config.resolve_severity_floor("sigma_engine") == "medium", "invalid JSON floor -> medium")

with project_config({"preset": "paranoid"}):
    check(config.resolve_ceiling("exfil_guard") == "deny", "unknown preset -> balanced")

with project_config({"preset": "balanced", "guards": {"exfil_guard": {"mode": "banana"}}}):
    check(config.resolve_ceiling("exfil_guard") == "deny", "bad mode ignored -> preset value")
    check(config.resolve_ceiling("totally_unknown_guard") == "deny", "unknown guard -> natural-max default")

with project_config("[1, 2, 3]"):
    check(config.resolve_ceiling("exfil_guard") == "deny", "non-dict config -> balanced")

print(f"test_config.py: {_n} assertions passed")
