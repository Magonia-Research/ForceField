#!/usr/bin/env python3
"""Assertion tests for hooks/config.py (tiered strictness config).

Plain executable assert script, like test_plugin.py: runs top to bottom, stops at
the first failed assert. Exercises the clamp ladder, the full-strength default,
preset resolution, per-guard overrides, the natural-max cap, the Sigma decision
clamp and severity floor, every fail-open path, and the two-source trust model
(untrusted project file vs trusted home file). Config governs only the eleven
enforcement guards; the advisory/output guards are always-on and not here.

The home file (~/.claude/forcefield.json) is pinned to an in-memory value via
``config._home_cache`` so a real home config on the test machine cannot leak in.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import signal
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

import _isolated_home  # noqa: F401  MUST precede every hook import

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "hooks"))

import config  # noqa: E402

_n = 0


def check(cond: bool, msg: str) -> None:
    global _n  # noqa: PLW0603
    assert cond, msg
    _n += 1


@contextmanager
def project(cfg=None):
    """chdir into a temp project whose (untrusted) .claude/forcefield.json is `cfg`.

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
            (claude / "forcefield.json").write_text(body, encoding="utf-8")
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
check(config.clamp("deny", "bogus") == "deny", "unknown ceiling -> unchanged")
check(config.clamp("mystery", "ask") == "mystery", "unknown decision -> unchanged")

# --- no file == full strength (each enforcement guard at its natural max) ---
with project(None):
    check(config.resolve_ceiling("exfil_guard") == "deny", "default exfil deny")
    check(config.resolve_ceiling("supply_chain_guard") == "deny", "default supply deny (shipped)")
    check(config.resolve_ceiling("container_first") == "deny", "default container deny")
    check(config.resolve_ceiling("webfetch_guard") == "deny", "default webfetch deny")
    check(config.resolve_ceiling("agent_guard") == "deny", "default agent deny")
    check(config.resolve_ceiling("git_guard") == "deny", "default git deny (ext:: transport)")
    check(config.resolve_ceiling("credential_guard") == "ask", "default credential_guard ask")
    check(config.resolve_ceiling("filesystem_guard") == "ask", "default filesystem ask")
    check(config.effective_decision("supply_chain_guard", "deny") == "deny", "default supply hard-deny preserved")
    check(config.resolve_ceiling("sigma_engine") == "warn", "default sigma decision warn")
    check(config.effective_decision("sigma_engine", "ask") == "warn", "default sigma effective warn")
    check(config.resolve_severity_floor("sigma_engine") == "medium", "default sigma floor medium")
    check(config.effective_decision("some_future_guard", "deny") == "deny", "unknown guard no-op ceiling")

    # The no-config default IS the default preset, guard for guard and rung for
    # rung. Asserting the identity rather than a copied table is what stops the
    # two from drifting apart the next time a preset is edited.
    check(config.DEFAULT_PRESET == "balanced", "shipped default preset is balanced")
    for _g, _ceiling in config.PRESETS[config.DEFAULT_PRESET].items():
        for _rung in ("deny", "ask", "warn"):
            check(config.resolve_ceiling(_g, _rung) == config.rung_of(_ceiling, _rung),
                  "no-config %s/%s resolves through the default preset" % (_g, _rung))
    # A guard the default preset does not name keeps its natural max.
    check("subagent_stop_guard" not in config.PRESETS[config.DEFAULT_PRESET],
          "subagent_stop_guard is unnamed by the preset (fixture for the next check)")
    check(config.resolve_ceiling("subagent_stop_guard") == "deny",
          "a guard the default preset omits falls back to its natural max")
    check(config.DEFAULT_SEVERITY_FLOOR == config._PRESET_SEVERITY_FLOOR[config.DEFAULT_PRESET],
          "default severity floor cannot drift from the default preset")
    # container_first.sh skips the python start-up entirely when no config file
    # exists and hardcodes "deny deny" for both rungs. That shortcut is only
    # right while the default preset leaves this guard at its natural max; if a
    # future default softens it, the shell guard would keep blocking and quietly
    # ignore the config. Pinned here because the coupling is invisible from
    # either file alone.
    check(config.PRESETS[config.DEFAULT_PRESET]["container_first"]
          == config.NATURAL_MAX["container_first"] == "deny",
          "container_first.sh's no-config fast path still matches the default preset")

# --- strict preset == full-strength default ---
with project({"preset": "strict"}):
    check(config.resolve_ceiling("supply_chain_guard") == "deny", "strict supply deny")
    check(config.resolve_ceiling("webfetch_guard") == "deny", "strict webfetch deny")
    check(config.resolve_ceiling("exfil_guard") == "deny", "strict exfil deny")
    check(config.resolve_ceiling("sigma_engine") == "ask", "strict sigma decision ask")
    check(config.resolve_severity_floor("sigma_engine") == "low", "strict sigma floor low")

# --- balanced: the shipped default; quieter sigma, same blocking ------------
with project({"preset": "balanced"}):
    check(config.resolve_ceiling("supply_chain_guard") == "deny", "balanced keeps supply deny")
    check(config.resolve_ceiling("webfetch_guard") == "deny", "balanced keeps webfetch deny")
    check(config.resolve_ceiling("exfil_guard") == "deny", "balanced keeps exfil deny")
    check(config.resolve_ceiling("container_first") == "deny", "balanced keeps container deny")
    check(config.effective_decision("supply_chain_guard", "deny") == "deny", "balanced supply effective deny")
    check(config.resolve_ceiling("sigma_engine") == "ask", "balanced sigma warn floored to ask in untrusted project")
    check(config.resolve_severity_floor("sigma_engine") == "medium", "balanced sigma floor medium")

# balanced differs from strict in exactly one guard. Pinned as a set difference
# so widening it is a deliberate edit to this line, not a silent side effect.
_drift = {g for g in config.PRESETS["strict"]
          if config.PRESETS["balanced"].get(g) != config.PRESETS["strict"][g]}
check(_drift == {"sigma_engine"}, "balanced softens sigma_engine and nothing else")

# The inversion that made balanced worth fixing: a plain `ask` ceiling clamps the
# deny rung too, so the default preset was blocking LESS than `passive` -- the
# posture whose entire premise is that it never prompts. No preset may take a
# hard-deny guard's deny rung below `deny`.
for _g, _natural in config.NATURAL_MAX.items():
    if _natural != "deny":
        continue
    for _preset in ("strict", "balanced", "passive"):
        _ceiling = config.PRESETS[_preset].get(_g)
        if _ceiling is None:
            continue
        check(config.rung_of(_ceiling, "deny") == "deny",
              "%s keeps %s's known-exploit rung blocking" % (_preset, _g))

# --- permissive: prompt for everything, block nothing; disables nothing ---
with project({"preset": "permissive"}):
    check(config.resolve_ceiling("exfil_guard") == "ask", "permissive exfil ask")
    check(config.resolve_ceiling("container_first") == "ask", "permissive container ask")
    check(config.resolve_ceiling("agent_guard") == "ask", "permissive agent ask")
    check(config.effective_decision("exfil_guard", "deny") == "ask", "permissive exfil effective ask")
    check(config.resolve_severity_floor("sigma_engine") == "high", "permissive sigma floor high")
    check(all(m != "off" for m in config.PRESETS["permissive"].values()), "permissive disables nothing")

# --- passive: never prompt, still block a known exploit --------------------
# The posture a single ceiling cannot express. A `warn` ceiling would clamp deny
# down to warn along with ask and leave nothing blocking; the per-rung map clamps
# each natural decision independently.
with project(None):
    config._home_cache = {"preset": "passive"}
    for _g in ("exfil_guard", "supply_chain_guard", "container_first",
               "webfetch_guard", "agent_guard", "git_guard"):
        check(config.effective_decision(_g, "deny") == "deny",
              "passive keeps %s hard-deny" % _g)
    for _g in config.PRESETS["passive"]:
        check(config.effective_decision(_g, "ask") == "warn",
              "passive never prompts (%s)" % _g)
    # A guard with no known-exploit tier has nothing to keep: sigma_engine's
    # rules are broad heuristics and it never emits deny, so it is pinned to warn
    # outright rather than given a map that would leave it at ask.
    check(config.PRESETS["passive"]["sigma_engine"] == "warn", "passive pins sigma to warn")
    check(config.resolve_severity_floor("sigma_engine") == "medium", "passive sigma floor medium")

# git_guard is the guard passive was blocked on: with an empty HARD_DENY_PATTERNS
# its natural max was `ask`, so passive would have left the clone-time takeover
# surface with no floor at all.
check(config.NATURAL_MAX["git_guard"] == "deny", "git_guard has a hard-deny floor to keep")

# --- a hostile repo must not be able to select passive ----------------------
# This is the whole point of the untrusted floor, applied per rung: passive's
# `ask -> warn` is below the floor and comes straight back to `ask`, so a cloned
# repo shipping .claude/forcefield.json cannot silence the prompts standing
# between it and the user.
with project({"preset": "passive"}):
    for _g in ("exfil_guard", "container_first", "git_guard", "webfetch_guard"):
        check(config.effective_decision(_g, "ask") == "ask",
              "project-selected passive is floored back to ask (%s)" % _g)
        check(config.effective_decision(_g, "deny") == "deny",
              "project-selected passive still cannot touch deny (%s)" % _g)

# ...and neither can it hand-write the rung map that passive is made of.
with project({"guards": {"exfil_guard": {"mode": {"deny": "off", "ask": "off"}}}}):
    check(config.effective_decision("exfil_guard", "ask") == "ask",
          "hand-written untrusted rung map floored to ask")
    check(config.effective_decision("exfil_guard", "deny") == "ask",
          "untrusted map may soften deny to ask, no further")

# --- rung_of: the reduction every layer above depends on --------------------
check(config.rung_of("warn", "deny") == "warn", "string ceiling governs every rung")
check(config.rung_of({"deny": "deny", "ask": "warn"}, "deny") == "deny", "map: deny rung")
check(config.rung_of({"deny": "deny", "ask": "warn"}, "ask") == "warn", "map: ask rung")
check(config.rung_of({"ask": "warn"}, "deny") == "deny", "unmentioned rung is not downgraded")
check(config.rung_of({"ask": "bogus"}, "ask") == "ask", "unknown rung value -> no downgrade")
check(config.rung_of(None, "deny") == "deny", "malformed ceiling -> no downgrade")
check(config.rung_of({}, "deny") == "deny", "empty map -> no downgrade")

# --- log level: opt-in, trusted-only ----------------------------------------
#
# The old `log_verbosity` key is REPLACED, not aliased. `_read_config` ignores an
# unrecognised key by construction, so an unmigrated file falls back to the
# default -- and the direction of that fallback is the safe one: `gating` was the
# quietest old setting, and `info` is exactly as complete as the old `all`. An
# unmigrated config gets MORE logging, never less.
check(not hasattr(config, "resolve_log_verbosity"),
      "the old verbosity API is gone, not aliased")
check(not hasattr(config, "should_log"), "should_log is gone, not aliased")
check(not hasattr(config, "LOG_VERBOSITY_LEVELS"), "the old level names are gone")

check(config.LOG_LEVELS == ("debug", "info", "warn", "error"),
      "four levels, ordered least to most selective")
check(config.DEFAULT_LOG_LEVEL == "info", "informational by default")

with project(None):
    check(config.resolve_log_level() == "info", "default level is info")

for _name in config.LOG_LEVELS:
    with project(None):
        config._home_cache = {"log_level": _name}
        check(config.resolve_log_level() == _name, "home config selects %s" % _name)

with project(None):
    config._home_cache = {"log_verbosity": "gating"}
    check(config.resolve_log_level() == "info",
          "an unmigrated log_verbosity resolves to info, i.e. more logging")

with project(None):
    config._home_cache = {"log_level": "bogus"}
    check(config.resolve_log_level() == "info", "unknown level falls back to info")

# A repo must not be able to turn down the record of what the guards did. There
# is no floor that makes that safe, so the project tier does not participate at
# all -- unlike a ceiling, which a repo may soften as far as `ask`.
with project({"log_level": "error"}):
    check(config.resolve_log_level() == "info", "project cannot lower the log level")

# A home per-project entry MAY, because the home file is the trusted tier.
with project(None):
    config._home_cache = {"projects": {os.getcwd(): {"log_level": "warn"}}}
    check(config.resolve_log_level() == "warn",
          "a trusted home per-project entry does select the level")

# --- free-text disclosure: can only ever TIGHTEN ----------------------------
check(config.LOG_FREE_TEXT_LEVELS == ("admin", "owner"), "two free-text policies")
check(config.DEFAULT_LOG_FREE_TEXT == "admin", "admin is the shipped policy")
check(config._CONF_ADMIN < config._CONF_OWNER,
      "owner is a strictly higher confidentiality floor than admin")

with project(None):
    check(config.resolve_log_free_text() == "admin", "default is admin")
    check(config.resolve_free_text_confidentiality() == config._CONF_ADMIN,
          "default resolves to the ADMIN confidentiality floor")

with project(None):
    config._home_cache = {"log_free_text": "owner"}
    check(config.resolve_free_text_confidentiality() == config._CONF_OWNER,
          "owner raises the floor to OWNER, i.e. the 0600 file only")

with project({"log_free_text": "owner"}):
    check(config.resolve_free_text_confidentiality() == config._CONF_ADMIN,
          "project tier cannot reach the free-text policy in either direction")

with project(None):
    config._home_cache = {"log_free_text": "bogus"}
    check(config.resolve_free_text_confidentiality() == config._CONF_ADMIN,
          "an unknown policy falls back to the default, never to something looser")

# The integers config restates must equal the ones log_sinks measures against.
# config deliberately imports nothing from hooks/, so this is the pin that stops
# the two drifting.
import log_sinks as _sinks  # noqa: E402

check(config._CONF_ADMIN == _sinks.CONF_ADMIN, "CONF_ADMIN matches log_sinks")
check(config._CONF_OWNER == _sinks.CONF_OWNER, "CONF_OWNER matches log_sinks")

# --- untrusted (project) config: floored at ask, never off/allow/warn ---
with project({"guards": {"webfetch_guard": {"mode": "off"}}}):
    check(config.resolve_ceiling("webfetch_guard") == "ask", "repo cannot disable webfetch, floored to ask")
    check(config.effective_decision("webfetch_guard", "deny") == "ask", "repo webfetch effective ask")
    check(config.resolve_ceiling("exfil_guard") == "deny", "other guards unaffected by override")

with project({"guards": {"exfil_guard": {"mode": "allow"}, "container_first": {"mode": "off"}}}):
    check(config.resolve_ceiling("exfil_guard") == "ask", "repo cannot allow exfil, floored to ask")
    check(config.resolve_ceiling("container_first") == "ask", "repo cannot disable container_first, floored to ask")

with project({"guards": {"sigma_engine": {"mode": "off"}}}):
    check(config.resolve_ceiling("sigma_engine") == "ask", "repo cannot silence sigma, floored to ask")

# --- sigma decision: a trusted home preset drops the heuristic guard to warn ---
with project(None):
    config._home_cache = {"preset": "balanced"}
    check(config.resolve_ceiling("sigma_engine") == "warn", "home balanced sigma -> warn")
    check(config.effective_decision("sigma_engine", "ask") == "warn", "home balanced sigma effective warn")
with project(None):
    config._home_cache = {"preset": "permissive"}
    check(config.resolve_ceiling("sigma_engine") == "warn", "home permissive sigma -> warn")

# --- trusted (home) config: may fully disable any guard ---
with project(None):
    config._home_cache = {"guards": {"webfetch_guard": {"mode": "off"}, "exfil_guard": {"mode": "allow"}}}
    check(config.resolve_ceiling("webfetch_guard") == "off", "home may fully disable webfetch")
    check(config.effective_decision("webfetch_guard", "deny") == "off", "home webfetch effective off")
    check(config.resolve_ceiling("exfil_guard") == "allow", "home may allow exfil")

# --- home cap: cannot exceed natural max even from the trusted file ---
with project(None):
    config._home_cache = {"guards": {"filesystem_guard": {"mode": "deny"}}}
    check(config.resolve_ceiling("filesystem_guard") == "ask", "home deny on ask-only guard capped to ask")

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

# --- override cannot exceed natural max (filesystem_guard is ask-only) ---
with project({"guards": {"filesystem_guard": {"mode": "deny"}}}):
    check(config.resolve_ceiling("filesystem_guard") == "ask", "deny override on ask-only guard capped to ask")
    check(config.effective_decision("filesystem_guard", "ask") == "ask", "capped override yields ask")

# --- sigma severity_floor: a separate knob from the decision clamp above ---
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

# --- a config path that is not a file must not be WAITED on -----------------
#
# "Fail open" has to include "a path that is not a file", and `Path.read_text`
# does not: `open()` on a FIFO in read mode blocks until a writer appears,
# indefinitely, raising nothing. The clamp is resolved before any verdict
# reaches stdout, so this open sits upstream of every ordering guarantee the
# logging path has. Measured before the fix: with `~/.claude/forcefield.json`
# replaced by a FIFO, `security_dispatcher` went from 0.124 s and a 337-byte
# deny to being killed at its 5 s timeout having written ZERO bytes -- the
# exfiltration deny neither delivered nor recorded.
#
# The check needs a DEADLINE, not an elapsed-time assertion afterwards: the
# defect blocks rather than raises, so without one a regression hangs this suite
# until something outside it gives up. `SIGALRM` and `mkfifo` are both POSIX, so
# they are available together.


class _Blocked(Exception):
    pass


@contextmanager
def _deadline(seconds, what):
    handler = getattr(signal, "SIGALRM", None)
    if handler is None:                     # pragma: no cover - Windows
        yield
        return

    def _fire(_signum, _frame):
        raise _Blocked(what)

    previous = signal.signal(handler, _fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(handler, previous)


_fifo_dir = tempfile.mkdtemp(prefix="forcefield-cfg-fifo-")
try:
    _fifo_cfg = pathlib.Path(_fifo_dir) / "forcefield.json"
    os.mkfifo(str(_fifo_cfg))
    _t0 = time.monotonic()
    _blocked = False
    try:
        with _deadline(5.0, "_read_config on a FIFO"):
            _read = config._read_config(_fifo_cfg)
    except _Blocked:
        _read, _blocked = None, True
    _fifo_wall = time.monotonic() - _t0
    check(not _blocked,
          "the config read did not WAIT on a FIFO: it blocked past 5s, which is "
          "the whole hook budget, and this read precedes every verdict")
    check(_fifo_wall < 1.0,
          "a config path that is a FIFO returns immediately (%.3fs)" % _fifo_wall)
    check(_read == {}, "and reads as an absent config rather than raising")

    # A directory, and a file with no read permission, for the same reason.
    _dir_cfg = pathlib.Path(_fifo_dir) / "as-a-dir"
    _dir_cfg.mkdir()
    check(config._read_config(_dir_cfg) == {}, "a directory reads as absent")

    # The ordinary case is unaffected: this must not have cost config its job.
    _real_cfg = pathlib.Path(_fifo_dir) / "real.json"
    _real_cfg.write_text('{"preset": "passive"}', encoding="utf-8")
    check(config._read_config(_real_cfg) == {"preset": "passive"},
          "an ordinary regular config file still reads")
    _big_cfg = pathlib.Path(_fifo_dir) / "big.json"
    _big_cfg.write_text('{"pad": "' + "x" * (config._MAX_CONFIG_BYTES + 4096)
                        + '"}', encoding="utf-8")
    check(config._read_config(_big_cfg) == {},
          "and one past the byte ceiling is truncated into unparseable, not "
          "read whole")

    # --- ...and the OTHER half of that pair, which the case above cannot see.
    #
    # An EMPTY FIFO reads as `{}` whether or not `S_ISREG` is consulted: the
    # read returns nothing and the blanket `except (JSONDecodeError, OSError,
    # ValueError)` swallows the difference. So deleting the check leaves every
    # assertion above passing, and a mutant appending `and False` to it -- which
    # keeps the `S_ISREG`, the `fstat` and the branch -- escaped all 18 suites.
    #
    # A FIFO that has a document QUEUED IN IT separates them. Measured on both
    # floors: with a reader holding the pipe open, a writer can queue a whole
    # config and close, and the next reader gets those bytes and then a clean
    # EOF -- so without `S_ISREG` this returns the ATTACKER's config. It is the
    # HOME tier that carries `log_level` and `log_free_text`, the two keys a
    # project file is deliberately not allowed to touch, so a config arriving
    # through a pipe is a config that can turn the audit trail down.
    _seeded = pathlib.Path(_fifo_dir) / "seeded.json"
    os.mkfifo(str(_seeded))
    _hold = os.open(str(_seeded), os.O_RDONLY | os.O_NONBLOCK)
    try:
        _w = os.open(str(_seeded), os.O_WRONLY)
        os.write(_w, b'{"preset": "passive", "log_level": "error"}')
        os.close(_w)

        # The premise, measured on a SECOND pipe so reading it does not consume
        # the one under test: those bytes really are retrievable this way.
        _premise = pathlib.Path(_fifo_dir) / "premise.json"
        os.mkfifo(str(_premise))
        _phold = os.open(str(_premise), os.O_RDONLY | os.O_NONBLOCK)
        try:
            _pw = os.open(str(_premise), os.O_WRONLY)
            os.write(_pw, b'{"preset": "passive", "log_level": "error"}')
            os.close(_pw)
            _pfd = os.open(str(_premise), os.O_RDONLY | os.O_NONBLOCK)
            try:
                _got = os.read(_pfd, config._MAX_CONFIG_BYTES)
                check(_got == b'{"preset": "passive", "log_level": "error"}'
                      and os.read(_pfd, 16) == b"",
                      "the premise holds on this platform: a queued document is "
                      "delivered whole and then EOF, so O_NONBLOCK is not what "
                      "refuses a seeded FIFO and S_ISREG is")
            finally:
                os.close(_pfd)
        finally:
            os.close(_phold)

        check(config._read_config(_seeded) == {},
              "a config delivered through a pipe is refused, not merged: "
              "S_ISREG on the descriptor is the only barrier here, and the "
              "keys it protects are the HOME-only ones a project file may not "
              "set")
    finally:
        os.close(_hold)
finally:
    shutil.rmtree(_fifo_dir, ignore_errors=True)

# --- Unhashable config values must not raise --------------------------------
# `preset in PRESETS` raised TypeError on an unhashable value, and the exception
# propagated out through resolve_ceiling -> clamp_and_emit to the dispatcher's
# fail-open handler: a repo shipping .claude/forcefield.json with {"preset": {}}
# — the UNTRUSTED tier — silently disabled every Bash guard at once. Config may
# only ever loosen a ceiling; it must never be able to remove the guard.
for _bad in ({}, [], 1, 0.5, True, None, [{"a": 1}], {"nested": {}}):
    with project({"preset": _bad}):
        check(config.resolve_ceiling("exfil_guard") == "deny",
              f"unhashable/odd preset {_bad!r} -> full strength, no raise")
        check(config.resolve_severity_floor() == config.DEFAULT_SEVERITY_FLOOR,
              f"unhashable/odd preset {_bad!r} -> default severity floor")

for _bad in ({}, [], 1, None):
    with project({"guards": {"exfil_guard": {"mode": _bad}}}):
        check(config.resolve_ceiling("exfil_guard") == "deny",
              f"unhashable/odd mode {_bad!r} -> full strength")
    with project({"guards": {"sigma_engine": {"severity_floor": _bad}}}):
        check(config.resolve_severity_floor() == config.DEFAULT_SEVERITY_FLOOR,
              f"unhashable/odd severity_floor {_bad!r} -> default")

# Same shapes in the TRUSTED home tier, including the per-project map.
with project(None):
    config._home_cache = {"preset": {}, "guards": {"exfil_guard": {"mode": []}}}
    check(config.resolve_ceiling("exfil_guard") == "deny",
          "unhashable home preset -> full strength")
    config._home_cache = {"projects": {os.getcwd(): {"preset": []}}}
    check(config.resolve_ceiling("exfil_guard") == "deny",
          "unhashable per-project preset -> full strength")

# The guarantee stated as one property: resolve_* never raises, whatever is in
# the file, and an unparseable config never resolves BELOW the no-config default
# — it loses its ability to loosen rather than gaining the ability to switch a
# guard off. Stated as a band rather than an equality because the two failure
# routes land in different places, and deliberately so: a shape that raises falls
# back to the guard's natural max, while a shape that merely fails validation
# (`{"preset": {}}`) is simply ignored and leaves the default preset standing.
# Both are at or above the default, which is the property that matters.
with project(None):
    _baseline = {_g: config.resolve_ceiling(_g) for _g in config.NATURAL_MAX}
for _shape in ({"preset": {}}, {"guards": {"exfil_guard": {"mode": {}}}},
               {"preset": [], "guards": {"sigma_engine": {"severity_floor": {}}}},
               {"projects": {"/": {"preset": {}}}}):
    with project(_shape):
        for _guard in config.NATURAL_MAX:
            _got = config.resolve_ceiling(_guard)
            check(config._RANK[_got] >= config._RANK[_baseline[_guard]],
                  f"{_guard} not loosened below the default under {_shape!r}")
            check(config._RANK[_got] <= config._RANK[config.NATURAL_MAX[_guard]],
                  f"{_guard} still capped at its natural max under {_shape!r}")

# --- scripts/posture.sh writes what this module reads -----------------------
# The script is the only supported way to set a posture, so it is worth pinning
# that the two agree: it validates against config.PRESETS / LOG_VERBOSITY_LEVELS
# rather than restating them, and it must not clobber hand-written overrides.
import subprocess  # noqa: E402

_POSTURE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "scripts", "posture.sh")


def _posture(args, home):
    env = dict(os.environ, HOME=home)
    return subprocess.run([_POSTURE] + args, env=env, capture_output=True, text=True)


with tempfile.TemporaryDirectory() as _home:
    os.makedirs(os.path.join(_home, ".claude"), exist_ok=True)
    _cfg = os.path.join(_home, ".claude", "forcefield.json")

    _r = _posture(["--preset", "passive", "--log", "warn"], _home)
    check(_r.returncode == 0, "posture.sh sets preset and log")
    with open(_cfg, encoding="utf-8") as _fh:
        _written = json.load(_fh)
    check(_written["preset"] == "passive", "preset written")
    check(_written["log_level"] == "warn", "log_level written")
    check(oct(os.stat(_cfg).st_mode)[-3:] == "600", "config is owner-only")

    _r = _posture(["--free-text", "owner"], _home)
    check(_r.returncode == 0, "posture.sh sets the free-text policy")
    with open(_cfg, encoding="utf-8") as _fh:
        check(json.load(_fh)["log_free_text"] == "owner", "log_free_text written")

    # Every name the script accepts must be one this module understands.
    for _p in config.PRESETS:
        check(_posture(["--preset", _p], _home).returncode == 0, f"accepts preset {_p}")
    for _lv in config.LOG_LEVELS:
        check(_posture(["--log", _lv], _home).returncode == 0, f"accepts log level {_lv}")
    for _ft in config.LOG_FREE_TEXT_LEVELS:
        check(_posture(["--free-text", _ft], _home).returncode == 0,
              f"accepts free-text policy {_ft}")
    check(_posture(["--preset", "nope"], _home).returncode == 2, "rejects unknown preset")
    check(_posture(["--log", "nope"], _home).returncode == 2, "rejects unknown log level")
    check(_posture(["--log", "findings"], _home).returncode == 2,
          "the retired verbosity names are rejected, not silently accepted")
    check(_posture(["--free-text", "nope"], _home).returncode == 2,
          "rejects unknown free-text policy")
    check(_posture(["--wat"], _home).returncode == 2, "rejects unknown flag")

    # --reset owns its own keys and nothing else -- and pops the retired
    # log_verbosity once, as a one-time removal of a dead key.
    with open(_cfg, "w", encoding="utf-8") as _fh:
        json.dump({"preset": "passive", "log_verbosity": "gating",
                   "log_level": "error", "log_free_text": "owner",
                   "guards": {"webfetch_guard": {"mode": "off"}},
                   "projects": {"/tmp/x": {"preset": "strict"}}}, _fh)
    check(_posture(["--reset"], _home).returncode == 0, "reset runs")
    with open(_cfg, encoding="utf-8") as _fh:
        _after = json.load(_fh)
    check("preset" not in _after and "log_level" not in _after
          and "log_free_text" not in _after, "reset clears its own keys")
    check("log_verbosity" not in _after, "reset removes the retired key once")
    check(_after["guards"]["webfetch_guard"]["mode"] == "off", "reset keeps per-guard overrides")
    check("/tmp/x" in _after["projects"], "reset keeps per-project overrides")

print(f"test_config.py: {_n} assertions passed")
