#!/usr/bin/env python3
"""Owner-only state primitives for the hooks that keep signed state on disk.

Two hooks persist something they later have to trust: ``inspect_remote`` stores
per-remote decisions, and ``write_ledger`` records the writes a session made.
Both sit under ``$HOME``, both are replaceable by anything running as this user,
and both therefore carry an HMAC. This module owns the three things that makes
necessary — the owner-only directory, the key, and the lock — so neither hook
has to re-derive them and they cannot drift apart.

It used to live in ``memo.py``, which was removed: the remembered-approval
feature it existed for never worked (no ``memos.json`` was ever written) and was
deleted rather than repaired. These primitives outlived it because two other
callers had reached into them.

The MAC raises the bar to same-user; it does not eliminate the threat. Anything
running as this user can read the key. It stops a hand-written record, not a
determined local process running as you.

Stdlib only, like every other runtime hook module.
"""

from __future__ import annotations

import contextlib
import errno
import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from hook_event import read_regular_bytes  # noqa: E402
from portable_lock import FileLock  # noqa: E402

STORE_DIR = Path.home() / ".claude" / "forcefield"

# The key predates this module under its old name. Adopting it keeps the
# signatures already on disk -- ``inspections.json`` in particular -- verifying
# across the rename, and the branch retires itself the first time it runs.
_LEGACY_KEY_NAME = "memo.key"


def key_path() -> Path:
    """Sibling of the store, resolved at call time so redirecting ``STORE_DIR``
    (tests, a non-default HOME) moves the key with it."""
    return STORE_DIR / "store.key"


def lock_path() -> Path:
    return STORE_DIR / "store.lock"


def open_private(path: Path, flags: int) -> int:
    """Open ``path`` with 0600 from the moment it is created, not after.

    ``os.chmod`` after the write leaves a window in which the file exists
    world-readable; on a shared machine that window is all an attacker needs.

    ``O_BINARY`` is 0 on POSIX and is what stops the Windows CRT expanding every
    0x0A on the way out. That matters here beyond newline hygiene: this is the
    descriptor ``store_key`` writes ``os.urandom(32)`` through, and a text-mode
    write would turn a random 32-byte key into a 32-to-40-byte one whose length
    depended on its content.

    ``O_NONBLOCK`` and the ``S_ISREG`` check are the same pair
    ``log_sinks._open_append`` and ``config._read_config`` carry. Every path
    opened here lives under ``$HOME``, which any same-uid process can replace,
    and ``open()`` on a FIFO waits for the other end forever -- raising nothing,
    with no deadline to expire, so no ``except`` and no budget catches it.
    Measured on both floors: ``O_RDWR|O_CREAT`` on a FIFO returns in 0.000 s but
    ``O_WRONLY|O_CREAT|O_TRUNC`` waits for a reader indefinitely.

    ``S_ISREG`` is on the DESCRIPTOR, never on a prior ``stat`` of the path,
    which races. Raising ``OSError`` is what every caller here already handles.
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


def ensure_store_dir() -> None:
    """Create the state directory owner-only, and correct it if it is not.

    A 0600 key inside a 0755 directory is not protected: another account can
    traverse in and replace the key that every signature rests on. A signature is
    worth exactly what the key's confidentiality is worth.
    """
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(STORE_DIR), 0o700)
    except OSError:
        pass


def log_key_distrusted(path: Path) -> None:
    """Record that the key was ignored because its permissions changed.

    Every signed record silently ceasing to verify is exactly the kind of change
    a user experiences as "ForceField started asking again for no reason", so it
    leaves a trail. Best-effort: logging must never be what stops a tool call.
    """
    try:
        from hook_logging import defer_log

        info = path.stat()
        defer_log(
            "secure_store", "warn",
            pattern_matched="key_not_private",
            file_path=str(path),
            extra={
                "reason": "the state key is not owner-only; signed records now "
                          "fail verification",
                "mode": oct(info.st_mode & 0o777),
                "owner_uid": info.st_uid,
            },
        )
    except Exception:  # noqa: BLE001 - never let logging break a lookup
        pass


def key_is_private(path: Path) -> bool:
    """Whether the key file is owned by us and readable by nobody else.

    A key that has become group- or world-accessible -- or that another account
    now owns -- is not evidence of anything and must not be treated as though it
    were. This does not *prevent* a same-user process from reading or replacing
    it; nothing here can. It makes the weakened state detectable.

    ``os.getuid`` is POSIX-only. Where it does not exist there is no owner or
    permission-bit check to make, so the answer is False -- the record does not
    verify -- rather than an ``AttributeError`` escaping into an unverified use.
    """
    getuid = getattr(os, "getuid", None)
    if getuid is None:
        return False
    try:
        info = path.stat()
    except OSError:
        return False
    return info.st_uid == getuid() and not (info.st_mode & 0o077)


def _adopt_legacy_key(path: Path) -> None:
    """Move a pre-rename key into place, best-effort. Atomic on POSIX."""
    legacy = STORE_DIR / _LEGACY_KEY_NAME
    try:
        if not path.exists() and legacy.is_file():
            legacy.replace(path)
    except OSError:
        pass


def store_key() -> bytes | None:
    """The HMAC key for this store, creating it on first use. None on failure.

    Returning None makes every signed record fail verification, which means
    "prompt the user" -- the safe direction. The key never leaves ``$HOME``.
    """
    try:
        ensure_store_dir()
        path = key_path()
        _adopt_legacy_key(path)
        if path.is_file():
            if not key_is_private(path):
                log_key_distrusted(path)
                return None
            # ``read_regular_bytes``, not ``read_bytes``: ``is_file()`` answers
            # about the path and the read then gets a descriptor, so a same-uid
            # process can swap a FIFO in between and ``open()`` waits for a
            # writer with no deadline. 64 rather than 32, so a key file that is
            # too long is visibly too long rather than silently truncated to a
            # valid length.
            key = read_regular_bytes(path, 64)
            return key if len(key) == 32 else None
        key = os.urandom(32)
        descriptor = open_private(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            os.write(descriptor, key)
        finally:
            os.close(descriptor)
        return key
    except FileExistsError:
        key = read_regular_bytes(key_path(), 64)
        return key if len(key) == 32 else None
    except OSError:
        return None


@contextlib.contextmanager
def store_lock(blocking: bool = True):
    """Hold an exclusive lock across a whole read-modify-write.

    Without it the sequence read -> mutate -> write is three operations on one
    object, which admits the lost-update anomaly. Yields None if the lock cannot
    be taken, and callers proceed -- state must never block a tool call.
    """
    handle = None
    lock = None
    try:
        ensure_store_dir()
        handle = os.fdopen(open_private(lock_path(), os.O_RDWR | os.O_CREAT), "r+b")
        # The blocking path carries a deadline too: an unbounded wait could sit
        # past the 5s hook timeout, be killed with its verdict undelivered, and
        # take another guard's hard deny with it. ``FileLock`` never raises, so a
        # failed acquisition is a False and the yield below is unchanged.
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
