"""Cross-platform advisory file locking for ForceField hooks. Stdlib only, 3.9 floor.

One API, three guarantees, on POSIX and on Windows:

* **Exclusive only.** No shared/reader mode. All three call sites in ``hooks/``
  do read-modify-write, so a shared mode would be a footgun with no user.
* **Bounded wait, never unbounded.** Every acquisition carries a deadline. A hook
  has 5 seconds total and the 5s timeout is a security boundary, so a lock that
  can block forever is a lock that can convert a computed hard deny into a
  silent allow. ``timeout=0`` is the non-blocking form.
* **Never raises.** Acquisition returns True/False. Failure to lock is reported,
  never thrown, because the fail-open invariant outranks mutual exclusion.

Why not ``fcntl.flock`` directly and ``msvcrt.locking`` directly at each site:

    POSIX  fcntl.flock    whole-file, ADVISORY, per open-file-description,
                          LOCK_EX|LOCK_NB returns EWOULDBLOCK immediately.
    NT     msvcrt.locking byte-RANGE from the current seek position, MANDATORY
                          (the kernel enforces it against every handle, not just
                          cooperating ones), per process. LK_LOCK retries once a
                          second for 10 attempts then raises -- 10s, which is
                          twice the entire hook budget. LK_NBLCK raises OSError
                          immediately on contention.
                          (docs.python.org/3/library/msvcrt.html#msvcrt.locking)

Two consequences drive the implementation:

1. **Never LK_LOCK.** Bounded blocking is a poll loop over the non-blocking
   primitive with a deadline, identical on both platforms. That also removes any
   need for SIGALRM, which does not exist on Windows either.
2. **Lock a sentinel byte past EOF, not byte 0.** Windows locking is mandatory:
   locking the first byte of the *data* file would make an ordinary read by a
   non-participating process fail with a sharing violation rather than merely
   race. The msvcrt docs state the locked region "may continue beyond the end of
   the file", so locking one byte at a very high offset gives back the advisory
   behaviour the POSIX sites were written against: only processes that ask for
   the lock are affected, and normal I/O on the real bytes is untouched.

Deliberately NOT re-entrant. ``flock`` on the same descriptor is an idempotent
upgrade; ``msvcrt.locking`` refuses overlapping regions ("Multiple regions in a
file may be locked at the same time, but may not overlap"), so a nested
acquisition succeeds on POSIX and fails on Windows. Rather than paper over that
divergence, the contract is: acquire once, release once.

The NT branch has been exercised only against a documented-contract ``msvcrt``
stand-in on POSIX. That proves this module's seek/lock/unlock/deadline logic,
**not** the Win32 kernel: no part of ForceField has been executed on Windows.
"""

from __future__ import annotations

import time
from typing import IO, Optional

try:  # POSIX
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - exercised on Windows
    _fcntl = None  # type: ignore[assignment]

try:  # Windows
    import msvcrt as _msvcrt
except ImportError:  # pragma: no cover - exercised on POSIX
    _msvcrt = None  # type: ignore[assignment]

# One byte, far past any plausible end of file, so a mandatory Windows lock
# never overlaps real data. 0x7FFF_FF00 keeps the region inside a signed 32-bit
# offset, which is the range the CRT _locking() call itself works in.
_SENTINEL_OFFSET = 0x7FFF_FF00
_SENTINEL_BYTES = 1

# How often to retry while waiting out a contended lock. Short enough that a
# 0.5s hold is not rounded up to a whole second, long enough not to spin.
_POLL_SECONDS = 0.01

# Default ceiling on any wait. Chosen well inside the 5s hook timeout so that a
# contended lock costs latency and never the verdict.
DEFAULT_TIMEOUT_SECONDS = 1.0


def _try_lock_once(handle: IO) -> bool:
    """One non-blocking attempt. True if the lock is now held by us."""
    fileno = handle.fileno()
    if _fcntl is not None:
        try:
            _fcntl.flock(fileno, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
            return True
        except OSError:
            return False
    if _msvcrt is not None:
        saved = None
        try:
            saved = handle.tell()
            handle.seek(_SENTINEL_OFFSET)
            _msvcrt.locking(fileno, _msvcrt.LK_NBLCK, _SENTINEL_BYTES)
            return True
        except OSError:
            return False
        finally:
            if saved is not None:
                try:
                    handle.seek(saved)
                except OSError:
                    pass
    return False


def _unlock(handle: IO) -> None:
    """Release. Never raises; closing the handle would release it anyway.

    The whole body is wrapped, not just the syscalls: ``handle.fileno()`` and
    ``handle.tell()`` raise ``ValueError`` -- not ``OSError`` -- on a closed
    handle, and ``release()`` is called from ``finally`` blocks where an
    exception would replace the caller's own.
    """
    try:
        fileno = handle.fileno()
        if _fcntl is not None:
            _fcntl.flock(fileno, _fcntl.LOCK_UN)
            return
        if _msvcrt is not None:
            saved = handle.tell()
            try:
                handle.seek(_SENTINEL_OFFSET)
                _msvcrt.locking(fileno, _msvcrt.LK_UNLCK, _SENTINEL_BYTES)
            finally:
                handle.seek(saved)
    except Exception:  # noqa: BLE001 - a release must never raise into a guard
        pass


class FileLock:
    """Exclusive, bounded-wait, cross-process lock on an already-open handle.

    ``with FileLock(handle) as locked:`` -- ``locked`` is True if the lock is
    held for the body and False if it could not be taken. The body runs either
    way: the caller decides what an unlocked run means. That is deliberate and
    matches ``memo._store_lock``, which yields None and lets the caller proceed
    rather than block a tool call on contention.

    ``timeout=0`` is a single non-blocking attempt.
    """

    def __init__(
        self,
        handle: IO,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        monotonic=time.monotonic,
        sleep=time.sleep,
    ) -> None:
        self._handle = handle
        self._timeout = max(0.0, float(timeout))
        self._monotonic = monotonic
        self._sleep = sleep
        self.locked = False

    def acquire(self) -> bool:
        if self.locked:
            return True
        deadline = self._monotonic() + self._timeout
        while True:
            try:
                if _try_lock_once(self._handle):
                    self.locked = True
                    return True
            except Exception:  # noqa: BLE001 - a lock must never raise into a guard
                return False
            if self._monotonic() >= deadline:
                return False
            self._sleep(_POLL_SECONDS)

    def release(self) -> None:
        if not self.locked:
            return
        _unlock(self._handle)
        self.locked = False

    def __enter__(self) -> bool:
        return self.acquire()

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.release()
        return False


class _NullLock:
    locked = False

    def acquire(self) -> bool:
        return False

    def release(self) -> None:
        return None

    def __enter__(self) -> bool:
        return False

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


def locked_handle(handle: Optional[IO], timeout: float = DEFAULT_TIMEOUT_SECONDS):
    """``FileLock`` for a handle that may be None (an open that already failed)."""
    if handle is None:
        return _NullLock()
    return FileLock(handle, timeout)


def platform_backend() -> str:
    """Which primitive is in use. For the log record and for tests."""
    if _fcntl is not None:
        return "fcntl.flock"
    if _msvcrt is not None:
        return "msvcrt.locking"
    return "none"
