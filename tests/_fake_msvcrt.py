"""A stand-in for the Windows ``msvcrt`` module, for testing the NT lock path.

Reproduces the documented contract of ``msvcrt.locking``:

  - a byte range, starting at the file's CURRENT seek position, ``nbytes`` long
  - ``LK_NBLCK``: raise ``OSError`` immediately if the region cannot be locked
  - ``LK_UNLCK``: release a previously locked region

on top of ``fcntl.lockf``, which is POSIX record locking — byte-range and
per-process, the same shape as the CRT call.

This is an EMULATION for exercising ``portable_lock``'s own seek/lock/unlock and
deadline logic. **It is not evidence about Windows**, and no part of ForceField
has been executed on Windows. ``LK_LOCK`` is deliberately not implemented:
``portable_lock`` never calls it, and a stub pretending to reproduce its
10 × 1 s retry would invite the reader to believe something untested.

**And it is POSIX-only, which is the second half of the same statement.** The
module that stands in for Windows' ``msvcrt`` is built on ``fcntl``, so the
Windows lock branch cannot be exercised *on Windows* with this helper — only the
branch selection and this repository's logic around it, on a POSIX host. The
import is guarded so the census can see that it is deliberate and so that
importing this file on Windows fails with a sentence rather than a
``ModuleNotFoundError``.
"""

import os

try:
    import fcntl
except ImportError as _exc:  # pragma: no cover - the point of the message
    raise ImportError(
        "tests/_fake_msvcrt.py emulates msvcrt.locking on top of fcntl.lockf "
        "and is therefore POSIX-only. On Windows the real msvcrt is present and "
        "portable_lock uses it directly; this stand-in has no purpose there."
    ) from _exc

LK_LOCK = 0
LK_NBLCK = 2
LK_NBRLCK = 3
LK_RLCK = 1
LK_UNLCK = 4


def locking(fd, mode, nbytes):
    start = os.lseek(fd, 0, os.SEEK_CUR)
    if mode == LK_UNLCK:
        fcntl.lockf(fd, fcntl.LOCK_UN, nbytes, start, os.SEEK_SET)
        return
    if mode in (LK_NBLCK, LK_NBRLCK):
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, nbytes, start, os.SEEK_SET)
        return
    raise NotImplementedError("portable_lock must never call LK_LOCK (mode=%r)" % mode)


def get_osfhandle(fd):
    return fd
