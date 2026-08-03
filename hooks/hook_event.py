"""Reading a Claude Code hook event: the bytes on stdin, and the ids inside it.

Two pure-ish helpers with no dependency on anything else in ``hooks/`` — this is
a leaf of the import graph, so a guard can use it before `hook_logging`,
`config` or `patterns` are reachable.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from typing import Any, Dict

# Correlation keys Claude Code puts on the stdin of a hook event, mapped to the
# name they keep in the returned context. Measured live on Claude Code 2.1.220
# across 9 main-session and 6 in-subagent events, and cross-checked against the
# payload builder in the binary (audit-forensics-gaps §2, §3.1).
_CONTEXT_KEYS = (
    "session_id",
    "tool_use_id",
    "prompt_id",
    "cwd",
    "agent_id",
    "agent_type",
    "permission_mode",
    "tool_name",
    "transcript_path",
    "hook_event_name",
)


def read_stdin_text(limit: int) -> str:
    """Read the hook event as bytes and decode it explicitly.

    NOT the platform locale: on a Windows ANSI code page a text-mode read either
    kills the hook before it sees the event (cp932) or silently re-interprets a
    homoglyph host into text no guard regex was written against (cp1252). The
    same mechanism fires on POSIX under LC_ALL=C. Measured, both.

    ``surrogateescape`` rather than ``replace``: collapsing an invalid byte
    sequence to U+FFFD is itself an evasion, because several distinct hostile
    byte strings become one benign-looking one. Surrogates survive the record
    path only because every serialisation uses ensure_ascii=True.

    ``limit`` is a byte count. A caller detecting an oversized payload compares
    against the *encoded* length, because a decoded prefix is never longer than
    the bytes it came from.

    When ``sys.stdin`` has no binary buffer — an in-process caller that replaced
    it with a text stream — the text read is used unchanged. There are no bytes
    to decode in that case, so there is no encoding to get wrong.
    """
    try:
        stream = getattr(sys.stdin, "buffer", None)
        if stream is None:
            return sys.stdin.read(limit)
        return stream.read(limit).decode("utf-8", "surrogateescape")
    except Exception:  # noqa: BLE001 - fail open: an unreadable stdin is not a verdict
        return ""


def parse_event(raw: Any) -> Any:
    """The hook event as a ``dict``, or ``None`` if it is not inspectable.

    One parse for every guard, because the failure that motivated it is not a
    ``JSONDecodeError``. ``json.loads`` raises **RecursionError** past roughly
    995 levels of nesting, and ``RecursionError`` is a ``RuntimeError``, not a
    ``ValueError`` — so a guard catching ``(json.JSONDecodeError, ValueError)``
    let it escape, past the deliberate "uninspectable implies ask" rung, into the
    module-level ``except Exception: emit({})`` that exists to fail open on a
    *crash*. Measured: adding one sibling key ``"x": [[[…3000 deep…]]]`` to an
    otherwise unchanged event turned ``security_dispatcher``'s 328-byte deny on
    ``nc -e /bin/sh`` and ``webfetch_guard``'s deny on a tunnelling domain into
    ``{}`` in 0.05 s, with no record, and stopped ``agent_guard`` emitting the
    subagent constraints its two-phase design promises even when detection
    crashes. Six of seven guards probed were defeated by that one key.

    A payload that parses but is not a JSON object is ``None`` too: every caller
    immediately does ``.get`` on it, so a top-level string or list is exactly as
    uninspectable as a parse failure, and saying so here keeps that judgement in
    one place rather than in an ``AttributeError`` handler per guard.

    Never raises.
    """
    try:
        data = json.loads(raw)
    except Exception:  # noqa: BLE001 - every parse failure is "uninspectable"
        return None
    return data if isinstance(data, dict) else None


def open_regular_fd(path: Any) -> Any:
    """A read descriptor for ``path`` if it is a **regular file**, else ``None``.

    This is the one primitive every read on the hook path goes through, and it
    exists because ``open()`` on some of the things that can sit at a path a hook
    reads does not return. A FIFO opened ``O_RDONLY`` blocks until a writer
    appears — forever, raising nothing, with no deadline to expire — and the hook
    is then killed at its ``hooks.json`` timeout with its verdict undelivered.
    Measured on this tree, one ``mkfifo`` per path: ``~/.claude/forcefield.json``
    took ``security_dispatcher`` from 0.124 s and a 337-byte deny to 6.005 s and
    **zero bytes of stdout**; the plugin's own ``.claude-plugin/plugin.json``,
    read while building the Resource block of every record, did the same to 19 of
    26 registrations and turned ``container_first.sh``'s ``exit 2`` hard deny on
    ``rm -rf /`` into a SIGKILL; a repository's ``.claude/hook-allowlist.json``
    hung 10 of 19 guards with no record written at all. That timeout is a
    security boundary, not a latency budget: a killed hook delivers no verdict,
    so a computed hard deny becomes a silent allow — and one unprivileged
    ``mkfifo`` no guard denies puts the machine there permanently.

    Two things close it, and both are needed. ``O_NONBLOCK`` makes the *open*
    return rather than wait, and ``S_ISREG`` on the resulting descriptor — not on
    a prior ``stat`` of the path, which is a race — rejects everything that is
    not an ordinary file, because a non-blocking read of a FIFO or a device
    yields no bytes anyway and a hook has no business reading either.

    Never raises. The caller owns the descriptor and must close it.
    """
    try:
        flags = (os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
                 | getattr(os, "O_BINARY", 0))
        descriptor = os.open(str(path), flags)
    except OSError:
        return None
    try:
        if stat.S_ISREG(os.fstat(descriptor).st_mode):
            return descriptor
    except OSError:
        pass
    close_fd(descriptor)
    return None


def close_fd(descriptor: Any) -> None:
    """Close a descriptor, ignoring an already-closed or invalid one."""
    try:
        os.close(descriptor)
    except (OSError, TypeError, ValueError):
        pass


def read_fd(descriptor: Any, limit: int) -> bytes:
    """At most ``limit`` bytes from an already-checked ``descriptor``.

    Loops over short reads, which a non-blocking descriptor can produce even on
    a regular file. Raises whatever ``os.read`` raises; every caller here is
    inside its own ``except``.
    """
    chunks = []
    remaining = max(0, int(limit))
    while remaining > 0:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_regular_bytes(path: Any, limit: int) -> bytes:
    """First ``limit`` bytes of a regular file, or ``b""`` for anything else.

    Bounds the **read**, not a slice taken after the whole file is in memory.
    Never raises: an unreadable file is indistinguishable from an absent one to
    every caller here, which is the fail-open direction for all of them.
    """
    descriptor = open_regular_fd(path)
    if descriptor is None:
        return b""
    try:
        return read_fd(descriptor, limit)
    except Exception:  # noqa: BLE001 - an unreadable file is never a verdict
        return b""
    finally:
        close_fd(descriptor)


def read_regular_text(path: Any, limit: int) -> str:
    """First ``limit`` bytes of a regular file as text, or "" for anything else."""
    return read_regular_bytes(path, limit).decode("utf-8", "replace")


def read_regular_tail(path: Any, limit: int) -> bytes:
    """LAST ``limit`` bytes of a regular file, or ``b""`` for anything else.

    For the two append-only files a hook reads back — the security log's tail in
    ``memo.last_ask`` and the per-session spawn tally in ``agent_guard`` — where
    the interesting end is the newest one. The seek is on the same descriptor the
    ``S_ISREG`` check ran against, so there is no window in which the path could
    become something else between the two. The first line of the returned slice
    may be a partial one; every caller here parses line by line and discards what
    does not parse.
    """
    descriptor = open_regular_fd(path)
    if descriptor is None:
        return b""
    try:
        size = os.fstat(descriptor).st_size
        bound = max(0, int(limit))
        if size > bound:
            os.lseek(descriptor, size - bound, os.SEEK_SET)
        return read_fd(descriptor, bound)
    except Exception:  # noqa: BLE001 - an unreadable file is never a verdict
        return b""
    finally:
        close_fd(descriptor)


def context_from_event(data: Any) -> Dict[str, str]:
    """Correlation fields Claude Code puts on the stdin of every hook event.

    Measured live on Claude Code 2.1.220 across 9 main-session and 6 in-subagent
    events, and cross-checked against the payload builder in the binary
    (audit-forensics-gaps §2, §3.1). Every one of these is already in the dict
    the hook parsed; 38 of 42 call sites drop it.

    Keys returned (absent when the event does not carry them): session_id,
    tool_use_id, prompt_id, cwd, agent_id, agent_type, permission_mode,
    tool_name, transcript_path, hook_event_name.

    Never raises, and never invents: a non-string value is dropped rather than
    coerced, so a correlation id in a record is always the one that arrived.
    """
    context = {}  # type: Dict[str, str]
    try:
        if isinstance(data, dict):
            for key in _CONTEXT_KEYS:
                value = data.get(key)
                if isinstance(value, str) and value:
                    context[key] = value
        if "session_id" not in context:
            # The one environment fallback, measured present in a live hook
            # process (audit-forensics-gaps §3.2).
            fallback = os.environ.get("CLAUDE_CODE_SESSION_ID")
            if fallback:
                context["session_id"] = fallback
    except Exception:  # noqa: BLE001 - correlation is never worth a verdict
        return {}
    return context
