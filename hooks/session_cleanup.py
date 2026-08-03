#!/usr/bin/env python3
"""SessionEnd cleanup hook for Claude Code.

Removes the per-session state under ``~/.claude/forcefield/state``:
``agent_guard``'s spawn-rate counters and ``write_ledger``'s write ledger. It
also sweeps state left behind by sessions that ended without firing this hook
(crash, kill) once it is older than a day, so the directory does not grow
without bound.

SessionEnd hooks have no decision control and cannot block termination, so this
only performs cleanup and returns an empty response. Stdlib-only, fail-open.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from patterns import MAX_STDIN_BYTES  # noqa: E402
from hook_event import (  # noqa: E402
    context_from_event, parse_event, read_stdin_text,
)

try:
    from hook_logging import (  # noqa: E402
        OCSF_LIFECYCLE_STOP, defer_log, emit,
    )
except Exception:  # pragma: no cover - logging is best-effort
    OCSF_LIFECYCLE_STOP = 4

    def defer_log(*_args, **_kwargs):  # type: ignore[misc]
        return None

    def emit(response=None):  # type: ignore[misc]
        json.dump(response if response else {}, sys.stdout)

_STALE_SECONDS = 24 * 3600


def _state_dir() -> Path:
    """The same directory the spawn counters and the write ledger live in.

    Imported rather than restated. This was a hand-copied duplicate kept in sync
    by a comment, so moving the state out of ``$TMPDIR`` would have left this
    hook sweeping a directory nothing writes to any more — cleanup silently
    doing nothing is the kind of failure that goes unnoticed for a long time.
    Falls back to the old location only if the import fails, so a broken module
    cannot stop cleanup from running.
    """
    try:
        from write_ledger import state_dir

        return state_dir()
    except Exception:  # noqa: BLE001 - cleanup must run even with a broken guard
        return Path.home() / ".claude" / "forcefield" / "state"


def _unlink(path: Path) -> bool:
    try:
        path.unlink()
        return True
    except OSError:
        return False


def cleanup_session_state(session_id: str, now: float | None = None) -> int:
    """Remove this session's per-session state and sweep what crashes left behind.

    Two file families, swept the same way: ``agent_guard``'s spawn counters and
    ``write_ledger``'s per-session ledger. The ledger entries expire on their own
    TTL and are bounded on read, so leaving one behind is harmless rather than
    unsafe — but it still names a session id and a set of paths, so it is removed
    with the rest rather than left in ``$HOME`` indefinitely.

    Returns the number of files removed. Never raises.
    """
    if now is None:
        now = time.time()
    state_dir = _state_dir()
    if not state_dir.is_dir():
        return 0

    removed = 0
    if session_id:
        for name in ("spawn-%s.json" % session_id, "ledger-%s.jsonl" % session_id):
            target = state_dir / name
            if target.exists() and _unlink(target):
                removed += 1

    stale_files = []
    for glob in ("spawn-*.json", "ledger-*.jsonl"):
        try:
            stale_files.extend(state_dir.glob(glob))
        except OSError:
            continue

    for path in stale_files:
        try:
            age = now - path.stat().st_mtime
        except OSError:
            continue
        if age > _STALE_SECONDS and _unlink(path):
            removed += 1

    return removed


def main() -> None:
    """Read the SessionEnd event and clean up session state. Fail-open."""
    raw = read_stdin_text(MAX_STDIN_BYTES)
    data = parse_event(raw)
    if data is None:
        emit({})
        return

    session_id = data.get("session_id", "")
    removed = cleanup_session_state(session_id)
    # The session id was read here and then thrown away, so the one record that
    # marks the end of a session could not be joined to the session it ended.
    #
    # This record used to also carry `records_emitted`, `native_writes_skipped`
    # and `native_records_dropped`. It cannot: all three are module globals and
    # every hook is its own process, so this process reports only its own work
    # and it did none of theirs. Measured -- a dispatcher that dropped four
    # consecutive denies against an undrained `/dev/log` had
    # `native_records_dropped = 1` in itself and `0` here, and `records_emitted`
    # here was `0` by construction because it was read while building the only
    # record this process will ever emit. They now ride the next record from the
    # process that owns them, beside `forcefield.rotation_failed`, which is the
    # same problem already solved the same way. See `hook_logging.build_event`.
    defer_log(
        "session_cleanup", "allow",
        context=context_from_event(data),
        record_class="lifecycle",
        event_name="session.end",
        activity_id=OCSF_LIFECYCLE_STOP,
        extra={
            "reason": data.get("reason", ""),
            "removed": removed,
        },
    )
    emit({})


if __name__ == "__main__":
    try:
        main()
    except Exception:
        emit({})
