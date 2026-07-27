#!/usr/bin/env python3
"""SessionEnd cleanup hook for Claude Code.

Removes the per-session state that ``agent_guard`` writes for spawn-rate
tracking (``spawn-<session_id>.json`` under ``$TMPDIR/portcullis`` or
``~/.claude/state``). It also sweeps spawn state left behind by sessions that
ended without firing this hook (crash, kill) once it is older than a day, so the
state directory does not grow without bound.

SessionEnd hooks have no decision control and cannot block termination, so this
only performs cleanup and returns an empty response. Stdlib-only, fail-open.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from patterns import MAX_STDIN_BYTES  # noqa: E402

try:
    from hook_logging import log_security_event  # noqa: E402
except Exception:  # pragma: no cover - logging is best-effort
    def log_security_event(*_args, **_kwargs):  # type: ignore[misc]
        return {}

# Match agent_guard._state_dir(): honor $TMPDIR, else ~/.claude/state.
_STALE_SECONDS = 24 * 3600


def _state_dir() -> Path:
    tmpdir = os.environ.get("TMPDIR", "")
    if tmpdir:
        return Path(tmpdir) / "portcullis"
    return Path.home() / ".claude" / "state"


def _unlink(path: Path) -> bool:
    try:
        path.unlink()
        return True
    except OSError:
        return False


def cleanup_session_state(session_id: str, now: float | None = None) -> int:
    """Remove this session's spawn state and sweep stale spawn files.

    Returns the number of files removed. Never raises.
    """
    if now is None:
        now = time.time()
    state_dir = _state_dir()
    if not state_dir.is_dir():
        return 0

    removed = 0
    if session_id:
        target = state_dir / f"spawn-{session_id}.json"
        if target.exists() and _unlink(target):
            removed += 1

    try:
        stale_files = list(state_dir.glob("spawn-*.json"))
    except OSError:
        stale_files = []

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
    try:
        raw = sys.stdin.read(MAX_STDIN_BYTES)
        data = json.loads(raw)
    except (json.JSONDecodeError, OSError, ValueError):
        json.dump({}, sys.stdout)
        return

    session_id = data.get("session_id", "")
    removed = cleanup_session_state(session_id)
    log_security_event(
        "session_cleanup", "allow",
        extra={"reason": data.get("reason", ""), "removed": removed},
    )
    json.dump({}, sys.stdout)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        json.dump({}, sys.stdout)
