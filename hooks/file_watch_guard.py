#!/usr/bin/env python3
"""FileChanged hook: deterministic logging of changes to sensitive paths.

``FileChanged`` is not a post-write tool callback. It is a **filesystem watcher
over absolute paths**, so it fires for a change made by any process at all: a
Bash redirect, a script the agent wrote and then ran, a package postinstall, a
Makefile, an external editor. None of those pass through the Write tool and most
never appear in a command string either, so neither ``PreToolUse[Write|Edit]``
nor the ``BASH_SINK_PATTERNS`` check in ``security_dispatcher`` can see them.
That gap is why this hook exists.

**It cannot block, and that is a property of the event, not a choice.**
``FileChanged``'s ``hookSpecificOutput`` accepts only ``watchPaths`` — no
``permissionDecision``, no ``additionalContext``. The watcher settles for 500 ms
before firing, so by the time this runs the write is already on disk. It can
write a log record, warn the user through ``systemMessage``, and extend its own
watch set. Nothing else.

Registered with an **empty matcher**, which is not cosmetic. Claude Code builds
watch paths from the matcher and then regex-tests that same matcher against the
changed file's *basename*, so a matcher of ``/etc/sudoers`` watches the right
file and then never fires: ``new RegExp("/etc/sudoers").test("sudoers")`` is
false. An empty matcher contributes no watch paths and matches every basename.
The watch set is delivered separately, by ``session_baseline`` through
``SessionStart``'s ``watchPaths``.

Three attribution classes, not two. A change is either accounted for by a gated
tool call, or by ForceField writing its own state, or by nothing — and only the
third is worth a record. The distinction is made from the ledger rather than
from the path, because suppressing ``~/.claude/forcefield/state`` by path would
also blind this hook to an agent editing the spawn counters, which is the
specific thing that directory is watched to catch.

Fail-open, like every other hook here: any error yields an empty response.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from patterns import MAX_STDIN_BYTES  # noqa: E402
from hook_event import (  # noqa: E402
    context_from_event, parse_event, read_stdin_text,
)
from watch_roots import watch_roots  # noqa: E402

try:
    from hook_logging import defer_log, emit  # noqa: E402
except Exception:  # pragma: no cover - logging is best-effort
    def defer_log(*_args, **_kwargs):  # type: ignore[misc]
        return None

    def emit(response=None):  # type: ignore[misc]
        json.dump(response if response else {}, sys.stdout)


def build_response(cwd: str | None) -> dict:
    """Re-assert the full watch set on every event.

    Claude Code's ``updateWatchPaths`` **replaces** the dynamic set rather than
    accumulating into it, and its ``CwdChanged`` handler assigns the new set
    unconditionally. A co-installed hook that returns no ``watchPaths`` therefore
    wipes ours on the next directory change. Re-asserting here is a cheap
    self-heal: the set is rebuilt from the same function ``SessionStart`` used,
    so the two can never disagree.
    """
    return {
        "hookSpecificOutput": {
            "hookEventName": "FileChanged",
            "watchPaths": watch_roots(cwd),
        },
    }


def classify(file_path: str) -> tuple[str, str] | None:
    """``(sink_name, canonical_path)`` if this path is a watched sink, else None.

    ``filesystem_guard``'s patterns are applied verbatim. The watch roots say
    *where to look*; these regexes remain the single source of *what counts*, so
    there is no second copy of the sink knowledge to drift out of step. A path
    matching neither is not recorded at all — the watcher is recursive, so a
    directory root delivers everything beneath it and most of that is noise.
    """
    try:
        from filesystem_guard import (  # noqa: PLC0415
            CONFIG_SINK_PATTERNS, WRITE_SINK_PATTERNS, _canonical,
        )
    except Exception:  # noqa: BLE001 - a broken import is "nothing to say"
        return None

    canonical = _canonical(file_path)
    if not canonical:
        return None
    for patterns in (CONFIG_SINK_PATTERNS, WRITE_SINK_PATTERNS):
        for name, pattern in patterns.items():
            if pattern.search(canonical):
                return (name, canonical)
    return None


def _is_config_sink(sink: str) -> bool:
    try:
        from filesystem_guard import CONFIG_SINK_PATTERNS  # noqa: PLC0415

        return sink in CONFIG_SINK_PATTERNS
    except Exception:  # noqa: BLE001
        return False


def _warning(sink: str, path: str, event: str) -> str:
    return (
        "ForceField: %s changed out of band (%s). Path: %s\n"
        "No tool call in this session accounts for this change. If you did not "
        "make it yourself, treat it as a modification to ForceField's own "
        "control surface." % (sink, event, path[:200])
    )


def main() -> None:
    """Read the FileChanged event, record it if it matters. Fail-open."""
    raw = read_stdin_text(MAX_STDIN_BYTES)
    data = parse_event(raw)
    if data is None:
        emit({})
        return

    # Only these keys are actually present. `permission_mode`, `agent_id`,
    # `agent_type` and `effort` appear in the binary's base-payload builder but
    # are undefined for this event and drop out of the JSON, so nothing here may
    # read them. Measured against a live session, not inferred.
    cwd = data.get("cwd") or None
    file_path = data.get("file_path") or ""
    file_event = data.get("event") or ""
    session_id = data.get("session_id") or ""

    result = classify(file_path) if file_path else None
    if result is None:
        # The verdict-first rule still applies even though there is no verdict:
        # the watch set is this hook's only output, and a hook killed at the 5 s
        # timeout has its stdout discarded wholesale.
        emit(build_response(cwd))
        return

    sink, canonical = result

    try:
        from write_ledger import attribution  # noqa: PLC0415

        source = attribution(session_id, canonical)
    except Exception:  # noqa: BLE001 - an unreadable ledger means "unattributed"
        source = None

    out_of_band = source is None
    response = build_response(cwd)
    if out_of_band and _is_config_sink(sink):
        # The one case worth interrupting for: ForceField's own control surface
        # changed and no tool call passed a gate on the way.
        response["systemMessage"] = _warning(sink, canonical, file_event)

    # `file_path`, not `command`: nothing here ran a command, and this guard
    # takes no memo, which is the only reason the filesystem guard puts its path
    # in the command field. `forcefield.pattern` already carries the sink name,
    # so it is not repeated in `extra`.
    defer_log(
        "file_watch_guard", "allow",
        pattern_matched=sink, file_path=canonical,
        context=context_from_event(data),
        extra={
            "file_event": file_event,
            "out_of_band": out_of_band,
            "attribution": source or "none",
        },
    )
    emit(response)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        emit({})
