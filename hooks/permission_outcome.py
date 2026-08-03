"""Record what happened to a tool call after ForceField asked about it.

Every other hook in this plugin records what ForceField *decided*. Nothing
recorded what the user then did, so an ``ask`` in the log had no outcome: a
reconstruction could see that a prompt was raised and could not see whether the
human approved it, rejected it, or never answered. That is the first question
anyone asks of a security prompt.

``PermissionDenied`` closes the denial half. The approval half stays *inferable*
— a ``PostToolUse`` record sharing the same ``tool.call.id`` means the call ran —
and only where ForceField already registers a PostToolUse hook (Bash, Read,
Agent). That limitation is stated rather than papered over: a catch-all
PostToolUse registration for correlation alone would cost a process spawn on
every tool call in the session.

Two things about this event are **unverified**. Whether ``PermissionDenied``
fires on human denials only, or also on policy denials, is not established here
— so ``forcefield.reason`` records the event's own ``reason`` string *without
interpretation*, and ``forcefield.pattern`` is the flat literal ``denied``
rather than a claim about who did the denying. The payload shape is confirmed in
the Claude Code 2.1.220 binary but has not been observed live, which is why
every field is read defensively and a shape this file does not recognise still
produces a record rather than an exception.

The record is ``record_class: "permission"``, so it is unsuppressible by the
level model: an outcome that only exists at one level is an outcome that is
missing from most logs.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from hook_event import (  # noqa: E402
    context_from_event, parse_event, read_stdin_text,
)
from patterns import MAX_STDIN_BYTES  # noqa: E402

try:
    from hook_logging import defer_log, emit  # noqa: E402
except Exception:  # pragma: no cover - logging is best-effort
    def defer_log(*_args, **_kwargs):  # type: ignore[misc]
        return None

    def emit(response=None):  # type: ignore[misc]
        json.dump(response if response else {}, sys.stdout)

# OCSF status_id 2 == Failure. The tool call did not run.
OCSF_STATUS_FAILURE = 2

# How much of the event's own reason text is carried. It is free-form and
# model- or user-supplied, so it goes through the same credential scrub as any
# other attribute (``build_event`` masks every string in ``extra``) and is
# bounded here so one record cannot carry an arbitrary payload.
MAX_REASON_CHARS = 2_000


def build_record(data: dict) -> None:
    """Queue one ``permission.outcome`` record for a denied tool call.

    Queued rather than written, like every other pre-response log call: the
    empty response still has to reach stdout before any sink does any work.
    Never raises: this hook exists to add evidence, and an exception here would
    trade a missing record for a broken hook.
    """
    reason = data.get("reason")
    if not isinstance(reason, str):
        reason = ""
    extra = {"reason": reason[:MAX_REASON_CHARS]}
    permission = data.get("permission_suggestions")
    if isinstance(permission, list) and permission:
        extra["permission_suggestions"] = [
            str(item)[:200] for item in permission[:8]
        ]
    defer_log(
        "permission_outcome", "warn",
        pattern_matched="denied",
        context=context_from_event(data),
        record_class="permission",
        event_name="permission.outcome",
        status_id=OCSF_STATUS_FAILURE,
        extra=extra,
    )


def main() -> None:
    """Read the PermissionDenied event, record it, and say nothing back.

    The response is always ``{}``. This hook observes; the call has already been
    denied by the time it runs, so there is no decision left to make and nothing
    it could usefully add to the model's context.
    """
    raw = read_stdin_text(MAX_STDIN_BYTES)
    data = parse_event(raw)
    if data is None:
        emit({})
        return
    if isinstance(data, dict):
        build_record(data)
    emit({})


if __name__ == "__main__":
    try:
        main()
    except Exception:
        emit({})
