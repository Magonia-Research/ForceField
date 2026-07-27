"""Cross-platform security event logging for Claude Code hooks.

One normalized event is built per decision and encoded to every available sink.
The record shape follows the OpenTelemetry Logs Data Model (field names,
``SeverityNumber``/``SeverityText``) and carries an OCSF Detection Finding
projection (``ocsf.*`` ids) in its ``Attributes``, so a downstream SIEM mapping
is a rename rather than a re-derivation. Timestamps are RFC 3339 (colon offset,
millisecond precision). A single decision->severity table drives all three
sinks, so a new decision can never silently fall through to INFO.

Sinks:
    macOS: Unified Logging via `log emit` (subsystem/category tagging).
    Linux: SysLogHandler to /dev/log (feeds journald), facility LOG_AUTH.
    Both:  RotatingFileHandler to ~/.claude/hooks/security.log (JSON Lines).

Query examples:

    # macOS - all hook events from last hour
    log show --predicate 'subsystem == "com.anthropic.claude-code.hooks"' \
        --style ndjson --last 1h

    # Fallback file - only high-severity findings (deny/block => ocsf 4)
    jq -c 'select(.Attributes."ocsf.severity_id" >= 4)' ~/.claude/hooks/security.log

    # Fallback file - by OTel severity text
    jq -c 'select(.SeverityText == "ERROR")' ~/.claude/hooks/security.log

    # Linux - all hook events from last hour
    journalctl -t cc-security --since "1 hour ago" -o json-pretty
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

SUBSYSTEM = "com.anthropic.claude-code.hooks"
CATEGORY = "security"
SYSLOG_IDENT = "cc-security"

FALLBACK_LOG_DIR = Path.home() / ".claude" / "hooks"
FALLBACK_LOG_FILE = FALLBACK_LOG_DIR / "security.log"
FALLBACK_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
FALLBACK_BACKUP_COUNT = 3

# One normalized severity table for every decision Portcullis emits, replacing
# the two partial maps that let warn/redact/block fall through to INFO. Columns:
#   OTel SeverityNumber, OTel SeverityText, python logging level (drives the
#   syslog PRI), macOS `log emit --type`, OCSF severity_id, OCSF action_id.
# Sources: OTel Logs Data Model SeverityNumber bands (9-12 INFO, 13-16 WARN,
# 17-20 ERROR); RFC 5424 Table 2 severities; OCSF Detection Finding severity_id
# {1 Info,2 Low,3 Medium,4 High} and action_id {1 Allowed,2 Denied}.
_SEV = {
    #            otel_num  otel_text  py_level            macos      ocsf_sev  ocsf_action
    "deny":    (17, "ERROR", logging.CRITICAL, "fault",   4, 2),
    "block":   (17, "ERROR", logging.CRITICAL, "fault",   4, 2),
    "redact":  (15, "WARN",  logging.WARNING,  "error",   3, 1),
    "ask":     (14, "WARN",  logging.WARNING,  "default", 3, 0),
    "warn":    (13, "WARN",  logging.WARNING,  "default", 2, 1),
    "allow":   (9,  "INFO",  logging.INFO,     "info",    1, 1),
    "debug":   (5,  "DEBUG", logging.DEBUG,    "debug",   1, 0),
}
# An unknown decision reports at WARN, never a silent INFO under-report.
_DEFAULT_SEV = (13, "WARN", logging.WARNING, "default", 3, 0)

# Known extra keys promoted to namespaced OTel-style attribute names.
_ATTR_RENAME = {"tool": "tool.name", "suppressed": "portcullis.suppressed"}

_logger: logging.Logger | None = None


def _severity(decision: str) -> tuple[int, str, int, str, int, int]:
    return _SEV.get(decision, _DEFAULT_SEV)


def _is_macos() -> bool:
    return sys.platform == "darwin"


def _syslog_socket() -> str | None:
    for path in ("/var/run/syslog", "/dev/log"):
        if os.path.exists(path):
            return path
    return None


def _build_logger() -> logging.Logger:
    logger = logging.getLogger("cc-security-hooks")
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)

    _attach_syslog_handler(logger)
    _attach_file_handler(logger)

    return logger


def _attach_syslog_handler(logger: logging.Logger) -> None:
    socket_path = _syslog_socket()
    if socket_path is None:
        return
    try:
        handler = logging.handlers.SysLogHandler(
            address=socket_path,
            facility=logging.handlers.SysLogHandler.LOG_AUTH,
        )
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter(
            f"{SYSLOG_IDENT}: %(message)s"
        ))
        logger.addHandler(handler)
    except OSError:
        pass


def _attach_file_handler(logger: logging.Logger) -> None:
    try:
        FALLBACK_LOG_DIR.mkdir(parents=True, exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(
            FALLBACK_LOG_FILE,
            maxBytes=FALLBACK_MAX_BYTES,
            backupCount=FALLBACK_BACKUP_COUNT,
            encoding="utf-8",
        )
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    except OSError:
        pass


def _emit_to_unified_log(message: str, macos_type: str) -> None:
    try:
        subprocess.run(
            [
                "log", "emit",
                "--subsystem", SUBSYSTEM,
                "--category", CATEGORY,
                "--type", macos_type,
                "--public", message,
            ],
            capture_output=True,
            timeout=2,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass


def build_event(
    hook_name: str,
    decision: str,
    *,
    pattern_matched: str | None = None,
    command: str | None = None,
    file_path: str | None = None,
    user_response: str | None = None,
    session_id: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one OTel-aligned log record with an OCSF Detection Finding projection.

    The severity fields come straight from the shared ``_SEV`` table, so the OTel
    ``SeverityNumber`` and the ``ocsf.severity_id`` never disagree and no decision
    is under-reported. All security detail lives in namespaced ``Attributes``.
    """
    otel_num, otel_text, _, _, ocsf_sev, ocsf_action = _severity(decision)

    attributes: dict[str, Any] = {
        "event.category": "security",
        "event.kind": "security_detection",
        "portcullis.guard": hook_name,
        "portcullis.decision": decision,
    }
    if pattern_matched is not None:
        attributes["portcullis.pattern"] = pattern_matched
    if command is not None:
        attributes["command.line"] = command
    if file_path is not None:
        attributes["file.path"] = file_path
    if user_response is not None:
        attributes["user.response"] = user_response
    if session_id is not None:
        attributes["session.id"] = session_id
    if extra:
        for key, value in extra.items():
            attributes[_ATTR_RENAME.get(key, f"portcullis.{key}")] = value

    attributes.update({
        "ocsf.category_uid": 2,     # Findings
        "ocsf.class_uid": 2004,     # Detection Finding
        "ocsf.activity_id": 1,      # Create
        "ocsf.type_uid": 200401,    # class_uid * 100 + activity_id
        "ocsf.severity_id": ocsf_sev,
        "ocsf.action_id": ocsf_action,
    })

    body = f"{hook_name}: {decision}"
    if pattern_matched:
        body += f" ({pattern_matched})"

    event: dict[str, Any] = {
        "Timestamp": datetime.now().astimezone().isoformat(timespec="milliseconds"),
        "ObservedTimestamp": time.time_ns(),
        "SeverityNumber": otel_num,
        "SeverityText": otel_text,
        "EventName": f"portcullis.{hook_name}",
        "Body": body,
        "Attributes": attributes,
    }
    if session_id is not None:
        event["TraceId"] = session_id
    return event


def log_security_event(
    hook_name: str,
    decision: str,
    *,
    pattern_matched: str | None = None,
    command: str | None = None,
    file_path: str | None = None,
    user_response: str | None = None,
    session_id: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Log a security event to all available backends.

    Fire-and-forget: never raises. Returns empty dict on any failure.
    """
    try:
        global _logger  # noqa: PLW0603
        if _logger is None:
            _logger = _build_logger()

        event = build_event(
            hook_name,
            decision,
            pattern_matched=pattern_matched,
            command=command,
            file_path=file_path,
            user_response=user_response,
            session_id=session_id,
            extra=extra,
        )
        message = json.dumps(event, separators=(",", ":"))

        _, _, py_level, macos_type, _, _ = _severity(decision)
        _logger.log(py_level, message)

        if _is_macos():
            _emit_to_unified_log(message, macos_type)

        return event
    except Exception:
        return {}


def clamp_and_emit(
    guard_name: str,
    natural_decision: str,
    reason: str,
    *,
    pattern_matched: str | None = None,
    command: str | None = None,
    file_path: str | None = None,
    session_id: str | None = None,
) -> dict[str, Any] | None:
    """Clamp a guard's natural decision by the tiered config, log it, and build
    the PreToolUse hook response.

    ``deny``/``ask`` -> a permissionDecision; ``warn`` -> context only
    (systemMessage); ``allow``/``off`` -> None (a config downgrade waves the call
    through). The clamp only ever loosens, so zero-false-positive-deny holds. The
    caller writes the returned dict (or ``{}`` when None) to stdout. Shared by the
    dispatcher and every standalone PreToolUse guard so the behavior is identical.
    """
    from config import effective_decision  # local import keeps config free of cycles

    decision = effective_decision(guard_name, natural_decision)
    extra = None if decision == natural_decision else {
        "natural": natural_decision,
        "config_downgraded": True,
    }
    log_security_event(
        guard_name, decision,
        pattern_matched=pattern_matched, command=command,
        file_path=file_path, session_id=session_id, extra=extra,
    )
    if decision in ("deny", "ask"):
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": reason,
            },
        }
    if decision == "warn":
        return {"systemMessage": reason}
    return None


if __name__ == "__main__":
    result = log_security_event(
        hook_name="hook-logging-selftest",
        decision="deny",
        pattern_matched="selftest",
        command="echo selftest",
        session_id="sess-123",
        extra={"test": True},
    )
    print(json.dumps(result, indent=2))
