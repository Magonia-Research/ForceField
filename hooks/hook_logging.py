"""Cross-platform security event logging for Claude Code hooks.

Logs to OS-native systems with JSON Lines fallback file.

macOS: Unified Logging via `log emit` (subsystem/category tagging),
       plus SysLogHandler to /var/run/syslog as secondary.
Linux: SysLogHandler to /dev/log (feeds into journald on systemd).
Both:  RotatingFileHandler to ~/.claude/hooks/security.log.

Query examples:

    # macOS - all hook events from last hour
    log show --predicate 'subsystem == "com.anthropic.claude-code.hooks"' \
        --style ndjson --last 1h

    # macOS - only deny decisions
    log show --predicate 'subsystem == "com.anthropic.claude-code.hooks" \
        AND composedMessage CONTAINS "deny"' --style ndjson --last 1h

    # macOS - stream live
    log stream --predicate 'subsystem == "com.anthropic.claude-code.hooks"'

    # macOS - enable info/debug persistence for this subsystem
    sudo log config --subsystem com.anthropic.claude-code.hooks \
        --mode level:debug,persist:info

    # Linux - all hook events from last hour
    journalctl -t cc-security --since "1 hour ago" -o json-pretty

    # Linux - only deny decisions
    journalctl -t cc-security --since "1 hour ago" -o json | \
        jq 'select(.MESSAGE | contains("deny"))'

    # Fallback file - tail or parse JSON Lines
    tail -f ~/.claude/hooks/security.log
    jq -c 'select(.decision == "deny")' ~/.claude/hooks/security.log
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

SUBSYSTEM = "com.anthropic.claude-code.hooks"
CATEGORY = "security"
SYSLOG_IDENT = "cc-security"

FALLBACK_LOG_DIR = Path.home() / ".claude" / "hooks"
FALLBACK_LOG_FILE = FALLBACK_LOG_DIR / "security.log"
FALLBACK_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
FALLBACK_BACKUP_COUNT = 3

_MACOS_TYPE_MAP = {
    "deny": "error",
    "ask": "default",
    "allow": "info",
    "debug": "debug",
}

_SYSLOG_PRIORITY_MAP = {
    "deny": logging.WARNING,
    "ask": logging.WARNING,
    "allow": logging.INFO,
    "debug": logging.DEBUG,
}

_logger: logging.Logger | None = None


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


def _emit_to_unified_log(message: str, decision: str) -> None:
    log_type = _MACOS_TYPE_MAP.get(decision, "default")
    try:
        subprocess.run(
            [
                "log", "emit",
                "--subsystem", SUBSYSTEM,
                "--category", CATEGORY,
                "--type", log_type,
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
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "epoch": time.time(),
        "hook": hook_name,
        "decision": decision,
    }
    if pattern_matched is not None:
        event["pattern"] = pattern_matched
    if command is not None:
        event["command"] = command
    if file_path is not None:
        event["file"] = file_path
    if user_response is not None:
        event["user_response"] = user_response
    if extra:
        event.update(extra)
    return event


def log_security_event(
    hook_name: str,
    decision: str,
    *,
    pattern_matched: str | None = None,
    command: str | None = None,
    file_path: str | None = None,
    user_response: str | None = None,
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
            extra=extra,
        )
        message = json.dumps(event, separators=(",", ":"))

        level = _SYSLOG_PRIORITY_MAP.get(decision, logging.INFO)
        _logger.log(level, message)

        if _is_macos():
            _emit_to_unified_log(message, decision)

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
        file_path=file_path, extra=extra,
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
        extra={"test": True},
    )
    print(json.dumps(result, indent=2))
