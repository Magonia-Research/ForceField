#!/usr/bin/env python3
"""Consolidated security dispatcher for Claude Code Bash hooks.

Runs exfil_guard + supply_chain_guard in a single Python process,
eliminating two extra interpreter cold-starts (~100ms saved).

Input: JSON on stdin (Claude Code PreToolUse hook format)
Output: JSON on stdout (hook response)

Returns the highest-precedence decision (deny > ask > allow).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from exfil_guard import check_command as exfil_check  # noqa: E402
from exfil_guard import format_alert as exfil_format  # noqa: E402
from exfil_guard import HARD_DENY_PATTERNS as EXFIL_HARD_DENY  # noqa: E402
from supply_chain_guard import (  # noqa: E402
    check_dangerous,
    check_typosquat,
    format_danger_alert,
    format_typosquat_alert,
    is_allowlisted as supply_allowlisted,
    HARD_DENY_PATTERNS as SUPPLY_HARD_DENY,
)
from allowlist import is_suppressed  # noqa: E402
from hook_logging import log_security_event  # noqa: E402

MAX_STDIN_BYTES = 1_048_576  # 1 MiB guard against oversized input


def run_exfil_guard(command: str) -> dict[str, object] | None:
    """Run exfil guard checks. Returns response dict or None."""
    result = exfil_check(command)
    if result is None:
        return None

    pattern_name, matched_text = result
    if is_suppressed("exfil_guard", pattern_name=pattern_name):
        log_security_event(
            "exfil_guard", "allow",
            pattern_matched=pattern_name, command=command,
            extra={"suppressed": True},
        )
        return None

    decision = "deny" if pattern_name in EXFIL_HARD_DENY else "ask"
    log_security_event(
        "exfil_guard", decision,
        pattern_matched=pattern_name, command=command,
    )
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": exfil_format(
                pattern_name, matched_text
            ),
        },
    }


def run_supply_chain_guard(command: str) -> dict[str, object] | None:
    """Run supply chain guard checks. Returns response dict or None."""
    typo_result = check_typosquat(command)
    if typo_result:
        typo, correct, installer = typo_result
        pattern_key = f"typosquat:{typo}"
        if is_suppressed("supply_chain_guard", pattern_name=pattern_key):
            log_security_event(
                "supply_chain_guard", "allow",
                pattern_matched=pattern_key, command=command,
                extra={"suppressed": True},
            )
            return None
        log_security_event(
            "supply_chain_guard", "ask",
            pattern_matched=pattern_key, command=command,
        )
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": format_typosquat_alert(
                    typo, correct, installer
                ),
            },
        }

    if supply_allowlisted(command):
        return None

    danger_result = check_dangerous(command)
    if danger_result:
        pattern_name, matched_text = danger_result
        if is_suppressed("supply_chain_guard", pattern_name=pattern_name):
            log_security_event(
                "supply_chain_guard", "allow",
                pattern_matched=pattern_name, command=command,
                extra={"suppressed": True},
            )
            return None
        decision = "deny" if pattern_name in SUPPLY_HARD_DENY else "ask"
        log_security_event(
            "supply_chain_guard", decision,
            pattern_matched=pattern_name, command=command,
        )
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": format_danger_alert(
                    pattern_name, matched_text
                ),
            },
        }

    return None


_DECISION_PRECEDENCE = {"deny": 3, "ask": 2, "allow": 1}


def _pick_highest(
    a: dict[str, object] | None, b: dict[str, object] | None,
) -> dict[str, object] | None:
    """Return whichever result has the highest-precedence decision.

    Per docs: deny > ask > allow.
    """
    if a is None:
        return b
    if b is None:
        return a
    dec_a = a.get("hookSpecificOutput", {}).get("permissionDecision", "allow")
    dec_b = b.get("hookSpecificOutput", {}).get("permissionDecision", "allow")
    if _DECISION_PRECEDENCE.get(dec_b, 0) > _DECISION_PRECEDENCE.get(dec_a, 0):
        return b
    return a


def main() -> None:
    """Dispatch stdin through exfil and supply-chain guards."""
    try:
        raw = sys.stdin.read(MAX_STDIN_BYTES)
        input_data = json.loads(raw)
    except (json.JSONDecodeError, OSError, ValueError):
        json.dump({}, sys.stdout)
        return

    tool_input = input_data.get("tool_input", {})
    command = tool_input.get("command", "")

    if not command:
        json.dump({}, sys.stdout)
        return

    exfil_result = run_exfil_guard(command)
    supply_result = run_supply_chain_guard(command)

    winner = _pick_highest(exfil_result, supply_result)
    if winner:
        json.dump(winner, sys.stdout)
        return

    log_security_event("security_dispatcher", "allow", command=command)
    json.dump({}, sys.stdout)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        json.dump({}, sys.stdout)
