#!/usr/bin/env python3
"""Consolidated security dispatcher for Claude Code Bash hooks.

Runs exfil_guard + supply_chain_guard + git_guard in a single Python process,
eliminating extra interpreter cold-starts.

Input: JSON on stdin (Claude Code PreToolUse hook format)
Output: JSON on stdout (hook response)

Returns the highest-precedence decision (deny > ask > allow).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from patterns import MAX_STDIN_BYTES, DECISION_PRECEDENCE as _DECISION_PRECEDENCE  # noqa: E402
from exfil_guard import check_command as exfil_check  # noqa: E402
from exfil_guard import format_alert as exfil_format  # noqa: E402
from exfil_guard import HARD_DENY_PATTERNS as EXFIL_HARD_DENY  # noqa: E402
from supply_chain_guard import (  # noqa: E402
    check_dangerous,
    check_typosquat,
    format_danger_alert,
    format_typosquat_alert,
    allowlist_clears_danger,
    HARD_DENY_PATTERNS as SUPPLY_HARD_DENY,
)
from git_guard import check_git  # noqa: E402
from git_guard import format_alert as git_format  # noqa: E402
from git_guard import HARD_DENY_PATTERNS as GIT_HARD_DENY  # noqa: E402
from credential_access_guard import check_command as cred_access_check  # noqa: E402
from credential_access_guard import format_alert as cred_access_format  # noqa: E402
from credential_access_guard import HARD_DENY_PATTERNS as CRED_ACCESS_HARD_DENY  # noqa: E402
from allowlist import is_suppressed  # noqa: E402
from hook_logging import log_security_event, clamp_and_emit  # noqa: E402


def _finish(
    guard_name: str,
    natural_decision: str,
    command: str,
    pattern_name: str,
    reason: str,
    session_id: str | None = None,
) -> dict[str, object] | None:
    """Clamp a guard's natural decision by config, log it, and build the response.

    Thin wrapper over ``hook_logging.clamp_and_emit`` so the dispatcher and the
    standalone guards share one clamp / warn / wave-through implementation.
    """
    return clamp_and_emit(
        guard_name, natural_decision, reason,
        pattern_matched=pattern_name, command=command, session_id=session_id,
    )


def run_exfil_guard(command: str, session_id: str | None = None) -> dict[str, object] | None:
    """Run exfil guard checks. Returns response dict or None."""
    result = exfil_check(command)
    if result is None:
        return None

    pattern_name, matched_text = result
    is_hard_deny = pattern_name in EXFIL_HARD_DENY
    if not is_hard_deny and is_suppressed("exfil_guard", pattern_name=pattern_name):
        log_security_event(
            "exfil_guard", "allow",
            pattern_matched=pattern_name, command=command,
            session_id=session_id, extra={"suppressed": True},
        )
        return None

    natural = "deny" if is_hard_deny else "ask"
    return _finish(
        "exfil_guard", natural, command, pattern_name,
        exfil_format(pattern_name, matched_text), session_id,
    )


def run_supply_chain_guard(command: str, session_id: str | None = None) -> dict[str, object] | None:
    """Run supply chain guard checks. Returns response dict or None."""
    typo_result = check_typosquat(command)
    if typo_result:
        typo, correct, installer = typo_result
        pattern_key = f"typosquat:{typo}"
        if is_suppressed("supply_chain_guard", pattern_name=pattern_key):
            log_security_event(
                "supply_chain_guard", "allow",
                pattern_matched=pattern_key, command=command,
                session_id=session_id, extra={"suppressed": True},
            )
            return None
        return _finish(
            "supply_chain_guard", "ask", command, pattern_key,
            format_typosquat_alert(typo, correct, installer), session_id,
        )

    danger_result = check_dangerous(command)
    if danger_result:
        pattern_name, matched_text = danger_result
        is_hard_deny = pattern_name in SUPPLY_HARD_DENY
        # A hard-deny (pipe-to-shell, fetch-exec) is never waved through by the
        # command allowlist or a per-project suppression; only ask-severity
        # patterns honor those layers. The allowlist is scoped to the segment
        # that carries the danger, so a benign install prefix cannot launder a
        # dangerous segment elsewhere in a compound command.
        if not is_hard_deny and (
            is_suppressed("supply_chain_guard", pattern_name=pattern_name)
            or allowlist_clears_danger(command, pattern_name)
        ):
            log_security_event(
                "supply_chain_guard", "allow",
                pattern_matched=pattern_name, command=command,
                session_id=session_id, extra={"suppressed": True},
            )
            return None
        natural = "deny" if is_hard_deny else "ask"
        return _finish(
            "supply_chain_guard", natural, command, pattern_name,
            format_danger_alert(pattern_name, matched_text), session_id,
        )

    return None


def run_git_guard(command: str, session_id: str | None = None) -> dict[str, object] | None:
    """Run git repo-execution guard checks. Returns response dict or None."""
    result = check_git(command)
    if result is None:
        return None

    pattern_name, matched_text = result
    is_hard_deny = pattern_name in GIT_HARD_DENY
    if not is_hard_deny and is_suppressed("git_guard", pattern_name=pattern_name):
        log_security_event(
            "git_guard", "allow",
            pattern_matched=pattern_name, command=command,
            session_id=session_id, extra={"suppressed": True},
        )
        return None

    natural = "deny" if is_hard_deny else "ask"
    return _finish(
        "git_guard", natural, command, pattern_name,
        git_format(pattern_name, matched_text), session_id,
    )


def run_credential_access_guard(command: str, session_id: str | None = None) -> dict[str, object] | None:
    """Run credential-file read guard checks. Returns response dict or None."""
    result = cred_access_check(command)
    if result is None:
        return None

    pattern_name, matched_text = result
    is_hard_deny = pattern_name in CRED_ACCESS_HARD_DENY
    if not is_hard_deny and is_suppressed("credential_access_guard", pattern_name=pattern_name):
        log_security_event(
            "credential_access_guard", "allow",
            pattern_matched=pattern_name, command=command,
            session_id=session_id, extra={"suppressed": True},
        )
        return None

    natural = "deny" if is_hard_deny else "ask"
    return _finish(
        "credential_access_guard", natural, command, pattern_name,
        cred_access_format(pattern_name, matched_text), session_id,
    )


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


def _emit_ask_uninspectable() -> None:
    """Emit an 'ask' when stdin is too large or malformed to inspect.

    Closes the fail-open hole where a payload larger than MAX_STDIN_BYTES truncates
    and the JSON parse fails: rather than a silent allow, prompt the user. Never a
    hard block (zero-false-positive-deny), never a silent pass.
    """
    log_security_event(
        "security_dispatcher", "ask", command="<uninspectable>",
        extra={"reason": "oversized_or_unparseable_input"},
    )
    json.dump({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": (
                "Portcullis could not inspect this Bash command: the hook input "
                f"exceeds {MAX_STDIN_BYTES} bytes or is malformed. Approve only if "
                "you trust this command."
            ),
        },
    }, sys.stdout)


def main() -> None:
    """Dispatch stdin through exfil and supply-chain guards."""
    raw = sys.stdin.read(MAX_STDIN_BYTES + 1)
    oversized = len(raw) > MAX_STDIN_BYTES
    try:
        input_data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        input_data = None

    if oversized or (raw.strip() and input_data is None):
        _emit_ask_uninspectable()
        return
    if not isinstance(input_data, dict):
        json.dump({}, sys.stdout)
        return

    tool_input = input_data.get("tool_input", {})
    command = tool_input.get("command", "") if isinstance(tool_input, dict) else ""
    session_id = input_data.get("session_id")
    if not isinstance(session_id, str):
        session_id = None

    if not command:
        json.dump({}, sys.stdout)
        return

    exfil_result = run_exfil_guard(command, session_id)
    supply_result = run_supply_chain_guard(command, session_id)
    git_result = run_git_guard(command, session_id)
    cred_result = run_credential_access_guard(command, session_id)

    winner = _pick_highest(
        _pick_highest(_pick_highest(exfil_result, supply_result), git_result),
        cred_result,
    )
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
