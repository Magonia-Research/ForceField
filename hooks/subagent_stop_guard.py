#!/usr/bin/env python3
"""SubagentStop output validation hook.

Per OWASP LLM02 (Insecure Output Handling):
Validates subagent output before the parent trusts it.
Scans last_assistant_message for credential leaks, prompt
injection targeting the parent, and exfiltration staging.

Input: JSON on stdin (Claude Code SubagentStop hook format)
Output: JSON on stdout (hook response)
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

MAX_STDIN_BYTES = 1_048_576

sys.path.insert(0, str(Path(__file__).parent))
from credential_guard import CREDENTIAL_PATTERNS, is_fake_value  # noqa: E402
from hook_logging import log_security_event  # noqa: E402

INJECTION_TARGETING_PARENT = re.compile(
    r"(?i)(ignore\s+(previous|prior|all|your)\s+(instructions?|rules?|constraints?)"
    r"|disregard\s+(safety|security|rules?|instructions?)"
    r"|override\s+(all|previous|prior)\s+(rules?|instructions?)"
    r"|new\s+instructions?\s*:"
    r"|<\s*/?\s*(system|system-reminder|tool_result|function_results)\s*>)"
)

EMBEDDED_COMMANDS = re.compile(
    r"(?m)(^```(?:bash|sh|shell|zsh)\s*\n.*?(rm\s+-rf|curl\s+.*\|\s*bash"
    r"|sudo\s+|chmod\s+777|nc\s+.*-e).*?\n```"
    r"|\$\(.*?(rm|curl|wget|nc|ncat).*?\))",
    re.DOTALL,
)

EXFIL_IN_OUTPUT = {
    "base64_blob": re.compile(r"[A-Za-z0-9+/]{200,}={0,2}"),
    "exfil_url": re.compile(
        r"https?://(ngrok\.io|requestbin\.com|hookbin\.com"
        r"|pipedream\.net|burpcollaborator\.net|interact\.sh"
        r"|canarytokens\.com|webhook\.site)"
    ),
    "data_uri": re.compile(r"data:[^;]{1,50};base64,[A-Za-z0-9+/]{100,}"),
}


def check_output_credentials(text: str) -> dict | None:
    for line in text.splitlines():
        for name, pattern in CREDENTIAL_PATTERNS.items():
            match = pattern.search(line)
            if match and not is_fake_value(match.group(0), line):
                redacted = match.group(0)[:8] + "..." + match.group(0)[-4:]
                log_security_event(
                    "subagent_stop_guard", "deny",
                    pattern_matched=f"output_credential:{name}",
                )
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "SubagentStop",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": (
                            "SUBAGENT OUTPUT GUARD: Credential detected in "
                            "subagent response\n\n"
                            f"Pattern: {name}\n"
                            f"Value: {redacted}\n\n"
                            "The subagent's response contains what appears to "
                            "be a credential.\nThis output should NOT be "
                            "trusted or forwarded."
                        ),
                    },
                }
    return None


def check_output_injection(text: str) -> dict | None:
    match = INJECTION_TARGETING_PARENT.search(text)
    if match:
        log_security_event(
            "subagent_stop_guard", "ask",
            pattern_matched="output_injection",
        )
        return {
            "hookSpecificOutput": {
                "hookEventName": "SubagentStop",
                "permissionDecision": "ask",
                "permissionDecisionReason": (
                    "SUBAGENT OUTPUT GUARD: Prompt injection in subagent "
                    "response\n\n"
                    f"Matched: {match.group(0)[:80]}\n\n"
                    "The subagent's output contains language that may "
                    "attempt to\nmanipulate the parent agent's behavior.\n\n"
                    "Review the output carefully before acting on it."
                ),
            },
        }
    return None


def check_output_commands(text: str) -> dict | None:
    match = EMBEDDED_COMMANDS.search(text)
    if match:
        log_security_event(
            "subagent_stop_guard", "ask",
            pattern_matched="output_embedded_commands",
        )
        return {
            "hookSpecificOutput": {
                "hookEventName": "SubagentStop",
                "permissionDecision": "ask",
                "permissionDecisionReason": (
                    "SUBAGENT OUTPUT GUARD: Dangerous commands in subagent "
                    "response\n\n"
                    f"Matched: {match.group(0)[:80]}\n\n"
                    "The subagent's output contains shell commands that "
                    "could be\nharmful if executed by the parent agent.\n\n"
                    "Verify these commands are safe before proceeding."
                ),
            },
        }
    return None


def check_output_exfil(text: str) -> dict | None:
    for name, pattern in EXFIL_IN_OUTPUT.items():
        match = pattern.search(text)
        if match:
            log_security_event(
                "subagent_stop_guard", "ask",
                pattern_matched=f"output_exfil:{name}",
            )
            return {
                "hookSpecificOutput": {
                    "hookEventName": "SubagentStop",
                    "permissionDecision": "ask",
                    "permissionDecisionReason": (
                        "SUBAGENT OUTPUT GUARD: Exfiltration indicator in "
                        "subagent response\n\n"
                        f"Pattern: {name}\n\n"
                        "The subagent's output contains encoded data or "
                        "exfiltration\nURLs that may stage data leakage.\n\n"
                        "Verify this content is expected before acting on it."
                    ),
                },
            }
    return None


def main() -> None:
    try:
        raw = sys.stdin.read(MAX_STDIN_BYTES)
        data = json.loads(raw)
    except Exception:
        json.dump({}, sys.stdout)
        return

    text = data.get("last_assistant_message", "")
    if not text:
        json.dump({}, sys.stdout)
        return

    checks = [
        check_output_credentials(text),
        check_output_injection(text),
        check_output_commands(text),
        check_output_exfil(text),
    ]

    precedence = {"deny": 3, "ask": 2, "allow": 1}
    best = None
    best_prec = 0
    for result in checks:
        if result is None:
            continue
        decision = result["hookSpecificOutput"]["permissionDecision"]
        prec = precedence.get(decision, 0)
        if prec > best_prec:
            best = result
            best_prec = prec

    if best:
        json.dump(best, sys.stdout)
    else:
        log_security_event("subagent_stop_guard", "allow")
        json.dump({}, sys.stdout)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        json.dump({}, sys.stdout)
