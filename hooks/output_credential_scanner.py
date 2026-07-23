#!/usr/bin/env python3
"""PostToolUse[Bash] output credential scanner.

Per OWASP LLM06 (Sensitive Information Disclosure):
Scans Bash command output for leaked credentials.
High-confidence matches are redacted via updatedToolOutput.
All matches emit a systemMessage warning.

Input: JSON on stdin (Claude Code PostToolUse hook format)
Output: JSON on stdout (hook response)
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

MAX_STDIN_BYTES = 1_048_576
MAX_SCAN_BYTES = 102_400

sys.path.insert(0, str(Path(__file__).parent))
from credential_guard import CREDENTIAL_PATTERNS, is_fake_value  # noqa: E402
from allowlist import is_suppressed  # noqa: E402
from hook_logging import log_security_event  # noqa: E402

HIGH_CONFIDENCE = frozenset([
    "aws_access_key", "anthropic_key", "github_token",
    "github_fine_grained", "private_key_header", "slack_token",
    "stripe_key",
])

LOW_CONFIDENCE = frozenset([
    "openai_key", "jwt_token", "generic_secret", "password_assignment",
])

SAFE_SIMPLE_COMMANDS = re.compile(
    r"^\s*(git\s+(log|diff|status|show|branch|remote|tag|rev-parse|blame)"
    r"|ls\b|find\s|wc\s|head\s|tail\s|pwd|which\s|type\s"
    r"|mkdir\s|mv\s|cp\s|trash\s|stat\s|file\s|diff\s)"
)

HAS_CHAINING = re.compile(r"[;&|]")

CREDENTIAL_SEARCH_INDICATORS = re.compile(
    r"(?i)(grep|rg|ag|ack)\s+.*(AKIA|ghp_|sk-ant|BEGIN.*PRIVATE|api.key"
    r"|secret|token|password)"
)


def is_safe_command(command: str) -> bool:
    if HAS_CHAINING.search(command):
        return False
    return bool(SAFE_SIMPLE_COMMANDS.match(command))


def is_credential_search(command: str) -> bool:
    return bool(CREDENTIAL_SEARCH_INDICATORS.search(command))


PATTERN_PRIORITY = [
    "anthropic_key", "aws_access_key", "aws_secret_key",
    "github_token", "github_fine_grained", "private_key_header",
    "slack_token", "stripe_key",
    "openai_key", "jwt_token", "generic_secret", "password_assignment",
]


def scan_output(text: str, command: str) -> dict | None:
    scan_text = text[:MAX_SCAN_BYTES]
    intentional_search = is_credential_search(command)

    high_matches: list[tuple[str, str]] = []
    low_matches: list[str] = []

    ordered_patterns = [
        (n, CREDENTIAL_PATTERNS[n])
        for n in PATTERN_PRIORITY if n in CREDENTIAL_PATTERNS
    ]

    for line in scan_text.splitlines():
        matched_spans: set[tuple[int, int]] = set()
        for name, pattern in ordered_patterns:
            match = pattern.search(line)
            if not match:
                continue
            span = (match.start(), match.end())
            if any(s <= span[0] < e for s, e in matched_spans):
                continue
            matched_text = match.group(0)
            if is_fake_value(matched_text, line):
                continue
            if is_suppressed("output_credential_scanner", pattern_name=name):
                continue
            matched_spans.add(span)
            if name in HIGH_CONFIDENCE:
                high_matches.append((name, matched_text))
            elif name in LOW_CONFIDENCE:
                low_matches.append(name)

    if not high_matches and not low_matches:
        return None

    pattern_names = [m[0] for m in high_matches] + low_matches
    command_prefix = command[:40]

    msg = (
        f"CREDENTIAL DETECTED IN COMMAND OUTPUT: "
        f"{', '.join(set(pattern_names))}\n"
        f"The output from '{command_prefix}...' contains what appears "
        f"to be a live credential.\n"
        f"Do NOT echo, log, or forward this value. "
        f"Reference it by name only.\n"
        f"If this credential was needed for a task, suggest the user "
        f"set it as an environment variable."
    )

    if high_matches and not intentional_search:
        redacted_text = text
        for name, matched_text in high_matches:
            redacted_text = redacted_text.replace(
                matched_text, f"[REDACTED: {name}]"
            )
        log_security_event(
            "output_credential_scanner", "redact",
            pattern_matched=",".join(set(m[0] for m in high_matches)),
            command=command_prefix,
        )
        return {
            "hookSpecificOutput": {"updatedToolOutput": redacted_text},
            "systemMessage": msg,
        }

    decision = "warn_high" if high_matches else "warn_low"
    log_security_event(
        "output_credential_scanner", decision,
        pattern_matched=",".join(set(pattern_names)),
        command=command_prefix,
    )
    return {"systemMessage": msg}


def main() -> None:
    try:
        raw = sys.stdin.read(MAX_STDIN_BYTES)
        data = json.loads(raw)
    except Exception:
        json.dump({}, sys.stdout)
        return

    tool_input = data.get("tool_input", {})
    command = tool_input.get("command", "")

    if is_safe_command(command):
        json.dump({}, sys.stdout)
        return

    response_text = data.get("tool_response", "")
    if not isinstance(response_text, str):
        response_text = json.dumps(response_text) if response_text else ""

    if not response_text:
        json.dump({}, sys.stdout)
        return

    result = scan_output(response_text, command)
    json.dump(result if result else {}, sys.stdout)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        json.dump({}, sys.stdout)
