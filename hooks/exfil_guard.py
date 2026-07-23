#!/usr/bin/env python3
"""Exfiltration guard hook for Claude Code.

Detects data exfiltration patterns in Bash commands.
Returns "ask" so the user can approve or deny.

Input: JSON on stdin (Claude Code PreToolUse hook format)
Output: JSON on stdout (hook response)
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

MAX_STDIN_BYTES = 1_048_576  # 1 MiB guard against oversized input

sys.path.insert(0, str(Path(__file__).parent))
from allowlist import is_suppressed  # noqa: E402
from hook_logging import log_security_event  # noqa: E402

EXFIL_PATTERNS = {
    "base64_in_url": re.compile(
        r"https?://.*[?&][^=]+=[A-Za-z0-9+/]{40,}={0,2}"
    ),
    "data_in_url": re.compile(
        r"https?://[^/]+/.*[?&](data|key|secret|password|token)="
    ),
    "curl_post_data": re.compile(
        r"curl\s+.*(-d\s+|--data\s+|--data-raw\s+|--data-binary\s+)"
    ),
    "wget_post": re.compile(
        r"wget\s+.*--post-(data|file)"
    ),
    "nc_connect": re.compile(
        r"(nc|ncat|netcat)\s+.*(-e|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"
    ),
    "exfil_domains": re.compile(
        r"(ngrok\.io|requestbin\.com|hookbin\.com|pipedream\.net"
        r"|burpcollaborator\.net|interact\.sh|canarytokens\.com|webhook\.site)"
    ),
    "pipe_to_network": re.compile(
        r"\|\s*(curl|wget|nc|ncat)"
    ),
    "sensitive_in_curl": re.compile(
        r"curl\s+.*(https?://.*\b(sk-|ghp_|AKIA)[a-zA-Z0-9_/-]*"
        r"|-H\s+['\"]Authorization:\s*(Bearer\s+)?[a-zA-Z0-9_-]{20,})"
    ),
    "bash_credential_write": re.compile(
        r"(echo|printf|cat|tee)\s+.*"
        r"\b(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}"
        r"|AKIA[0-9A-Z]{16}"
        r"|-----BEGIN\s+\w+\s+PRIVATE\s+KEY-----)\b"
        r".*(>|>>|\|.*tee)"
    ),
}

ALLOWLIST_PATTERNS = [
    re.compile(r"^curl\s+(-[sSkLfO#]+\s+)*https?://"),
    re.compile(r"curl\s+.*(localhost|127\.0\.0\.1|::1|\[::1\])"),
    re.compile(r"^git\s+(push|pull|fetch|clone|remote)\b"),
    re.compile(r"^(npm|cargo|pnpm)\s+publish\b"),
]

CURL_HAS_DATA_FLAG = re.compile(
    r"curl\s+.*(-d\s|--data|--data-raw|--data-binary|-F\s|--form\s"
    r"|--upload-file|-T\s)"
)


def is_allowlisted(command: str) -> bool:
    for pattern in ALLOWLIST_PATTERNS:
        if pattern.search(command):
            if pattern is ALLOWLIST_PATTERNS[0]:
                if CURL_HAS_DATA_FLAG.search(command):
                    continue
                return True
            return True
    return False


NEVER_ALLOWLIST = {
    "exfil_domains", "nc_connect", "bash_credential_write", "sensitive_in_curl",
}

HARD_DENY_PATTERNS: frozenset[str] = frozenset([
    "exfil_domains", "nc_connect",
])


def check_command(command: str) -> tuple[str, str] | None:
    """Return (pattern_name, matched_text) or None."""
    for name in NEVER_ALLOWLIST:
        match = EXFIL_PATTERNS[name].search(command)
        if match:
            return (name, match.group(0))

    if is_allowlisted(command):
        return None

    for name, pattern in EXFIL_PATTERNS.items():
        if name in NEVER_ALLOWLIST:
            continue
        match = pattern.search(command)
        if match:
            return (name, match.group(0))

    return None


PATTERN_RISKS = {
    "base64_in_url": "Base64-encoded data in URL parameter",
    "data_in_url": "Sensitive keyword in URL parameter",
    "curl_post_data": "Sending data via HTTP POST",
    "wget_post": "Sending data via wget POST",
    "nc_connect": "Netcat connection to remote host",
    "exfil_domains": "Known exfiltration/tunneling domain",
    "pipe_to_network": "Piping data to network tool",
    "sensitive_in_curl": "Credential pattern in curl command",
    "bash_credential_write": "Writing credential to file via shell",
}


def format_alert(pattern_name: str, matched_text: str) -> str:
    risk = PATTERN_RISKS.get(pattern_name, "Potential data exfiltration")
    msg = f"EXFIL GUARD: {pattern_name}\n\n"
    msg += f"Matched: {matched_text[:120]}\n"
    msg += f"Risk: {risk}\n\n"
    msg += "Before approving:\n"
    msg += "- Is this destination trusted?\n"
    msg += "- Is sensitive data included?\n"
    msg += "- Could this be done without network access?"
    return msg


def main() -> None:
    """Entry point: read stdin, check for exfiltration patterns."""
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

    result = check_command(command)

    if result is None:
        log_security_event(
            "exfil_guard", "allow", command=command,
        )
        json.dump({}, sys.stdout)
        return

    pattern_name, matched_text = result

    if is_suppressed("exfil_guard", pattern_name=pattern_name):
        log_security_event(
            "exfil_guard", "allow",
            pattern_matched=pattern_name, command=command,
            extra={"suppressed": True},
        )
        json.dump({}, sys.stdout)
        return

    decision = "deny" if pattern_name in HARD_DENY_PATTERNS else "ask"
    log_security_event(
        "exfil_guard", decision,
        pattern_matched=pattern_name, command=command,
    )

    response = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": format_alert(
                pattern_name, matched_text
            ),
        },
    }
    json.dump(response, sys.stdout)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        json.dump({}, sys.stdout)
