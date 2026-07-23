#!/usr/bin/env python3
"""MCP tool monitoring guard for Claude Code.

Detects sensitive data leakage through MCP tool arguments.
MCP tools with network access can exfiltrate data via search queries,
fetch URLs, or tool arguments.

Returns "ask" if sensitive data is detected in MCP tool calls.

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

CREDENTIAL_PATTERNS = {
    "openai_key": re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    "anthropic_key": re.compile(r"sk-ant-[a-zA-Z0-9-]{20,}"),
    "github_token": re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    "github_fine_grained": re.compile(r"github_pat_[a-zA-Z0-9_]{20,}"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "private_key_header": re.compile(
        r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----"
    ),
    "jwt_token": re.compile(
        r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\."
    ),
    "slack_token": re.compile(r"xox[baprs]-[a-zA-Z0-9-]+"),
    "stripe_key": re.compile(r"(sk|pk)_(test|live)_[a-zA-Z0-9]{24,}"),
    "generic_password": re.compile(
        r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]"
    ),
}

EXFIL_INDICATORS = {
    "base64_blob": re.compile(r"[A-Za-z0-9+/]{60,}={0,2}"),
    "exfil_domain": re.compile(
        r"(ngrok\.io|requestbin\.com|hookbin\.com|pipedream\.net"
        r"|burpcollaborator\.net|interact\.sh|webhook\.site)"
    ),
    "encoded_url_data": re.compile(
        r"https?://.*[?&][^=]+=[A-Za-z0-9+/]{40,}={0,2}"
    ),
}

NETWORK_CAPABLE_PREFIXES = [
    "mcp__exa__",
    "mcp__context7__",
    "mcp__greptile__",
    "mcp__playwright__",
    "mcp__github__",
    "mcp__gitlab__",
    "mcp__linear__",
    "mcp__discord__",
    "mcp__telegram__",
    "mcp__slack__",
    "mcp__firebase__",
    "mcp__asana__",
]


def is_network_capable(tool_name: str) -> bool:
    for prefix in NETWORK_CAPABLE_PREFIXES:
        if tool_name.startswith(prefix):
            return True
    if tool_name.startswith("mcp__") and "fetch" in tool_name.lower():
        return True
    return False


def extract_all_string_values(obj, depth: int = 0) -> list[str]:
    """Recursively extract all string values from a JSON-like object."""
    if depth > 10:
        return []
    values = []
    if isinstance(obj, str):
        values.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            values.extend(extract_all_string_values(v, depth + 1))
    elif isinstance(obj, list):
        for item in obj:
            values.extend(extract_all_string_values(item, depth + 1))
    return values


def check_for_credentials(text: str) -> tuple[str, str] | None:
    for name, pattern in CREDENTIAL_PATTERNS.items():
        match = pattern.search(text)
        if match:
            return (name, match.group(0))
    return None


def check_for_exfil(text: str) -> tuple[str, str] | None:
    for name, pattern in EXFIL_INDICATORS.items():
        match = pattern.search(text)
        if match:
            return (name, match.group(0))
    return None


def format_alert(
    pattern_name: str, matched_text: str, tool_name: str, category: str,
) -> str:
    redacted = matched_text[:12] + "..." + matched_text[-4:]
    msg = f"MCP GUARD: {category} in tool arguments\n\n"
    msg += f"Tool: {tool_name}\n"
    msg += f"Pattern: {pattern_name}\n"
    msg += f"Value: {redacted}\n\n"
    msg += "Before approving:\n"
    msg += "- Is this data intended to be sent to this MCP service?\n"
    msg += "- Could this leak credentials or sensitive data?\n"
    msg += "- Does this tool need access to this information?"
    return msg


def main() -> None:
    try:
        raw = sys.stdin.read(MAX_STDIN_BYTES)
        input_data = json.loads(raw)
    except (json.JSONDecodeError, OSError, ValueError):
        json.dump({}, sys.stdout)
        return

    tool_name = input_data.get("tool_name", "")

    if not tool_name.startswith("mcp__"):
        json.dump({}, sys.stdout)
        return

    if not is_network_capable(tool_name):
        json.dump({}, sys.stdout)
        return

    tool_input = input_data.get("tool_input", {})
    all_values = extract_all_string_values(tool_input)
    combined = "\n".join(all_values)

    if not combined:
        json.dump({}, sys.stdout)
        return

    cred_result = check_for_credentials(combined)
    if cred_result:
        pattern_name, matched_text = cred_result
        if is_suppressed("mcp_guard", pattern_name=pattern_name):
            log_security_event(
                "mcp_guard", "allow",
                pattern_matched=pattern_name,
                extra={"tool": tool_name, "suppressed": True},
            )
            json.dump({}, sys.stdout)
            return

        log_security_event(
            "mcp_guard", "ask",
            pattern_matched=pattern_name,
            extra={"tool": tool_name},
        )
        response = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": format_alert(
                    pattern_name, matched_text, tool_name, "Credential",
                ),
            },
        }
        json.dump(response, sys.stdout)
        return

    exfil_result = check_for_exfil(combined)
    if exfil_result:
        pattern_name, matched_text = exfil_result
        if is_suppressed("mcp_guard", pattern_name=pattern_name):
            log_security_event(
                "mcp_guard", "allow",
                pattern_matched=pattern_name,
                extra={"tool": tool_name, "suppressed": True},
            )
            json.dump({}, sys.stdout)
            return

        log_security_event(
            "mcp_guard", "ask",
            pattern_matched=pattern_name,
            extra={"tool": tool_name},
        )
        response = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": format_alert(
                    pattern_name, matched_text, tool_name, "Exfiltration indicator",
                ),
            },
        }
        json.dump(response, sys.stdout)
        return

    log_security_event(
        "mcp_guard", "allow",
        extra={"tool": tool_name},
    )
    json.dump({}, sys.stdout)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        json.dump({}, sys.stdout)
